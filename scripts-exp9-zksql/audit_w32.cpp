// w32 harness (ours, not part of ZKSQL). Structure copied from bench/zksql-feas/harness/audit_test.cpp (itself a copy of the structure of
// ZKSQL's test/tpch_test.cpp): filter + COUNT/SUM through ZKSQL's own plan parser and operators.
// Additions against the feasibility harness: RESULT_SETUP_S (VOLE setup + connect, before the test body), RESULT_TEARDOWN_S (the finalize =
// cheat check + closing the sockets, i.e. ZkTest::TearDown), RESULT_GTEST_PASSED (0 if the cheat check or the plaintext comparison failed),
// RESULT_PEAK_RSS_KB_END (getrusage at the very end), RESULT_PROC_WALL_S (wall of this process from main()).
// Env: ZK_DB (database name; Bob uses an empty database with the same schema), ZK_PLAN (plan name -> conf/plans/zk-<ZK_PLAN>.json relative to cwd),
//      ZK_SQL (plaintext reference query; Alice only).
// Output lines "RESULT_*" are what analyze_w32.py reads. Bytes = bytes SENT by this party (emp NetIO counter) up to the end of the test body;
// the finalize message (constant, small) is not counted.
#include <gflags/gflags.h>
#include <gtest/gtest.h>
#include <operators/sql_input.h>
#include <parser/plan_parser.h>
#include <test/support/zk_base_test.h>
#include <ctime>
#include <cstdlib>
#include <chrono>
#include <sys/resource.h>

using namespace emp;
using namespace vaultdb;

DEFINE_int32(party, 1, "party for EMP execution");
DEFINE_int32(port, 54321, "port for EMP execution");
DEFINE_string(alice_host, "127.0.0.1", "alice hostname for execution");

typedef std::chrono::steady_clock W32Clock;
static W32Clock::time_point g_main_start;
static W32Clock::time_point g_body_start;
static W32Clock::time_point g_body_end;
static bool g_body_started = false, g_body_ended = false;
static double secs(W32Clock::time_point a, W32Clock::time_point b) { return std::chrono::duration<double>(b - a).count(); }

class AuditTest : public ZkTest {
public:
    AuditTest() { const char *d = getenv("ZK_DB"); if(d) db_name_ = d; }
    void TearDown() override {
        g_body_ended = true;                       // (also reached after an ASSERT failure in the body)
        g_body_end = W32Clock::now();
        ZkTest::TearDown();                         // gv.reset(); finalize_zk_bool (the cheat check); closes the sockets
        double td = secs(g_body_end, W32Clock::now());
        std::cout << "RESULT_TEARDOWN_S " << td << std::endl;
    }
};

struct BodyGuard { ~BodyGuard() { g_body_end = W32Clock::now(); } };

class W32Listener : public ::testing::EmptyTestEventListener {
    void OnTestEnd(const ::testing::TestInfo &ti) override {
        std::cout << "RESULT_GTEST_PASSED " << (ti.result()->Passed() ? 1 : 0) << std::endl;
        struct rusage ru;
        if(!getrusage(RUSAGE_SELF, &ru)) std::cout << "RESULT_PEAK_RSS_KB_END " << ru.ru_maxrss << std::endl;
        std::cout << "RESULT_PROC_WALL_S " << secs(g_main_start, W32Clock::now()) << std::endl;
    }
};

TEST_F(AuditTest, run) {
    g_body_start = W32Clock::now();
    g_body_started = true;
    BodyGuard guard;
    std::string plan = getenv("ZK_PLAN") ? getenv("ZK_PLAN") : "w32_n10000_s10";
    std::string sql  = getenv("ZK_SQL")  ? getenv("ZK_SQL")  : "";
    std::cout << "RESULT_PARTY " << FLAGS_party << " db " << db_name_ << " plan " << plan << std::endl;
    std::cout << "RESULT_SETUP_S " << secs(g_main_start, g_body_start) << std::endl;   // from main() to here = VOLE setup + connect (SetUp)
    std::cout << "RESULT_INITIAL_RSS_BYTES " << Utilities::checkMemoryUtilization(false) << std::endl;

    // plaintext reference (Alice only): the same SQL, on PostgreSQL
    auto t_plain = clock_start();
    shared_ptr<PlainTable> expected;
    if(FLAGS_party == ALICE && !sql.empty()) expected = DataUtilities::getExpectedResults(db_name_, sql, false, 0);
    std::cout << "RESULT_PLAINTEXT_S " << time_from(t_plain) / 1e6 << std::endl;

    // plan parsing includes SqlInput = reading the table from PostgreSQL (Alice) + committing it (Alice and Bob; VOLE authentication)
    auto t_commit = clock_start();
    uint64_t c0 = ios_[0]->io->counter;
    PlanParser plan_reader(db_name_, plan, ios_[0], FLAGS_party, -1);
    shared_ptr<Operator> root = plan_reader.getRoot();
    double commit_s = time_from(t_commit) / 1e6;
    uint64_t c1 = ios_[0]->io->counter;
    std::cout << "RESULT_COMMIT_S " << commit_s << std::endl;
    std::cout << "RESULT_COMMIT_SENT_BYTES " << (c1 - c0) << std::endl;

    auto t_run = clock_start();
    ZkQueryTable result = root->run();
    double run_s = time_from(t_run) / 1e6;
    uint64_t c2 = ios_[0]->io->counter;
    std::cout << "RESULT_QUERY_S " << run_s << std::endl;
    std::cout << "RESULT_QUERY_SENT_BYTES " << (c2 - c1) << std::endl;
    std::cout << "RESULT_PEAK_RSS_BYTES " << Utilities::checkMemoryUtilization(false) << std::endl;

    shared_ptr<PlainTable> observed = result.secure_table_->reveal(PUBLIC);
    observed = DataUtilities::removeDummies(observed);
    std::cout << "RESULT_REVEALED " << observed->toString() << std::endl;
    std::cout << "RESULT_TOTAL_SENT_BYTES_PRE_FINALIZE " << ios_[0]->io->counter << std::endl;
    if(FLAGS_party == ALICE && expected) {
        expected = DataUtilities::removeDummies(expected);
        ASSERT_EQ(*expected, *observed);
        std::cout << "RESULT_MATCHES_PLAINTEXT 1" << std::endl;
    }
}

int main(int argc, char **argv) {
    g_main_start = W32Clock::now();
    ::testing::InitGoogleTest(&argc, argv);
    gflags::ParseCommandLineFlags(&argc, &argv, false);
    ::testing::TestEventListeners &ls = ::testing::UnitTest::GetInstance()->listeners();
    ls.Append(new W32Listener);
    return RUN_ALL_TESTS();
}
