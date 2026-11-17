// pqzbench: Exp 5 (w45) load generator for Hyperledger Fabric 2.5.16 (fabric-gateway Go client).
package main

import (
	"context"
	"crypto/sha3"
	"crypto/x509"
	"encoding/binary"
	"flag"
	"fmt"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/hash"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"
)

const payloadLen = 13531

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(2)
	}
}

func readOne(dir string) []byte {
	es, err := os.ReadDir(dir)
	must(err)
	b, err := os.ReadFile(filepath.Join(dir, es[0].Name()))
	must(err)
	return b
}

type conn struct {
	g *client.Gateway
	c *client.Contract
	q *client.Contract
}

func connect(tn, channel, cc string, n int) []conn {
	org := filepath.Join(tn, "organizations", "peerOrganizations", "org1.example.com")
	tlsPEM, err := os.ReadFile(filepath.Join(org, "peers", "peer0.org1.example.com", "tls", "ca.crt"))
	must(err)
	tc, err := identity.CertificateFromPEM(tlsPEM)
	must(err)
	pool := x509.NewCertPool()
	pool.AddCert(tc)
	cert, err := identity.CertificateFromPEM(readOne(filepath.Join(org, "users", "User1@org1.example.com", "msp", "signcerts")))
	must(err)
	id, err := identity.NewX509Identity("Org1MSP", cert)
	must(err)
	key, err := identity.PrivateKeyFromPEM(readOne(filepath.Join(org, "users", "User1@org1.example.com", "msp", "keystore")))
	must(err)
	sign, err := identity.NewPrivateKeySign(key)
	must(err)
	var out []conn
	for i := 0; i < n; i++ {
		gc, err := grpc.NewClient("localhost:7051", grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(pool, "peer0.org1.example.com")))
		must(err)
		gw, err := client.Connect(id, client.WithSign(sign), client.WithHash(hash.SHA256), client.WithClientConnection(gc))
		must(err)
		net := gw.GetNetwork(channel)
		out = append(out, conn{gw, net.GetContract(cc), net.GetContract("qscc")})
	}
	return out
}

func height(c conn, channel string) uint64 {
	b, err := c.q.EvaluateTransaction("GetChainInfo", channel)
	must(err)
	var bi common.BlockchainInfo
	must(proto.Unmarshal(b, &bi))
	return bi.Height
}

func blockBytes(channel string) int64 {
	cmd := fmt.Sprintf("stat -c %%s /var/hyperledger/production/ledgersData/chains/chains/%s/blockfile_*", channel)
	out, err := exec.Command("docker", "exec", "peer0.org1.example.com", "sh", "-c", cmd).Output()
	must(err)
	var s int64
	for _, f := range strings.Fields(string(out)) {
		v, _ := strconv.ParseInt(f, 10, 64)
		s += v
	}
	return s
}

func u64(x uint64) []byte { b := make([]byte, 8); binary.BigEndian.PutUint64(b, x); return b }

func sha3h(parts ...[]byte) []byte {
	h := sha3.New256()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

type job struct {
	fn   string
	data []byte
}

func main() {
	tn := flag.String("tn", "./test-network", "test-network dir")
	mode := flag.String("mode", "pqz", "pqz|v1|v2")
	n := flag.Int("n", 10000, "records per epoch (nominal for pqz)")
	batch := flag.Int("batch", 1, "records per transaction (v1/v2)")
	runs := flag.Int("runs", 1, "runs")
	run0 := flag.Int("run0", 1, "first run number")
	workers := flag.Int("workers", 1000, "concurrent in-flight txs")
	conns := flag.Int("conns", 4, "gateway connections")
	capMin := flag.Int("capmin", 40, "per-run timeout minutes")
	out := flag.String("out", "results/exp5_runs.csv", "csv (append)")
	channel := flag.String("channel", "mychannel", "")
	flag.Parse()

	cs := connect(*tn, *channel, "pqzcc", *conns)
	hdr := "ts_utc,system,N,batch,tx_count,workers,run,epoch,ok_tx,failed_tx,timed_out_tx,first_err,latency_s,txlat_p50_ms,txlat_p99_ms,arg_bytes,bytes_before,bytes_after,bytes_added,height_before,height_after,blocks_added\n"
	if _, err := os.Stat(*out); err != nil {
		must(os.WriteFile(*out, []byte(hdr), 0o644))
	}
	for r := 0; r < *runs; r++ {
		run := *run0 + r
		e := uint64(time.Now().UnixMilli())
		rng := rand.New(rand.NewPCG(uint64(run)*7919, uint64(*n)^0x5eed))
		var jobs []job
		var argBytes int
		switch *mode {
		case "pqz":
			p := make([]byte, payloadLen)
			for i := range p {
				p[i] = byte(rng.Uint32())
			}
			jobs = []job{{"AnchorPQZ", p}}
		case "v1", "v2":
			rs := 48
			fn := "CommitV1"
			if *mode == "v2" {
				rs, fn = 80, "CommitV2"
			}
			for s := 0; s < *n; s += *batch {
				end := min(s+*batch, *n)
				buf := make([]byte, 0, (end-s)*rs)
				for i := s; i < end; i++ {
					buf = append(buf, u64(e)...)
					buf = append(buf, u64(uint64(i))...)
					if *mode == "v1" {
						buf = append(buf, sha3h([]byte("record"), u64(uint64(i)))...)
					} else {
						ph := make([]byte, 32)
						for k := range ph {
							ph[k] = byte(rng.Uint32())
						}
						buf = append(buf, ph...)
						buf = append(buf, sha3h([]byte("PQZ-REC"), u64(e), u64(uint64(i)), ph)...)
					}
				}
				jobs = append(jobs, job{fn, buf})
			}
		}
		for _, j := range jobs {
			argBytes += len(j.data) + 8
		}
		time.Sleep(2 * time.Second)
		b0 := blockBytes(*channel)
		h0 := height(cs[0], *channel)

		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*capMin)*time.Minute)
		var next, okc, failc, toc atomic.Int64
		var firstErr atomic.Value
		lat := make([]time.Duration, len(jobs))
		var wg sync.WaitGroup
		w := min(*workers, len(jobs))
		t0 := time.Now()
		for k := 0; k < w; k++ {
			wg.Add(1)
			go func(k int) {
				defer wg.Done()
				c := cs[k%len(cs)].c
				for {
					i := int(next.Add(1) - 1)
					if i >= len(jobs) {
						return
					}
					ts := time.Now()
					fail := func(err error) {
						if ctx.Err() != nil {
							toc.Add(1)
						} else {
							failc.Add(1)
						}
						firstErr.CompareAndSwap(nil, err.Error())
					}
					pr, err := c.NewProposal(jobs[i].fn, client.WithBytesArguments(u64(e), jobs[i].data))
					if err != nil {
						fail(err)
						continue
					}
					tx, err := pr.EndorseWithContext(ctx)
					if err != nil {
						fail(err)
						continue
					}
					cm, err := tx.SubmitWithContext(ctx)
					if err != nil {
						fail(err)
						continue
					}
					st, err := cm.StatusWithContext(ctx)
					if err != nil {
						fail(err)
						continue
					}
					if !st.Successful {
						fail(fmt.Errorf("commit code %d", st.Code))
						continue
					}
					lat[i] = time.Since(ts)
					okc.Add(1)
				}
			}(k)
		}
		wg.Wait()
		el := time.Since(t0)
		cancel()
		var ls []time.Duration
		for _, d := range lat {
			if d > 0 {
				ls = append(ls, d)
			}
		}
		sort.Slice(ls, func(a, b int) bool { return ls[a] < ls[b] })
		var p50, p99 float64
		if len(ls) > 0 {
			p50 = float64(ls[len(ls)/2].Microseconds()) / 1000
			p99 = float64(ls[len(ls)*99/100].Microseconds()) / 1000
		}
		time.Sleep(2 * time.Second)
		b1 := blockBytes(*channel)
		h1 := height(cs[0], *channel)
		fe, _ := firstErr.Load().(string)
		fe = strings.NewReplacer(",", ";", "\n", " ").Replace(fe)
		if len(fe) > 160 {
			fe = fe[:160]
		}
		line := fmt.Sprintf("%s,%s,%d,%d,%d,%d,%d,%d,%d,%d,%d,%s,%.4f,%.1f,%.1f,%d,%d,%d,%d,%d,%d,%d\n",
			time.Now().UTC().Format(time.RFC3339), *mode, *n, *batch, len(jobs), w, run, e, okc.Load(), failc.Load(), toc.Load(), fe,
			el.Seconds(), p50, p99, argBytes, b0, b1, b1-b0, h0, h1, h1-h0)
		f, err := os.OpenFile(*out, os.O_APPEND|os.O_WRONLY, 0o644)
		must(err)
		f.WriteString(line)
		f.Close()
		fmt.Print(line)
	}
}
