//! w36 (S3): `Bloom35::open_many` (one tree walk per filter) and `openings_for_blocks` (parallel across blocks) give openings
//! byte-identical to the w35 method (one `merkle_path` call per index, sequential loop): same leaf_idx, word and path.
use pqz_eval::search::{Formula, Tag};
use pqz_integrated_w46::w35::*;
use pqz_ledger::hashing::{leaf_hash, verify_path};

fn rand_tags(n: usize, seed: u64) -> Vec<Tag> {
    (0..n as u64)
        .map(|i| {
            let mut m = seed.to_le_bytes().to_vec();
            m.extend_from_slice(&i.to_le_bytes());
            pqz_eval::sha3_256(&m)[..16].try_into().unwrap()
        })
        .collect()
}

fn lcg(s: &mut u64) -> usize {
    *s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    (*s >> 33) as usize
}

#[test]
fn open_many_equals_per_index_paths_on_several_filters() {
    // filter sizes (words): 64 bits minimum (1 word) up to a few thousand words; non-powers of two on purpose
    for (count, seed) in [(1usize, 1u64), (2, 2), (7, 3), (100, 4), (123, 5), (500, 6), (777, 7), (2000, 8), (5000, 9)] {
        let tags = rand_tags(count * 45, seed);
        let b = Bloom35::build(count, tags.iter());
        let n = b.bits.len();
        let root = b.mroot();
        let mut idx_sets: Vec<Vec<usize>> = vec![vec![0], vec![n - 1], vec![0, n - 1], (0..n.min(64)).collect(), vec![n / 2, n / 3, n / 2, 0]];
        let mut s = seed;
        for m in [1usize, 3, 10, 40] {
            idx_sets.push((0..m).map(|_| lcg(&mut s) % n).collect()); // unsorted, may repeat
        }
        if n <= 600 {
            idx_sets.push((0..n).collect()); // every leaf
        }
        for idx in &idx_sets {
            let a = b.open_many_per_index(idx);
            let c = b.open_many(idx);
            assert_eq!(a, c, "count {count} (n_words {n}) idx {idx:?}");
            for o in &c {
                assert!(verify_path(&leaf_hash(&o.word.to_le_bytes()), o.leaf_idx, n, &o.path, &root));
            }
        }
        println!("count {count}: {n} words, {} index sets: identical", idx_sets.len());
    }
}

#[test]
fn openings_for_blocks_parallel_equals_w35_sequential() {
    let counts = [100usize, 100, 37, 250, 100, 100, 512, 100, 64, 100, 100, 3];
    let tags: Vec<Vec<Tag>> = counts.iter().enumerate().map(|(i, &c)| rand_tags(c * 45, 100 + i as u64)).collect();
    let blooms: Vec<Bloom35> = counts.iter().zip(&tags).map(|(&c, t)| Bloom35::build(c, t.iter())).collect();
    // a query tag that is in none of the filters
    let q = rand_tags(5, 999);
    for f in [Formula::leaf(vec![q[0]]), Formula::leaf(vec![q[1], q[2]]), Formula::and(Formula::leaf(vec![q[3]]), Formula::leaf(vec![q[4]])), Formula::or(Formula::leaf(vec![q[0]]), Formula::leaf(vec![q[4]]))] {
        let sel: Vec<usize> = (0..blooms.len()).filter(|i| i % 3 != 1).collect();
        let a = openings_for_blocks_w35(&blooms, &f, sel.iter().copied());
        let c = openings_for_blocks(&blooms, &f, sel.iter().copied());
        assert_eq!(a, c);
        let all = openings_for_blocks(&blooms, &f, 0..blooms.len()).expect("absent in all");
        assert_eq!(all.len(), blooms.len());
        assert!(all.iter().enumerate().all(|(i, (g, _))| *g == i as u64 + 1), "order is by block index");
    }
    // a block whose filter contains the query: both report the same error (the first failing block in index order)
    let own = rand_tags(100 * 45, 100); // the tags of block 0
    let f = Formula::leaf(vec![own[0]]);
    let a = openings_for_blocks_w35(&blooms, &f, 0..blooms.len());
    let c = openings_for_blocks(&blooms, &f, 0..blooms.len());
    assert!(a.is_err());
    assert_eq!(a, c);
}
