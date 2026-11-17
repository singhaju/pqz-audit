# pqz-ledger-fabric-w45 (2026-11-16): Exp 5 (B1) on a real Hyperledger Fabric 2.5.16 chain, laptop only

## Setup
- `test-network/`, `config/`, `bin/`: COPIED from `bench/zkalba-eval/chain/network/fabric-samples` (original untouched). Only change: `test-network/configtx/configtx.yaml` orderer
  BatchTimeout 500ms, MaxMessageCount 500, PreferredMaxBytes 4 MB (AbsoluteMaxBytes 99 MB unchanged). Defaults were 2s/10/512KB. Same settings for ALL runs.
- Topology: 1 Raft orderer (single node, so no real consensus fault tolerance), 2 orgs x 1 peer, LevelDB, channel `mychannel`, MAJORITY endorsement (both orgs endorse every tx), docker, one host.
- Chaincode `pqzcc/` (Go, shim v2, vendored; built offline by fabric-ccenv:2.5.16; nothing downloaded). Raw byte arguments:
  `AnchorPQZ(e, 13,531 B)`; `CommitV1(e, k x 48 B = e,i,c)`; `CommitV2(e, k x 80 B = e,i,ph,c)`, v2 recomputes c = SHA3-256("PQZ-REC"||e||i||ph) and rejects a duplicate; v1 stores c only (as w37).
  Record sizes match the w37 tuples. Data: seeded random payload/ph (PCG, seed from run number and N).
- Client `client/` (Go, fabric-gateway v1.12.1 from the local module cache, `GOPROXY=off`): 1000 in-flight txs over 4 gRPC connections to peer0.org1; endorse -> submit -> wait commit status. 
  Latency = first submit to last commit status (peer0.org1). Bytes = growth of `blockfile_*` on peer0.org1 (docker exec stat), blocks = ledger height delta (qscc GetChainInfo).
- Commands (run from a path WITHOUT spaces; fabric-samples scripts break on spaces, so a symlink was used):
      cd test-network; ./network.sh up createChannel -c mychannel
      ./network.sh deployCC -ccn pqzcc -ccp ../pqzcc -ccl go
      cd ..; ./run_all.sh          # writes results/exp5_runs.csv
      ./test-network/network.sh down
  `summarize.py results/exp5_runs.csv` gives the medians (`results/summary_medians.txt`).

## Results files
`results/exp5_runs.csv` (one row per run, 100 runs, all columns incl. failed/timed-out counts), `results/machine.txt`, `results/run_all.log`, `results/summary_medians.txt`.
Before the matrix, 4 small smoke runs (not in the csv) warmed the network. Runs are sequential on one ledger, so the ledger grows over the session.

## What is and is not modelled
- Real: endorsement by 2 peers, ordering (Raft, one orderer), block cutting, validation and commit, ECDSA signatures and certificates in every tx.
- Not modelled: WAN latency (single host), multi-node Raft, on-chain proof verification (none for any system; PQZ epoch proof is just stored), ML-DSA signatures (Fabric uses ECDSA), the
  w37 shared epoch-check and sequence counter.
- The PQZ tx is the same 13,531 B payload for both N; the two N rows are 10 repeats each of the same transaction (N is nominal).
- PQZ latency is dominated by the 500 ms BatchTimeout (a lone tx waits for the block timeout); it is a property of the setting, not of PQZ.
- Ledger bytes for one PQZ tx (~32 KB) are about 2.4x the payload because the tx envelope carries the payload in the proposal and the read-write set, plus certificates and endorsements.

## Choices that favour the baselines
1. Batched variant (100 records per tx) is reported next to one-record-per-tx; the batch removes per-tx envelope/endorsement overhead.
2. v1/v2 chaincode has no shared counter and no epoch-open check (a counter would serialise concurrent txs through MVCC conflicts); less work and no conflicts for the baselines.
3. Large blocks (500 txs, 4 MB) so the baselines are not cut into many small blocks; 1000 txs in flight.
4. Ledger bytes count only block files, not state DB or indexes (same for all systems).
Against the baselines: the baselines are our own v1/v2 designs, not Dong et al.'s scheme.
Variance note: some 1e5 per-tx runs took 70-76 s against a typical 38-45 s (laptop shared with other containers; not isolated). Reported as is.
