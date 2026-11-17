// pqzcc: Exp 5 (w45) chaincode. Raw-bytes arguments so the on-ledger sizes match the w37 formats.
//   AnchorPQZ  e(8B BE) payload(13531 B)          -> state key "EP|e" = payload
//   CommitV1   e(8B) recs(k*48 B: e,i,c)          -> state key "R|e|i" = c                  (c = SHA3("record"||i), not recomputed: as w37 v1)
//   CommitV2   e(8B) recs(k*80 B: e,i,ph,c)       -> state key "R|e|i" = ph||c, c recomputed = SHA3("PQZ-REC"||e||i||ph), duplicate rejected
// No shared counter and no epoch-open check (they would serialise concurrent txs by MVCC): this favours the baselines.
package main

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"fmt"

	"github.com/hyperledger/fabric-chaincode-go/v2/shim"
	pb "github.com/hyperledger/fabric-protos-go-apiv2/peer"
)

type CC struct{}

func (CC) Init(shim.ChaincodeStubInterface) *pb.Response { return shim.Success(nil) }

func recKey(e, i uint64) string { return fmt.Sprintf("R|%d|%d", e, i) }

func (CC) Invoke(stub shim.ChaincodeStubInterface) *pb.Response {
	fn, args := stub.GetFunctionAndParameters()
	_ = args
	raw := stub.GetArgs()
	err := func() error {
		if len(raw) != 3 || len(raw[1]) != 8 {
			return fmt.Errorf("bad args")
		}
		e := binary.BigEndian.Uint64(raw[1])
		data := raw[2]
		switch fn {
		case "AnchorPQZ":
			if len(data) != 13531 {
				return fmt.Errorf("payload must be 13531 bytes, got %d", len(data))
			}
			return stub.PutState(fmt.Sprintf("EP|%d", e), data)
		case "CommitV1":
			if len(data)%48 != 0 {
				return fmt.Errorf("v1 batch not multiple of 48")
			}
			for o := 0; o < len(data); o += 48 {
				re := binary.BigEndian.Uint64(data[o:])
				i := binary.BigEndian.Uint64(data[o+8:])
				if re != e {
					return fmt.Errorf("epoch mismatch")
				}
				if err := stub.PutState(recKey(e, i), data[o+16:o+48]); err != nil {
					return err
				}
			}
			return nil
		case "CommitV2":
			if len(data)%80 != 0 {
				return fmt.Errorf("v2 batch not multiple of 80")
			}
			for o := 0; o < len(data); o += 80 {
				re := binary.BigEndian.Uint64(data[o:])
				i := binary.BigEndian.Uint64(data[o+8:])
				ph := data[o+16 : o+48]
				c := data[o+48 : o+80]
				if re != e {
					return fmt.Errorf("epoch mismatch")
				}
				h := sha3.New256()
				h.Write([]byte("PQZ-REC"))
				h.Write(raw[1])
				h.Write(data[o+8 : o+16])
				h.Write(ph)
				if !bytes.Equal(h.Sum(nil), c) {
					return fmt.Errorf("commitment mismatch")
				}
				k := recKey(e, i)
				old, err := stub.GetState(k)
				if err != nil {
					return err
				}
				if old != nil {
					return fmt.Errorf("duplicate record")
				}
				if err := stub.PutState(k, data[o+16:o+80]); err != nil {
					return err
				}
			}
			return nil
		}
		return fmt.Errorf("unknown function %s", fn)
	}()
	if err != nil {
		return shim.Error(err.Error())
	}
	return shim.Success(nil)
}

func main() {
	if err := shim.Start(CC{}); err != nil {
		panic(err)
	}
}
