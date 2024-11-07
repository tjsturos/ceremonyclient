package protobufs

import "math/big"

func (t *TokenRequest) Priority() *big.Int {
	switch p := t.Request.(type) {
	case *TokenRequest_Mint:
		if len(p.Mint.Proofs) >= 3 {
			return new(big.Int).SetBytes(p.Mint.Proofs[2])
		}
	}
	return big.NewInt(0)
}
