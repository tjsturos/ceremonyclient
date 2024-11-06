package application

import (
	"bytes"
	"encoding/binary"
	"math/big"

	"github.com/iden3/go-iden3-crypto/poseidon"
	pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/mr-tron/base58"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/crypto/sha3"
	"source.quilibrium.com/quilibrium/monorepo/node/crypto"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
)

func (a *TokenApplication) handleMint(
	currentFrameNumber uint64,
	lockMap map[string]struct{},
	t *protobufs.MintCoinRequest,
	frame *protobufs.ClockFrame,
) ([]*protobufs.TokenOutput, error) {
	if t == nil || t.Proofs == nil || t.Signature == nil {
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle mint")
	}

	payload := []byte("mint")
	for _, p := range t.Proofs {
		payload = append(payload, p...)
	}
	if err := t.Signature.Verify(payload); err != nil {
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle mint")
	}
	pk, err := pcrypto.UnmarshalEd448PublicKey(
		t.Signature.PublicKey.KeyValue,
	)
	if err != nil {
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle mint")
	}

	peerId, err := peer.IDFromPublicKey(pk)
	if err != nil {
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle mint")
	}

	addr, err := poseidon.HashBytes(
		t.Signature.PublicKey.KeyValue,
	)
	if err != nil {
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle mint")
	}

	altAddr, err := poseidon.HashBytes([]byte(peerId))
	if err != nil {
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle mint")
	}

	// todo: set termination frame for this:
	if len(t.Proofs) == 1 && a.Tries[0].Contains(
		addr.FillBytes(make([]byte, 32)),
	) && bytes.Equal(t.Signature.PublicKey.KeyValue, a.Beacon) {
		if len(t.Proofs[0]) != 64 {
			return nil, errors.Wrap(ErrInvalidStateTransition, "handle mint")
		}

		if _, touched := lockMap[string(t.Proofs[0][32:])]; touched {
			return nil, errors.Wrap(ErrInvalidStateTransition, "handle mint")
		}

		_, pr, err := a.CoinStore.GetPreCoinProofsForOwner(t.Proofs[0][32:])
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, errors.Wrap(ErrInvalidStateTransition, "handle mint")
		}

		for _, p := range pr {
			if p.IndexProof == nil && bytes.Equal(p.Amount, t.Proofs[0][:32]) {
				return nil, errors.Wrap(ErrInvalidStateTransition, "handle mint")
			}
		}

		lockMap[string(t.Proofs[0][32:])] = struct{}{}

		outputs := []*protobufs.TokenOutput{
			&protobufs.TokenOutput{
				Output: &protobufs.TokenOutput_Proof{
					Proof: &protobufs.PreCoinProof{
						Amount: t.Proofs[0][:32],
						Owner: &protobufs.AccountRef{
							Account: &protobufs.AccountRef_ImplicitAccount{
								ImplicitAccount: &protobufs.ImplicitAccount{
									ImplicitType: 0,
									Address:      t.Proofs[0][32:],
								},
							},
						},
						Proof: t.Signature.Signature,
					},
				},
			},
			&protobufs.TokenOutput{
				Output: &protobufs.TokenOutput_Coin{
					Coin: &protobufs.Coin{
						Amount:       t.Proofs[0][:32],
						Intersection: make([]byte, 1024),
						Owner: &protobufs.AccountRef{
							Account: &protobufs.AccountRef_ImplicitAccount{
								ImplicitAccount: &protobufs.ImplicitAccount{
									ImplicitType: 0,
									Address:      t.Proofs[0][32:],
								},
							},
						},
					},
				},
			},
		}
		return outputs, nil
	} else if len(t.Proofs) > 0 && currentFrameNumber > 0 {
		a.Logger.Debug(
			"got mint from peer",
			zap.String("peer_id", base58.Encode([]byte(peerId))),
			zap.Uint64("frame_number", currentFrameNumber),
		)
		if _, touched := lockMap[string(t.Signature.PublicKey.KeyValue)]; touched {
			a.Logger.Debug(
				"already received",
				zap.String("peer_id", base58.Encode([]byte(peerId))),
				zap.Uint64("frame_number", currentFrameNumber),
			)
			return nil, errors.Wrap(ErrInvalidStateTransition, "handle mint")
		}
		ring := -1
		proverSet := int64((len(a.Tries) - 1) * 1024)
		for i, t := range a.Tries[1:] {
			if t.Contains(altAddr.FillBytes(make([]byte, 32))) {
				ring = i
			}
		}
		if ring == -1 {
			a.Logger.Debug(
				"not in ring",
				zap.String("peer_id", base58.Encode([]byte(peerId))),
				zap.Uint64("frame_number", currentFrameNumber),
			)
			return nil, errors.Wrap(ErrInvalidStateTransition, "handle mint")
		}
		challenge := []byte{}
		challenge = append(challenge, peerId...)
		challenge = binary.BigEndian.AppendUint64(
			challenge,
			currentFrameNumber-1,
		)

		digest := make([]byte, 128)
		s := sha3.NewShake256()
		pubkey, _ := pk.Raw()
		s.Write(pubkey)
		_, err = s.Read(digest)
		if err != nil {
			panic(err)
		}

		outputs := []*protobufs.TokenOutput{}
		proofs := []byte{}
		hits := 0

		for i, p := range t.Proofs {
			individualChallenge := append([]byte{}, challenge...)
			individualChallenge = binary.BigEndian.AppendUint32(
				individualChallenge,
				uint32(i),
			)
			individualChallenge = append(individualChallenge, frame.Output...)
			if len(p) != 516 {
				a.Logger.Debug(
					"invalid size",
					zap.String("peer_id", base58.Encode([]byte(peerId))),
					zap.Uint64("frame_number", currentFrameNumber),
					zap.Int("proof_size", len(p)),
				)
				continue
			}

			hits++

			wesoProver := crypto.NewWesolowskiFrameProver(a.Logger)

			if !wesoProver.VerifyChallengeProof(
				individualChallenge,
				frame.Difficulty,
				p,
			) {
				a.Logger.Debug(
					"invalid proof",
					zap.String("peer_id", base58.Encode([]byte(peerId))),
					zap.Uint64("frame_number", currentFrameNumber),
				)
				return nil, errors.Wrap(ErrInvalidStateTransition, "handle mint")
			}

			proofs = append(proofs, p...)
		}

		if hits == 0 {
			a.Logger.Debug(
				"no proofs",
				zap.String("peer_id", base58.Encode([]byte(peerId))),
				zap.Uint64("frame_number", currentFrameNumber),
			)
			return nil, errors.Wrap(ErrInvalidStateTransition, "handle mint")
		}

		ringFactor := big.NewInt(2)
		ringFactor.Exp(ringFactor, big.NewInt(int64(ring)), nil)

		storage := big.NewInt(int64(512 * hits))
		unitFactor := big.NewInt(8000000000)
		storage.Mul(storage, unitFactor)
		storage.Quo(storage, big.NewInt(proverSet))
		storage.Quo(storage, ringFactor)

		a.Logger.Debug(
			"issued reward",
			zap.String("peer_id", base58.Encode([]byte(peerId))),
			zap.Uint64("frame_number", currentFrameNumber),
			zap.String("reward", storage.String()),
		)

		outputs = append(
			outputs,
			&protobufs.TokenOutput{
				Output: &protobufs.TokenOutput_Proof{
					Proof: &protobufs.PreCoinProof{
						Amount:     storage.FillBytes(make([]byte, 32)),
						Proof:      proofs,
						Difficulty: a.Difficulty,
						Owner: &protobufs.AccountRef{
							Account: &protobufs.AccountRef_ImplicitAccount{
								ImplicitAccount: &protobufs.ImplicitAccount{
									ImplicitType: 0,
									Address:      addr.FillBytes(make([]byte, 32)),
								},
							},
						},
					},
				},
			},
			&protobufs.TokenOutput{
				Output: &protobufs.TokenOutput_Coin{
					Coin: &protobufs.Coin{
						Amount:       storage.FillBytes(make([]byte, 32)),
						Intersection: make([]byte, 1024),
						Owner: &protobufs.AccountRef{
							Account: &protobufs.AccountRef_ImplicitAccount{
								ImplicitAccount: &protobufs.ImplicitAccount{
									ImplicitType: 0,
									Address:      addr.FillBytes(make([]byte, 32)),
								},
							},
						},
					},
				},
			},
		)
		lockMap[string(t.Signature.PublicKey.KeyValue)] = struct{}{}
		return outputs, nil
	}
	a.Logger.Debug(
		"could not find case for proof",
		zap.String("peer_id", base58.Encode([]byte(peerId))),
		zap.Uint64("frame_number", currentFrameNumber),
	)
	return nil, errors.Wrap(ErrInvalidStateTransition, "handle mint")
}
