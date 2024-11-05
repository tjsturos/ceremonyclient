package application

import (
	"encoding/binary"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

func (a *TokenApplication) getAddressFromSignature(
	sig *protobufs.Ed448Signature,
) ([]byte, error) {
	if sig.PublicKey == nil || sig.PublicKey.KeyValue == nil {
		return nil, errors.New("invalid data")
	}
	addrBI, err := poseidon.HashBytes(sig.PublicKey.KeyValue)
	if err != nil {
		return nil, errors.Wrap(err, "get address from signature")
	}

	return addrBI.FillBytes(make([]byte, 32)), nil
}

func (a *TokenApplication) handleDataAnnounceProverJoin(
	currentFrameNumber uint64,
	lockMap map[string]struct{},
	t *protobufs.AnnounceProverJoin,
) (
	[]*protobufs.TokenOutput,
	error,
) {
	payload := []byte("join")

	if t == nil || t.PublicKeySignatureEd448 == nil {
		a.Logger.Debug("invalid data for join")

		return nil, errors.Wrap(ErrInvalidStateTransition, "handle join")
	}

	if t.PublicKeySignatureEd448.PublicKey == nil ||
		t.PublicKeySignatureEd448.Signature == nil ||
		t.PublicKeySignatureEd448.PublicKey.KeyValue == nil ||
		t.Filter == nil || len(t.Filter) != 32 ||
		t.FrameNumber < currentFrameNumber-1 || t.FrameNumber > currentFrameNumber {
		a.Logger.Debug(
			"bad payload",
			zap.Uint64("given_frame_number", t.FrameNumber),
			zap.Uint64("current_frame_number", currentFrameNumber),
			zap.Int("filter_length", len(t.Filter)),
		)

		return nil, errors.Wrap(ErrInvalidStateTransition, "handle join")
	}
	if _, touched := lockMap[string(
		t.PublicKeySignatureEd448.PublicKey.KeyValue,
	)]; touched {
		a.Logger.Debug("already attempted join")

		return nil, errors.Wrap(ErrInvalidStateTransition, "handle join")
	}
	payload = binary.BigEndian.AppendUint64(payload, t.FrameNumber)
	payload = append(payload, t.Filter...)

	if err := t.PublicKeySignatureEd448.Verify(
		t.PublicKeySignatureEd448.PublicKey.KeyValue,
	); err != nil {
		a.Logger.Debug("can't verify signature")
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle join")
	}

	address, err := a.getAddressFromSignature(t.PublicKeySignatureEd448)
	if err != nil {
		a.Logger.Debug("can't get address from signature")
		return nil, errors.Wrap(err, "handle join")
	}

	for _, t := range a.Tries {
		if t.Contains(address) {
			a.Logger.Debug("prover already in trie", zap.Binary("address", address))
			return nil, errors.Wrap(ErrInvalidStateTransition, "handle join")
		}
	}

	lockMap[string(t.PublicKeySignatureEd448.PublicKey.KeyValue)] = struct{}{}
	return []*protobufs.TokenOutput{
		&protobufs.TokenOutput{
			Output: &protobufs.TokenOutput_Join{
				Join: t,
			},
		},
	}, nil
}
