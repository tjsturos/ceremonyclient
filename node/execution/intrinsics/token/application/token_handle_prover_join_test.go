package application_test

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token/application"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
	"source.quilibrium.com/quilibrium/monorepo/node/tries"
)

func TestHandleProverJoin(t *testing.T) {
	log, _ := zap.NewDevelopment()
	bpub, _, _ := ed448.GenerateKey(rand.Reader)
	app := &application.TokenApplication{
		Beacon:     bpub,
		CoinStore:  store.NewPebbleCoinStore(store.NewInMemKVDB(), log),
		Logger:     log,
		Difficulty: 200000,
		Tries: []*tries.RollingFrecencyCritbitTrie{
			&tries.RollingFrecencyCritbitTrie{},
			&tries.RollingFrecencyCritbitTrie{},
		},
	}

	baddr, _ := poseidon.HashBytes(bpub)

	app.Tries[0].Add(baddr.FillBytes(make([]byte, 32)), 0)

	peerPrivKey, err := hex.DecodeString("8bdc6de5a6781375b2915a74ccc97c0572ca69766ae41dba40170ee88313ade030ad5e5f4fe4ca111141d54c60e2c73ccbc51e1442366446b3a678a36247e9d0889b384a4e7ce9a6323fe3a386446ec1214d374a42d55fb741d4888f74fbfe60cf2595da44b659eae88db06210bc33c88000")
	if err != nil {
		t.FailNow()
	}

	privKey, err := crypto.UnmarshalEd448PrivateKey(peerPrivKey)
	if err != nil {
		t.FailNow()
	}

	pub := privKey.GetPublic()
	pubkey, err := pub.Raw()
	if err != nil {
		t.FailNow()
	}

	peerId, err := peer.IDFromPublicKey(pub)
	if err != nil {
		t.FailNow()
	}

	addrBI, err := poseidon.HashBytes([]byte(peerId))
	if err != nil {
		t.FailNow()
	}

	addr := addrBI.FillBytes(make([]byte, 32))

	payload := []byte("join")
	payload = binary.BigEndian.AppendUint64(payload, 0)
	payload = append(payload, bytes.Repeat([]byte{0xff}, 32)...)
	sig, _ := privKey.Sign(payload)
	app, success, fail, err := app.ApplyTransitions(
		0,
		&protobufs.TokenRequests{
			Requests: []*protobufs.TokenRequest{
				&protobufs.TokenRequest{
					Request: &protobufs.TokenRequest_Join{
						Join: &protobufs.AnnounceProverJoin{
							Filter:      bytes.Repeat([]byte{0xff}, 32),
							FrameNumber: 0,
							PublicKeySignatureEd448: &protobufs.Ed448Signature{
								Signature: sig,
								PublicKey: &protobufs.Ed448PublicKey{
									KeyValue: pubkey,
								},
							},
						},
					},
				},
			},
		},
		false,
	)
	assert.NoError(t, err)

	assert.Len(t, success.Requests, 1)
	assert.Len(t, fail.Requests, 0)
	app.Tries[1].Add(addr, 0)
	app, success, fail, err = app.ApplyTransitions(
		0,
		&protobufs.TokenRequests{
			Requests: []*protobufs.TokenRequest{
				&protobufs.TokenRequest{
					Request: &protobufs.TokenRequest_Join{
						Join: &protobufs.AnnounceProverJoin{
							Filter:      bytes.Repeat([]byte{0xff}, 32),
							FrameNumber: 0,
							PublicKeySignatureEd448: &protobufs.Ed448Signature{
								Signature: sig,
								PublicKey: &protobufs.Ed448PublicKey{
									KeyValue: pubkey,
								},
							},
						},
					},
				},
			},
		},
		false,
	)

	assert.Error(t, err)
}
