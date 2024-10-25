package data

import (
	"bytes"
	"time"

	"golang.org/x/crypto/sha3"
	"source.quilibrium.com/quilibrium/monorepo/node/config"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token/application"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

func (e *DataClockConsensusEngine) prove(
	previousFrame *protobufs.ClockFrame,
) (*protobufs.ClockFrame, error) {
	e.stagedTransactionsMx.Lock()
	executionOutput := &protobufs.IntrinsicExecutionOutput{}
	app, err := application.MaterializeApplicationFromFrame(
		e.provingKey,
		previousFrame,
		e.frameProverTries,
		e.coinStore,
		e.logger,
	)
	if err != nil {
		e.stagedTransactionsMx.Unlock()
		return nil, errors.Wrap(err, "prove")
	}

	if e.stagedTransactions == nil {
		e.stagedTransactions = &protobufs.TokenRequests{}
	}

	e.logger.Info(
		"proving new frame",
		zap.Int("transactions", len(e.stagedTransactions.Requests)),
	)

	var validTransactions *protobufs.TokenRequests
	var invalidTransactions *protobufs.TokenRequests
	app, validTransactions, invalidTransactions, err = app.ApplyTransitions(
		previousFrame.FrameNumber,
		e.stagedTransactions,
		true,
	)
	if err != nil {
		e.stagedTransactions = &protobufs.TokenRequests{}
		e.stagedTransactionsMx.Unlock()
		return nil, errors.Wrap(err, "prove")
	}

	e.logger.Info(
		"applied transitions",
		zap.Int("successful", len(validTransactions.Requests)),
		zap.Int("failed", len(invalidTransactions.Requests)),
	)
	e.stagedTransactions = &protobufs.TokenRequests{}
	e.stagedTransactionsMx.Unlock()

	outputState, err := app.MaterializeStateFromApplication()
	if err != nil {
		return nil, errors.Wrap(err, "prove")
	}

	executionOutput.Address = application.TOKEN_ADDRESS
	executionOutput.Output, err = proto.Marshal(outputState)
	if err != nil {
		return nil, errors.Wrap(err, "prove")
	}

	executionOutput.Proof, err = proto.Marshal(validTransactions)
	if err != nil {
		return nil, errors.Wrap(err, "prove")
	}

	data, err := proto.Marshal(executionOutput)
	if err != nil {
		return nil, errors.Wrap(err, "prove")
	}

	e.logger.Debug("encoded execution output")
	digest := sha3.NewShake256()
	_, err = digest.Write(data)
	if err != nil {
		e.logger.Error(
			"error writing digest",
			zap.Error(err),
		)
		return nil, errors.Wrap(err, "prove")
	}

	expand := make([]byte, 1024)
	_, err = digest.Read(expand)
	if err != nil {
		e.logger.Error(
			"error expanding digest",
			zap.Error(err),
		)
		return nil, errors.Wrap(err, "prove")
	}

	commitment, err := e.inclusionProver.CommitRaw(
		expand,
		16,
	)
	if err != nil {
		return nil, errors.Wrap(err, "prove")
	}

	e.logger.Debug("creating kzg proof")
	proof, err := e.inclusionProver.ProveRaw(
		expand,
		int(expand[0]%16),
		16,
	)
	if err != nil {
		return nil, errors.Wrap(err, "prove")
	}

	e.logger.Debug("finalizing execution proof")

	frame, err := e.frameProver.ProveDataClockFrame(
		previousFrame,
		[][]byte{proof},
		[]*protobufs.InclusionAggregateProof{
			{
				Filter:      e.filter,
				FrameNumber: previousFrame.FrameNumber + 1,
				InclusionCommitments: []*protobufs.InclusionCommitment{
					{
						Filter:      e.filter,
						FrameNumber: previousFrame.FrameNumber + 1,
						TypeUrl:     protobufs.IntrinsicExecutionOutputType,
						Commitment:  commitment,
						Data:        data,
						Position:    0,
					},
				},
				Proof: proof,
			},
		},
		e.provingKey,
		time.Now().UnixMilli(),
		e.difficulty,
	)
	if err != nil {
		return nil, errors.Wrap(err, "prove")
	}
	e.logger.Info(
		"returning new proven frame",
		zap.Uint64("frame_number", frame.FrameNumber),
		zap.Int("proof_count", len(frame.AggregateProofs)),
		zap.Int("commitment_count", len(frame.Input[516:])/74),
	)
	return frame, nil
}

func (e *DataClockConsensusEngine) GetMostAheadPeer(
	frameNumber uint64,
) (
	[]byte,
	uint64,
	error,
) {
	e.logger.Info(
		"checking peer list",
		zap.Int("peers", len(e.peerMap)),
		zap.Int("uncooperative_peers", len(e.uncooperativePeersMap)),
		zap.Uint64("current_head_frame", frameNumber),
	)

	if e.GetFrameProverTries()[0].Contains(e.provingKeyAddress) {
		return e.pubSub.GetPeerID(), frameNumber, nil
	}

	max := frameNumber
	var peer []byte = nil
	e.peerMapMx.RLock()
	for _, v := range e.peerMap {
		e.logger.Debug(
			"checking peer info",
			zap.Binary("peer_id", v.peerId),
			zap.Uint64("max_frame_number", v.maxFrame),
			zap.Int64("timestamp", v.timestamp),
			zap.Binary("version", v.version),
		)
		_, ok := e.uncooperativePeersMap[string(v.peerId)]
		if v.maxFrame > max &&
			v.timestamp > config.GetMinimumVersionCutoff().UnixMilli() &&
			bytes.Compare(v.version, config.GetMinimumVersion()) >= 0 && !ok {
			peer = v.peerId
			max = v.maxFrame
		}
	}
	e.peerMapMx.RUnlock()

	if peer == nil {
		return nil, 0, p2p.ErrNoPeersAvailable
	}

	return peer, max, nil
}
