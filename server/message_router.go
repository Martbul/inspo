package server

import (
	"github.com/martbul/inspo/inspo-common/rtapi"
	"go.uber.org/zap"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// Deferred message expected to be batched with other deferred messages.
// All deferred messages in a batch are expected to be for the same stream/mode and share a logger context.
type DeferredMessage struct {
	PresenceIDs []*PresenceID
	Envelope    *rtapi.Envelope
	Reliable    bool
}

// MessageRouter is responsible for sending a message to a list of presences or to an entire stream.
type MessageRouter interface {
	SendToPresenceIDs(*zap.Logger, []*PresenceID, *rtapi.Envelope, bool)
	SendToStream(*zap.Logger, PresenceStream, *rtapi.Envelope, bool)
	SendDeferred(*zap.Logger, []*DeferredMessage)
	SendToAll(*zap.Logger, *rtapi.Envelope, bool)
}

type LocalMessageRouter struct {
	protojsonMarshaler *protojson.MarshalOptions
	sessionRegistry    SessionRegistry
	tracker            Tracker
}

func NewLocalMessageRouter(sessionRegistry SessionRegistry, tracker Tracker, protojsonMarshaler *protojson.MarshalOptions) MessageRouter {
	return &LocalMessageRouter{
		protojsonMarshaler: protojsonMarshaler,
		sessionRegistry:    sessionRegistry,
		tracker:            tracker,
	}
}

func (r *LocalMessageRouter) SendToPresenceIDs(logger *zap.Logger, presenceIDs []*PresenceID, envelope *rtapi.Envelope, reliable bool) {
	if len(presenceIDs) == 0 {
		return
	}

	// Prepare payload variables but do not initialize until we hit a session that needs them to avoid unnecessary work.
	var payloadProtobuf []byte
	var payloadJSON []byte

	for _, presenceID := range presenceIDs {
		session := r.sessionRegistry.Get(presenceID.SessionID)
		if session == nil {
			logger.Debug("No session to route to", zap.String("sid", presenceID.SessionID.String()))
			continue
		}

		var err error
		switch session.Format() {
		case SessionFormatProtobuf:
			if payloadProtobuf == nil {
				// Marshal the payload now that we know this format is needed.
				payloadProtobuf, err = proto.Marshal(envelope)
				if err != nil {
					logger.Error("Could not marshal message", zap.Error(err))
					return
				}
			}
			err = session.SendBytes(payloadProtobuf, reliable)
		case SessionFormatJson:
			fallthrough
		default:
			if payloadJSON == nil {
				// Marshal the payload now that we know this format is needed.
				if buf, err := r.protojsonMarshaler.Marshal(envelope); err == nil {
					payloadJSON = buf
				} else {
					logger.Error("Could not marshal message", zap.Error(err))
					return
				}
			}
			err = session.SendBytes(payloadJSON, reliable)
		}
		if err != nil {
			logger.Error("Failed to route message", zap.String("sid", presenceID.SessionID.String()), zap.Error(err))
		}
	}
}

func (r *LocalMessageRouter) SendToStream(logger *zap.Logger, stream PresenceStream, envelope *rtapi.Envelope, reliable bool) {
	presenceIDs := r.tracker.ListPresenceIDByStream(stream)
	r.SendToPresenceIDs(logger, presenceIDs, envelope, reliable)
}

func (r *LocalMessageRouter) SendDeferred(logger *zap.Logger, messages []*DeferredMessage) {
	for _, message := range messages {
		r.SendToPresenceIDs(logger, message.PresenceIDs, message.Envelope, message.Reliable)
	}
}

func (r *LocalMessageRouter) SendToAll(logger *zap.Logger, envelope *rtapi.Envelope, reliable bool) {
	// Prepare payload variables but do not initialize until we hit a session that needs them to avoid unnecessary work.
	var payloadProtobuf []byte
	var payloadJSON []byte

	r.sessionRegistry.Range(func(session Session) bool {
		var err error
		switch session.Format() {
		case SessionFormatProtobuf:
			if payloadProtobuf == nil {
				// Marshal the payload now that we know this format is needed.
				payloadProtobuf, err = proto.Marshal(envelope)
				if err != nil {
					logger.Error("Could not marshal message", zap.Error(err))
					return false
				}
			}
			err = session.SendBytes(payloadProtobuf, reliable)
		case SessionFormatJson:
			fallthrough
		default:
			if payloadJSON == nil {
				// Marshal the payload now that we know this format is needed.
				if buf, err := r.protojsonMarshaler.Marshal(envelope); err == nil {
					payloadJSON = buf
				} else {
					logger.Error("Could not marshal message", zap.Error(err))
					return false
				}
			}
			err = session.SendBytes(payloadJSON, reliable)
		}
		if err != nil {
			logger.Error("Failed to route message", zap.String("sid", session.ID().String()), zap.Error(err))
		}
		return true
	})
}
