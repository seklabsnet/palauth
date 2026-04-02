package audit

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEvent_Struct(t *testing.T) {
	event := Event{
		EventType: EventAuthSignup,
		Actor: ActorInfo{
			UserID: "usr_123",
			Email:  "test@example.com",
			IP:     "192.168.1.1",
		},
		Target: &TargetInfo{
			Type: "user",
			ID:   "usr_123",
		},
		Result:     "success",
		AuthMethod: "password",
		RiskScore:  0.0,
		ProjectID:  "prj_456",
		TraceID:    "req_789",
		Metadata:   map[string]any{"browser": "chrome"},
	}

	assert.Equal(t, EventAuthSignup, event.EventType)
	assert.Equal(t, "usr_123", event.Actor.UserID)
	assert.Equal(t, "test@example.com", event.Actor.Email)
	assert.Equal(t, "192.168.1.1", event.Actor.IP)
	assert.Equal(t, "user", event.Target.Type)
	assert.Equal(t, "usr_123", event.Target.ID)
	assert.Equal(t, "success", event.Result)
	assert.Equal(t, "password", event.AuthMethod)
	assert.Equal(t, 0.0, event.RiskScore)
	assert.Equal(t, "prj_456", event.ProjectID)
	assert.Equal(t, "req_789", event.TraceID)
	assert.Equal(t, "chrome", event.Metadata["browser"])
}

func TestActorInfo_WithoutPII(t *testing.T) {
	actor := ActorInfo{
		UserID: "usr_system",
	}
	assert.Equal(t, "usr_system", actor.UserID)
	assert.Empty(t, actor.Email)
	assert.Empty(t, actor.IP)
}

func TestTargetInfo(t *testing.T) {
	target := TargetInfo{
		Type: "session",
		ID:   "sess_abc",
	}
	assert.Equal(t, "session", target.Type)
	assert.Equal(t, "sess_abc", target.ID)
}
