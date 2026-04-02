package session

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/palauth/palauth/internal/database/sqlc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

func TestAALTimeouts(t *testing.T) {
	tests := []struct {
		name        string
		acr         string
		wantIdle    time.Duration
		wantAbs     time.Duration
	}{
		{
			name:     "AAL1 — no idle, 30 day absolute",
			acr:      "aal1",
			wantIdle: 0,
			wantAbs:  30 * 24 * time.Hour,
		},
		{
			name:     "AAL2 — 1 hour idle, 24 hour absolute",
			acr:      "aal2",
			wantIdle: 1 * time.Hour,
			wantAbs:  24 * time.Hour,
		},
		{
			name:     "AAL3 — 15 min idle, 12 hour absolute",
			acr:      "aal3",
			wantIdle: 15 * time.Minute,
			wantAbs:  12 * time.Hour,
		},
		{
			name:     "unknown defaults to AAL1",
			acr:      "unknown",
			wantIdle: 0,
			wantAbs:  30 * 24 * time.Hour,
		},
		{
			name:     "empty defaults to AAL1",
			acr:      "",
			wantIdle: 0,
			wantAbs:  30 * 24 * time.Hour,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idle, abs := AALTimeouts(tt.acr)
			assert.Equal(t, tt.wantIdle, idle)
			assert.Equal(t, tt.wantAbs, abs)
		})
	}
}

func TestIsExpired(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name       string
		session    *Session
		wantExpired bool
		wantReason  string
	}{
		{
			name: "valid session — no idle timeout",
			session: &Session{
				AbsTimeoutAt: now.Add(1 * time.Hour),
			},
			wantExpired: false,
		},
		{
			name: "valid session — idle timeout not reached",
			session: &Session{
				AbsTimeoutAt:  now.Add(1 * time.Hour),
				IdleTimeoutAt: timePtr(now.Add(30 * time.Minute)),
			},
			wantExpired: false,
		},
		{
			name: "expired — absolute timeout",
			session: &Session{
				AbsTimeoutAt: now.Add(-1 * time.Second),
			},
			wantExpired: true,
			wantReason:  "absolute_timeout",
		},
		{
			name: "expired — idle timeout",
			session: &Session{
				AbsTimeoutAt:  now.Add(1 * time.Hour),
				IdleTimeoutAt: timePtr(now.Add(-1 * time.Second)),
			},
			wantExpired: true,
			wantReason:  "idle_timeout",
		},
		{
			name: "absolute timeout takes priority over valid idle",
			session: &Session{
				AbsTimeoutAt:  now.Add(-1 * time.Second),
				IdleTimeoutAt: timePtr(now.Add(1 * time.Hour)),
			},
			wantExpired: true,
			wantReason:  "absolute_timeout",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expired, reason := isExpired(tt.session)
			assert.Equal(t, tt.wantExpired, expired)
			if tt.wantExpired {
				assert.Equal(t, tt.wantReason, reason)
			}
		})
	}
}

func TestToSession(t *testing.T) {
	now := time.Now()
	ip := "192.168.1.1"
	ua := "Mozilla/5.0"

	t.Run("converts all fields", func(t *testing.T) {
		row := &sqlc.Session{
			ID:        "sess_test-id",
			ProjectID: "prj_test",
			UserID:    "usr_test",
			Ip:        &ip,
			UserAgent: &ua,
			Acr:       "aal2",
			Amr:       []byte(`["pwd","otp"]`),
			IdleTimeoutAt: pgtype.Timestamptz{Time: now.Add(1 * time.Hour), Valid: true},
			AbsTimeoutAt:  pgtype.Timestamptz{Time: now.Add(24 * time.Hour), Valid: true},
			LastActivity:  pgtype.Timestamptz{Time: now, Valid: true},
			CreatedAt:     pgtype.Timestamptz{Time: now, Valid: true},
		}

		sess := toSession(row)

		assert.Equal(t, "sess_test-id", sess.ID)
		assert.Equal(t, "prj_test", sess.ProjectID)
		assert.Equal(t, "usr_test", sess.UserID)
		assert.Equal(t, "192.168.1.1", sess.IP)
		assert.Equal(t, "Mozilla/5.0", sess.UserAgent)
		assert.Equal(t, "aal2", sess.ACR)
		assert.Equal(t, []string{"pwd", "otp"}, sess.AMR)
		require.NotNil(t, sess.IdleTimeoutAt)
	})

	t.Run("handles nil optional fields", func(t *testing.T) {
		row := &sqlc.Session{
			ID:           "sess_test",
			ProjectID:    "prj_test",
			UserID:       "usr_test",
			Acr:          "aal1",
			Amr:          []byte(`["pwd"]`),
			AbsTimeoutAt: pgtype.Timestamptz{Time: now.Add(30 * 24 * time.Hour), Valid: true},
			LastActivity: pgtype.Timestamptz{Time: now, Valid: true},
			CreatedAt:    pgtype.Timestamptz{Time: now, Valid: true},
		}

		sess := toSession(row)

		assert.Empty(t, sess.IP)
		assert.Empty(t, sess.UserAgent)
		assert.Nil(t, sess.IdleTimeoutAt)
	})
}

// Property-based test: AALTimeouts always returns non-negative durations.
func TestAALTimeouts_Property(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		acr := rapid.SampledFrom([]string{"aal1", "aal2", "aal3", "", "unknown", "aal4"}).Draw(t, "acr")
		idle, abs := AALTimeouts(acr)
		if idle < 0 {
			t.Fatalf("idle timeout is negative: %v", idle)
		}
		if abs <= 0 {
			t.Fatalf("absolute timeout is not positive: %v", abs)
		}
		// abs must always be >= idle
		if idle > 0 && abs < idle {
			t.Fatalf("absolute timeout (%v) < idle timeout (%v)", abs, idle)
		}
	})
}

// Property-based test: a session that just started should never be expired.
func TestIsExpired_FreshSession_Property(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		acr := rapid.SampledFrom([]string{"aal1", "aal2", "aal3"}).Draw(t, "acr")
		idle, abs := AALTimeouts(acr)

		now := time.Now()
		sess := &Session{
			AbsTimeoutAt: now.Add(abs),
		}
		if idle > 0 {
			idleAt := now.Add(idle)
			sess.IdleTimeoutAt = &idleAt
		}

		expired, _ := isExpired(sess)
		if expired {
			t.Fatalf("fresh %s session should not be expired", acr)
		}
	})
}

func timePtr(t time.Time) *time.Time {
	return &t
}
