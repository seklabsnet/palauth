package audit

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/palauth/palauth/internal/crypto"
	"github.com/palauth/palauth/internal/database/sqlc"
	"github.com/palauth/palauth/internal/id"
)

var (
	ErrProjectIDRequired = errors.New("project_id is required")
	ErrEventTypeRequired = errors.New("event_type is required")
	ErrResultRequired    = errors.New("result is required")
	ErrUnsupportedFormat = errors.New("unsupported export format")
)

// Service handles audit log operations with tamper-evident hash chain and PII encryption.
type Service struct {
	db     *pgxpool.Pool
	kek    []byte
	logger *slog.Logger
}

// NewService creates a new audit service.
func NewService(db *pgxpool.Pool, kek []byte, logger *slog.Logger) *Service {
	return &Service{
		db:     db,
		kek:    kek,
		logger: logger,
	}
}

// Log records an audit event with encrypted PII and hash chain linkage.
// Uses a transaction with advisory lock to prevent concurrent chain forks.
func (s *Service) Log(ctx context.Context, event AuditEvent) error {
	if event.ProjectID == "" {
		return ErrProjectIDRequired
	}
	if event.EventType == "" {
		return ErrEventTypeRequired
	}
	if event.Result == "" {
		return ErrResultRequired
	}

	// Start transaction — the get-last-hash + insert must be atomic
	// to prevent concurrent Log() calls from forking the chain.
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback is a no-op after commit

	// Acquire per-project advisory lock to serialize chain writes.
	// Uses a hash of project_id as the lock key.
	lockKey := advisoryLockKey(event.ProjectID)
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", lockKey); err != nil {
		return fmt.Errorf("advisory lock: %w", err)
	}

	q := sqlc.New(tx)

	// Get or create per-user DEK for PII encryption, scoped to project.
	userDEK, err := s.getOrCreateUserDEK(ctx, q, event.Actor.UserID, event.ProjectID)
	if err != nil {
		return fmt.Errorf("get or create user DEK: %w", err)
	}

	// Encrypt PII fields using canonical JSON for deterministic serialization.
	// AAD binds ciphertext to its context, preventing cross-event/cross-project swap attacks.
	piiAAD := []byte(event.ProjectID + ":" + event.Actor.UserID)

	actorJSON, err := CanonicalJSON(event.Actor)
	if err != nil {
		return fmt.Errorf("canonical json actor: %w", err)
	}
	actorCiphertext, err := crypto.Encrypt(actorJSON, userDEK, piiAAD)
	if err != nil {
		return fmt.Errorf("encrypt actor: %w", err)
	}
	// Frame: 2-byte userID length + userID + ciphertext.
	// This allows extracting the userID for DEK lookup during decryption.
	actorEncrypted := frameWithUserID(event.Actor.UserID, actorCiphertext)

	metadata := event.Metadata
	if metadata == nil {
		metadata = map[string]any{}
	}
	metadataJSON, err := CanonicalJSON(metadata)
	if err != nil {
		return fmt.Errorf("canonical json metadata: %w", err)
	}
	metadataCiphertext, err := crypto.Encrypt(metadataJSON, userDEK, piiAAD)
	if err != nil {
		return fmt.Errorf("encrypt metadata: %w", err)
	}
	metadataEncrypted := frameWithUserID(event.Actor.UserID, metadataCiphertext)

	// Get previous event hash for chain linkage (within the transaction).
	var prevHash *string
	lastLog, err := q.GetLastAuditLog(ctx, event.ProjectID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("get last audit log: %w", err)
	}
	if err == nil {
		prevHash = &lastLog.EventHash
	}

	// Compute event hash on CIPHERTEXT (not plaintext).
	eventHash, err := computeEventHash(computeHashInput{
		EventType:         event.EventType,
		ProjectID:         event.ProjectID,
		ActorEncrypted:    hex.EncodeToString(actorEncrypted),
		TargetType:        targetTypeStr(event.Target),
		TargetID:          targetIDStr(event.Target),
		Result:            event.Result,
		AuthMethod:        event.AuthMethod,
		MetadataEncrypted: hex.EncodeToString(metadataEncrypted),
		PrevHash:          derefStr(prevHash),
	}, prevHash)
	if err != nil {
		return fmt.Errorf("compute event hash: %w", err)
	}

	// Build insert params.
	eventID := id.New("aud_")
	var traceID *string
	if event.TraceID != "" {
		traceID = &event.TraceID
	}
	var targetType, targetID *string
	if event.Target != nil {
		targetType = &event.Target.Type
		targetID = &event.Target.ID
	}
	var authMethod *string
	if event.AuthMethod != "" {
		authMethod = &event.AuthMethod
	}
	riskScore := float32(event.RiskScore)

	_, err = q.CreateAuditLog(ctx, sqlc.CreateAuditLogParams{
		ID:                eventID,
		ProjectID:         event.ProjectID,
		TraceID:           traceID,
		EventType:         event.EventType,
		ActorEncrypted:    actorEncrypted,
		TargetType:        targetType,
		TargetID:          targetID,
		Result:            event.Result,
		AuthMethod:        authMethod,
		RiskScore:         &riskScore,
		MetadataEncrypted: metadataEncrypted,
		PrevHash:          prevHash,
		EventHash:         eventHash,
	})
	if err != nil {
		return fmt.Errorf("create audit log: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}

	return nil
}

// IntegrityReport contains the results of a hash chain verification.
type IntegrityReport struct {
	Valid    bool        `json:"valid"`
	Total   int         `json:"total"`
	BrokenAt *BrokenLink `json:"broken_at,omitempty"`
}

// BrokenLink identifies where the hash chain broke.
type BrokenLink struct {
	EventID string `json:"event_id"`
	Index   int    `json:"index"`
}

// Verify checks the integrity of the audit log hash chain for a project.
func (s *Service) Verify(ctx context.Context, projectID string) (*IntegrityReport, error) {
	if projectID == "" {
		return nil, ErrProjectIDRequired
	}

	q := sqlc.New(s.db)
	logs, err := q.ListAuditLogsAsc(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("list audit logs: %w", err)
	}

	report := &IntegrityReport{
		Valid: true,
		Total: len(logs),
	}

	for i, log := range logs {
		var prevHash *string
		if i > 0 {
			prevHash = &logs[i-1].EventHash
		}

		expectedHash, err := computeEventHash(computeHashInput{
			EventType:         log.EventType,
			ProjectID:         log.ProjectID,
			ActorEncrypted:    hex.EncodeToString(log.ActorEncrypted),
			TargetType:        derefStr(log.TargetType),
			TargetID:          derefStr(log.TargetID),
			Result:            log.Result,
			AuthMethod:        derefStr(log.AuthMethod),
			MetadataEncrypted: hex.EncodeToString(log.MetadataEncrypted),
			PrevHash:          derefStr(prevHash),
		}, prevHash)
		if err != nil {
			return nil, fmt.Errorf("compute event hash for verification at index %d: %w", i, err)
		}

		if subtle.ConstantTimeCompare([]byte(expectedHash), []byte(log.EventHash)) != 1 {
			report.Valid = false
			report.BrokenAt = &BrokenLink{
				EventID: log.ID,
				Index:   i,
			}
			return report, nil
		}

		// Also verify prev_hash linkage.
		if i == 0 && log.PrevHash != nil {
			report.Valid = false
			report.BrokenAt = &BrokenLink{
				EventID: log.ID,
				Index:   i,
			}
			return report, nil
		}
		if i > 0 {
			expectedPrev := logs[i-1].EventHash
			if log.PrevHash == nil || subtle.ConstantTimeCompare([]byte(*log.PrevHash), []byte(expectedPrev)) != 1 {
				report.Valid = false
				report.BrokenAt = &BrokenLink{
					EventID: log.ID,
					Index:   i,
				}
				return report, nil
			}
		}
	}

	return report, nil
}

// ListOptions configures audit log listing.
type ListOptions struct {
	Limit     int32
	Cursor    *Cursor
	EventType string
}

// Cursor represents a pagination cursor using created_at + id.
type Cursor struct {
	CreatedAt time.Time `json:"created_at"`
	ID        string    `json:"id"`
}

// ListResult contains paginated audit log results.
type ListResult struct {
	Events     []DecryptedEvent `json:"events"`
	NextCursor *Cursor          `json:"next_cursor,omitempty"`
	Total      int64            `json:"total"`
}

// DecryptedEvent is an audit event with decrypted PII fields.
type DecryptedEvent struct {
	ID         string         `json:"id"`
	ProjectID  string         `json:"project_id"`
	TraceID    string         `json:"trace_id,omitempty"`
	EventType  string         `json:"event_type"`
	Actor      *ActorInfo     `json:"actor,omitempty"`
	TargetType string         `json:"target_type,omitempty"`
	TargetID   string         `json:"target_id,omitempty"`
	Result     string         `json:"result"`
	AuthMethod string         `json:"auth_method,omitempty"`
	RiskScore  float32        `json:"risk_score"`
	Metadata   map[string]any `json:"metadata,omitempty"`
	PrevHash   string         `json:"prev_hash,omitempty"`
	EventHash  string         `json:"event_hash"`
	CreatedAt  time.Time      `json:"created_at"`
}

// List returns paginated audit logs with decrypted PII.
func (s *Service) List(ctx context.Context, projectID string, opts ListOptions) (*ListResult, error) {
	if projectID == "" {
		return nil, ErrProjectIDRequired
	}

	q := sqlc.New(s.db)

	if opts.Limit <= 0 {
		opts.Limit = 50
	}
	if opts.Limit > 100 {
		opts.Limit = 100
	}

	var logs []sqlc.AuditLog
	var err error

	fetchLimit := opts.Limit + 1

	if opts.Cursor != nil {
		ts := pgtype.Timestamptz{Time: opts.Cursor.CreatedAt, Valid: true}
		if opts.EventType != "" {
			logs, err = q.ListAuditLogsCursorByType(ctx, sqlc.ListAuditLogsCursorByTypeParams{
				ProjectID: projectID,
				EventType: opts.EventType,
				CreatedAt: ts,
				ID:        opts.Cursor.ID,
				Limit:     fetchLimit,
			})
		} else {
			logs, err = q.ListAuditLogsCursor(ctx, sqlc.ListAuditLogsCursorParams{
				ProjectID: projectID,
				CreatedAt: ts,
				ID:        opts.Cursor.ID,
				Limit:     fetchLimit,
			})
		}
	} else {
		if opts.EventType != "" {
			logs, err = q.ListAuditLogsFirstByType(ctx, sqlc.ListAuditLogsFirstByTypeParams{
				ProjectID: projectID,
				EventType: opts.EventType,
				Limit:     fetchLimit,
			})
		} else {
			logs, err = q.ListAuditLogsFirst(ctx, sqlc.ListAuditLogsFirstParams{
				ProjectID: projectID,
				Limit:     fetchLimit,
			})
		}
	}
	if err != nil {
		return nil, fmt.Errorf("list audit logs: %w", err)
	}

	var total int64
	if opts.EventType != "" {
		total, err = q.CountAuditLogsByType(ctx, projectID, opts.EventType)
	} else {
		total, err = q.CountAuditLogs(ctx, projectID)
	}
	if err != nil {
		return nil, fmt.Errorf("count audit logs: %w", err)
	}

	var nextCursor *Cursor
	if int32(len(logs)) > opts.Limit {
		logs = logs[:opts.Limit]
		last := logs[len(logs)-1]
		nextCursor = &Cursor{
			CreatedAt: last.CreatedAt.Time,
			ID:        last.ID,
		}
	}

	events := make([]DecryptedEvent, 0, len(logs))
	for _, log := range logs {
		de := s.decryptEvent(ctx, q, log)
		events = append(events, de)
	}

	return &ListResult{
		Events:     events,
		NextCursor: nextCursor,
		Total:      total,
	}, nil
}

// Export exports audit logs in JSON or CSV format with decrypted PII.
func (s *Service) Export(ctx context.Context, projectID string, format string) ([]byte, error) {
	if projectID == "" {
		return nil, ErrProjectIDRequired
	}

	format = strings.ToLower(format)
	if format != "json" && format != "csv" {
		return nil, ErrUnsupportedFormat
	}

	q := sqlc.New(s.db)
	logs, err := q.ListAuditLogsAsc(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("list audit logs: %w", err)
	}

	events := make([]DecryptedEvent, 0, len(logs))
	for _, log := range logs {
		de := s.decryptEvent(ctx, q, log)
		events = append(events, de)
	}

	switch format {
	case "json":
		return json.MarshalIndent(events, "", "  ")
	case "csv":
		return s.exportCSV(events)
	default:
		return nil, ErrUnsupportedFormat
	}
}

// Erase performs GDPR cryptographic erasure by revoking the user's DEK.
func (s *Service) Erase(ctx context.Context, projectID, userID string) error {
	if projectID == "" {
		return ErrProjectIDRequired
	}

	q := sqlc.New(s.db)

	// Revoke the user's DEK scoped to this project — makes their encrypted PII unreadable.
	if err := q.RevokeUserDEKByProject(ctx, &userID, &projectID); err != nil {
		return fmt.Errorf("revoke user DEK: %w", err)
	}

	// Log the GDPR erasure event — this event uses no PII (actor is system).
	return s.Log(ctx, AuditEvent{
		EventType: EventGDPRErasure,
		Actor: ActorInfo{
			UserID: "system",
		},
		Target: &TargetInfo{
			Type: "user",
			ID:   userID,
		},
		Result:    "success",
		ProjectID: projectID,
	})
}

// getOrCreateUserDEK retrieves or creates a per-user data encryption key, scoped to a project.
func (s *Service) getOrCreateUserDEK(ctx context.Context, q *sqlc.Queries, userID, projectID string) ([]byte, error) {
	dekAAD := []byte("dek:" + projectID + ":" + userID)

	ek, err := q.GetUserDEKByProject(ctx, &userID, &projectID)
	if err == nil {
		return crypto.Decrypt(ek.EncryptedKey, s.kek, dekAAD)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("get user DEK: %w", err)
	}

	dek, err := crypto.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generate DEK: %w", err)
	}

	encryptedDEK, err := crypto.Encrypt(dek, s.kek, dekAAD)
	if err != nil {
		return nil, fmt.Errorf("encrypt DEK: %w", err)
	}

	_, err = q.CreateEncryptionKey(ctx, sqlc.CreateEncryptionKeyParams{
		ID:           id.New("ek_"),
		ProjectID:    &projectID,
		UserID:       &userID,
		EncryptedKey: encryptedDEK,
		KeyType:      "user_dek",
	})
	if err != nil {
		return nil, fmt.Errorf("create encryption key: %w", err)
	}

	return dek, nil
}

// computeHashInput contains the fields used to compute the event hash.
type computeHashInput struct {
	EventType         string `json:"event_type"`
	ProjectID         string `json:"project_id"`
	ActorEncrypted    string `json:"actor_encrypted"`
	TargetType        string `json:"target_type"`
	TargetID          string `json:"target_id"`
	Result            string `json:"result"`
	AuthMethod        string `json:"auth_method"`
	MetadataEncrypted string `json:"metadata_encrypted"`
	PrevHash          string `json:"prev_hash"`
}

// computeEventHash computes SHA-256(prev_hash + canonicalJSON(hashInput)).
func computeEventHash(input computeHashInput, prevHash *string) (string, error) {
	canonical, err := CanonicalJSON(input)
	if err != nil {
		return "", fmt.Errorf("canonical json for hash: %w", err)
	}

	h := sha256.New()
	if prevHash != nil {
		h.Write([]byte(*prevHash))
	}
	h.Write(canonical)

	return hex.EncodeToString(h.Sum(nil)), nil
}

// advisoryLockKey derives a stable int64 lock key from a project ID.
func advisoryLockKey(projectID string) int64 {
	h := sha256.Sum256([]byte("audit-chain:" + projectID))
	// Use first 8 bytes as int64.
	return int64(binary.BigEndian.Uint64(h[:8]))
}

// frameWithUserID prepends the userID to encrypted data so it can be extracted
// during decryption without needing to decrypt first.
// Format: [2-byte big-endian userID length][userID bytes][ciphertext]
func frameWithUserID(userID string, ciphertext []byte) []byte {
	uidBytes := []byte(userID)
	buf := make([]byte, 2+len(uidBytes)+len(ciphertext))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(uidBytes)))
	copy(buf[2:2+len(uidBytes)], uidBytes)
	copy(buf[2+len(uidBytes):], ciphertext)
	return buf
}

// extractUserIDAndCiphertext extracts the userID and ciphertext from framed data.
func extractUserIDAndCiphertext(data []byte) (string, []byte, error) {
	if len(data) < 2 {
		return "", nil, errors.New("framed data too short")
	}
	uidLen := int(binary.BigEndian.Uint16(data[:2]))
	if len(data) < 2+uidLen {
		return "", nil, errors.New("framed data truncated")
	}
	userID := string(data[2 : 2+uidLen])
	ciphertext := data[2+uidLen:]
	return userID, ciphertext, nil
}

// decryptEvent converts a DB audit log to a decrypted event.
func (s *Service) decryptEvent(ctx context.Context, q *sqlc.Queries, log sqlc.AuditLog) DecryptedEvent {
	de := DecryptedEvent{
		ID:         log.ID,
		ProjectID:  log.ProjectID,
		EventType:  log.EventType,
		TargetType: derefStr(log.TargetType),
		TargetID:   derefStr(log.TargetID),
		Result:     log.Result,
		AuthMethod: derefStr(log.AuthMethod),
		PrevHash:   derefStr(log.PrevHash),
		EventHash:  log.EventHash,
		CreatedAt:  log.CreatedAt.Time,
	}
	if log.TraceID != nil {
		de.TraceID = *log.TraceID
	}
	if log.RiskScore != nil {
		de.RiskScore = *log.RiskScore
	}

	if len(log.ActorEncrypted) > 0 {
		actor := s.decryptFramedJSON(ctx, q, log.ActorEncrypted, log.ProjectID)
		if actor != nil {
			var a ActorInfo
			if err := json.Unmarshal(actor, &a); err == nil {
				de.Actor = &a
			}
		}
	}

	if len(log.MetadataEncrypted) > 0 {
		metaBytes := s.decryptFramedJSON(ctx, q, log.MetadataEncrypted, log.ProjectID)
		if metaBytes != nil {
			var m map[string]any
			if err := json.Unmarshal(metaBytes, &m); err == nil {
				de.Metadata = m
			}
		}
	}

	return de
}

// decryptFramedJSON extracts userID from framed data, looks up DEK scoped to project, and decrypts.
func (s *Service) decryptFramedJSON(ctx context.Context, q *sqlc.Queries, framedData []byte, projectID string) []byte {
	userID, ciphertext, err := extractUserIDAndCiphertext(framedData)
	if err != nil {
		s.logger.Warn("failed to extract user ID from framed data", "error", err)
		return nil
	}

	ek, err := q.GetUserDEKByProject(ctx, &userID, &projectID)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			s.logger.Warn("failed to get user DEK for decryption", "user_id", userID, "project_id", projectID, "error", err)
		}
		// DEK revoked or not found — PII unreadable (GDPR erasure case).
		return nil
	}

	dekAAD := []byte("dek:" + projectID + ":" + userID)
	dek, err := crypto.Decrypt(ek.EncryptedKey, s.kek, dekAAD)
	if err != nil {
		s.logger.Warn("failed to decrypt DEK", "user_id", userID, "error", err)
		return nil
	}

	piiAAD := []byte(projectID + ":" + userID)
	plaintext, err := crypto.Decrypt(ciphertext, dek, piiAAD)
	if err != nil {
		s.logger.Warn("failed to decrypt audit PII data", "user_id", userID, "error", err)
		return nil
	}

	return plaintext
}

func targetTypeStr(t *TargetInfo) string {
	if t == nil {
		return ""
	}
	return t.Type
}

func targetIDStr(t *TargetInfo) string {
	if t == nil {
		return ""
	}
	return t.ID
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func (s *Service) exportCSV(events []DecryptedEvent) ([]byte, error) {
	var buf strings.Builder
	w := csv.NewWriter(&buf)

	headers := []string{"id", "project_id", "trace_id", "event_type", "actor_user_id", "actor_email", "actor_ip", "target_type", "target_id", "result", "auth_method", "risk_score", "prev_hash", "event_hash", "created_at"}
	if err := w.Write(headers); err != nil {
		return nil, fmt.Errorf("csv write headers: %w", err)
	}

	for _, e := range events {
		actorUserID, actorEmail, actorIP := "", "", ""
		if e.Actor != nil {
			actorUserID = e.Actor.UserID
			actorEmail = e.Actor.Email
			actorIP = e.Actor.IP
		}
		row := []string{
			e.ID,
			e.ProjectID,
			e.TraceID,
			e.EventType,
			actorUserID,
			actorEmail,
			actorIP,
			e.TargetType,
			e.TargetID,
			e.Result,
			e.AuthMethod,
			fmt.Sprintf("%.2f", e.RiskScore),
			e.PrevHash,
			e.EventHash,
			e.CreatedAt.Format(time.RFC3339),
		}
		if err := w.Write(row); err != nil {
			return nil, fmt.Errorf("csv write row: %w", err)
		}
	}

	w.Flush()
	if err := w.Error(); err != nil {
		return nil, fmt.Errorf("csv flush: %w", err)
	}

	return []byte(buf.String()), nil
}
