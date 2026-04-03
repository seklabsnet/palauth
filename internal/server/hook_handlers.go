package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/palauth/palauth/internal/database/sqlc"
	"github.com/palauth/palauth/internal/hook"
	"github.com/palauth/palauth/internal/id"
)

type createHookRequest struct {
	Event       string `json:"event"`
	URL         string `json:"url"`
	TimeoutMs   int32  `json:"timeout_ms"`
	FailureMode string `json:"failure_mode"`
}

type updateHookRequest struct {
	Event       string `json:"event"`
	URL         string `json:"url"`
	TimeoutMs   int32  `json:"timeout_ms"`
	FailureMode string `json:"failure_mode"`
	Enabled     bool   `json:"enabled"`
}

type hookConfigResponse struct {
	ID          string `json:"id"`
	ProjectID   string `json:"project_id"`
	Event       string `json:"event"`
	URL         string `json:"url"`
	TimeoutMs   int32  `json:"timeout_ms"`
	FailureMode string `json:"failure_mode"`
	Enabled     bool   `json:"enabled"`
	CreatedAt   string `json:"created_at"`
}

func toHookConfigResponse(h *sqlc.HookConfig) hookConfigResponse {
	return hookConfigResponse{
		ID:          h.ID,
		ProjectID:   h.ProjectID,
		Event:       h.Event,
		URL:         h.Url,
		TimeoutMs:   h.TimeoutMs,
		FailureMode: h.FailureMode,
		Enabled:     h.Enabled,
		CreatedAt:   h.CreatedAt.Time.UTC().Format("2006-01-02T15:04:05Z"),
	}
}

func (s *Server) handleListHooks(w http.ResponseWriter, r *http.Request) {
	projectID := chi.URLParam(r, "id")

	q := s.newQueries()
	hooks, err := q.ListHooksByProject(r.Context(), projectID)
	if err != nil {
		s.logger.Error("failed to list hooks", "error", err)
		s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		return
	}

	result := make([]hookConfigResponse, 0, len(hooks))
	for i := range hooks {
		result = append(result, toHookConfigResponse(&hooks[i]))
	}

	s.WriteJSON(w, http.StatusOK, result)
}

func (s *Server) handleCreateHook(w http.ResponseWriter, r *http.Request) {
	projectID := chi.URLParam(r, "id")

	if s.hookEngine == nil {
		s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "Hook engine not available")
		return
	}

	var req createHookRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.WriteError(w, r, http.StatusBadRequest, "invalid_request", "Invalid JSON body")
		return
	}

	if req.Event == "" {
		s.WriteError(w, r, http.StatusBadRequest, "event_required", "Hook event is required")
		return
	}
	if !hook.ValidEvents[req.Event] {
		s.WriteError(w, r, http.StatusBadRequest, "invalid_event", "Invalid hook event type")
		return
	}
	if req.URL == "" {
		s.WriteError(w, r, http.StatusBadRequest, "url_required", "Hook URL is required")
		return
	}

	// Validate URL for SSRF.
	if err := hook.ValidateHookURL(req.URL, s.hookEngine.DevMode()); err != nil {
		switch {
		case errors.Is(err, hook.ErrPrivateURL):
			s.WriteError(w, r, http.StatusBadRequest, "private_url", "Hook URL must not resolve to a private IP address")
		case errors.Is(err, hook.ErrHTTPSRequired):
			s.WriteError(w, r, http.StatusBadRequest, "https_required", "Hook URL must use HTTPS")
		default:
			s.WriteError(w, r, http.StatusBadRequest, "invalid_url", "Invalid hook URL")
		}
		return
	}

	if req.TimeoutMs == 0 {
		req.TimeoutMs = 15000
	}
	if req.TimeoutMs < hook.MinHookTimeoutMs || req.TimeoutMs > hook.MaxHookTimeoutMs {
		s.WriteError(w, r, http.StatusBadRequest, "invalid_timeout",
			fmt.Sprintf("Hook timeout must be between %d and %d milliseconds", hook.MinHookTimeoutMs, hook.MaxHookTimeoutMs))
		return
	}
	if req.FailureMode == "" {
		req.FailureMode = "deny"
	}
	if req.FailureMode != "deny" && req.FailureMode != "allow" {
		s.WriteError(w, r, http.StatusBadRequest, "invalid_failure_mode", "Failure mode must be 'deny' or 'allow'")
		return
	}

	hookID := id.New("hk_")

	// Generate and encrypt signing key.
	encryptedKey, err := hook.GenerateSigningKey(s.hookEngine.KEK(), projectID, hookID)
	if err != nil {
		s.logger.Error("failed to generate signing key", "error", err)
		s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		return
	}

	q := s.newQueries()
	created, err := q.CreateHookConfig(r.Context(), sqlc.CreateHookConfigParams{
		ID:                  hookID,
		ProjectID:           projectID,
		Event:               req.Event,
		Url:                 req.URL,
		SigningKeyEncrypted: encryptedKey,
		TimeoutMs:           req.TimeoutMs,
		FailureMode:         req.FailureMode,
		Enabled:             true,
	})
	if err != nil {
		s.logger.Error("failed to create hook config", "error", err)
		s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		return
	}

	s.WriteJSON(w, http.StatusCreated, toHookConfigResponse(&created))
}

func (s *Server) handleUpdateHook(w http.ResponseWriter, r *http.Request) {
	projectID := chi.URLParam(r, "id")
	hookID := chi.URLParam(r, "hid")

	if s.hookEngine == nil {
		s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "Hook engine not available")
		return
	}

	var req updateHookRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.WriteError(w, r, http.StatusBadRequest, "invalid_request", "Invalid JSON body")
		return
	}

	if req.Event == "" {
		s.WriteError(w, r, http.StatusBadRequest, "event_required", "Hook event is required")
		return
	}
	if !hook.ValidEvents[req.Event] {
		s.WriteError(w, r, http.StatusBadRequest, "invalid_event", "Invalid hook event type")
		return
	}
	if req.URL == "" {
		s.WriteError(w, r, http.StatusBadRequest, "url_required", "Hook URL is required")
		return
	}

	if err := hook.ValidateHookURL(req.URL, s.hookEngine.DevMode()); err != nil {
		switch {
		case errors.Is(err, hook.ErrPrivateURL):
			s.WriteError(w, r, http.StatusBadRequest, "private_url", "Hook URL must not resolve to a private IP address")
		case errors.Is(err, hook.ErrHTTPSRequired):
			s.WriteError(w, r, http.StatusBadRequest, "https_required", "Hook URL must use HTTPS")
		default:
			s.WriteError(w, r, http.StatusBadRequest, "invalid_url", "Invalid hook URL")
		}
		return
	}

	if req.TimeoutMs == 0 {
		req.TimeoutMs = 15000
	}
	if req.TimeoutMs < hook.MinHookTimeoutMs || req.TimeoutMs > hook.MaxHookTimeoutMs {
		s.WriteError(w, r, http.StatusBadRequest, "invalid_timeout",
			fmt.Sprintf("Hook timeout must be between %d and %d milliseconds", hook.MinHookTimeoutMs, hook.MaxHookTimeoutMs))
		return
	}
	if req.FailureMode != "deny" && req.FailureMode != "allow" {
		s.WriteError(w, r, http.StatusBadRequest, "invalid_failure_mode", "Failure mode must be 'deny' or 'allow'")
		return
	}

	q := s.newQueries()
	updated, err := q.UpdateHookConfig(r.Context(), sqlc.UpdateHookConfigParams{
		ID:          hookID,
		ProjectID:   projectID,
		Event:       req.Event,
		Url:         req.URL,
		TimeoutMs:   req.TimeoutMs,
		FailureMode: req.FailureMode,
		Enabled:     req.Enabled,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			s.WriteError(w, r, http.StatusNotFound, "not_found", "Hook not found")
			return
		}
		s.logger.Error("failed to update hook config", "error", err)
		s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		return
	}

	s.WriteJSON(w, http.StatusOK, toHookConfigResponse(&updated))
}

func (s *Server) handleDeleteHook(w http.ResponseWriter, r *http.Request) {
	projectID := chi.URLParam(r, "id")
	hookID := chi.URLParam(r, "hid")

	q := s.newQueries()
	if err := q.DeleteHookConfig(r.Context(), sqlc.DeleteHookConfigParams{
		ID:        hookID,
		ProjectID: projectID,
	}); err != nil {
		s.logger.Error("failed to delete hook config", "error", err)
		s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		return
	}

	s.WriteJSON(w, http.StatusOK, map[string]bool{"success": true})
}

func (s *Server) handleTestHook(w http.ResponseWriter, r *http.Request) {
	projectID := chi.URLParam(r, "id")
	hookID := chi.URLParam(r, "hid")

	q := s.newQueries()
	hookConfig, err := q.GetHookConfig(r.Context(), sqlc.GetHookConfigParams{
		ID:        hookID,
		ProjectID: projectID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			s.WriteError(w, r, http.StatusNotFound, "not_found", "Hook not found")
			return
		}
		s.logger.Error("failed to get hook config", "error", err)
		s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		return
	}

	// Send a test payload.
	testPayload := hook.Payload{
		Event:     hookConfig.Event,
		ProjectID: projectID,
		User: &hook.UserInfo{
			ID:    id.New("usr_"),
			Email: "test@example.com",
		},
	}

	resp, err := s.hookEngine.ExecuteBlocking(r.Context(), projectID, hookConfig.Event, testPayload)
	if err != nil {
		s.WriteJSON(w, http.StatusOK, map[string]any{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	s.WriteJSON(w, http.StatusOK, map[string]any{
		"success":  true,
		"verdict":  resp.Verdict,
		"reason":   resp.Reason,
		"metadata": resp.Metadata,
	})
}

func (s *Server) handleHookLogs(w http.ResponseWriter, r *http.Request) {
	projectID := chi.URLParam(r, "id")
	hookID := chi.URLParam(r, "hid")

	q := s.newQueries()
	logs, err := q.ListHookLogs(r.Context(), sqlc.ListHookLogsParams{
		HookConfigID: hookID,
		ProjectID:    projectID,
		Limit:        100,
	})
	if err != nil {
		s.logger.Error("failed to list hook logs", "error", err)
		s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		return
	}

	type hookLogResponse struct {
		ID             string `json:"id"`
		HookConfigID   string `json:"hook_config_id"`
		Event          string `json:"event"`
		RequestBody    any    `json:"request_body,omitempty"`
		ResponseBody   any    `json:"response_body,omitempty"`
		ResponseStatus *int32 `json:"response_status,omitempty"`
		LatencyMs      int32  `json:"latency_ms"`
		Result         string `json:"result"`
		CreatedAt      string `json:"created_at"`
	}

	result := make([]hookLogResponse, 0, len(logs))
	for i := range logs {
		entry := hookLogResponse{
			ID:             logs[i].ID,
			HookConfigID:   logs[i].HookConfigID,
			Event:          logs[i].Event,
			ResponseStatus: logs[i].ResponseStatus,
			LatencyMs:      logs[i].LatencyMs,
			Result:         logs[i].Result,
			CreatedAt:      logs[i].CreatedAt.Time.UTC().Format("2006-01-02T15:04:05Z"),
		}
		if logs[i].RequestBody != nil {
			var reqBody any
			if err := json.Unmarshal(logs[i].RequestBody, &reqBody); err == nil {
				entry.RequestBody = reqBody
			}
		}
		if logs[i].ResponseBody != nil {
			var respBody any
			if err := json.Unmarshal(logs[i].ResponseBody, &respBody); err == nil {
				entry.ResponseBody = respBody
			}
		}
		result = append(result, entry)
	}

	s.WriteJSON(w, http.StatusOK, result)
}
