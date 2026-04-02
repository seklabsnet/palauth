package server

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/palauth/palauth/internal/audit"
)

func (s *Server) handleListAuditLogs(w http.ResponseWriter, r *http.Request) {
	projectID := chi.URLParam(r, "id")

	opts := audit.ListOptions{}

	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		limit, err := strconv.ParseInt(limitStr, 10, 32)
		if err != nil || limit < 1 {
			s.WriteError(w, r, http.StatusBadRequest, "invalid_limit", "Limit must be a positive integer")
			return
		}
		opts.Limit = int32(limit) //nolint:gosec // G109: range validated above
	}

	if eventType := r.URL.Query().Get("event_type"); eventType != "" {
		opts.EventType = eventType
	}

	cursorTime := r.URL.Query().Get("cursor_time")
	cursorID := r.URL.Query().Get("cursor_id")
	if cursorTime != "" && cursorID != "" {
		t, err := time.Parse(time.RFC3339Nano, cursorTime)
		if err != nil {
			s.WriteError(w, r, http.StatusBadRequest, "invalid_cursor", "cursor_time must be RFC3339 format")
			return
		}
		opts.Cursor = &audit.Cursor{
			CreatedAt: t,
			ID:        cursorID,
		}
	}

	result, err := s.auditSvc.List(r.Context(), projectID, opts)
	if err != nil {
		s.logger.Error("list audit logs failed", "error", err)
		s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		return
	}

	s.WriteJSON(w, http.StatusOK, result)
}

func (s *Server) handleVerifyAuditLogs(w http.ResponseWriter, r *http.Request) {
	projectID := chi.URLParam(r, "id")

	report, err := s.auditSvc.Verify(r.Context(), projectID)
	if err != nil {
		s.logger.Error("verify audit logs failed", "error", err)
		s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		return
	}

	s.WriteJSON(w, http.StatusOK, report)
}

func (s *Server) handleExportAuditLogs(w http.ResponseWriter, r *http.Request) {
	projectID := chi.URLParam(r, "id")

	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}

	data, err := s.auditSvc.Export(r.Context(), projectID, format)
	if err != nil {
		if errors.Is(err, audit.ErrUnsupportedFormat) {
			s.WriteError(w, r, http.StatusBadRequest, "invalid_format", "Supported formats: json, csv")
			return
		}
		s.logger.Error("export audit logs failed", "error", err)
		s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		return
	}

	switch format {
	case "csv":
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=audit_logs.csv")
	default:
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=audit_logs.json")
	}

	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(data); err != nil {
		s.logger.Warn("failed to write export response", "error", err, "project_id", projectID, "format", format)
	}
}
