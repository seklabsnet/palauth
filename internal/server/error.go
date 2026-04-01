package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

type ErrorResponse struct {
	Error       string `json:"error"`
	Description string `json:"error_description"`
	Status      int    `json:"status"`
	RequestID   string `json:"request_id"`
}

func (s *Server) WriteError(w http.ResponseWriter, r *http.Request, status int, errCode, description string) {
	resp := ErrorResponse{
		Error:       errCode,
		Description: description,
		Status:      status,
		RequestID:   GetRequestID(r.Context()),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.logger.Error("failed to write error response", "error", err)
	}
}

func (s *Server) WriteJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		s.logger.Error("failed to write json response", "error", err)
	}
}

// writeErrorWithLogger is used by middleware that doesn't have access to the Server struct.
func writeErrorWithLogger(logger *slog.Logger, w http.ResponseWriter, r *http.Request, status int, errCode, description string) {
	resp := ErrorResponse{
		Error:       errCode,
		Description: description,
		Status:      status,
		RequestID:   GetRequestID(r.Context()),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		logger.Error("failed to write error response", "error", err)
	}
}
