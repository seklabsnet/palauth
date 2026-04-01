package server

import (
	"log/slog"
	"net/http"

	"github.com/palauth/palauth/internal/httputil"
)

// ErrorResponse re-exports for backward compatibility with existing tests.
type ErrorResponse = httputil.ErrorResponse

func (s *Server) WriteError(w http.ResponseWriter, r *http.Request, status int, errCode, description string) {
	httputil.WriteError(s.logger, w, r, status, errCode, description)
}

func (s *Server) WriteJSON(w http.ResponseWriter, status int, data any) {
	httputil.WriteJSON(s.logger, w, status, data)
}

// writeErrorWithLogger is used by middleware that doesn't have access to the Server struct.
func writeErrorWithLogger(logger *slog.Logger, w http.ResponseWriter, r *http.Request, status int, errCode, description string) {
	httputil.WriteError(logger, w, r, status, errCode, description)
}
