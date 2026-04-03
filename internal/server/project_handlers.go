package server

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/palauth/palauth/internal/project"
)

type createProjectRequest struct {
	Name   string                `json:"name"`
	Config *project.Config `json:"config,omitempty"`
}

type updateProjectRequest struct {
	Name   string                `json:"name"`
	Config *project.Config `json:"config,omitempty"`
}

type rotateKeysRequest struct {
	KeyType string `json:"key_type"`
}

type rotateKeysResponse struct {
	NewKey string `json:"new_key"`
}

func (s *Server) handleCreateProject(w http.ResponseWriter, r *http.Request) {
	var req createProjectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.WriteError(w, r, http.StatusBadRequest, "invalid_request", "Invalid JSON body")
		return
	}

	cfg := project.DefaultConfig()
	if req.Config != nil {
		cfg = *req.Config
	}

	prj, err := s.projectSvc.Create(r.Context(), req.Name, &cfg)
	if err != nil {
		if errors.Is(err, project.ErrEmptyName) {
			s.WriteError(w, r, http.StatusBadRequest, "name_required", "Project name is required")
			return
		}
		s.logger.Error("create project failed", "error", err)
		s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		return
	}

	// Generate 4 API keys for the new project.
	keys, err := s.apikeySvc.GenerateAllForProject(r.Context(), prj.ID)
	if err != nil {
		s.logger.Error("generate api keys failed", "error", err)
		s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		return
	}

	s.WriteJSON(w, http.StatusCreated, map[string]any{
		"project":  prj,
		"api_keys": keys,
	})
}

func (s *Server) handleListProjects(w http.ResponseWriter, r *http.Request) {
	projects, err := s.projectSvc.List(r.Context())
	if err != nil {
		s.logger.Error("list projects failed", "error", err)
		s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		return
	}

	s.WriteJSON(w, http.StatusOK, projects)
}

func (s *Server) handleGetProject(w http.ResponseWriter, r *http.Request) {
	projectID := chi.URLParam(r, "id")

	prj, err := s.projectSvc.Get(r.Context(), projectID)
	if err != nil {
		if errors.Is(err, project.ErrNotFound) {
			s.WriteError(w, r, http.StatusNotFound, "not_found", "Project not found")
			return
		}
		s.logger.Error("get project failed", "error", err)
		s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		return
	}

	s.WriteJSON(w, http.StatusOK, prj)
}

func (s *Server) handleUpdateProject(w http.ResponseWriter, r *http.Request) {
	projectID := chi.URLParam(r, "id")

	var req updateProjectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.WriteError(w, r, http.StatusBadRequest, "invalid_request", "Invalid JSON body")
		return
	}

	// When config is not provided, preserve the existing project config.
	var cfg project.Config
	if req.Config != nil {
		cfg = *req.Config
	} else {
		existing, err := s.projectSvc.Get(r.Context(), projectID)
		if err != nil {
			if errors.Is(err, project.ErrNotFound) {
				s.WriteError(w, r, http.StatusNotFound, "not_found", "Project not found")
				return
			}
			s.logger.Error("get project for update failed", "error", err)
			s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
			return
		}
		cfg = existing.Config
	}

	prj, err := s.projectSvc.Update(r.Context(), projectID, req.Name, &cfg)
	if err != nil {
		if errors.Is(err, project.ErrNotFound) {
			s.WriteError(w, r, http.StatusNotFound, "not_found", "Project not found")
			return
		}
		if errors.Is(err, project.ErrEmptyName) {
			s.WriteError(w, r, http.StatusBadRequest, "name_required", "Project name is required")
			return
		}
		s.logger.Error("update project failed", "error", err)
		s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		return
	}

	s.WriteJSON(w, http.StatusOK, prj)
}

func (s *Server) handleDeleteProject(w http.ResponseWriter, r *http.Request) {
	projectID := chi.URLParam(r, "id")

	if err := s.projectSvc.Delete(r.Context(), projectID); err != nil {
		if errors.Is(err, project.ErrNotFound) {
			s.WriteError(w, r, http.StatusNotFound, "not_found", "Project not found")
			return
		}
		s.logger.Error("delete project failed", "error", err)
		s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRotateKeys(w http.ResponseWriter, r *http.Request) {
	projectID := chi.URLParam(r, "id")

	var req rotateKeysRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.WriteError(w, r, http.StatusBadRequest, "invalid_request", "Invalid JSON body")
		return
	}

	newKey, err := s.apikeySvc.Rotate(r.Context(), projectID, req.KeyType)
	if err != nil {
		s.logger.Error("rotate keys failed", "error", err)
		s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		return
	}

	s.WriteJSON(w, http.StatusOK, rotateKeysResponse{NewKey: newKey})
}

func (s *Server) handleListKeys(w http.ResponseWriter, r *http.Request) {
	projectID := chi.URLParam(r, "id")

	keys, err := s.apikeySvc.List(r.Context(), projectID)
	if err != nil {
		s.logger.Error("list keys failed", "error", err)
		s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		return
	}

	s.WriteJSON(w, http.StatusOK, keys)
}
