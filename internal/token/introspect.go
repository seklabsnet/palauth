package token

// IntrospectionResponse represents the RFC 7662 token introspection response.
type IntrospectionResponse struct {
	Active    bool   `json:"active"`
	Subject   string `json:"sub,omitempty"`
	Scope     string `json:"scope,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	ProjectID string `json:"project_id,omitempty"`
	TokenType string `json:"token_type,omitempty"`
	JWTID     string `json:"jti,omitempty"`
}

// IntrospectAccessToken verifies a JWT access token and returns introspection data.
// Verify() already checks signature, expiry, and mandatory claims — no need for
// a separate expiry check.
func (s *JWTService) IntrospectAccessToken(tokenStr string) *IntrospectionResponse {
	claims, err := s.Verify(tokenStr)
	if err != nil {
		return &IntrospectionResponse{Active: false}
	}

	return &IntrospectionResponse{
		Active:    true,
		Subject:   claims.Subject,
		ExpiresAt: claims.ExpiresAt.Unix(),
		IssuedAt:  claims.IssuedAt.Unix(),
		ProjectID: claims.ProjectID,
		TokenType: "Bearer",
		JWTID:     claims.JWTID,
	}
}
