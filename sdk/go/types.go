// Package palauth provides a Go client SDK for PalAuth authentication server.
package palauth

// AuthResult is returned from signup and login operations.
type AuthResult struct {
	AccessToken       string   `json:"access_token"`
	RefreshToken      string   `json:"refresh_token"`
	TokenType         string   `json:"token_type"`
	ExpiresIn         int      `json:"expires_in"`
	User              UserInfo `json:"user"`
	VerificationToken string   `json:"verification_token,omitempty"`
	VerificationCode  string   `json:"verification_code,omitempty"`
}

// UserInfo contains user information.
type UserInfo struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	CreatedAt     string `json:"created_at"`
}

// TokenResponse is returned from token refresh and exchange operations.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

// IntrospectionResponse is the result of token introspection.
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

// UserDetail contains detailed user information from admin API.
type UserDetail struct {
	ID             string                 `json:"id"`
	ProjectID      string                 `json:"project_id"`
	Email          string                 `json:"email"`
	EmailVerified  bool                   `json:"email_verified"`
	Banned         bool                   `json:"banned"`
	BanReason      string                 `json:"ban_reason,omitempty"`
	Metadata       map[string]interface{} `json:"metadata"`
	ActiveSessions int64                  `json:"active_sessions"`
	LastLoginAt    string                 `json:"last_login_at,omitempty"`
	CreatedAt      string                 `json:"created_at"`
	UpdatedAt      string                 `json:"updated_at,omitempty"`
}

// UserListResult contains paginated user results.
type UserListResult struct {
	Users      []UserDetail `json:"users"`
	NextCursor *UserCursor  `json:"next_cursor,omitempty"`
	Total      int64        `json:"total"`
}

// UserCursor represents a pagination cursor.
type UserCursor struct {
	CreatedAt string `json:"created_at"`
	ID        string `json:"id"`
}

// UserListOptions configures user listing.
type UserListOptions struct {
	Limit           int
	CursorCreatedAt string
	CursorID        string
	Banned          *bool
	Email           string
}

// ErrorResponse is the standard PalAuth error response.
type ErrorResponse struct {
	Error       string `json:"error"`
	Description string `json:"error_description"`
	Status      int    `json:"status"`
	RequestID   string `json:"request_id"`
}

// Session represents an active user session.
type Session struct {
	ID           string   `json:"id"`
	IP           string   `json:"ip,omitempty"`
	UserAgent    string   `json:"user_agent,omitempty"`
	ACR          string   `json:"acr"`
	AMR          []string `json:"amr"`
	LastActivity string   `json:"last_activity"`
	CreatedAt    string   `json:"created_at"`
	Current      bool     `json:"current"`
}
