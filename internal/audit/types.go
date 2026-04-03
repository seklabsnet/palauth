package audit

// Event type constants for all auditable auth operations.
const (
	EventAuthSignup           = "auth.signup"
	EventAuthSignupFailure    = "auth.signup.failure"
	EventAuthLoginSuccess     = "auth.login.success"
	EventAuthLoginFailure     = "auth.login.failure"
	EventAuthLogout           = "auth.logout"
	EventAuthPasswordResetReq = "auth.password.reset.request"
	EventAuthPasswordResetDone = "auth.password.reset.complete"
	EventAuthPasswordChange   = "auth.password.change"
	EventAuthEmailVerify      = "auth.email.verify"
	EventSessionCreate        = "session.create"
	EventSessionRevoke        = "session.revoke"
	EventTokenIssue           = "token.issue"
	EventTokenRefresh         = "token.refresh"
	EventTokenRevoke          = "token.revoke"
	EventAdminUserCreate      = "admin.user.create"
	EventAdminUserUpdate      = "admin.user.update"
	EventAdminUserDelete      = "admin.user.delete"
	EventAdminConfigChange    = "admin.config.change"
	EventAdminKeyRotate              = "admin.key.rotate"
	EventAdminUserDeactivateInactive = "admin.user.deactivate_inactive"
	EventAdminInvite                 = "admin.invite"
	EventGDPRErasure                 = "gdpr.erasure"
)

// AllEventTypes lists all valid event types for validation.
var AllEventTypes = []string{
	EventAuthSignup,
	EventAuthSignupFailure,
	EventAuthLoginSuccess,
	EventAuthLoginFailure,
	EventAuthLogout,
	EventAuthPasswordResetReq,
	EventAuthPasswordResetDone,
	EventAuthPasswordChange,
	EventAuthEmailVerify,
	EventSessionCreate,
	EventSessionRevoke,
	EventTokenIssue,
	EventTokenRefresh,
	EventTokenRevoke,
	EventAdminUserCreate,
	EventAdminUserUpdate,
	EventAdminUserDelete,
	EventAdminConfigChange,
	EventAdminKeyRotate,
	EventAdminUserDeactivateInactive,
	EventAdminInvite,
	EventGDPRErasure,
}
