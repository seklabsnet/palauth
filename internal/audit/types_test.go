package audit

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEventTypeConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{"signup", EventAuthSignup, "auth.signup"},
		{"signup failure", EventAuthSignupFailure, "auth.signup.failure"},
		{"login success", EventAuthLoginSuccess, "auth.login.success"},
		{"login failure", EventAuthLoginFailure, "auth.login.failure"},
		{"logout", EventAuthLogout, "auth.logout"},
		{"password reset request", EventAuthPasswordResetReq, "auth.password.reset.request"},
		{"password reset complete", EventAuthPasswordResetDone, "auth.password.reset.complete"},
		{"password change", EventAuthPasswordChange, "auth.password.change"},
		{"email verify", EventAuthEmailVerify, "auth.email.verify"},
		{"session create", EventSessionCreate, "session.create"},
		{"session revoke", EventSessionRevoke, "session.revoke"},
		{"token issue", EventTokenIssue, "token.issue"},
		{"token refresh", EventTokenRefresh, "token.refresh"},
		{"token revoke", EventTokenRevoke, "token.revoke"},
		{"admin user create", EventAdminUserCreate, "admin.user.create"},
		{"admin user update", EventAdminUserUpdate, "admin.user.update"},
		{"admin user delete", EventAdminUserDelete, "admin.user.delete"},
		{"admin config change", EventAdminConfigChange, "admin.config.change"},
		{"admin key rotate", EventAdminKeyRotate, "admin.key.rotate"},
		{"admin user deactivate inactive", EventAdminUserDeactivateInactive, "admin.user.deactivate_inactive"},
		{"admin invite", EventAdminInvite, "admin.invite"},
		{"gdpr erasure", EventGDPRErasure, "gdpr.erasure"},
		{"mfa enroll", EventMFAEnroll, "mfa.enroll"},
		{"mfa verify success", EventMFAVerifySuccess, "mfa.verify.success"},
		{"mfa verify failure", EventMFAVerifyFailure, "mfa.verify.failure"},
		{"mfa remove", EventMFARemove, "mfa.remove"},
		{"mfa recovery used", EventMFARecoveryUsed, "mfa.recovery.used"},
		{"social login", EventSocialLogin, "auth.social.login"},
		{"social link", EventSocialLink, "social.link"},
		{"social unlink", EventSocialUnlink, "social.unlink"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.constant)
		})
	}
}

func TestAllEventTypesContainsAll(t *testing.T) {
	expected := []string{
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
		EventMFAEnroll,
		EventMFAVerifySuccess,
		EventMFAVerifyFailure,
		EventMFARemove,
		EventMFARecoveryUsed,
		EventSocialLogin,
		EventSocialLink,
		EventSocialUnlink,
	}

	assert.Equal(t, expected, AllEventTypes)
	assert.Len(t, AllEventTypes, 30)
}
