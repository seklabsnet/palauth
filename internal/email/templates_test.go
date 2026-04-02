package email

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTemplateRenderer(t *testing.T) {
	renderer, err := NewTemplateRenderer()
	require.NoError(t, err)
	require.NotNil(t, renderer)
	assert.Len(t, renderer.htmlTemplates, 4)
	assert.Len(t, renderer.textTemplates, 4)
}

func TestTemplateRenderer_VerificationLink(t *testing.T) {
	renderer, err := NewTemplateRenderer()
	require.NoError(t, err)

	data := &TemplateData{
		ProjectName:   "MyApp",
		UserEmail:     "user@example.com",
		Token:         "abc123",
		Link:          "https://example.com/verify?token=abc123",
		ExpiryMinutes: 1440,
	}

	htmlOut, textOut, err := renderer.Render(TemplateVerificationLink, data)
	require.NoError(t, err)

	// HTML assertions.
	assert.Contains(t, htmlOut, "MyApp")
	assert.Contains(t, htmlOut, "https://example.com/verify?token=abc123")
	assert.Contains(t, htmlOut, "1440")
	assert.Contains(t, htmlOut, "Verify")

	// Plaintext assertions.
	assert.Contains(t, textOut, "MyApp")
	assert.Contains(t, textOut, "https://example.com/verify?token=abc123")
	assert.Contains(t, textOut, "1440")
}

func TestTemplateRenderer_VerificationCode(t *testing.T) {
	renderer, err := NewTemplateRenderer()
	require.NoError(t, err)

	data := &TemplateData{
		ProjectName:   "TestProject",
		Code:          "123456",
		ExpiryMinutes: 5,
	}

	htmlOut, textOut, err := renderer.Render(TemplateVerificationCode, data)
	require.NoError(t, err)

	assert.Contains(t, htmlOut, "123456")
	assert.Contains(t, htmlOut, "TestProject")
	assert.Contains(t, htmlOut, "5")

	assert.Contains(t, textOut, "123456")
	assert.Contains(t, textOut, "TestProject")
}

func TestTemplateRenderer_PasswordReset(t *testing.T) {
	renderer, err := NewTemplateRenderer()
	require.NoError(t, err)

	data := &TemplateData{
		ProjectName:   "SecureApp",
		Link:          "https://example.com/reset?token=xyz",
		ExpiryMinutes: 15,
	}

	htmlOut, textOut, err := renderer.Render(TemplatePasswordReset, data)
	require.NoError(t, err)

	assert.Contains(t, htmlOut, "SecureApp")
	assert.Contains(t, htmlOut, "https://example.com/reset?token=xyz")
	assert.Contains(t, htmlOut, "15")
	assert.Contains(t, htmlOut, "Reset")

	assert.Contains(t, textOut, "SecureApp")
	assert.Contains(t, textOut, "https://example.com/reset?token=xyz")
}

func TestTemplateRenderer_Welcome(t *testing.T) {
	renderer, err := NewTemplateRenderer()
	require.NoError(t, err)

	data := &TemplateData{
		ProjectName: "WelcomeApp",
	}

	htmlOut, textOut, err := renderer.Render(TemplateWelcome, data)
	require.NoError(t, err)

	assert.Contains(t, htmlOut, "WelcomeApp")
	assert.Contains(t, htmlOut, "Welcome")

	assert.Contains(t, textOut, "WelcomeApp")
	assert.Contains(t, textOut, "Welcome")
}

func TestTemplateRenderer_UnknownType(t *testing.T) {
	renderer, err := NewTemplateRenderer()
	require.NoError(t, err)

	_, _, err = renderer.Render(TemplateType("nonexistent"), &TemplateData{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown template type")
}

func TestTemplateRenderer_XSSPrevention(t *testing.T) {
	renderer, err := NewTemplateRenderer()
	require.NoError(t, err)

	maliciousData := &TemplateData{
		ProjectName:   `<script>alert("xss")</script>`,
		UserEmail:     `"><img src=x onerror=alert(1)>`,
		Link:          `javascript:alert(1)`,
		Code:          `<script>steal()</script>`,
		ExpiryMinutes: 5,
	}

	// Test all templates with malicious data.
	templates := []TemplateType{
		TemplateVerificationLink,
		TemplateVerificationCode,
		TemplatePasswordReset,
		TemplateWelcome,
	}

	for _, tt := range templates {
		t.Run(string(tt), func(t *testing.T) {
			htmlOut, _, err := renderer.Render(tt, maliciousData)
			require.NoError(t, err)

			// html/template should escape these.
			assert.NotContains(t, htmlOut, `<script>`, "script tag should be escaped in HTML output")
			assert.NotContains(t, htmlOut, `onerror=`, "event handler should be escaped in HTML output")

			// Verify the escaped versions are present.
			if strings.Contains(htmlOut, "alert") {
				assert.Contains(t, htmlOut, "&lt;script&gt;", "script tags should be HTML-escaped")
			}
		})
	}
}

func TestTemplateRenderer_PlaintextFallbackExists(t *testing.T) {
	renderer, err := NewTemplateRenderer()
	require.NoError(t, err)

	data := &TemplateData{
		ProjectName:   "TestApp",
		UserEmail:     "user@example.com",
		Token:         "token123",
		Code:          "123456",
		Link:          "https://example.com/action",
		ExpiryMinutes: 30,
	}

	templates := []TemplateType{
		TemplateVerificationLink,
		TemplateVerificationCode,
		TemplatePasswordReset,
		TemplateWelcome,
	}

	for _, tt := range templates {
		t.Run(string(tt), func(t *testing.T) {
			htmlOut, textOut, err := renderer.Render(tt, data)
			require.NoError(t, err)

			assert.NotEmpty(t, htmlOut, "HTML output should not be empty")
			assert.NotEmpty(t, textOut, "plaintext output should not be empty")

			// Plaintext should NOT contain HTML tags.
			assert.NotContains(t, textOut, "<html", "plaintext should not contain HTML tags")
			assert.NotContains(t, textOut, "<body", "plaintext should not contain body tags")
			assert.NotContains(t, textOut, "<p ", "plaintext should not contain p tags")
		})
	}
}

func TestTemplateRenderer_AllTemplatesRenderBothVersions(t *testing.T) {
	renderer, err := NewTemplateRenderer()
	require.NoError(t, err)

	data := &TemplateData{
		ProjectName:   "App",
		Code:          "000000",
		Link:          "https://example.com",
		ExpiryMinutes: 10,
	}

	templates := []TemplateType{
		TemplateVerificationLink,
		TemplateVerificationCode,
		TemplatePasswordReset,
		TemplateWelcome,
	}

	for _, tt := range templates {
		t.Run(string(tt)+"_html", func(t *testing.T) {
			htmlOut, _, err := renderer.Render(tt, data)
			require.NoError(t, err)
			assert.NotEmpty(t, htmlOut)
		})
		t.Run(string(tt)+"_text", func(t *testing.T) {
			_, textOut, err := renderer.Render(tt, data)
			require.NoError(t, err)
			assert.NotEmpty(t, textOut)
		})
	}
}
