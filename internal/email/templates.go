package email

import (
	"bytes"
	"embed"
	"fmt"
	htmltemplate "html/template"
	texttemplate "text/template"
)

//go:embed templates/*.html templates/*.txt
var templateFS embed.FS

// TemplateType identifies which email template to render.
type TemplateType string

const (
	TemplateVerificationLink TemplateType = "verification_link"
	TemplateVerificationCode TemplateType = "verification_code"
	TemplatePasswordReset    TemplateType = "password_reset"
	TemplateWelcome          TemplateType = "welcome"
)

// TemplateData contains the data passed to email templates.
type TemplateData struct {
	ProjectName  string
	UserEmail    string
	Token        string
	Code         string
	Link         string
	ExpiryMinutes int
}

// TemplateRenderer renders email templates from embedded files.
type TemplateRenderer struct {
	htmlTemplates map[TemplateType]*htmltemplate.Template
	textTemplates map[TemplateType]*texttemplate.Template
}

// NewTemplateRenderer parses all embedded templates and returns a renderer.
func NewTemplateRenderer() (*TemplateRenderer, error) {
	types := []TemplateType{
		TemplateVerificationLink,
		TemplateVerificationCode,
		TemplatePasswordReset,
		TemplateWelcome,
	}

	htmlTemplates := make(map[TemplateType]*htmltemplate.Template, len(types))
	textTemplates := make(map[TemplateType]*texttemplate.Template, len(types))

	for _, tt := range types {
		htmlFile := fmt.Sprintf("templates/%s.html", tt)
		htmlData, err := templateFS.ReadFile(htmlFile)
		if err != nil {
			return nil, fmt.Errorf("read html template %s: %w", tt, err)
		}
		htmlTmpl, err := htmltemplate.New(string(tt)).Parse(string(htmlData))
		if err != nil {
			return nil, fmt.Errorf("parse html template %s: %w", tt, err)
		}
		htmlTemplates[tt] = htmlTmpl

		textFile := fmt.Sprintf("templates/%s.txt", tt)
		textData, err := templateFS.ReadFile(textFile)
		if err != nil {
			return nil, fmt.Errorf("read text template %s: %w", tt, err)
		}
		textTmpl, err := texttemplate.New(string(tt)).Parse(string(textData))
		if err != nil {
			return nil, fmt.Errorf("parse text template %s: %w", tt, err)
		}
		textTemplates[tt] = textTmpl
	}

	return &TemplateRenderer{
		htmlTemplates: htmlTemplates,
		textTemplates: textTemplates,
	}, nil
}

// Render renders both HTML and plaintext versions of a template.
func (r *TemplateRenderer) Render(tt TemplateType, data *TemplateData) (htmlOut, textOut string, err error) {
	htmlTmpl, ok := r.htmlTemplates[tt]
	if !ok {
		return "", "", fmt.Errorf("unknown template type: %s", tt)
	}
	textTmpl, ok := r.textTemplates[tt]
	if !ok {
		return "", "", fmt.Errorf("unknown text template type: %s", tt)
	}

	var htmlBuf bytes.Buffer
	if err := htmlTmpl.Execute(&htmlBuf, data); err != nil {
		return "", "", fmt.Errorf("execute html template %s: %w", tt, err)
	}

	var textBuf bytes.Buffer
	if err := textTmpl.Execute(&textBuf, data); err != nil {
		return "", "", fmt.Errorf("execute text template %s: %w", tt, err)
	}

	return htmlBuf.String(), textBuf.String(), nil
}
