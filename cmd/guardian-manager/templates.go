package main

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"io"
	"time"
)

//go:embed templates/layouts/*.html templates/partials/*.html templates/pages/*.html
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

var funcMap = template.FuncMap{
	"timeAgo": func(t time.Time) string {
		d := time.Since(t)
		switch {
		case d < time.Minute:
			return "just now"
		case d < time.Hour:
			m := int(d.Minutes())
			if m == 1 {
				return "1 minute ago"
			}
			return fmt.Sprintf("%d minutes ago", m)
		case d < 24*time.Hour:
			h := int(d.Hours())
			if h == 1 {
				return "1 hour ago"
			}
			return fmt.Sprintf("%d hours ago", h)
		default:
			return t.Format("Jan 2, 2006")
		}
	},
	"formatDate": func(t time.Time) string {
		if t.IsZero() {
			return "-"
		}
		return t.Format("Jan 2, 2006")
	},
	"formatDateTime": func(t time.Time) string {
		if t.IsZero() {
			return "-"
		}
		return t.Format("Jan 2, 2006 15:04")
	},
	"isAdmin": func(role string) bool {
		return role == "admin"
	},
	"seq": func(n int) []int {
		s := make([]int, n)
		for i := range s {
			s[i] = i + 1
		}
		return s
	},
	"add": func(a, b int) int { return a + b },
	"sub": func(a, b int) int { return a - b },
}

// Templates manages page templates with layout composition.
type Templates struct {
	pages map[string]*template.Template
}

// NewTemplates parses all embedded templates.
// Each page template is combined with the layouts and partials.
func NewTemplates() (*Templates, error) {
	t := &Templates{pages: make(map[string]*template.Template)}

	// Read shared templates (layouts + partials).
	sharedPatterns := []string{
		"templates/layouts/*.html",
		"templates/partials/*.html",
	}

	// Read all page files.
	entries, err := templateFS.ReadDir("templates/pages")
	if err != nil {
		return nil, fmt.Errorf("read pages dir: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		pageName := entry.Name()
		pagePattern := "templates/pages/" + pageName

		// Each page gets its own template tree: shared + that specific page.
		patterns := append(sharedPatterns, pagePattern)
		tmpl, err := template.New("").Funcs(funcMap).ParseFS(templateFS, patterns...)
		if err != nil {
			return nil, fmt.Errorf("parse page %s: %w", pageName, err)
		}

		// Store without the .html suffix.
		name := pageName[:len(pageName)-5]
		t.pages[name] = tmpl
	}

	return t, nil
}

// Render renders a layout with the specified page's content block.
// The layout parameter is the layout name (e.g., "base" or "auth").
func (t *Templates) Render(w io.Writer, layout string, data interface{}) error {
	// Determine which page template to use based on the layout name.
	// For "auth" layout, use the login page template.
	// For "base" layout, we need the page name from data.
	pageTmpl := t.findPage(layout, data)
	if pageTmpl == nil {
		return fmt.Errorf("template not found for layout %q", layout)
	}

	var buf bytes.Buffer
	if err := pageTmpl.ExecuteTemplate(&buf, layout, data); err != nil {
		return fmt.Errorf("execute template %q: %w", layout, err)
	}
	_, err := buf.WriteTo(w)
	return err
}

// RenderPage renders a specific page within a layout.
func (t *Templates) RenderPage(w io.Writer, page, layout string, data interface{}) error {
	pageTmpl, ok := t.pages[page]
	if !ok {
		return fmt.Errorf("page template %q not found", page)
	}

	var buf bytes.Buffer
	if err := pageTmpl.ExecuteTemplate(&buf, layout, data); err != nil {
		return fmt.Errorf("execute %s/%s: %w", layout, page, err)
	}
	_, err := buf.WriteTo(w)
	return err
}

type pageDataInterface interface {
	GetActive() string
}

func (t *Templates) findPage(layout string, data interface{}) *template.Template {
	switch layout {
	case "auth":
		return t.pages["login"]
	case "base":
		// Try to get active page from data.
		if pd, ok := data.(interface{ GetPageName() string }); ok {
			if tmpl, exists := t.pages[pd.GetPageName()]; exists {
				return tmpl
			}
		}
		// Default to dashboard.
		return t.pages["dashboard"]
	default:
		return t.pages[layout]
	}
}
