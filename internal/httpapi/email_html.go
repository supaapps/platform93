package httpapi

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	xhtml "golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

var blockedEmailElements = map[string]bool{
	"script": true, "iframe": true, "object": true, "embed": true, "form": true, "input": true, "button": true,
	"textarea": true, "select": true, "option": true, "meta": true, "base": true, "link": true, "svg": true,
	"math": true, "video": true, "audio": true, "source": true, "canvas": true,
}

func unsafeEmailHTML(value string) bool {
	_, err := validateEmailHTML(value)
	return err != nil
}

// validateEmailHTML rejects active content and returns managed image IDs used by
// this immutable template version. It validates rather than silently rewriting.
func validateEmailHTML(value string) ([]string, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	root := &xhtml.Node{Type: xhtml.ElementNode, Data: "div", DataAtom: atom.Div}
	nodes, err := xhtml.ParseFragment(strings.NewReader(value), root)
	if err != nil {
		return nil, fmt.Errorf("HTML could not be parsed")
	}
	assets := map[string]struct{}{}
	var walk func(*xhtml.Node) error
	walk = func(node *xhtml.Node) error {
		if node.Type == xhtml.ElementNode {
			tag := strings.ToLower(node.Data)
			if blockedEmailElements[tag] {
				return fmt.Errorf("%s elements are not allowed", tag)
			}
			managedID := ""
			for _, attribute := range node.Attr {
				name, raw := strings.ToLower(attribute.Key), strings.TrimSpace(attribute.Val)
				lower := strings.ToLower(raw)
				if strings.HasPrefix(name, "on") || name == "srcset" || name == "background" || strings.Contains(lower, "javascript:") || strings.Contains(lower, "vbscript:") {
					return fmt.Errorf("unsafe HTML attribute %s", name)
				}
				if name == "style" && (strings.Contains(lower, "url(") || strings.Contains(lower, "expression(")) {
					return fmt.Errorf("external CSS resources are not allowed")
				}
				if name == "src" && (tag != "img" || !validHTTPSResource(raw)) {
					return fmt.Errorf("image sources must be absolute HTTPS URLs")
				}
				if name == "href" && !validEmailLink(raw) {
					return fmt.Errorf("links must use HTTPS, mailto, fragments, or a declared template code")
				}
				if name == "data-p93-object-id" {
					if tag != "img" {
						return fmt.Errorf("managed asset identifiers are only valid on images")
					}
					parsed, parseErr := uuid.Parse(raw)
					if parseErr != nil {
						return fmt.Errorf("managed image identifier is invalid")
					}
					managedID = parsed.String()
				}
			}
			if managedID != "" {
				assets[managedID] = struct{}{}
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			if err := walk(child); err != nil {
				return err
			}
		}
		return nil
	}
	for _, node := range nodes {
		if err := walk(node); err != nil {
			return nil, err
		}
	}
	result := make([]string, 0, len(assets))
	for id := range assets {
		result = append(result, id)
	}
	return result, nil
}

func validHTTPSResource(raw string) bool {
	parsed, err := url.Parse(raw)
	return err == nil && parsed.Scheme == "https" && parsed.Hostname() != "" && parsed.User == nil
}

func validEmailLink(raw string) bool {
	if raw == "" || strings.HasPrefix(raw, "#") || strings.HasPrefix(raw, "mailto:") {
		return true
	}
	if strings.HasPrefix(raw, "{{") && strings.HasSuffix(raw, "}}") {
		return true
	}
	return validHTTPSResource(raw)
}

func syncNotificationTemplateAssets(ctx context.Context, tx pgx.Tx, templateID string, assetIDs []string) error {
	for _, assetID := range assetIDs {
		if _, err := tx.Exec(ctx, `INSERT INTO notification_template_assets(notification_template_id,storage_object_id) VALUES($1,$2)`, templateID, assetID); err != nil {
			return err
		}
	}
	return nil
}
