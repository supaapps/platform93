package jobs

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/smtp"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type smtpConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	TLSMode  string `json:"tls_mode"`
}

func (r *Runner) deliverNotification(ctx context.Context) (bool, error) {
	tx, err := r.app.DB.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	var id, recipient, payloadCipher string
	var requestedProviderID *string
	var attemptCount int
	var applicationID, organizationID *string
	err = tx.QueryRow(ctx, `SELECT id,application_id,organization_id,notification_provider_id,recipient,payload_ciphertext,attempt_count FROM notifications
WHERE status IN ('queued','failed') AND next_attempt_at<=now() AND attempt_count<10
ORDER BY next_attempt_at,id FOR UPDATE SKIP LOCKED LIMIT 1`).Scan(&id, &applicationID, &organizationID, &requestedProviderID, &recipient, &payloadCipher, &attemptCount)
	if err == pgx.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	attemptID := uuid.NewString()
	if _, err = tx.Exec(ctx, `INSERT INTO notification_attempts(id,notification_id,attempt_number,status)
VALUES($1,$2,$3,'sending')`, attemptID, id, attemptCount+1); err != nil {
		return false, err
	}
	var providerID, configCipher, senderEmail, senderName string
	if requestedProviderID != nil {
		err = tx.QueryRow(ctx, `SELECT id,config_ciphertext,sender_email,sender_name FROM notification_providers
WHERE id=$1 AND disabled_at IS NULL`, *requestedProviderID).Scan(&providerID, &configCipher, &senderEmail, &senderName)
	} else if organizationID != nil {
		err = tx.QueryRow(ctx, `SELECT id,config_ciphertext,sender_email,sender_name FROM notification_providers
WHERE disabled_at IS NULL AND (organization_id=$1 OR (application_id IS NULL AND organization_id IS NULL AND inheritable))
ORDER BY CASE WHEN organization_id=$1 THEN 0 ELSE 1 END,created_at DESC LIMIT 1`, *organizationID).Scan(&providerID, &configCipher, &senderEmail, &senderName)
	} else if applicationID == nil {
		err = tx.QueryRow(ctx, `SELECT id,config_ciphertext,sender_email,sender_name FROM notification_providers
WHERE application_id IS NULL AND organization_id IS NULL AND disabled_at IS NULL ORDER BY created_at DESC LIMIT 1`).Scan(&providerID, &configCipher, &senderEmail, &senderName)
	} else {
		err = tx.QueryRow(ctx, `SELECT id,config_ciphertext,sender_email,sender_name FROM notification_providers
WHERE disabled_at IS NULL AND (application_id=$1 OR
(application_id IS NULL AND organization_id=(SELECT organization_id FROM applications WHERE id=$1) AND inheritable) OR
(application_id IS NULL AND organization_id IS NULL AND inheritable))
ORDER BY CASE WHEN application_id=$1 THEN 0 WHEN organization_id IS NOT NULL THEN 1 ELSE 2 END,created_at DESC LIMIT 1`, *applicationID).Scan(&providerID, &configCipher, &senderEmail, &senderName)
	}
	if err != nil {
		return true, r.failNotification(ctx, tx, id, attemptID, "no active SMTP provider is configured")
	}
	_, _ = tx.Exec(ctx, `UPDATE notification_attempts SET notification_provider_id=$1 WHERE id=$2`, providerID, attemptID)
	_ = tx.QueryRow(ctx, `SELECT email,name FROM sender_identities
WHERE notification_provider_id=$1 AND disabled_at IS NULL ORDER BY is_default DESC,created_at LIMIT 1`, providerID).Scan(&senderEmail, &senderName)
	configJSON, err := r.app.Vault.Decrypt(configCipher, "notification-provider:"+providerID)
	if err != nil {
		return true, r.failNotification(ctx, tx, id, attemptID, "SMTP provider credentials are unavailable")
	}
	payloadJSON, err := r.app.Vault.Decrypt(payloadCipher, "notification:"+id)
	if err != nil {
		return true, r.failNotification(ctx, tx, id, attemptID, "notification payload is unavailable")
	}
	var config smtpConfig
	var payload map[string]any
	if json.Unmarshal(configJSON, &config) != nil || json.Unmarshal(payloadJSON, &payload) != nil {
		return true, r.failNotification(ctx, tx, id, attemptID, "notification configuration is invalid")
	}
	subject, textBody, htmlBody := r.notificationContent(payload)
	attachments, err := loadAttachments(ctx, tx, id)
	if err != nil {
		return true, r.failNotification(ctx, tx, id, attemptID, "notification attachments are unavailable")
	}
	if err := sendSMTP(ctx, config, senderEmail, senderName, recipient, subject, textBody, htmlBody, attachments); err != nil {
		return true, r.failNotification(ctx, tx, id, attemptID, "SMTP delivery failed")
	}
	_, err = tx.Exec(ctx, "UPDATE notifications SET status='delivered',attempt_count=attempt_count+1,last_error=NULL,delivered_at=now() WHERE id=$1", id)
	if err == nil {
		_, err = tx.Exec(ctx, "UPDATE notification_providers SET verified_at=COALESCE(verified_at,now()) WHERE id=$1", providerID)
	}
	if err == nil {
		_, err = tx.Exec(ctx, `UPDATE sender_identities SET verified_at=COALESCE(verified_at,now())
WHERE notification_provider_id=$1 AND email=$2`, providerID, senderEmail)
	}
	if err == nil {
		_, err = tx.Exec(ctx, `UPDATE notification_attempts SET status='delivered',completed_at=now() WHERE id=$1`, attemptID)
	}
	if err != nil {
		return true, err
	}
	if err = tx.Commit(ctx); err != nil {
		return true, err
	}
	deliveryAttempts.WithLabelValues("notification", "delivered").Inc()
	return true, nil
}

func (r *Runner) notificationContent(payload map[string]any) (string, string, string) {
	if subject, ok := payload["subject"].(string); ok && subject != "" {
		textBody, _ := payload["text"].(string)
		htmlBody, _ := payload["html"].(string)
		return subject, textBody, htmlBody
	}
	if intent, _ := payload["intent"].(string); intent == "organization_invitation" {
		role, _ := payload["role"].(string)
		token, _ := payload["invitation_token"].(string)
		expiresAt, _ := payload["expires_at"].(string)
		parts := []string{"You were invited to administer a Platform93 organization as " + role + "."}
		if token != "" {
			parts = append(parts, "Invitation credential: "+token)
		}
		if expiresAt != "" {
			parts = append(parts, "Expires at: "+expiresAt)
		}
		parts = append(parts, "Open the Platform93 administrator interface and accept the invitation. If you did not expect this invitation, ignore this message.")
		return "Platform93 organization invitation", strings.Join(parts, "\r\n\r\n"), ""
	}
	if intent, _ := payload["intent"].(string); intent == "workspace_invitation" {
		token, _ := payload["invitation_token"].(string)
		workspaceID, _ := payload["workspace_id"].(string)
		expiresAt, _ := payload["expires_at"].(string)
		parts := []string{"You were invited to join an application workspace.", "Workspace ID: " + workspaceID}
		if token != "" {
			parts = append(parts, "Invitation credential: "+token)
		}
		if expiresAt != "" {
			parts = append(parts, "Expires at: "+expiresAt)
		}
		parts = append(parts, "Use the application invitation flow to accept this membership. If you did not expect this invitation, ignore this message.")
		return "Workspace invitation", strings.Join(parts, "\r\n\r\n"), ""
	}
	operator, _ := payload["operator"].(bool)
	subject := "Your Platform93 sign-in code"
	parts := []string{"A sign-in was requested for your account."}
	if code, ok := payload["code"].(string); ok && code != "" {
		parts = append(parts, "Code: "+code)
	}
	if token, ok := payload["link_token"].(string); ok && token != "" {
		if challenge, ok := payload["challenge_id"].(string); ok {
			base := r.app.PublicURL + "/?operator_challenge=true"
			if !operator {
				if redirect, ok := payload["redirect_uri"].(string); ok && redirect != "" {
					base = redirect
				}
			}
			parsed, err := url.Parse(base)
			if err == nil {
				query := parsed.Query()
				query.Set("challenge_id", challenge)
				query.Set("link_token", token)
				parsed.RawQuery = query.Encode()
				parts = append(parts, "Magic link: "+parsed.String())
			}
		}
	}
	parts = append(parts, "This credential expires in 10 minutes. If you did not request it, ignore this message.")
	return subject, strings.Join(parts, "\r\n\r\n"), ""
}

type emailAttachment struct {
	Filename    string
	ContentType string
	Content     []byte
}

func loadAttachments(ctx context.Context, tx pgx.Tx, notificationID string) ([]emailAttachment, error) {
	rows, err := tx.Query(ctx, `SELECT filename,content_type,content FROM notification_attachments WHERE notification_id=$1 ORDER BY created_at,id`, notificationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []emailAttachment{}
	for rows.Next() {
		var attachment emailAttachment
		if err = rows.Scan(&attachment.Filename, &attachment.ContentType, &attachment.Content); err != nil {
			return nil, err
		}
		result = append(result, attachment)
	}
	return result, rows.Err()
}

func sendSMTP(ctx context.Context, config smtpConfig, from, fromName, to, subject, textBody, htmlBody string, attachments []emailAttachment) error {
	address := net.JoinHostPort(config.Host, strconv.Itoa(config.Port))
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	var connection net.Conn
	var err error
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: config.Host}
	if config.TLSMode == "implicit_tls" {
		connection, err = tls.DialWithDialer(dialer, "tcp", address, tlsConfig)
	} else {
		connection, err = dialer.DialContext(ctx, "tcp", address)
	}
	if err != nil {
		return err
	}
	defer connection.Close()
	client, err := smtp.NewClient(connection, config.Host)
	if err != nil {
		return err
	}
	defer client.Close()
	if config.TLSMode == "starttls" {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return fmt.Errorf("SMTP server does not support STARTTLS")
		}
		if err := client.StartTLS(tlsConfig); err != nil {
			return err
		}
	}
	if config.Username != "" {
		if err := client.Auth(smtp.PlainAuth("", config.Username, config.Password, config.Host)); err != nil {
			return err
		}
	}
	if err := client.Mail(from); err != nil {
		return err
	}
	if err := client.Rcpt(to); err != nil {
		return err
	}
	writer, err := client.Data()
	if err != nil {
		return err
	}
	message, err := buildMIMEMessage(from, fromName, to, subject, textBody, htmlBody, attachments)
	if err != nil {
		return err
	}
	if _, err = writer.Write(message); err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	return client.Quit()
}

func buildMIMEMessage(from, fromName, to, subject, textBody, htmlBody string, attachments []emailAttachment) ([]byte, error) {
	var output bytes.Buffer
	headers := textproto.MIMEHeader{}
	headers.Set("From", formatMailbox(fromName, from))
	headers.Set("To", to)
	headers.Set("Subject", subject)
	headers.Set("MIME-Version", "1.0")
	var body bytes.Buffer
	if len(attachments) > 0 {
		mixed := multipart.NewWriter(&body)
		headers.Set("Content-Type", `multipart/mixed; boundary="`+mixed.Boundary()+`"`)
		content, contentType, err := alternativeContent(textBody, htmlBody)
		if err != nil {
			return nil, err
		}
		partHeader := textproto.MIMEHeader{}
		partHeader.Set("Content-Type", contentType)
		part, _ := mixed.CreatePart(partHeader)
		_, _ = part.Write(content)
		for _, attachment := range attachments {
			attachmentHeader := textproto.MIMEHeader{}
			attachmentHeader.Set("Content-Type", attachment.ContentType)
			attachmentHeader.Set("Content-Disposition", `attachment; filename="`+strings.ReplaceAll(attachment.Filename, `"`, `'`)+`"`)
			attachmentHeader.Set("Content-Transfer-Encoding", "base64")
			part, _ = mixed.CreatePart(attachmentHeader)
			encoder := base64.NewEncoder(base64.StdEncoding, part)
			_, _ = encoder.Write(attachment.Content)
			_ = encoder.Close()
		}
		_ = mixed.Close()
	} else if htmlBody != "" {
		alternative := multipart.NewWriter(&body)
		headers.Set("Content-Type", `multipart/alternative; boundary="`+alternative.Boundary()+`"`)
		if err := writeAlternativeParts(alternative, textBody, htmlBody); err != nil {
			return nil, err
		}
		_ = alternative.Close()
	} else {
		headers.Set("Content-Type", "text/plain; charset=UTF-8")
		headers.Set("Content-Transfer-Encoding", "8bit")
		body.WriteString(textBody)
	}
	for key, values := range headers {
		for _, value := range values {
			_, _ = fmt.Fprintf(&output, "%s: %s\r\n", key, value)
		}
	}
	output.WriteString("\r\n")
	_, _ = io.Copy(&output, &body)
	output.WriteString("\r\n")
	return output.Bytes(), nil
}

func alternativeContent(textBody, htmlBody string) ([]byte, string, error) {
	if htmlBody == "" {
		return []byte(textBody), "text/plain; charset=UTF-8", nil
	}
	var content bytes.Buffer
	writer := multipart.NewWriter(&content)
	if err := writeAlternativeParts(writer, textBody, htmlBody); err != nil {
		return nil, "", err
	}
	if err := writer.Close(); err != nil {
		return nil, "", err
	}
	return content.Bytes(), `multipart/alternative; boundary="` + writer.Boundary() + `"`, nil
}

func writeAlternativeParts(writer *multipart.Writer, textBody, htmlBody string) error {
	textHeader := textproto.MIMEHeader{}
	textHeader.Set("Content-Type", "text/plain; charset=UTF-8")
	textPart, err := writer.CreatePart(textHeader)
	if err != nil {
		return err
	}
	_, _ = textPart.Write([]byte(textBody))
	htmlHeader := textproto.MIMEHeader{}
	htmlHeader.Set("Content-Type", "text/html; charset=UTF-8")
	htmlPart, err := writer.CreatePart(htmlHeader)
	if err != nil {
		return err
	}
	_, _ = htmlPart.Write([]byte(htmlBody))
	return nil
}

func formatMailbox(name, email string) string {
	name = strings.NewReplacer("\r", "", "\n", "", "\"", "'").Replace(name)
	if name == "" {
		return email
	}
	return fmt.Sprintf("\"%s\" <%s>", name, email)
}

func (r *Runner) failNotification(ctx context.Context, tx pgx.Tx, id, attemptID, message string) error {
	_, err := tx.Exec(ctx, `UPDATE notifications SET status=CASE WHEN attempt_count>=9 THEN 'dead' ELSE 'failed' END,
attempt_count=attempt_count+1,next_attempt_at=now()+(interval '1 second'*power(2,least(attempt_count,10))),last_error=$1 WHERE id=$2`, message, id)
	if err == nil {
		_, err = tx.Exec(ctx, `UPDATE notification_attempts SET status='failed',error=$1,completed_at=now() WHERE id=$2`, message, attemptID)
	}
	if err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	deliveryAttempts.WithLabelValues("notification", "failed").Inc()
	return nil
}
