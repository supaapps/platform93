package jobs

import (
	"encoding/json"
	"io"
	"net"
	"net/mail"
	"net/textproto"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/supaapps/platform93/internal/kernel"
)

type capturedEmail struct {
	from, envelope string
}

func TestSenderNameMailboxFormatting(t *testing.T) {
	for _, name := range []string{"App Support", "Bücher & Co", `Team "Support"`, `Support \ Team`, strings.Repeat("é", 200), strings.Repeat("😀", 200)} {
		body, err := buildMIMEMessage("noreply@example.test", name, "recipient@example.test", "Test", "Body", "", nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(strings.SplitN(string(body), "\r\n\r\n", 2)[0], "\r\n") {
			if len(line) > 998 {
				t.Fatalf("header line exceeds SMTP limit: %d octets", len(line))
			}
		}
		message, err := mail.ReadMessage(strings.NewReader(string(body)))
		if err != nil {
			t.Fatal(err)
		}
		address, err := mail.ParseAddress(message.Header.Get("From"))
		if err != nil || address.Name != name || address.Address != "noreply@example.test" {
			t.Fatalf("display name did not round-trip: %+v %v", address, err)
		}
	}
}

func captureSMTP(t *testing.T) (smtpConfig, <-chan capturedEmail) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	messages := make(chan capturedEmail, 20)
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			func() {
				defer connection.Close()
				_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
				c := textproto.NewConn(connection)
				_ = c.PrintfLine("220 localhost test SMTP")
				var message capturedEmail
				for {
					line, err := c.ReadLine()
					if err != nil {
						return
					}
					switch {
					case strings.HasPrefix(line, "MAIL FROM:"):
						message.envelope = strings.TrimPrefix(line, "MAIL FROM:")
					case line == "DATA":
						_ = c.PrintfLine("354 Send message")
						body, err := io.ReadAll(c.DotReader())
						if err != nil {
							return
						}
						email, err := mail.ReadMessage(strings.NewReader(string(body)))
						if err != nil {
							return
						}
						message.from = email.Header.Get("From")
						messages <- message
					case line == "QUIT":
						_ = c.PrintfLine("221 Goodbye")
						return
					}
					_ = c.PrintfLine("250 OK")
				}
			}()
		}
	}()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	portNumber, _ := strconv.Atoi(port)
	// Plaintext is used only by this loopback test server, never provider setup.
	return smtpConfig{Host: "127.0.0.1", Port: portNumber, TLSMode: "test"}, messages
}

func TestApplicationEmailSenderDeliveryPostgres(t *testing.T) {
	f := newDeliveryFixture(t, "platform93")
	db, vault := f.runner.app.DB, f.runner.app.Vault
	ctx := t.Context()
	config, messages := captureSMTP(t)
	encoded, _ := json.Marshal(config)
	var org string
	if err := db.QueryRow(ctx, `SELECT organization_id FROM applications WHERE id=$1`, f.applicationID).Scan(&org); err != nil {
		t.Fatal(err)
	}
	sibling := kernel.NewID().String()
	if _, err := db.Exec(ctx, `INSERT INTO applications(id,organization_id,name,slug) VALUES($1,$2,'Sibling',$3)`, sibling, org, sibling); err != nil {
		t.Fatal(err)
	}
	providers := map[string]string{}
	for _, scope := range []string{"installation", "organization", "application"} {
		id := kernel.NewID().String()
		cipher, err := vault.Encrypt(encoded, "notification-provider:"+id)
		if err != nil {
			t.Fatal(err)
		}
		var applicationID, organizationID *string
		if scope == "application" {
			applicationID = &f.applicationID
		}
		if scope == "organization" {
			organizationID = &org
		}
		if _, err = db.Exec(ctx, `INSERT INTO notification_providers(id,application_id,organization_id,name,config_ciphertext,sender_email,sender_name,inheritable,disabled_at)
VALUES($1,$2,$3,$4,$5,$6,$7,true,now())`, id, applicationID, organizationID, scope, cipher, scope+"@example.test", scope+" Sender"); err != nil {
			t.Fatal(err)
		}
		providers[scope] = id
	}
	deliver := func(app, organization, requested *string, wantName, wantEmail string) {
		t.Helper()
		id := kernel.NewID().String()
		cipher, err := vault.Encrypt([]byte(`{"subject":"Test","text":"Test body"}`), "notification:"+id)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.Exec(ctx, `INSERT INTO notifications(id,application_id,organization_id,notification_provider_id,recipient,payload_ciphertext,next_attempt_at)
VALUES($1,$2,$3,$4,'recipient@example.test',$5,now())`, id, app, organization, requested, cipher); err != nil {
			t.Fatal(err)
		}
		processed, err := f.runner.deliverNotification(ctx)
		if err != nil || !processed {
			t.Fatalf("delivery: %v %v", processed, err)
		}
		var status string
		if err = db.QueryRow(ctx, `SELECT status FROM notifications WHERE id=$1`, id).Scan(&status); err != nil || status != "delivered" {
			t.Fatalf("status: %s %v", status, err)
		}
		select {
		case got := <-messages:
			address, err := mail.ParseAddress(got.from)
			if err != nil || address.Name != wantName || address.Address != wantEmail || got.envelope != "<"+wantEmail+">" {
				t.Fatalf("wrong sender: %+v parsed=%+v err=%v", got, address, err)
			}
		case <-time.After(time.Second):
			t.Fatal("SMTP message not received")
		}
	}
	for _, scope := range []string{"installation", "organization", "application"} {
		t.Run(scope, func(t *testing.T) {
			if _, err := db.Exec(ctx, `UPDATE notification_providers SET disabled_at=CASE WHEN id=$1 THEN NULL ELSE now() END`, providers[scope]); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"App Support", "Bücher & Co", `Team "Support"`, strings.Repeat("é", 200), strings.Repeat("😀", 200), "", "   "} {
				value, _ := json.Marshal(map[string]any{"email_sender_name": name})
				if _, err := db.Exec(ctx, `UPDATE applications SET internal_config=internal_config||$1::jsonb WHERE id=$2`, value, f.applicationID); err != nil {
					t.Fatal(err)
				}
				want := strings.TrimSpace(name)
				if want == "" {
					want = scope + " Sender"
				}
				deliver(&f.applicationID, nil, nil, want, scope+"@example.test")
			}
		})
	}
	if _, err := db.Exec(ctx, `UPDATE notification_providers SET disabled_at=CASE WHEN id=$1 THEN NULL ELSE now() END`, providers["installation"]); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `UPDATE applications SET internal_config=internal_config||'{"email_sender_name":"App Only"}'::jsonb WHERE id=$1`, f.applicationID); err != nil {
		t.Fatal(err)
	}
	deliver(&sibling, nil, nil, "installation Sender", "installation@example.test")
	deliver(nil, nil, nil, "installation Sender", "installation@example.test")
	deliver(nil, &org, nil, "installation Sender", "installation@example.test")
	provider := providers["installation"]
	deliver(&f.applicationID, nil, &provider, "App Only", "installation@example.test")
	var name string
	if err := db.QueryRow(ctx, `SELECT sender_name FROM notification_providers WHERE id=$1`, provider).Scan(&name); err != nil || name != "installation Sender" {
		t.Fatalf("shared provider mutated: %s %v", name, err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO sender_identities(id,notification_provider_id,email,name,is_default)
VALUES($1,$2,'authorized@example.test','Selected Identity',true)`, kernel.NewID(), provider); err != nil {
		t.Fatal(err)
	}
	deliver(&f.applicationID, nil, nil, "App Only", "authorized@example.test")
	if _, err := db.Exec(ctx, `UPDATE applications SET internal_config=internal_config-'email_sender_name' WHERE id=$1`, f.applicationID); err != nil {
		t.Fatal(err)
	}
	deliver(&f.applicationID, nil, nil, "Selected Identity", "authorized@example.test")
	unsafeName, _ := json.Marshal(map[string]any{"email_sender_name": "Name\r\nBcc: other@example.test"})
	if _, err := db.Exec(ctx, `UPDATE applications SET internal_config=internal_config||$1::jsonb WHERE id=$2`, unsafeName, f.applicationID); err != nil {
		t.Fatal(err)
	}
	badID := kernel.NewID()
	cipher, err := vault.Encrypt([]byte(`{"subject":"Test","text":"Invalid stored sender"}`), "notification:"+badID.String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO notifications(id,application_id,recipient,payload_ciphertext) VALUES($1,$2,'recipient@example.test',$3)`, badID, f.applicationID, cipher); err != nil {
		t.Fatal(err)
	}
	if processed, err := f.runner.deliverNotification(ctx); err != nil || !processed {
		t.Fatalf("invalid stored sender: %v %v", processed, err)
	}
	var status, lastError string
	if err := db.QueryRow(ctx, `SELECT status,last_error FROM notifications WHERE id=$1`, badID).Scan(&status, &lastError); err != nil || status != "failed" || lastError != "application email sender name is invalid" {
		t.Fatalf("unsafe sender did not fail safely: %s %s %v", status, lastError, err)
	}
	select {
	case <-messages:
		t.Fatal("invalid stored sender reached SMTP")
	default:
	}
}
