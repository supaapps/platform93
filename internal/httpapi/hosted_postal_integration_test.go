package httpapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/platform"
)

// Opt-in compatibility check against the unmodified released Postal image.
// All containers, credentials and application records are disposable fixtures.
func testHostedPostalCompatibility(t *testing.T, app *platform.App, router http.Handler, application, client, email string) {
	t.Helper()
	ctx := context.Background()
	run := func(args ...string) string {
		t.Helper()
		command := exec.Command("docker", args...)
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("docker %s: %v\n%s", args[0], err, output)
		}
		return strings.TrimSpace(string(output))
	}
	prefix := "p93-postal-" + kernel.NewID().String()
	run("network", "create", prefix)
	defer exec.Command("docker", "network", "rm", prefix).Run()
	database := prefix + "-db"
	password := kernel.NewID().String()
	run("run", "-d", "--name", database, "--network", prefix, "-e", "MARIADB_ROOT_PASSWORD="+password, "-e", "MARIADB_ROOT_HOST=%", "mariadb:10.11")
	defer exec.Command("docker", "rm", "-f", database).Run()
	ready := false
	for attempt := 0; attempt < 60; attempt++ {
		if exec.Command("docker", "exec", database, "mariadb-admin", "ping", "-h", "127.0.0.1", "-uroot", "-p"+password).Run() == nil {
			ready = true
			break
		}
		time.Sleep(time.Second)
	}
	if !ready {
		t.Fatal("Postal fixture database did not become ready")
	}
	host := httptest.NewUnstartedServer(router)
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	_ = host.Listener.Close()
	host.Listener = listener
	t.Logf("Postal fixture issuer listener: %s", listener.Addr())
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "host.docker.internal"}, DNSNames: []string{"host.docker.internal"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	host.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
	host.StartTLS()
	defer host.Close()
	app.PublicURL = fmt.Sprintf("https://host.docker.internal:%d", listener.Addr().(*net.TCPAddr).Port)
	postalPort := 18025
	callback := fmt.Sprintf("http://localhost:%d/auth/oidc/callback", postalPort)
	if _, err := app.DB.Exec(ctx, `UPDATE clients SET redirect_uris=ARRAY[$2] WHERE id=$1`, client, callback); err != nil {
		t.Fatal(err)
	}
	unknownEmail := "unknown+" + application + "@example.test"
	unknown := kernel.NewID().String()
	if _, err := app.DB.Exec(ctx, `INSERT INTO users(id,application_id,email,normalized_email,first_name,last_name,password_hash,email_verified_at) SELECT $1,application_id,$2,$2,'Unknown','User',password_hash,now() FROM users WHERE application_id=$3 AND normalized_email=$4`, unknown, unknownEmail, application, email); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = app.DB.Exec(ctx, `DELETE FROM hosted_auth_sessions WHERE application_id=$1`, application)
		_, _ = app.DB.Exec(ctx, `DELETE FROM oauth_consents WHERE user_id=$1`, unknown)
		_, _ = app.DB.Exec(ctx, `DELETE FROM oauth_sessions WHERE application_id=$1`, application)
		_, _ = app.DB.Exec(ctx, `DELETE FROM user_sessions WHERE user_id=$1`, unknown)
		_, _ = app.DB.Exec(ctx, `DELETE FROM users WHERE id=$1`, unknown)
	}()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "fixture-ca.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		t.Fatal(err)
	}
	configuration := fmt.Sprintf("postal:\n  web_hostname: localhost:%d\n  web_protocol: http\nweb_server:\n  default_bind_address: 0.0.0.0\nmain_db:\n  host: %s\n  username: root\n  password: %s\n  database: postal\nrails:\n  secret_key: %s\noidc:\n  enabled: true\n  name: Platform93\n  issuer: %s/oidc\n  identifier: %s\n  secret: test-client-secret\n  scopes: [openid, email, profile]\n", postalPort, database, password, strings.ReplaceAll(kernel.NewID().String()+kernel.NewID().String(), "-", ""), app.PublicURL, client)
	if err := os.WriteFile(filepath.Join(directory, "postal.yml"), []byte("version: 2\n"+configuration), 0644); err != nil {
		t.Fatal(err)
	}
	image := "ghcr.io/postalserver/postal:3.3.7@sha256:e54b4a7eb106ee15eda5664311c4b9415546d4196f5c4336d23a78d6ce57b819"
	options := []string{"--platform", "linux/amd64", "--network", prefix, "--add-host", "host.docker.internal:host-gateway", "-e", "SSL_CERT_FILE=/config/fixture-ca.crt", "-v", directory + ":/config:ro"}
	initialize := append([]string{"run", "--rm"}, options...)
	run(append(initialize, image, "postal", "initialize")...)
	web := prefix + "-web"
	start := append([]string{"run", "-d", "--name", web, "-p", fmt.Sprintf("127.0.0.1:%d:5000", postalPort)}, options...)
	run(append(start, image, "postal", "web-server")...)
	defer exec.Command("docker", "rm", "-f", web).Run()
	run("exec", "-u", "0", web, "sh", "-c", "cp /config/fixture-ca.crt /usr/local/share/ca-certificates/platform93-fixture.crt && update-ca-certificates")
	run("exec", web, "ruby", "-rnet/http", "-e", fmt.Sprintf("response=Net::HTTP.get_response(URI(%q)); abort(response.code) unless response.code=='200'", app.Issuer()+"/.well-known/openid-configuration"))
	run("exec", web, "bundle", "exec", "rails", "runner", fmt.Sprintf("User.create!(email_address: %q, first_name: 'Hosted', last_name: 'User', admin: true)", email))
	command := exec.Command("pnpm", "exec", "playwright", "test", "e2e/hosted-postal.spec.ts")
	command.Dir = filepath.Join("..", "..", "web")
	command.Env = append(os.Environ(), fmt.Sprintf("PLATFORM93_POSTAL_URL=http://localhost:%d", postalPort), "PLATFORM93_HOSTED_EMAIL="+email, "PLATFORM93_POSTAL_UNKNOWN_EMAIL="+unknownEmail)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("Postal browser compatibility: %v\n%s\n%s", err, output, run("logs", web))
	}
	t.Log(string(output))
}
