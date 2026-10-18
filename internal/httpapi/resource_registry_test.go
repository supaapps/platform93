package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/supaapps/platform93/internal/database"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/platform"
	"github.com/supaapps/platform93/internal/secure"
)

func registryTestResource() OAuthResource {
	return OAuthResource{URI: "https://api.example.test", Name: "Example resource", Enabled: true, ClientIDs: []string{}, Capabilities: []ResourceCapability{{Key: "documents:read", Name: "Read documents", Context: "personal", Permissions: []string{"documents:read"}}}}
}

func TestResourceURICanonicalization(t *testing.T) {
	for input, want := range map[string]string{"https://API.example.test:443/": "https://api.example.test", "https://api.example.test/a/../b": "https://api.example.test/b", "https://api.example.test/%64ocuments": "https://api.example.test/documents", "https://[2001:db8::1]:8443/api": "https://[2001:db8::1]:8443/api"} {
		got, err := canonicalOAuthResourceURI(input)
		if err != nil || got != want {
			t.Errorf("%q: got %q, %v; want %q", input, got, err, want)
		}
	}
	for _, input := range []string{"http://api.example.test", "https://localhost/api", "https://LOCALHOST", "https://a.localhost", "https://127.0.0.1", "https://127.1", "https://2130706433", "https://[::1]", "https://[::ffff:127.0.0.1]", "https://0.0.0.0", "https://[::]", "https://user:pass@api.example.test", "https://api.example.test?x=1", "https://api.example.test?", "https://api.example.test#", "https://api.example.test#x", "https://api.example.test:0", "https://api.example.test:65536", "https://api.example.test./", "https://api.example.test/%00", "https://api.example.test/%01", "https://api.example.test/%5c", "https://api.example.test/\n"} {
		if got, err := canonicalOAuthResourceURI(input); err == nil {
			t.Errorf("accepted %q as %q", input, got)
		}
	}
}

func TestResourceCapabilityValidation(t *testing.T) {
	for _, key := range []string{"*", "documents:*", "roles:owner", "workspaces:read", "documents:read other:write", "documents::read", "../read", "Documents:read"} {
		v := registryTestResource()
		v.Capabilities[0].Key = key
		if validateOAuthResource(&v) == nil {
			t.Errorf("accepted key %q", key)
		}
	}
	for _, permission := range []string{"*", "documents:*", "documents:read other:write", "documents::read", "documents:*:read"} {
		v := registryTestResource()
		v.Capabilities[0].Permissions = []string{permission}
		if validateOAuthResource(&v) == nil {
			t.Errorf("accepted permission %q", permission)
		}
	}
	cases := []func(*OAuthResource){
		func(v *OAuthResource) { v.Capabilities[0].Permissions = nil },
		func(v *OAuthResource) { v.Capabilities[0].Permissions = []string{"documents:read", "documents:read"} },
		func(v *OAuthResource) { v.Capabilities[0].Context = "application" },
		func(v *OAuthResource) { v.Capabilities = append(v.Capabilities, v.Capabilities[0]) },
		func(v *OAuthResource) { v.Capabilities = nil },
		func(v *OAuthResource) { v.ClientIDs = []string{"a", "a"} },
		func(v *OAuthResource) { v.ClientIDs = []string{strings.Repeat("x", 2049)} },
		func(v *OAuthResource) { v.Capabilities[0].Permissions = make([]string, 201) },
		func(v *OAuthResource) { v.ClientIDs = make([]string, 33) },
		func(v *OAuthResource) { v.Capabilities = make([]ResourceCapability, 33) },
	}
	for i, mutate := range cases {
		v := registryTestResource()
		mutate(&v)
		if validateOAuthResource(&v) == nil {
			t.Errorf("accepted invalid case %d", i)
		}
	}
	v := registryTestResource()
	if err := validateOAuthResource(&v); err != nil {
		t.Fatal(err)
	}
}

func TestResourcePreconditionsAndRedaction(t *testing.T) {
	for _, tc := range []struct {
		etag string
		want int
	}{{"", 428}, {"*", 412}, {`"v2"`, 412}, {`"v1"`, 200}} {
		r := httptest.NewRequest("PATCH", "/", nil)
		r.Header.Set("If-Match", tc.etag)
		w := httptest.NewRecorder()
		resourceIfMatch(w, r, 1)
		if w.Code != tc.want {
			t.Errorf("etag %q: %d", tc.etag, w.Code)
		}
	}
	b, err := json.Marshal(OAuthConnection{SessionID: kernel.NewID()})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "session_id") {
		t.Fatal("session metadata missing")
	}
	s := &Server{}
	r := requestWithRoute(t, "GET", "/", nil, nil, kernel.Actor{Type: "client", ID: kernel.NewID().String()})
	w := httptest.NewRecorder()
	s.listMyConnections(w, r)
	if w.Code != 403 {
		t.Fatal(w.Code)
	}
	r = requestWithRoute(t, "POST", "/", nil, nil, kernel.Actor{})
	w = httptest.NewRecorder()
	s.createOAuthResource(w, r)
	if w.Code != 400 {
		t.Fatal(w.Code)
	}
}

func TestResourceExplicitEmptyPermissions(t *testing.T) {
	for _, capabilityContext := range []string{"personal", "workspace"} {
		for _, tc := range []struct {
			name  string
			field string
			valid bool
		}{
			{"empty", `,"permissions":[]`, true},
			{"null", `,"permissions":null`, false},
			{"omitted", ``, false},
		} {
			t.Run(capabilityContext+"/"+tc.name, func(t *testing.T) {
				var capability ResourceCapability
				data := `{"key":"profile:read","name":"Read profile","context":"` + capabilityContext + `"` + tc.field + `}`
				if err := json.Unmarshal([]byte(data), &capability); err != nil {
					t.Fatal(err)
				}
				v := registryTestResource()
				v.Capabilities = []ResourceCapability{capability}
				if err := validateOAuthResource(&v); (err == nil) != tc.valid {
					t.Fatalf("valid=%v, error=%v", tc.valid, err)
				}
			})
		}
	}
}

func TestResourceSelfRoutesRejectDelegatedSessions(t *testing.T) {
	s := &Server{}
	current := kernel.Actor{Type: "user", ID: kernel.NewID().String(), DelegatedBy: kernel.NewID().String()}
	params := map[string]string{"application_id": kernel.NewID().String(), "connection_id": kernel.NewID().String()}
	for name, handler := range map[string]http.HandlerFunc{"list": s.listMyConnections, "get": s.getMyConnection, "revoke": s.revokeMyConnection} {
		t.Run(name, func(t *testing.T) {
			r := requestWithRoute(t, "GET", "/", nil, params, current)
			r.Header.Set("If-Match", `"v1"`)
			w := httptest.NewRecorder()
			handler(w, r)
			if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "delegated_session_forbidden") {
				t.Fatalf("delegated route: %d %s", w.Code, w.Body)
			}
		})
	}
}

func TestResourceRoutesRejectInvalidUUIDs(t *testing.T) {
	s := &Server{}
	for name, tc := range map[string]struct {
		handler http.HandlerFunc
		ids     []string
	}{
		"resource_get":      {s.getOAuthResource, []string{"application_id", "resource_id"}},
		"resource_update":   {s.updateOAuthResource, []string{"application_id", "resource_id"}},
		"resource_list":     {s.listOAuthResources, []string{"application_id"}},
		"connections_list":  {s.listResourceConnections, []string{"application_id", "resource_id"}},
		"connection_get":    {s.getResourceConnection, []string{"application_id", "resource_id", "connection_id"}},
		"connection_revoke": {s.revokeResourceConnection, []string{"application_id", "resource_id", "connection_id"}},
		"self_list":         {s.listMyConnections, []string{"application_id"}},
		"self_get":          {s.getMyConnection, []string{"application_id", "connection_id"}},
		"self_revoke":       {s.revokeMyConnection, []string{"application_id", "connection_id"}},
	} {
		for _, id := range tc.ids {
			t.Run(name+"/"+id, func(t *testing.T) {
				params := map[string]string{"application_id": kernel.NewID().String(), "resource_id": kernel.NewID().String(), "connection_id": kernel.NewID().String()}
				params[id] = "not-a-uuid"
				r := requestWithRoute(t, "GET", "/", nil, params, kernel.Actor{Type: "user", ID: kernel.NewID().String()})
				w := httptest.NewRecorder()
				tc.handler(w, r)
				if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "invalid_"+id) {
					t.Fatalf("invalid UUID: %d %s", w.Code, w.Body)
				}
			})
		}
	}
}

func TestResourceMutationErrorClassification(t *testing.T) {
	for name, tc := range map[string]struct {
		err    error
		update bool
		want   int
	}{
		"uri_unique":             {&pgconn.PgError{Code: "23505", ConstraintName: "oauth_resources_uri_key"}, false, 409},
		"wrapped_uri_unique":     {fmt.Errorf("insert: %w", &pgconn.PgError{Code: "23505", ConstraintName: "oauth_resources_uri_key"}), false, 409},
		"unrelated_unique":       {&pgconn.PgError{Code: "23505", ConstraintName: "outbox_pkey"}, false, 500},
		"foreign_key":            {&pgconn.PgError{Code: "23503"}, false, 500},
		"unexpected":             {errors.New("private database details"), false, 500},
		"update_stale":           {fmt.Errorf("update: %w", pgx.ErrNoRows), true, 412},
		"update_unique":          {&pgconn.PgError{Code: "23505", ConstraintName: "oauth_resources_uri_key"}, true, 409},
		"update_unexpected":      {errors.New("private database details"), true, 500},
		"missing_event_contract": {pgx.ErrNoRows, false, 500},
	} {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/", nil)
			w := httptest.NewRecorder()
			if tc.update {
				resourceUpdateProblem(w, r, tc.err)
			} else {
				resourceMutationProblem(w, r, tc.err)
			}
			if w.Code != tc.want || strings.Contains(w.Body.String(), "private database details") {
				t.Fatalf("classification: %d %s", w.Code, w.Body)
			}
		})
	}
}

func TestResourceRegistryPostgres(t *testing.T) {
	dsn := os.Getenv("PLATFORM93_DATABASE_URL")
	if dsn == "" {
		t.Skip("PLATFORM93_DATABASE_URL is not configured")
	}
	if err := database.Migrate(dsn); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	db, err := database.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	vault, _ := secure.NewVault(make([]byte, 32))
	s := &Server{app: platform.New(db, vault, "https://platform93.test")}
	org, app, other, user, otherUser, session := kernel.NewID(), kernel.NewID(), kernel.NewID(), kernel.NewID(), kernel.NewID(), kernel.NewID()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := db.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO organizations(id,name,slug) VALUES($1,'Resource test',$2)`, org, "resource-"+org.String())
	for _, id := range []uuid.UUID{app, other} {
		exec(`INSERT INTO applications(id,organization_id,name,slug) VALUES($1,$2,'Resource test',$3)`, id, org, "resource-"+id.String())
	}
	for _, id := range []uuid.UUID{user, otherUser} {
		exec(`INSERT INTO users(id,application_id,email,normalized_email) VALUES($1,$2,$3,$3)`, id, app, id.String()+"@example.test")
	}
	exec(`INSERT INTO user_sessions(id,application_id,user_id,refresh_digest,expires_at) VALUES($1,$2,$3,$4,now()+interval '2 days')`, session, app, user, []byte(session.String()))
	clientID := "registry-" + app.String()
	clientDB := kernel.NewID()
	exec(`INSERT INTO clients(id,application_id,client_id,name,client_type,redirect_uris,allowed_grants,allowed_scopes) VALUES($1,$2,$3,'Registry client','public',ARRAY['https://client.example.test/callback'],ARRAY['authorization_code'],ARRAY['openid'])`, clientDB, app, clientID)
	actor := kernel.Actor{Type: "control_user", ID: kernel.NewID().String()}
	routes := map[string]string{"application_id": app.String()}
	call := func(method string, body any, params map[string]string, current kernel.Actor, etag string, handler http.HandlerFunc) *httptest.ResponseRecorder {
		t.Helper()
		r := requestWithRoute(t, method, "/", body, params, current)
		r.Header.Set("Idempotency-Key", kernel.NewID().String())
		if etag != "" {
			r.Header.Set("If-Match", etag)
		}
		w := httptest.NewRecorder()
		handler(w, r)
		return w
	}
	v := registryTestResource()
	v.URI = "https://" + app.String() + ".example.test"
	v.ClientIDs = []string{clientID}
	v.Capabilities = append(v.Capabilities, ResourceCapability{Key: "documents:workspace", Name: "Read workspace documents", Context: "workspace", Permissions: []string{"documents:read"}})
	createBody := map[string]any{"uri": v.URI, "name": v.Name, "client_ids": v.ClientIDs, "capabilities": v.Capabilities}
	w := call("POST", createBody, routes, actor, "", s.createOAuthResource)
	if w.Code != 201 {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	if err = json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	routes["resource_id"] = v.ID.String()
	w = call("POST", createBody, routes, actor, "", s.createOAuthResource)
	if w.Code != 409 {
		t.Fatalf("duplicate: %d %s", w.Code, w.Body)
	}
	crossApplicationBody := map[string]any{"uri": v.URI + "/", "name": v.Name, "capabilities": v.Capabilities}
	w = call("POST", crossApplicationBody, map[string]string{"application_id": other.String()}, actor, "", s.createOAuthResource)
	if w.Code != 409 {
		t.Fatalf("global canonical URI collision: %d %s", w.Code, w.Body)
	}
	crossApplicationBody["uri"] = v.URI + "/other-application"
	crossApplicationBody["client_ids"] = []string{clientID}
	w = call("POST", crossApplicationBody, map[string]string{"application_id": other.String()}, actor, "", s.createOAuthResource)
	if w.Code != 422 {
		t.Fatalf("cross-application client allowlist: %d %s", w.Code, w.Body)
	}
	metadataID := "https://client.example.test/" + app.String() + "/metadata.json"
	metadataBody := map[string]any{"uri": v.URI + "/metadata", "name": "Metadata resource", "client_ids": []string{metadataID}, "allow_client_metadata": true, "capabilities": v.Capabilities}
	w = call("POST", metadataBody, routes, actor, "", s.createOAuthResource)
	if w.Code != 201 {
		t.Fatalf("metadata resource: %d %s", w.Code, w.Body)
	}
	var metadataResource OAuthResource
	if err = json.Unmarshal(w.Body.Bytes(), &metadataResource); err != nil {
		t.Fatal(err)
	}
	shadowID := kernel.NewID()
	exec(`INSERT INTO clients(id,application_id,client_id,name,client_type,resource_only,authorization_ui,pkce_required,redirect_uris,allowed_grants,allowed_scopes,disabled_at) VALUES($1,$2,$3,'Metadata client','public',true,'hosted',true,'{}','{}','{}',now())`, shadowID, app, "p93_resource_"+shadowID.String())
	exec(`INSERT INTO oauth_resource_clients(application_id,resource_id,client_id,client_database_id,metadata_digest,name,redirect_uris,allowed_grants) VALUES($1,$2,$3,$4,$5,'Metadata client',ARRAY['https://client.example.test/callback'],ARRAY['authorization_code'])`, app, metadataResource.ID, metadataID, shadowID, []byte("metadata digest"))
	metadataConnection := kernel.NewID()
	exec(`INSERT INTO oauth_connections(id,application_id,resource_id,resource_version,user_id,client_id,session_id,capabilities,personal_access,expires_at) VALUES($1,$2,$3,1,$4,$5,$6,ARRAY['documents:read'],true,now()+interval '1 day')`, metadataConnection, app, metadataResource.ID, user, metadataID, session)
	unlistedID := "https://client.example.test/unlisted/" + app.String()
	exec(`INSERT INTO oauth_resource_clients(application_id,resource_id,client_id,client_database_id,metadata_digest,name,redirect_uris) VALUES($1,$2,$3,$4,$5,'Metadata client',ARRAY['https://client.example.test/callback'])`, app, metadataResource.ID, unlistedID, shadowID, []byte("metadata digest"))
	if _, err = db.Exec(ctx, `UPDATE oauth_connections SET client_id=$1 WHERE id=$2`, unlistedID, metadataConnection); err == nil {
		t.Fatal("metadata binding bypassed resource allowlist")
	}
	firstPage := httptest.NewRecorder()
	s.listOAuthResources(firstPage, requestWithRoute(t, "GET", "/?limit=1", nil, routes, actor))
	var page struct {
		Items []OAuthResource `json:"items"`
		Next  *string         `json:"next_cursor"`
	}
	if err = json.Unmarshal(firstPage.Body.Bytes(), &page); err != nil || firstPage.Code != 200 || len(page.Items) != 1 || page.Next == nil {
		t.Fatalf("resource first page: %d %s", firstPage.Code, firstPage.Body)
	}
	firstID := page.Items[0].ID
	secondPage := httptest.NewRecorder()
	s.listOAuthResources(secondPage, requestWithRoute(t, "GET", "/?limit=1&cursor="+*page.Next, nil, routes, actor))
	if err = json.Unmarshal(secondPage.Body.Bytes(), &page); err != nil || secondPage.Code != 200 || len(page.Items) != 1 || page.Items[0].ID == firstID || page.Next != nil {
		t.Fatalf("resource second page: %d %s", secondPage.Code, secondPage.Body)
	}
	invalidCursor := httptest.NewRecorder()
	s.listOAuthResources(invalidCursor, requestWithRoute(t, "GET", "/?cursor=invalid", nil, routes, actor))
	if invalidCursor.Code != 400 {
		t.Fatalf("invalid cursor returned %d", invalidCursor.Code)
	}
	w = call("PATCH", map[string]any{"name": "Changed"}, routes, actor, "", s.updateOAuthResource)
	if w.Code != 428 {
		t.Fatal(w.Code)
	}
	w = call("PATCH", map[string]any{"name": "Changed"}, routes, actor, `"v9"`, s.updateOAuthResource)
	if w.Code != 412 {
		t.Fatal(w.Code)
	}
	w = call("GET", nil, map[string]string{"application_id": other.String(), "resource_id": v.ID.String()}, actor, "", s.getOAuthResource)
	if w.Code != 404 {
		t.Fatal(w.Code)
	}
	connection := kernel.NewID()
	exec(`INSERT INTO oauth_connections(id,application_id,resource_id,resource_version,user_id,client_id,session_id,capabilities,personal_access,expires_at) VALUES($1,$2,$3,1,$4,$5,$6,ARRAY['documents:read'],true,now()+interval '1 day')`, connection, app, v.ID, user, clientID, session)
	workspace, unrelatedWorkspace := kernel.NewID(), kernel.NewID()
	exec(`INSERT INTO workspaces(id,application_id,owner_user_id,key,name) VALUES($1,$2,$3,$4,'Owned workspace')`, workspace, app, user, "owned-"+workspace.String())
	exec(`INSERT INTO workspaces(id,application_id,owner_user_id,key,name) VALUES($1,$2,$3,$4,'Unrelated workspace')`, unrelatedWorkspace, app, otherUser, "unrelated-"+unrelatedWorkspace.String())
	exec(`UPDATE oauth_connections SET capabilities=ARRAY['documents:workspace'],personal_access=false,workspace_ids=ARRAY[$1::uuid] WHERE id=$2`, workspace, connection)
	workspaceConnection, loadErr := s.loadOAuthConnection(ctx, app.String(), connection.String())
	if loadErr != nil || len(workspaceConnection.WorkspaceIDs) != 1 || workspaceConnection.WorkspaceIDs[0] != workspace {
		t.Fatalf("workspace connection decoding: %+v %v", workspaceConnection, loadErr)
	}
	if _, err = db.Exec(ctx, `UPDATE oauth_connections SET workspace_ids=ARRAY[$1::uuid] WHERE id=$2`, unrelatedWorkspace, connection); err == nil {
		t.Fatal("accepted workspace without membership or ownership")
	}
	exec(`UPDATE oauth_connections SET capabilities=ARRAY['documents:read'],personal_access=true,workspace_ids='{}' WHERE id=$1`, connection)
	if _, err = db.Exec(ctx, `INSERT INTO oauth_connections(application_id,resource_id,resource_version,user_id,client_id,session_id,capabilities,personal_access,expires_at) VALUES($1,$2,1,$3,$4,$5,ARRAY['documents:read'],true,now()+interval '3 days')`, app, v.ID, user, clientID, session); err == nil {
		t.Fatal("accepted connection beyond session expiry")
	}
	if _, err = db.Exec(ctx, `UPDATE oauth_connections SET application_id=$1 WHERE id=$2`, other, connection); err == nil {
		t.Fatal("accepted cross-app connection")
	}
	if _, err = db.Exec(ctx, `UPDATE oauth_connections SET workspace_ids=ARRAY[$1::uuid] WHERE id=$2`, kernel.NewID(), connection); err == nil {
		t.Fatal("accepted invalid workspace")
	}
	if _, err = db.Exec(ctx, `UPDATE oauth_connections SET capabilities=ARRAY['unknown'] WHERE id=$1`, connection); err == nil {
		t.Fatal("accepted unknown capability")
	}
	params := map[string]string{"application_id": app.String(), "connection_id": connection.String(), "resource_id": v.ID.String()}
	w = call("GET", nil, params, kernel.Actor{Type: "user", ID: otherUser.String()}, "", s.getMyConnection)
	if w.Code != 404 {
		t.Fatal(w.Code)
	}
	w = call("GET", nil, params, kernel.Actor{Type: "user", ID: user.String()}, "", s.getMyConnection)
	if w.Code != 200 || !strings.Contains(w.Body.String(), session.String()) {
		t.Fatalf("self get: %d %s", w.Code, w.Body)
	}
	w = call("GET", nil, params, kernel.Actor{Type: "user", ID: otherUser.String()}, "", s.listMyConnections)
	var connectionPage struct {
		Items []OAuthConnection `json:"items"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &connectionPage); err != nil || w.Code != 200 || len(connectionPage.Items) != 0 {
		t.Fatalf("other user list: %d %s", w.Code, w.Body)
	}
	w = call("GET", nil, params, actor, "", s.listResourceConnections)
	if err = json.Unmarshal(w.Body.Bytes(), &connectionPage); err != nil || w.Code != 200 || len(connectionPage.Items) != 1 || connectionPage.Items[0].ID != connection {
		t.Fatalf("resource list: %d %s", w.Code, w.Body)
	}
	w = call("PATCH", map[string]any{"enabled": false}, routes, actor, `"v1"`, s.updateOAuthResource)
	if w.Code != 200 {
		t.Fatalf("update: %d %s", w.Code, w.Body)
	}
	current, err := s.loadOAuthResource(ctx, app.String(), v.ID.String())
	if err != nil || current.Version != 2 || current.Enabled {
		t.Fatalf("resource update: %+v %v", current, err)
	}
	w = call("DELETE", nil, params, kernel.Actor{Type: "user", ID: user.String()}, `"v1"`, s.revokeMyConnection)
	if w.Code != 204 {
		t.Fatalf("revoke: %d %s", w.Code, w.Body)
	}
	c, err := s.loadOAuthConnection(ctx, app.String(), connection.String())
	if err != nil || c.RevokedAt == nil || c.Version != 2 {
		t.Fatalf("revocation: %+v %v", c, err)
	}
	var events, audits, consents int
	if err = db.QueryRow(ctx, `SELECT count(*) FROM domain_events WHERE application_id=$1 AND event_type IN ('resource.created','resource.updated','connection.revoked')`, app).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(ctx, `SELECT count(*) FROM audit_records WHERE application_id=$1`, app).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(ctx, `SELECT count(*) FROM oauth_consents WHERE application_id=$1`, app).Scan(&consents); err != nil {
		t.Fatal(err)
	}
	if events != 4 || audits != 4 || consents != 0 {
		t.Fatalf("events=%d audits=%d consents=%d", events, audits, consents)
	}
	// An unavailable event contract must roll back the data mutation and audit together.
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `UPDATE oauth_resources SET name='Rollback candidate' WHERE id=$1`, v.ID)
	if err != nil {
		t.Fatal(err)
	}
	err = s.emitResourceMutation(requestWithRoute(t, "PATCH", "/", nil, routes, actor), tx, app, "resource.missing", "resource", v.ID, map[string]any{"resource_id": v.ID, "version": 3})
	if err == nil {
		t.Fatal("missing contract accepted")
	}
	if err = tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	current, err = s.loadOAuthResource(ctx, app.String(), v.ID.String())
	if err != nil || current.Name == "Rollback candidate" {
		t.Fatal("mutation survived rollback")
	}
	t.Run("unexpected mutation failures return 500 and roll back", func(t *testing.T) {
		exec(`UPDATE event_type_definitions SET status='archived' WHERE application_id IS NULL AND source='platform93' AND name IN ('resource.created','resource.updated')`)
		defer func() {
			if _, restoreErr := db.Exec(ctx, `UPDATE event_type_definitions SET status='active' WHERE application_id IS NULL AND source='platform93' AND name IN ('resource.created','resource.updated')`); restoreErr != nil {
				t.Error(restoreErr)
			}
		}()
		failureURI := v.URI + "/failed-mutation"
		body := map[string]any{"uri": failureURI, "name": "Failed creation", "capabilities": v.Capabilities}
		failedCreate := call("POST", body, routes, actor, "", s.createOAuthResource)
		if failedCreate.Code != 500 {
			t.Fatalf("unexpected create failure: %d %s", failedCreate.Code, failedCreate.Body)
		}
		var exists bool
		if queryErr := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM oauth_resources WHERE uri=$1)`, failureURI).Scan(&exists); queryErr != nil || exists {
			t.Fatalf("creation did not roll back: exists=%v err=%v", exists, queryErr)
		}
		failedUpdate := call("PATCH", map[string]any{"name": "Failed update"}, routes, actor, `"v2"`, s.updateOAuthResource)
		if failedUpdate.Code != 500 {
			t.Fatalf("unexpected update failure: %d %s", failedUpdate.Code, failedUpdate.Body)
		}
		unchanged, loadErr := s.loadOAuthResource(ctx, app.String(), v.ID.String())
		if loadErr != nil || unchanged.Version != 2 || unchanged.Name == "Failed update" {
			t.Fatalf("update did not roll back: %+v %v", unchanged, loadErr)
		}
		var count int
		if queryErr := db.QueryRow(ctx, `SELECT count(*) FROM audit_records WHERE application_id=$1`, app).Scan(&count); queryErr != nil || count != 4 {
			t.Fatalf("failed mutation audit survived: count=%d err=%v", count, queryErr)
		}
	})
	for _, uri := range []string{"https://localhost", "https://127.0.0.1", "https://[::1]", "https://example.test?x=1", "https://EXAMPLE.test"} {
		var valid bool
		if err = db.QueryRow(ctx, `SELECT valid_oauth_resource_uri($1)`, uri).Scan(&valid); err != nil || valid {
			t.Errorf("database URI %q: %v %v", uri, valid, err)
		}
	}
	for _, bad := range []string{`[]`, `[{"key":"roles:owner","name":"Owner","context":"personal","permissions":["documents:read"]}]`, `[{"key":"documents:read","name":"Read","context":"personal","permissions":["documents:*"]}]`, `[{"key":"documents:read","name":"Read","context":"personal","permissions":null}]`, `[{"key":"documents:read","name":"Read","context":"personal"}]`} {
		var valid bool
		if err = db.QueryRow(ctx, `SELECT valid_resource_capabilities($1::jsonb)`, bad).Scan(&valid); err != nil || valid {
			t.Errorf("database capabilities: %v %v", valid, err)
		}
	}
	for _, capabilityContext := range []string{"personal", "workspace"} {
		var valid bool
		value := `[{"key":"profile:read","name":"Read profile","context":"` + capabilityContext + `","permissions":[]}]`
		if err = db.QueryRow(ctx, `SELECT valid_resource_capabilities($1::jsonb)`, value).Scan(&valid); err != nil || !valid {
			t.Errorf("database rejected explicit empty %s permissions: valid=%v err=%v", capabilityContext, valid, err)
		}
	}
}
