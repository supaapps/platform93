package httpapi

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/supaapps/platform93/internal/database"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/platform"
	"github.com/supaapps/platform93/internal/secure"
)

func TestStorageProviderInheritanceAndObjectIsolation(t *testing.T) {
	databaseURL := os.Getenv("PLATFORM93_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("PLATFORM93_DATABASE_URL is not configured")
	}
	if err := database.Migrate(databaseURL); err != nil {
		t.Fatal(err)
	}
	db, err := database.Open(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	vault, _ := secure.NewVault(make([]byte, 32))
	server := &Server{app: platform.New(db, vault, "https://platform93.test")}

	organizationID, appOneID, appTwoID := kernel.NewID(), kernel.NewID(), kernel.NewID()
	userOneID, userTwoID := kernel.NewID(), kernel.NewID()
	installationProviderID, organizationProviderID, applicationProviderID := kernel.NewID(), kernel.NewID(), kernel.NewID()
	suffix := appOneID.String()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Storage test',$2)`, []any{organizationID, "storage-" + suffix}},
		{`INSERT INTO applications(id,organization_id,name,slug) VALUES($1,$2,'Storage one',$3)`, []any{appOneID, organizationID, "storage-one-" + suffix}},
		{`INSERT INTO applications(id,organization_id,name,slug) VALUES($1,$2,'Storage two',$3)`, []any{appTwoID, organizationID, "storage-two-" + suffix}},
		{`INSERT INTO users(id,application_id,email,normalized_email) VALUES($1,$2,$3,$3)`, []any{userOneID, appOneID, "one-" + suffix + "@example.test"}},
		{`INSERT INTO users(id,application_id,email,normalized_email) VALUES($1,$2,$3,$3)`, []any{userTwoID, appTwoID, "two-" + suffix + "@example.test"}},
		{`INSERT INTO storage_providers(id,name,endpoint,region,public_bucket,credentials_ciphertext,inheritable,status,verified_at) VALUES($1,'Installation','https://s3.example.test','test','public-installation','cipher',true,'active',$2)`, []any{installationProviderID, time.Now()}},
		{`INSERT INTO storage_providers(id,organization_id,name,endpoint,region,private_bucket,credentials_ciphertext,inheritable,status,verified_at) VALUES($1,$2,'Organization','https://s3.example.test','test','private-organization','cipher',true,'active',$3)`, []any{organizationProviderID, organizationID, time.Now()}},
		{`INSERT INTO storage_providers(id,application_id,name,endpoint,region,public_bucket,credentials_ciphertext,status,verified_at) VALUES($1,$2,'Application','https://s3.example.test','test','public-application','cipher','active',$3)`, []any{applicationProviderID, appOneID, time.Now()}},
	}
	for _, statement := range statements {
		if _, err = db.Exec(context.Background(), statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}

	publicOne, err := server.resolveStorageProvider(context.Background(), appOneID.String(), "public")
	if err != nil || publicOne.ID != applicationProviderID.String() {
		t.Fatalf("application public provider was not selected: %#v, %v", publicOne, err)
	}
	privateOne, err := server.resolveStorageProvider(context.Background(), appOneID.String(), "private")
	if err != nil || privateOne.ID != organizationProviderID.String() {
		t.Fatalf("organization private provider was not selected: %#v, %v", privateOne, err)
	}
	publicTwo, err := server.resolveStorageProvider(context.Background(), appTwoID.String(), "public")
	if err != nil || publicTwo.ID != installationProviderID.String() {
		t.Fatalf("installation public provider was not selected: %#v, %v", publicTwo, err)
	}

	_, err = db.Exec(context.Background(), `INSERT INTO storage_objects
(id,application_id,storage_provider_id,owner_type,owner_id,visibility,bucket_role,bucket_name,object_key,filename,content_type,size_bytes,upload_expires_at)
VALUES($1,$2,$3,'user',$4,'public','public','public-application','invalid','invalid.txt','text/plain',1,now()+interval '10 minutes')`,
		kernel.NewID(), appOneID, applicationProviderID, userTwoID)
	if err == nil {
		t.Fatal("cross-application storage owner was accepted")
	}

	if _, err = db.Exec(context.Background(), "UPDATE storage_providers SET inheritable=false WHERE id=$1", organizationProviderID); err != nil {
		t.Fatal(err)
	}
	if _, err = server.resolveStorageProvider(context.Background(), appTwoID.String(), "private"); err == nil {
		t.Fatal("non-inheritable organization private provider resolved for an application")
	}
}
