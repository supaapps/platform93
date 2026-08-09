-- +goose Up
CREATE TABLE storage_providers (
    id uuid PRIMARY KEY,
    organization_id uuid REFERENCES organizations(id),
    application_id uuid REFERENCES applications(id),
    provider text NOT NULL DEFAULT 's3' CHECK (provider='s3'),
    name text NOT NULL CHECK (name<>'' AND length(name)<=200),
    endpoint text NOT NULL CHECK (endpoint<>'' AND length(endpoint)<=2000),
    region text NOT NULL CHECK (region<>'' AND length(region)<=100),
    force_path_style boolean NOT NULL DEFAULT false,
    public_bucket text,
    private_bucket text,
    public_base_url text,
    credentials_ciphertext text NOT NULL,
    inheritable boolean NOT NULL DEFAULT false,
    allow_private_endpoint boolean NOT NULL DEFAULT false,
    max_object_bytes bigint NOT NULL DEFAULT 26214400 CHECK (max_object_bytes BETWEEN 1 AND 5368709120),
    max_email_image_bytes bigint NOT NULL DEFAULT 2097152 CHECK (max_email_image_bytes BETWEEN 1 AND 26214400),
    max_application_bytes bigint NOT NULL DEFAULT 10737418240 CHECK (max_application_bytes>=max_object_bytes),
    max_application_objects bigint NOT NULL DEFAULT 100000 CHECK (max_application_objects BETWEEN 1 AND 100000000),
    status text NOT NULL DEFAULT 'unverified' CHECK (status IN ('unverified','active','error','disabled')),
    verified_at timestamptz,
    disabled_at timestamptz,
    last_error text,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((application_id IS NOT NULL AND organization_id IS NULL) OR
           (application_id IS NULL AND organization_id IS NOT NULL) OR
           (application_id IS NULL AND organization_id IS NULL)),
    CHECK (public_bucket IS NOT NULL OR private_bucket IS NOT NULL),
    CHECK (public_bucket IS NULL OR private_bucket IS NULL OR public_bucket<>private_bucket),
    CHECK (application_id IS NULL OR inheritable=false),
    CHECK (allow_private_endpoint=false OR (application_id IS NULL AND organization_id IS NULL))
);
CREATE INDEX storage_providers_scope ON storage_providers(application_id,organization_id,status,created_at DESC);

CREATE TABLE storage_objects (
    id uuid PRIMARY KEY,
    application_id uuid REFERENCES applications(id),
    storage_provider_id uuid NOT NULL REFERENCES storage_providers(id),
    owner_type text NOT NULL CHECK (owner_type IN ('installation','application','user','workspace')),
    owner_id uuid,
    visibility text NOT NULL CHECK (visibility IN ('public','private')),
    bucket_role text NOT NULL CHECK (bucket_role IN ('public','private')),
    bucket_name text NOT NULL,
    object_key text NOT NULL CHECK (object_key<>'' AND length(object_key)<=1024),
    filename text NOT NULL CHECK (filename<>'' AND length(filename)<=500),
    content_type text NOT NULL CHECK (content_type<>'' AND length(content_type)<=255),
    size_bytes bigint NOT NULL CHECK (size_bytes>0),
    etag text,
    metadata jsonb NOT NULL DEFAULT '{}',
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','ready','deleting','deleted','failed')),
    upload_expires_at timestamptz,
    ready_at timestamptz,
    deleted_at timestamptz,
    last_error text,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (storage_provider_id,bucket_name,object_key),
    CHECK ((owner_type='installation' AND application_id IS NULL AND owner_id IS NULL) OR
           (owner_type='application' AND application_id IS NOT NULL AND owner_id IS NULL) OR
           (owner_type IN ('user','workspace') AND application_id IS NOT NULL AND owner_id IS NOT NULL)),
    CHECK (visibility=bucket_role),
    CHECK ((status='pending' AND upload_expires_at IS NOT NULL) OR status<>'pending')
);
CREATE INDEX storage_objects_application ON storage_objects(application_id,owner_type,owner_id,status,created_at DESC);
CREATE INDEX storage_objects_provider ON storage_objects(storage_provider_id,status,created_at DESC);
CREATE INDEX storage_objects_pending ON storage_objects(upload_expires_at) WHERE status='pending';

-- +goose StatementBegin
CREATE FUNCTION enforce_storage_object_scope() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    provider_application uuid;
    provider_organization uuid;
    provider_public_bucket text;
    provider_private_bucket text;
BEGIN
    SELECT application_id,organization_id,public_bucket,private_bucket
      INTO provider_application,provider_organization,provider_public_bucket,provider_private_bucket
      FROM storage_providers WHERE id=NEW.storage_provider_id;
    IF NEW.bucket_role='public' AND provider_public_bucket IS DISTINCT FROM NEW.bucket_name THEN
        RAISE EXCEPTION 'public object bucket must match its storage provider';
    END IF;
    IF NEW.bucket_role='private' AND provider_private_bucket IS DISTINCT FROM NEW.bucket_name THEN
        RAISE EXCEPTION 'private object bucket must match its storage provider';
    END IF;
    IF NEW.owner_type='installation' THEN
        IF provider_application IS NOT NULL OR provider_organization IS NOT NULL THEN
            RAISE EXCEPTION 'installation assets require an installation storage provider';
        END IF;
        RETURN NEW;
    END IF;
    IF provider_application IS NOT NULL AND provider_application<>NEW.application_id THEN
        RAISE EXCEPTION 'storage provider belongs to another application';
    END IF;
    IF provider_organization IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM applications a WHERE a.id=NEW.application_id AND a.organization_id=provider_organization
    ) THEN
        RAISE EXCEPTION 'storage provider belongs to another organization';
    END IF;
    IF NEW.owner_type='user' AND NOT EXISTS (
        SELECT 1 FROM users u WHERE u.id=NEW.owner_id AND u.application_id=NEW.application_id AND u.status='active'
    ) THEN
        RAISE EXCEPTION 'storage object user must be active in the application';
    END IF;
    IF NEW.owner_type='workspace' AND NOT EXISTS (
        SELECT 1 FROM workspaces w WHERE w.id=NEW.owner_id AND w.application_id=NEW.application_id AND w.deleted_at IS NULL
    ) THEN
        RAISE EXCEPTION 'storage object workspace must be active in the application';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER storage_object_scope_guard BEFORE INSERT OR UPDATE OF application_id,storage_provider_id,owner_type,owner_id,bucket_role,bucket_name
ON storage_objects FOR EACH ROW EXECUTE FUNCTION enforce_storage_object_scope();

CREATE TABLE notification_template_assets (
    notification_template_id uuid NOT NULL REFERENCES notification_templates(id) ON DELETE CASCADE,
    storage_object_id uuid NOT NULL REFERENCES storage_objects(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (notification_template_id,storage_object_id)
);

-- +goose StatementBegin
CREATE FUNCTION enforce_notification_template_asset_scope() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM notification_templates t JOIN storage_objects o ON o.id=NEW.storage_object_id
        WHERE t.id=NEW.notification_template_id AND o.status='ready' AND o.visibility='public'
          AND o.content_type IN ('image/png','image/jpeg','image/gif')
          AND ((t.application_id IS NULL AND o.owner_type='installation') OR
               (t.application_id IS NOT NULL AND (
                   (o.application_id=t.application_id AND o.owner_type='application') OR
                   o.owner_type='installation'
               )))
    ) THEN
        RAISE EXCEPTION 'template assets must be ready public images from the template scope';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER notification_template_asset_scope_guard BEFORE INSERT OR UPDATE ON notification_template_assets
FOR EACH ROW EXECUTE FUNCTION enforce_notification_template_asset_scope();

UPDATE roles SET permissions=array_append(permissions,'storage:read')
WHERE built_in AND key='workspace_member' AND NOT ('storage:read'=ANY(permissions));

INSERT INTO event_type_definitions(id,application_id,name,description,source,example_subject,data_schema,example_data) VALUES
(gen_random_uuid(),NULL,'storage.object.upload_requested','An object upload was authorized.','platform93','storage_object/01900000-0000-7000-8000-000000000020','{"type":"object","required":["object_id","owner_type","visibility","size_bytes"],"properties":{"object_id":{"type":"string","format":"uuid"},"owner_type":{"enum":["installation","application","user","workspace"]},"visibility":{"enum":["public","private"]},"size_bytes":{"type":"integer","minimum":1}},"additionalProperties":false}'::jsonb,'{"object_id":"01900000-0000-7000-8000-000000000020","owner_type":"workspace","visibility":"private","size_bytes":1024}'::jsonb),
(gen_random_uuid(),NULL,'storage.object.ready','An object upload completed and was verified.','platform93','storage_object/01900000-0000-7000-8000-000000000020','{"type":"object","required":["object_id","owner_type","visibility","size_bytes"],"properties":{"object_id":{"type":"string","format":"uuid"},"owner_type":{"enum":["installation","application","user","workspace"]},"visibility":{"enum":["public","private"]},"size_bytes":{"type":"integer","minimum":1}},"additionalProperties":false}'::jsonb,'{"object_id":"01900000-0000-7000-8000-000000000020","owner_type":"workspace","visibility":"private","size_bytes":1024}'::jsonb),
(gen_random_uuid(),NULL,'storage.object.deleted','An object was deleted.','platform93','storage_object/01900000-0000-7000-8000-000000000020','{"type":"object","required":["object_id","owner_type","visibility","size_bytes"],"properties":{"object_id":{"type":"string","format":"uuid"},"owner_type":{"enum":["installation","application","user","workspace"]},"visibility":{"enum":["public","private"]},"size_bytes":{"type":"integer","minimum":1}},"additionalProperties":false}'::jsonb,'{"object_id":"01900000-0000-7000-8000-000000000020","owner_type":"workspace","visibility":"private","size_bytes":1024}'::jsonb),
(gen_random_uuid(),NULL,'storage.provider.verified','An S3-compatible storage provider was verified.','platform93','storage_provider/01900000-0000-7000-8000-000000000021','{"type":"object","required":["provider_id","scope","public_enabled","private_enabled"],"properties":{"provider_id":{"type":"string","format":"uuid"},"scope":{"enum":["installation","organization","application"]},"public_enabled":{"type":"boolean"},"private_enabled":{"type":"boolean"}},"additionalProperties":false}'::jsonb,'{"provider_id":"01900000-0000-7000-8000-000000000021","scope":"application","public_enabled":true,"private_enabled":true}'::jsonb),
(gen_random_uuid(),NULL,'storage.provider.disabled','An S3-compatible storage provider was disabled in Platform93.','platform93','storage_provider/01900000-0000-7000-8000-000000000021','{"type":"object","required":["provider_id","scope","public_enabled","private_enabled"],"properties":{"provider_id":{"type":"string","format":"uuid"},"scope":{"enum":["installation","organization","application"]},"public_enabled":{"type":"boolean"},"private_enabled":{"type":"boolean"}},"additionalProperties":false}'::jsonb,'{"provider_id":"01900000-0000-7000-8000-000000000021","scope":"application","public_enabled":true,"private_enabled":true}'::jsonb)
ON CONFLICT(application_id,name) DO NOTHING;

-- +goose Down
UPDATE roles SET permissions=array_remove(permissions,'storage:read') WHERE built_in AND key='workspace_member';
DELETE FROM event_type_definitions WHERE application_id IS NULL AND name IN (
    'storage.object.upload_requested','storage.object.ready','storage.object.deleted',
    'storage.provider.verified','storage.provider.disabled'
);
DROP TRIGGER notification_template_asset_scope_guard ON notification_template_assets;
DROP FUNCTION enforce_notification_template_asset_scope();
DROP TABLE notification_template_assets;
DROP TRIGGER storage_object_scope_guard ON storage_objects;
DROP FUNCTION enforce_storage_object_scope();
DROP TABLE storage_objects;
DROP TABLE storage_providers;
