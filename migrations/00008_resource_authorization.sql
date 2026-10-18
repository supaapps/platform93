-- +goose Up
ALTER TABLE clients ADD COLUMN resource_only boolean NOT NULL DEFAULT false;

-- +goose StatementBegin
CREATE FUNCTION valid_oauth_resource_uri(value text) RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE authority text; hostname text; port text; address inet;
BEGIN
    IF length(value) NOT BETWEEN 1 AND 2048 OR value !~ '^https://[^/?#@[:space:]\\]+(/[^?#[:space:]\\]*)?$' THEN RETURN false; END IF;
    authority := substring(value FROM '^https://([^/]+)');
    IF left(authority,1)='[' THEN
        hostname := substring(authority FROM '^\[([^]]+)\]');
        port := substring(authority FROM '\]:([0-9]+)$');
        IF authority !~ '^\[[0-9a-f:]+\](:[0-9]+)?$' THEN RETURN false; END IF;
        BEGIN address := hostname::inet; EXCEPTION WHEN invalid_text_representation THEN RETURN false; END;
    ELSE
        hostname := split_part(authority,':',1);
        port := substring(authority FROM ':([0-9]+)$');
        IF authority !~ '^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]+)?$' OR hostname ~ '(^|\.)localhost$'
           OR hostname ~ '\.\.' THEN RETURN false; END IF;
        IF hostname ~ '^[0-9.]+$' THEN
            BEGIN address := hostname::inet; EXCEPTION WHEN invalid_text_representation THEN RETURN false; END;
        END IF;
    END IF;
    IF address IS NOT NULL AND (address <<= '127.0.0.0/8'::inet OR address='::1'::inet OR address='0.0.0.0'::inet OR address='::'::inet) THEN RETURN false; END IF;
    IF port IS NOT NULL AND (length(port)>5 OR port::integer NOT BETWEEN 1 AND 65535 OR port='443' OR left(port,1)='0') THEN RETURN false; END IF;
    RETURN value !~ '^https://[^/]+/$' AND value !~ '/\.\.?(/|$)' AND value !~ '//[^/]*//';
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION valid_resource_capabilities(value jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE c jsonb; p jsonb; keys text[] := '{}'; permissions text[];
BEGIN
    IF jsonb_typeof(value) IS DISTINCT FROM 'array' THEN RETURN false; END IF;
    IF jsonb_array_length(value) NOT BETWEEN 1 AND 32 THEN RETURN false; END IF;
    FOR c IN SELECT * FROM jsonb_array_elements(value) LOOP
        IF jsonb_typeof(c) IS DISTINCT FROM 'object'
           OR (SELECT count(*) FROM jsonb_object_keys(c)) <> 4
           OR jsonb_typeof(c->'key') IS DISTINCT FROM 'string'
           OR NOT valid_permission_key(c->>'key') OR position('*' in c->>'key') > 0
           OR split_part(c->>'key',':',1) IN ('roles','workspaces')
           OR c->>'key' = ANY(keys)
           OR jsonb_typeof(c->'name') IS DISTINCT FROM 'string'
           OR length(btrim(c->>'name')) NOT BETWEEN 1 AND 160
           OR jsonb_typeof(c->'context') IS DISTINCT FROM 'string'
           OR c->>'context' NOT IN ('personal','workspace')
           OR jsonb_typeof(c->'permissions') IS DISTINCT FROM 'array' THEN RETURN false; END IF;
        keys := array_append(keys,c->>'key');
        IF jsonb_array_length(c->'permissions') NOT BETWEEN 0 AND 200 THEN RETURN false; END IF;
        permissions := '{}';
        FOR p IN SELECT * FROM jsonb_array_elements(c->'permissions') LOOP
            IF jsonb_typeof(p) IS DISTINCT FROM 'string' OR NOT valid_permission_key(p #>> '{}')
               OR position('*' in p #>> '{}') > 0 OR (p #>> '{}') = ANY(permissions) THEN RETURN false; END IF;
            permissions := array_append(permissions,p #>> '{}');
        END LOOP;
    END LOOP;
    RETURN true;
END $$;
-- +goose StatementEnd

CREATE TABLE oauth_resources (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id uuid NOT NULL REFERENCES applications(id),
    uri text NOT NULL UNIQUE CHECK (valid_oauth_resource_uri(uri)),
    name text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 160),
    enabled boolean NOT NULL DEFAULT false,
    allow_client_metadata boolean NOT NULL DEFAULT false,
    client_ids text[] NOT NULL DEFAULT '{}' CHECK (cardinality(client_ids) <= 32 AND array_position(client_ids,NULL) IS NULL),
    capabilities jsonb NOT NULL CHECK (valid_resource_capabilities(capabilities)),
    version integer NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(application_id,id)
);
CREATE INDEX oauth_resources_page ON oauth_resources(application_id,created_at DESC,id DESC);

CREATE TABLE oauth_resource_clients (
    application_id uuid NOT NULL,
    resource_id uuid NOT NULL,
    client_id text NOT NULL CHECK (length(client_id) BETWEEN 1 AND 2048 AND client_id ~ '^https://'),
    client_database_id uuid NOT NULL,
    metadata_digest bytea NOT NULL,
    PRIMARY KEY(resource_id,client_id),
    FOREIGN KEY(application_id,resource_id) REFERENCES oauth_resources(application_id,id),
    FOREIGN KEY(application_id,client_database_id) REFERENCES clients(application_id,id)
);

ALTER TABLE user_sessions ADD CONSTRAINT user_sessions_resource_identity UNIQUE(application_id,user_id,id);
CREATE TABLE oauth_connections (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id uuid NOT NULL,
    resource_id uuid NOT NULL,
    resource_version bigint NOT NULL CHECK (resource_version > 0),
    user_id uuid NOT NULL,
    client_id text NOT NULL CHECK (length(client_id) BETWEEN 1 AND 2048),
    session_id uuid NOT NULL,
    capabilities text[] NOT NULL CHECK (cardinality(capabilities) BETWEEN 1 AND 32 AND array_position(capabilities,NULL) IS NULL),
    personal_access boolean NOT NULL DEFAULT false,
    workspace_ids uuid[] NOT NULL DEFAULT '{}' CHECK (cardinality(workspace_ids) <= 100 AND array_position(workspace_ids,NULL) IS NULL),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY(application_id,resource_id) REFERENCES oauth_resources(application_id,id),
    FOREIGN KEY(application_id,user_id) REFERENCES users(application_id,id),
    FOREIGN KEY(application_id,user_id,session_id) REFERENCES user_sessions(application_id,user_id,id),
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '30 days'),
    CHECK (personal_access OR cardinality(workspace_ids)>0),
    UNIQUE(application_id,id)
);
CREATE INDEX oauth_connections_resource_page ON oauth_connections(application_id,resource_id,created_at DESC,id DESC);
CREATE INDEX oauth_connections_user_page ON oauth_connections(application_id,user_id,created_at DESC,id DESC);

-- +goose StatementBegin
CREATE FUNCTION enforce_oauth_connection() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE resource oauth_resources; session user_sessions;
BEGIN
    -- Revocation must remain possible after the underlying authorization expires or changes.
    IF TG_OP='UPDATE' AND (to_jsonb(NEW)-ARRAY['revoked_at','version','updated_at']) =
                         (to_jsonb(OLD)-ARRAY['revoked_at','version','updated_at']) THEN RETURN NEW; END IF;
    SELECT * INTO resource FROM oauth_resources WHERE application_id=NEW.application_id AND id=NEW.resource_id FOR SHARE;
    SELECT * INTO session FROM user_sessions WHERE application_id=NEW.application_id AND user_id=NEW.user_id AND id=NEW.session_id FOR SHARE;
    IF resource.id IS NULL OR NOT resource.enabled OR resource.version <> NEW.resource_version
       OR session.id IS NULL OR session.revoked_at IS NOT NULL OR NEW.expires_at > session.expires_at
       OR NEW.expires_at <= now()
       OR NOT EXISTS (SELECT 1 FROM users WHERE application_id=NEW.application_id AND id=NEW.user_id AND status='active') THEN
        RAISE EXCEPTION 'resource connection authorization is invalid';
    END IF;
    IF NOT (NEW.client_id=ANY(resource.client_ids) AND EXISTS(SELECT 1 FROM clients WHERE application_id=NEW.application_id AND client_id=NEW.client_id AND NOT resource_only AND disabled_at IS NULL))
       AND NOT (resource.allow_client_metadata AND NEW.client_id=ANY(resource.client_ids) AND EXISTS(SELECT 1 FROM oauth_resource_clients b JOIN clients c ON c.id=b.client_database_id
         WHERE b.application_id=NEW.application_id AND b.resource_id=NEW.resource_id AND b.client_id=NEW.client_id AND c.resource_only AND c.disabled_at IS NULL)) THEN
        RAISE EXCEPTION 'resource connection client is not allowed';
    END IF;
    IF cardinality(NEW.capabilities) <> (SELECT count(DISTINCT c) FROM unnest(NEW.capabilities) c)
       OR EXISTS(SELECT 1 FROM unnest(NEW.capabilities) k WHERE NOT EXISTS(SELECT 1 FROM jsonb_array_elements(resource.capabilities) c WHERE c->>'key'=k))
       OR (NEW.personal_access AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(resource.capabilities) c WHERE c->>'context'='personal' AND c->>'key'=ANY(NEW.capabilities)))
       OR (cardinality(NEW.workspace_ids)>0 AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(resource.capabilities) c WHERE c->>'context'='workspace' AND c->>'key'=ANY(NEW.capabilities)))
       OR cardinality(NEW.workspace_ids) <> (SELECT count(DISTINCT w) FROM unnest(NEW.workspace_ids) w)
       OR EXISTS(SELECT 1 FROM unnest(NEW.workspace_ids) wid WHERE NOT EXISTS(SELECT 1 FROM workspaces w
         WHERE w.id=wid AND w.application_id=NEW.application_id AND w.deleted_at IS NULL
         AND (w.owner_user_id=NEW.user_id OR EXISTS(SELECT 1 FROM workspace_memberships m WHERE m.workspace_id=w.id AND m.user_id=NEW.user_id)))) THEN
        RAISE EXCEPTION 'resource connection selection is invalid';
    END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER oauth_connection_guard BEFORE INSERT OR UPDATE ON oauth_connections FOR EACH ROW EXECUTE FUNCTION enforce_oauth_connection();

INSERT INTO event_type_definitions(id,application_id,name,description,schema_version,source,status,example_subject,data_schema,example_data,version)
SELECT gen_random_uuid(),NULL,event_name,'Resource authorization lifecycle event.','1.0','platform93','active',
       subject_type||'/01900000-0000-7000-8000-000000000004',
       jsonb_build_object('type','object','required',CASE WHEN id_field='resource_id' THEN jsonb_build_array('resource_id','version') ELSE jsonb_build_array(id_field,'resource_id','version') END,'properties',
         jsonb_build_object(id_field,jsonb_build_object('type','string','format','uuid'),'resource_id',jsonb_build_object('type','string','format','uuid'),'version',jsonb_build_object('type','integer','minimum',1)),'additionalProperties',false),
       jsonb_build_object(id_field,'01900000-0000-7000-8000-000000000004','resource_id','01900000-0000-7000-8000-000000000004','version',1),1
FROM (VALUES ('resource.created','resource','resource_id'),('resource.updated','resource','resource_id'),
             ('connection.approved','connection','connection_id'),('connection.revoked','connection','connection_id')) events(event_name,subject_type,id_field);

-- +goose Down
DELETE FROM event_type_definitions WHERE application_id IS NULL AND source='platform93' AND name IN ('resource.created','resource.updated','connection.approved','connection.revoked');
DROP TABLE oauth_connections;
DROP FUNCTION enforce_oauth_connection();
DROP TABLE oauth_resource_clients;
DROP TABLE oauth_resources;
DROP FUNCTION valid_resource_capabilities(jsonb);
DROP FUNCTION valid_oauth_resource_uri(text);
ALTER TABLE user_sessions DROP CONSTRAINT user_sessions_resource_identity;
ALTER TABLE clients DROP COLUMN resource_only;
