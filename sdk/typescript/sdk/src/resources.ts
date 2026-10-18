export type ResourceCapability = { key: string; name: string; context: "personal" | "workspace"; permissions: string[] };
export type OAuthResource = {
  id: string;
  application_id: string;
  uri: string;
  name: string;
  enabled: boolean;
  allow_client_metadata: boolean;
  client_ids: string[];
  capabilities: ResourceCapability[];
  version: number;
  created_at: string;
  updated_at: string;
};
export type OAuthConnection = {
  id: string;
  application_id: string;
  resource_id: string;
  resource_version: number;
  user_id: string;
  client_id: string;
  session_id: string;
  capabilities: string[];
  personal_access: boolean;
  workspace_ids: string[];
  expires_at: string;
  version: number;
  created_at: string;
  updated_at: string;
  revoked_at: string | null;
};
export type ResourceAccessCheckRequest = {
  token: string;
  resource: string;
  capability: string;
  workspace_id?: string;
};
export type ResourceAccessCheckResponse = {
  allowed: boolean;
  reason: string;
  user_id?: string;
  connection_id?: string;
  workspace_id?: string;
};
