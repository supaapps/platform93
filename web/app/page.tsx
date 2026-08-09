"use client";
import { startTransition, useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { Platform93Client, Platform93Error } from "@supaapps/platform93-sdk";
import Papa from "papaparse";

type Organization = { id: string; name: string; slug: string; role: string; version?: number; retired_at?: string | null };
type Application = {
  id: string;
  organization_id?: string;
  name: string;
  slug: string;
  issuer: string;
  version?: number;
  retired_at?: string | null;
  auth_config?: Record<string, unknown>;
  public_config?: Record<string, unknown>;
  internal_config?: Record<string, unknown>;
};
type Page<T> = { items: T[]; next_cursor: null | string };
type OrganizationPage = Page<Organization> & { installation_role?: "owner" | "admin" | "auditor" | null };
type OrganizationPolicy = {
  organization_id: string;
  max_applications: number | null;
  max_users: number | null;
  enabled_settings: Record<string, boolean>;
  usage: { applications: number; users: number };
  version: number;
};
type ManagementAPIStatus = { enabled: boolean; can_manage: boolean; active_clients: number; token_endpoint: string; api_base: string };
type OperatorAccount = {
  id: string;
  email: string;
  display_name: string;
  status: string;
  installation_role: string | null;
  organizations: { id: string; name: string; role: string }[];
  sign_in_methods: { email_code: boolean; magic_link: boolean; password: boolean; external_identities: unknown[] };
};
type FreeFormFormat = "text" | "csv" | "json";
type CatalogFeature = { id: string; key: string; name: string; value_type: "boolean" | "quantity" | "free_form"; free_form_format?: FreeFormFormat };
type EventTypeDefinition = { id: string; name: string; description: string; schema_version: string; data_schema: Record<string, unknown>; example_subject: string; example_data: Record<string, unknown>; example_event: Record<string, unknown>; source: "platform93" | "application"; status: "active" | "archived"; version: number; event_count?: number; last_occurred_at?: string | null };
type TemplateVariableDefinition = { key: string; label: string; description: string; type: "string" | "integer" | "number" | "boolean"; availability: "always" | "user"; sample: unknown };
type CustomTemplateVariable = { key: string; label: string; type: TemplateVariableDefinition["type"]; sample: string; required: boolean };
type StorageObject = { id: string; owner_type: string; owner_id?: string | null; visibility: "public" | "private"; filename: string; content_type: string; size_bytes: number; status: string; public_url?: string | null; metadata: Record<string, unknown>; created_at: string };
type StorageUploadAuthorization = { object: StorageObject; upload_url: string; upload_expires_at: string; required_headers: Record<string, string> };
type AdminIconName =
  | "open" | "archive" | "restore" | "details" | "refresh" | "replay"
  | "trash" | "remove" | "revoke" | "disable" | "suspend" | "approve"
  | "reject" | "verify" | "send" | "key-rotate" | "star" | "publish"
  | "edit" | "download";
type FieldSpec = {
  name: string;
  label: string;
  type?: "text" | "email" | "password" | "number" | "textarea" | "checkbox";
  required?: boolean;
  placeholder?: string;
  options?: { label: string; value: string }[];
  showWhen?: { field: string; value: string };
};
type CreateSpec = { label: string; fields: FieldSpec[] };
type Resource = { label: string; path: string; create?: CreateSpec };
const operatorSessionExpiredEvent = "platform93:operator-session-expired";
const networkActivityEvent = "platform93:network-activity";
const errorMessagePrefix = "platform93-error:";
let operatorRefresh: Promise<boolean> | null = null;
let activeNetworkRequests = 0;

function updateNetworkActivity(delta: number) {
  activeNetworkRequests = Math.max(0, activeNetworkRequests + delta);
  globalThis.dispatchEvent?.(new CustomEvent(networkActivityEvent, { detail: activeNetworkRequests }));
}

function requestPath(input: RequestInfo | URL): string {
  const value = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
  return new URL(value, typeof location === "undefined" ? "http://localhost" : location.origin).pathname;
}

function canRefreshOperatorRequest(path: string): boolean {
  return path.startsWith("/v1/control/") && ![
    "/v1/control/auth/email/start",
    "/v1/control/auth/email/verify",
    "/v1/control/auth/token/refresh",
    "/v1/control/auth/logout",
    "/v1/control/organization-invitations/accept",
  ].includes(path);
}

async function refreshOperatorSession(): Promise<boolean> {
  const response = await globalThis.fetch("/v1/control/auth/token/refresh", {
    method: "POST",
    credentials: "same-origin",
    headers: { Accept: "application/json" },
  });
  return response.ok;
}

const adminFetch: typeof globalThis.fetch = async (input, init) => {
  updateNetworkActivity(1);
  try {
    const response = await globalThis.fetch(input, init);
    if (response.status !== 401 || !canRefreshOperatorRequest(requestPath(input))) return response;

    operatorRefresh ??= refreshOperatorSession().finally(() => {
      operatorRefresh = null;
    });
    if (!(await operatorRefresh)) {
      globalThis.dispatchEvent?.(new Event(operatorSessionExpiredEvent));
      return response;
    }
    return globalThis.fetch(input, init);
  } finally {
    updateNetworkActivity(-1);
  }
};

const api = new Platform93Client({
  baseUrl:
    typeof location === "undefined" ? "http://localhost" : location.origin,
  fetch: adminFetch,
});
type NavigationModule = { label: string; group: string };
const platformModules: NavigationModule[] = [
  { label: "Overview", group: "Platform" },
  { label: "Operators", group: "Access" },
  { label: "Sessions", group: "Access" },
  { label: "Providers", group: "Configuration" },
  { label: "Email", group: "Configuration" },
  { label: "Management API", group: "Configuration" },
];
const organizationModules: NavigationModule[] = [
  { label: "Overview", group: "Organization" },
  { label: "Operators", group: "Access" },
  { label: "Sessions", group: "Access" },
  { label: "Policy", group: "Governance" },
  { label: "Providers", group: "Configuration" },
];
const applicationModules = [
  { label: "Overview", group: "Application" },
  { label: "Settings", group: "Application" },
  { label: "Providers", group: "Application" },
  { label: "Storage", group: "Application" },
  { label: "Identity", group: "Access" },
  { label: "Workspaces", group: "Access" },
  { label: "Catalog", group: "Commerce" },
  { label: "Billing", group: "Commerce" },
  { label: "Entitlements", group: "Commerce" },
  { label: "Requests", group: "Commerce" },
  { label: "Notifications", group: "Delivery" },
  { label: "Webhooks", group: "Delivery" },
  { label: "Events", group: "Delivery" },
  { label: "Audit", group: "Operations" },
  { label: "Operations", group: "Operations" },
];
const resources: Record<string, Resource[]> = {
  Identity: [
    { label: "Users", path: "users", create: { label: "Create user", fields: [{ name: "email", label: "Email", type: "email", required: true }, { name: "first_name", label: "First name" }, { name: "last_name", label: "Last name" }, { name: "locale", label: "Preferred locale", placeholder: "de-CH" }] } },
    { label: "Roles", path: "roles", create: { label: "Create role", fields: [{ name: "key", label: "Key", required: true }, { name: "name", label: "Name", required: true }, { name: "scope", label: "Scope", placeholder: "application", required: true }, { name: "permissions", label: "Permissions, comma separated", required: true }] } },
    { label: "Role assignments", path: "role-assignments", create: { label: "Assign role", fields: [{ name: "user_id", label: "User ID (choose user or client)" }, { name: "client_id", label: "Client database ID (choose user or client)" }, { name: "role_id", label: "Role ID", required: true }, { name: "workspace_id", label: "Workspace ID (workspace roles only)" }] } },
    { label: "OAuth consents", path: "oauth-consents" },
    { label: "Domains", path: "domains", create: { label: "Add domain", fields: [{ name: "hostname", label: "Hostname", required: true }] } },
    { label: "Clients", path: "clients", create: { label: "Create client", fields: [{ name: "client_id", label: "Client ID", required: true }, { name: "name", label: "Name", required: true }, { name: "client_type", label: "Type", placeholder: "public", required: true }, { name: "redirect_uris", label: "Redirect URIs, comma separated", required: true }, { name: "allowed_grants", label: "Grants, comma separated", placeholder: "authorization_code,refresh_token" }, { name: "allowed_scopes", label: "Scopes, comma separated", placeholder: "openid,profile,email" }] } },
  ],
  Workspaces: [
    { label: "Workspaces", path: "workspaces", create: { label: "Create workspace", fields: [{ name: "owner_user_id", label: "Owner user ID", required: true }, { name: "key", label: "Key", required: true }, { name: "name", label: "Name", required: true }] } },
    { label: "Invitations", path: "workspace-invitations", create: { label: "Invite member", fields: [{ name: "workspace_id", label: "Workspace ID", required: true }, { name: "email", label: "Email", type: "email", required: true }, { name: "role_keys", label: "Workspace role keys, comma separated", required: true }, { name: "expires_in", label: "Expires in seconds", type: "number", placeholder: "604800" }] } },
    { label: "Delegations", path: "delegations" },
  ],
  Catalog: [
    { label: "Products", path: "products", create: { label: "Create product", fields: [{ name: "key", label: "Key", required: true }, { name: "name", label: "Name", required: true }, { name: "description", label: "Description", type: "textarea" }, { name: "listable", label: "Publicly listed", type: "checkbox" }] } },
    { label: "Features", path: "features", create: { label: "Create feature", fields: [{ name: "key", label: "Key", required: true }, { name: "name", label: "Name", required: true }, { name: "value_type", label: "Value type", required: true, options: [{ label: "Boolean", value: "boolean" }, { label: "Quantity (numeric)", value: "quantity" }, { label: "Free form", value: "free_form" }] }, { name: "free_form_format", label: "Free-form format", required: true, showWhen: { field: "value_type", value: "free_form" }, options: [{ label: "Raw text", value: "text" }, { label: "CSV", value: "csv" }, { label: "JSON", value: "json" }] }] } },
  ],
  Billing: [
    { label: "Subscriptions", path: "billing/subscriptions" }, { label: "Invoices", path: "billing/invoices" },
    { label: "Payments", path: "billing/payments" }, { label: "Refunds", path: "billing/refunds" },
    { label: "Disputes", path: "billing/disputes" }, { label: "Provider events", path: "billing/provider-events" },
    { label: "Reconciliation", path: "billing/reconciliation-runs" },
  ],
  Entitlements: [{ label: "Grants", path: "entitlements", create: { label: "Grant entitlement", fields: [{ name: "subject_type", label: "Subject type", placeholder: "user", required: true }, { name: "subject_id", label: "Subject ID", required: true }, { name: "product_id", label: "Product ID", required: true }, { name: "price_id", label: "Price ID" }, { name: "expires_at", label: "Expires at, RFC3339" }] } }],
  Requests: [{ label: "Local requests", path: "local-entitlement-requests" }],
  Notifications: [
    { label: "Messages", path: "notifications" },
    { label: "Templates", path: "notification-templates" },
    { label: "Senders", path: "sender-identities" },
  ],
  Webhooks: [{ label: "Endpoints", path: "webhooks" }, { label: "Deliveries", path: "webhook-deliveries" }],
  Events: [{ label: "Event types", path: "event-types" }, { label: "Domain events", path: "events" }], Audit: [{ label: "Audit records", path: "audit-logs" }],
  Operations: [{ label: "Webhook deliveries", path: "webhook-deliveries" }, { label: "Billing events", path: "billing/provider-events" }, { label: "Reconciliation", path: "billing/reconciliation-runs" }],
};

export default function Home() {
  return <><NetworkActivity /><PlatformAdmin /></>;
}

function NetworkActivity() {
  const [active, setActive] = useState(activeNetworkRequests > 0);
  useEffect(() => {
    const update = (event: Event) => setActive((event as CustomEvent<number>).detail > 0);
    globalThis.addEventListener?.(networkActivityEvent, update);
    return () => globalThis.removeEventListener?.(networkActivityEvent, update);
  }, []);
  return <div className={`network-activity ${active ? "active" : ""}`} data-testid="network-activity" data-active={active} aria-hidden={!active}>
    <i />
    <span>Working</span>
  </div>;
}

function PlatformAdmin() {
  const [setup, setSetup] = useState<boolean | null>(null);
  const [operatorEmailLoginAvailable, setOperatorEmailLoginAvailable] = useState(false);
  const [needsLogin, setNeedsLogin] = useState(false);
  const [section, setSection] = useState("Overview");
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [applications, setApplications] = useState<Application[]>([]);
  const [installationRole, setInstallationRole] = useState<OrganizationPage["installation_role"]>(undefined);
  const [organization, setOrganization] = useState<Organization | null>(null);
  const [application, setApplication] = useState<Application | null>(null);
  const [message, setMessage] = useState("");
  const [accountOpen, setAccountOpen] = useState(false);
  const loadOrganizationsRef = useRef<() => Promise<void>>(async () => undefined);
  useEffect(() => {
    loadOrganizationsRef.current = loadOrganizations;
  });
  useEffect(() => {
    api
      .request<{ available: boolean; operator_email_login_available: boolean }>("GET", "/v1/setup/status")
      .then((value) => {
        setSetup(value.available);
        setOperatorEmailLoginAvailable(value.operator_email_login_available);
        if (!value.available) {
          if (new URLSearchParams(location.search).get("operator_challenge") === "true") setNeedsLogin(true);
          else void loadOrganizationsRef.current();
        }
      })
      .catch((error) => setMessage(readError(error)));
  }, []);
  useEffect(() => {
    const requireLogin = () => setNeedsLogin(true);
    globalThis.addEventListener?.(operatorSessionExpiredEvent, requireLogin);
    return () => globalThis.removeEventListener?.(operatorSessionExpiredEvent, requireLogin);
  }, []);
  async function loadOrganizations() {
    try {
      const value = await api.request<OrganizationPage>(
        "GET",
        "/v1/control/organizations?include_retired=true",
      );
      const applicationPages = await Promise.all(
        value.items.filter((item) => !item.retired_at).map(async (item) => {
          const page = await api.request<Page<Application>>(
            "GET",
            `/v1/control/organizations/${item.id}/applications?include_retired=true`,
          );
          return page.items.map((applicationItem) => ({
            ...applicationItem,
            organization_id: item.id,
          }));
        }),
      );
      const loadedApplications = applicationPages.flat();
      const inferredInstallationRole = value.items
        .find((item) => item.role.startsWith("installation:"))?.role.slice("installation:".length) as OrganizationPage["installation_role"];
      const effectiveInstallationRole = value.installation_role !== undefined
        ? value.installation_role
        : inferredInstallationRole ?? (value.items.length === 0 ? "owner" : null);
      const shouldEnterOrganizationRoot = !effectiveInstallationRole && (installationRole === undefined || Boolean(installationRole));
      startTransition(() => {
        setOrganizations(value.items);
        setApplications(loadedApplications);
        setInstallationRole(effectiveInstallationRole ?? null);
        if (shouldEnterOrganizationRoot) {
          setOrganization(value.items.find((item) => !item.retired_at) ?? null);
          setApplication(null);
        }
        setNeedsLogin(false);
      });
    } catch (error) {
      if (error instanceof Platform93Error && error.problem.status === 401)
        setNeedsLogin(true);
      else setMessage(readError(error));
    }
  }
  if (setup === null)
    return (
      <main className="boot">
        <div className="signal" />
        <p>Contacting the control plane</p>
      </main>
    );
  if (setup)
    return (
      <Setup
        onComplete={() => {
          setMessage("Installation setup completed.");
          setSetup(false);
          void loadOrganizations();
        }}
      />
    );
  if (needsLogin)
    return <OperatorLogin available={operatorEmailLoginAvailable} onComplete={() => {
      setMessage("Operator signed in.");
      void loadOrganizations();
    }} />;
  const contextValue = application
    ? `application:${application.id}`
    : organization
      ? `organization:${organization.id}`
      : "platform";
  const contextModules = application
    ? applicationModules
    : organization
      ? organizationModules
      : platformModules;
  function selectContext(value: string) {
    if (value === "platform") {
      setOrganization(null);
      setApplication(null);
    } else if (value.startsWith("organization:")) {
      const selected = organizations.find((item) => item.id === value.slice("organization:".length));
      setOrganization(selected ?? null);
      setApplication(null);
    } else if (value.startsWith("application:")) {
      const selected = applications.find((item) => item.id === value.slice("application:".length));
      const owningOrganization = organizations.find((item) => item.id === selected?.organization_id);
      setOrganization(owningOrganization ?? null);
      setApplication(selected ?? null);
    }
    setSection("Overview");
  }
  function goToHighestHome() {
    if (installationRole) {
      selectContext("platform");
      return;
    }
    const firstOrganization = organizations.find((item) => !item.retired_at);
    if (firstOrganization) selectContext(`organization:${firstOrganization.id}`);
  }
  async function logout() {
    try {
      await api.request("POST", "/v1/control/auth/logout", {});
      setAccountOpen(false);
      setOrganization(null);
      setApplication(null);
      setOrganizations([]);
      setApplications([]);
      setInstallationRole(undefined);
      setNeedsLogin(true);
    } catch (error) {
      setMessage(readError(error));
    }
  }
  return (
    <div className="shell">
      <aside>
        <button className="brand" type="button" aria-label="Go to highest accessible home" onClick={goToHighestHome}>
          <span aria-hidden="true">p93</span>
          <strong>Platform93</strong>
        </button>
        <div className="context-picker">
          <label htmlFor="access-context">Access context</label>
          <select id="access-context" value={contextValue} onChange={(event) => selectContext(event.target.value)}>
            {installationRole !== null && <option value="platform">Platform</option>}
            {organizations.filter((item) => !item.retired_at).map((item) => (
              <optgroup label={`${item.name} organization`} key={item.id}>
                <option value={`organization:${item.id}`}>{item.name}</option>
                {applications.filter((applicationItem) => applicationItem.organization_id === item.id && !applicationItem.retired_at).map((applicationItem) => (
                  <option value={`application:${applicationItem.id}`} key={applicationItem.id}>{applicationItem.name}</option>
                ))}
              </optgroup>
            ))}
          </select>
          <small>{application ? "Application" : organization ? "Organization" : "Installation root"}</small>
        </div>
        <nav>
          {[...new Set(contextModules.map((item) => item.group))].map((group) => (
            <div className="nav-group" key={group}>
              <span>{group}</span>
              {contextModules.filter((item) => item.group === group).map((item) => (
                <button
                  className={item.label === section ? "active" : ""}
                  key={item.label}
                  onClick={() => setSection(item.label)}
                >
                  <i />
                  {item.label}
                </button>
              ))}
            </div>
          ))}
        </nav>
        <div className="aside-foot">
          <div><span className="status-dot" />System connected</div>
          <div className="account-actions">
            <button onClick={() => setAccountOpen(true)}>Account</button>
            <button onClick={() => void logout()}>Log out</button>
          </div>
        </div>
      </aside>
      <main>
        <header className="context-header">
          <div>
            <span>{application?.name ?? organization?.name ?? "Platform"}</span>
            <i aria-hidden="true">/</i>
            <h1>{section}</h1>
          </div>
        </header>
        {message && <Toast message={message} onDismiss={() => setMessage("")} />}
        <div className="view-stage" key={`${section}:${application?.id ?? organization?.id ?? "installation"}`}>
          <Workspace
            section={section}
            organizations={organizations}
            applications={applications}
            organization={organization}
            application={application}
            setOrganization={setOrganization}
            setApplication={setApplication}
            setOrganizations={setOrganizations}
            setApplications={setApplications}
            reloadBoundaries={loadOrganizations}
            setMessage={setMessage}
          />
        </div>
      </main>
      {accountOpen && <OperatorAccountPanel
        onClose={() => setAccountOpen(false)}
        onLogout={() => void logout()}
        onOpenSessions={() => {
          setAccountOpen(false);
          setApplication(null);
          if (installationRole) setOrganization(null);
          setSection("Sessions");
        }}
        setMessage={setMessage}
      />}
    </div>
  );
}

function Setup({ onComplete }: { onComplete: () => void }) {
  const [session, setSession] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    const target = event.currentTarget;
    const form = new FormData(target);
    try {
      if (!session) {
        await api.request("POST", "/v1/setup/bootstrap", {
          credential: form.get("credential"),
          email: form.get("email"),
          display_name: form.get("display_name"),
        });
        setSession(true);
        setMessage("Installation owner established. Configure SMTP now or complete setup and add it later.");
      } else {
        if (form.get("configure_smtp") === "on")
          await api.request(
            "POST",
            "/v1/setup/notification-providers",
            smtpInput(form),
          );
        await api.request("POST", "/v1/setup/complete", {});
        onComplete();
      }
    } catch (error) {
      setMessage(readError(error));
    } finally {
      setBusy(false);
    }
  }
  return (
    <main className="setup">
      <section>
        <p className="eyebrow">FIRST INSTALLATION</p>
        <h1>Make the platform yours.</h1>
        <p>
          Consume the one-time console credential, establish the first operator,
          then permanently close setup.
        </p>
        <form onSubmit={submit}>
          {!session ? (
            <>
              <label>
                Bootstrap credential
                <input
                  required
                  name="credential"
                  type="password"
                  autoComplete="off"
                />
              </label>
              <div className="fields">
                <label>
                  Operator email
                  <input required name="email" type="email" />
                </label>
                <label>
                  Display name
                  <input name="display_name" />
                </label>
              </div>
            </>
          ) : (
            <>
              <p className="eyebrow">OPERATOR EMAIL</p>
              <label>
                <input name="configure_smtp" type="checkbox" /> Configure SMTP now
              </label>
              <div className="fields">
                <label>
                  SMTP host
                  <input name="host" placeholder="smtp.example.com" autoComplete="off" />
                </label>
                <label>
                  Port
                  <input name="port" type="number" defaultValue="587" />
                </label>
                <label>
                  Username
                  <input name="username" autoComplete="off" />
                </label>
                <label>
                  Password
                  <input name="password" type="password" autoComplete="new-password" />
                </label>
                <label>
                  Sender email
                  <input name="sender_email" type="email" autoComplete="off" />
                </label>
                <label>
                  TLS mode
                  <select name="tls_mode" defaultValue="starttls">
                    <option value="starttls">STARTTLS</option>
                    <option value="implicit_tls">Implicit TLS</option>
                  </select>
                </label>
              </div>
              <p>
                SMTP can be skipped, but operator email login will remain
                unavailable until it is configured.
              </p>
            </>
          )}{" "}
          {message && <Toast message={message} onDismiss={() => setMessage("")} />}
          <button disabled={busy}>
            {busy
              ? "Working..."
              : session
                ? "Complete installation"
                : "Establish operator"}
          </button>
        </form>
      </section>
      <aside>
        <div className="number">93</div>
        <p>
          PostgreSQL only.
          <br />
          Your data. Your boundary.
        </p>
      </aside>
    </main>
  );
}

function OperatorLogin({ available, onComplete }: { available: boolean; onComplete: () => void }) {
  const [challenge, setChallenge] = useState("");
  const [method, setMethod] = useState<"email" | "password">(available ? "email" : "password");
  const [accessPath, setAccessPath] = useState<"sign-in" | "invitation">("sign-in");
  const [invitationToken, setInvitationToken] = useState("");
  const [busy, setBusy] = useState(false);
  const [magicLinkProcessing, setMagicLinkProcessing] = useState(false);
  const [message, setMessage] = useState("");
  const magicLinkStarted = useRef(false);
  const invitationLinkStarted = useRef(false);
  const onCompleteRef = useRef(onComplete);
  onCompleteRef.current = onComplete;
  useEffect(() => {
    if (magicLinkStarted.current) return;
    const params = new URLSearchParams(location.search);
    if (params.get("operator_challenge") !== "true") return;
    magicLinkStarted.current = true;
    const challengeID = params.get("challenge_id");
    const linkToken = params.get("link_token");
    params.delete("challenge_id");
    params.delete("link_token");
    params.delete("operator_challenge");
    const query = params.toString();
    history.replaceState(null, "", `${location.pathname}${query ? `?${query}` : ""}${location.hash}`);
    if (!challengeID || !linkToken) {
      setMessage(`${errorMessagePrefix}This operator magic link is incomplete. Request a new sign-in email.`);
      return;
    }
    setBusy(true);
    setMagicLinkProcessing(true);
    api.request("POST", "/v1/control/auth/email/verify", {
      challenge_id: challengeID,
      link_token: linkToken,
    }).then(() => onCompleteRef.current()).catch((error) => {
      setMessage(readError(error));
    }).finally(() => {
      setBusy(false);
      setMagicLinkProcessing(false);
    });
  }, []);
  useEffect(() => {
    if (invitationLinkStarted.current) return;
    const params = new URLSearchParams(location.search);
    if (params.get("organization_invitation") !== "true") return;
    invitationLinkStarted.current = true;
    const token = params.get("invitation_token") ?? "";
    setAccessPath("invitation");
    setInvitationToken(token);
    params.delete("organization_invitation");
    params.delete("invitation_id");
    params.delete("invitation_token");
    const query = params.toString();
    history.replaceState(null, "", `${location.pathname}${query ? `?${query}` : ""}${location.hash}`);
    if (!token) setMessage(`${errorMessagePrefix}This organization invitation link is incomplete. Ask for a new invitation.`);
  }, []);
  function selectAccessPath(path: "sign-in" | "invitation") {
    setAccessPath(path);
    setMessage("");
  }
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    const target = event.currentTarget;
    const form = new FormData(target);
    try {
      if (!challenge) {
        const value = await api.request<{ challenge_id: string }>(
          "POST",
          "/v1/control/auth/email/start",
          { email: form.get("email"), delivery: "both" },
        );
        target.reset();
        setChallenge(value.challenge_id);
        setMessage("Sign-in request accepted. Check your inbox and spam folder; the credential expires in 10 minutes.");
      } else {
        await api.request("POST", "/v1/control/auth/email/verify", {
          challenge_id: challenge,
          code: String(form.get("code") ?? "").toUpperCase(),
        });
        onComplete();
      }
    } catch (error) {
      setMessage(readError(error));
    } finally {
      setBusy(false);
    }
  }
  async function acceptInvitation(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    const form = new FormData(event.currentTarget);
    try {
      await api.request("POST", "/v1/control/organization-invitations/accept", {
        invitation_token: form.get("invitation_token"),
        display_name: form.get("display_name"),
      });
      onComplete();
    } catch (error) {
      setMessage(readError(error));
    } finally {
      setBusy(false);
    }
  }
  async function submitPassword(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    const form = new FormData(event.currentTarget);
    try {
      await api.request("POST", "/v1/control/auth/password", { email: form.get("email"), password: form.get("password") });
      onComplete();
    } catch (error) {
      setMessage(readError(error));
    } finally {
      setBusy(false);
    }
  }
  return (
    <main className="setup">
      <section>
        <p className="eyebrow">{accessPath === "sign-in" ? "OPERATOR ACCESS" : "ORGANIZATION INVITATION"}</p>
        <h1>{accessPath === "sign-in" ? "Return to control." : "Join your organization."}</h1>
        <p>{accessPath === "sign-in" ? method === "email" ? "We will send a one-time code and sign-in link to your operator email." : "Use the password configured for your operator account." : "Use the one-time credential from your invitation to create or update your operator account."}</p>
        {message && <Toast message={message} onDismiss={() => setMessage("")} />}
        {magicLinkProcessing ? <div className="magic-link-progress" role="status"><div className="mini-loader" /><div><strong>Completing sign-in</strong><span>Verifying your one-time operator link.</span></div></div> : <>
        {accessPath === "sign-in" ? <>
        {method === "email" && available && <form className="operator-access-form" onSubmit={submit}>
          {challenge ? (
            <label>
              Eight-character code
              <input
                required
                name="code"
                minLength={8}
                maxLength={8}
                autoComplete="one-time-code"
                autoFocus
              />
            </label>
          ) : (
            <label>
              Operator email
              <input required name="email" type="email" autoComplete="email" />
            </label>
          )}
          <button disabled={busy}>
            {busy
              ? "Working..."
              : challenge
                ? "Verify and continue"
                : "Send sign-in code"}
          </button>
        </form>}
        {!available && <p className="error">Operator email login is unavailable because no installation SMTP provider is configured. Use a configured password, restore an existing session, or run <code>platform93 recover</code>.</p>}
        {method === "password" && <form className="operator-access-form" onSubmit={submitPassword}>
          <label>Operator email<input required name="email" type="email" autoComplete="username" /></label>
          <label>Password<input required name="password" type="password" minLength={12} autoComplete="current-password" /></label>
          <button disabled={busy}>{busy ? "Working..." : "Sign in with password"}</button>
        </form>}
        <div className="login-alternatives">
          {available && <button type="button" disabled={busy} onClick={() => setMethod(method === "email" ? "password" : "email")}>{method === "email" ? "Use password instead" : "Use an email code or link"}</button>}
          {available && <span aria-hidden="true">·</span>}
          <button type="button" disabled={busy} onClick={() => selectAccessPath("invitation")}>Accept an organization invitation</button>
        </div>
        </> : <form className="operator-access-form" onSubmit={(event) => void acceptInvitation(event)}>
          <label>
            Invitation credential
            <input required name="invitation_token" type="password" autoComplete="off" value={invitationToken} onChange={(event) => setInvitationToken(event.target.value)} />
          </label>
          <label>
            Display name
            <input name="display_name" autoComplete="name" />
          </label>
          <button disabled={busy}>{busy ? "Working..." : "Accept invitation"}</button>
          <div className="login-alternatives"><button type="button" disabled={busy} onClick={() => selectAccessPath("sign-in")}>Back to operator sign-in</button></div>
        </form>}
        </>}
      </section>
      <aside>
        <div className="number">93</div>
        <p>Operator authority stays outside application-user identity.</p>
      </aside>
    </main>
  );
}

function OperatorAccountPanel({ onClose, onLogout, onOpenSessions, setMessage }: { onClose: () => void; onLogout: () => void; onOpenSessions: () => void; setMessage: (value: string) => void }) {
  const [account, setAccount] = useState<OperatorAccount | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState("");
  useEffect(() => {
    api.request<OperatorAccount>("GET", "/v1/control/auth/me")
      .then(setAccount)
      .catch((error) => setMessage(readError(error)))
      .finally(() => setLoading(false));
  }, [setMessage]);
  async function updateProfile(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!account) return;
    setBusy("profile");
    const form = new FormData(event.currentTarget);
    const displayName = String(form.get("display_name") ?? "").trim();
    try {
      await api.request("PATCH", "/v1/control/auth/me", { display_name: displayName });
      setAccount({ ...account, display_name: displayName });
      setMessage("Operator profile updated.");
    } catch (error) { setMessage(readError(error)); }
    finally { setBusy(""); }
  }
  async function updatePassword(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!account) return;
    setBusy("password");
    const target = event.currentTarget;
    const form = new FormData(target);
    try {
      await api.request("PUT", "/v1/control/auth/password", { current_password: form.get("current_password"), new_password: form.get("new_password") });
      setAccount({ ...account, sign_in_methods: { ...account.sign_in_methods, password: true } });
      target.reset();
      setMessage(account.sign_in_methods.password ? "Operator password changed. Other sessions were revoked." : "Operator password added. Other sessions were revoked.");
    } catch (error) { setMessage(readError(error)); }
    finally { setBusy(""); }
  }
  return <div className="account-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}>
    <aside className="account-panel" role="dialog" aria-modal="true" aria-labelledby="operator-account-title">
      <header><div><p className="eyebrow">CONTROL IDENTITY</p><h2 id="operator-account-title">Operator account</h2></div><button className="outline" onClick={onClose}>Close</button></header>
      {loading ? <LoadingState label="Loading operator account" /> : account && <>
        <div className="account-identity"><strong>{account.display_name}</strong><span>{account.email}</span><small>{account.installation_role ? `Installation ${account.installation_role}` : `${account.organizations.length} organization role${account.organizations.length === 1 ? "" : "s"}`}</small></div>
        <form className="account-form" onSubmit={(event) => void updateProfile(event)}>
          <h3>Profile</h3>
          <label>Display name<input required name="display_name" maxLength={200} defaultValue={account.display_name} /></label>
          <label>Email<input disabled value={account.email} /><small>Email changes require a separately verified change flow and are not available yet.</small></label>
          <button disabled={busy !== ""}>{busy === "profile" ? "Saving..." : "Save profile"}</button>
        </form>
        <section className="sign-in-method-list"><h3>Sign-in methods</h3><div><strong>Email code</strong><span>Enabled</span></div><div><strong>Magic link</strong><span>Enabled</span></div><div><strong>Password</strong><span>{account.sign_in_methods.password ? "Configured" : "Not configured"}</span></div><p>Google, Apple, and other external identities need a dedicated operator-linking flow. Application login providers are intentionally not reused for control access.</p></section>
        <form className="account-form" onSubmit={(event) => void updatePassword(event)}>
          <h3>{account.sign_in_methods.password ? "Change password" : "Add password"}</h3>
          {account.sign_in_methods.password && <label>Current password<input required name="current_password" type="password" autoComplete="current-password" /></label>}
          <label>New password<input required name="new_password" type="password" minLength={12} maxLength={1024} autoComplete="new-password" /><small>Use at least 12 characters. Adding a first password requires an email sign-in from the last 10 minutes.</small></label>
          <button disabled={busy !== ""}>{busy === "password" ? "Saving..." : account.sign_in_methods.password ? "Change password" : "Add password"}</button>
        </form>
        <div className="account-panel-actions"><button onClick={onOpenSessions}>Manage sessions</button><button className="danger-action" onClick={onLogout}>Log out</button></div>
      </>}
    </aside>
  </div>;
}

function Workspace({
  section,
  organizations,
  applications,
  organization,
  application,
  setOrganization,
  setApplication,
  setOrganizations,
  setApplications,
  reloadBoundaries,
  setMessage,
}: {
  section: string;
  organizations: Organization[];
  applications: Application[];
  organization: Organization | null;
  application: Application | null;
  setOrganization: (v: Organization | null) => void;
  setApplication: (v: Application | null) => void;
  setOrganizations: (v: Organization[]) => void;
  setApplications: (v: Application[]) => void;
  reloadBoundaries: () => Promise<void>;
  setMessage: (v: string) => void;
}) {
  const [items, setItems] = useState<Record<string, unknown>[]>([]);
  const [loading, setLoading] = useState(false);
  const sectionResources = resources[section] ?? [];
  const [resourcePath, setResourcePath] = useState("");
  const [refresh, setRefresh] = useState(0);
  const [detail, setDetail] = useState<Record<string, unknown> | null>(null);
  const [boundaryAction, setBoundaryAction] = useState("");
  const selectedResource = sectionResources.find((item) => item.path === resourcePath) ?? sectionResources[0];
  useEffect(() => {
    if (!application) {
      setItems([]);
      return;
    }
    if (!selectedResource) {
      setItems([]);
      return;
    }
    setLoading(true);
    api
      .request<Page<Record<string, unknown>>>(
        "GET",
        `/v1/control/applications/${application.id}/${selectedResource.path}`,
      )
      .then((value) => setItems(value.items))
      .catch((error) => setMessage(readError(error)))
      .finally(() => setLoading(false));
  }, [application, selectedResource, refresh, setMessage]);
  async function inspect(item: Record<string, unknown>) {
    if (!selectedResource || !application) return;
    const path = resourceDetailPath(selectedResource.path, String(item.id ?? ""));
    if (!path) return;
    try {
      const value = await api.request<Record<string, unknown>>("GET", `/v1/control/applications/${application.id}/${path}`);
      setDetail(value);
      const query = new URLSearchParams(location.search);
      query.set("resource", selectedResource.path);
      query.set("id", String(item.id));
      history.replaceState(null, "", `${location.pathname}?${query}`);
    } catch (error) { setMessage(readError(error)); }
  }
  function closeDetail() {
    setDetail(null);
    history.replaceState(null, "", location.pathname);
  }
  async function setOrganizationRetirement(org: Organization, restore: boolean) {
    const actionKey = `${restore ? "restore" : "archive"}-${org.id}`;
    setBoundaryAction(actionKey);
    try {
      await api.request(restore ? "POST" : "DELETE", `/v1/control/organizations/${org.id}${restore ? "/restore" : ""}`);
      setOrganizations(organizations.map((item) => item.id === org.id ? {
        ...item,
        retired_at: restore ? null : new Date().toISOString(),
        version: Number(item.version ?? 1) + 1,
      } : item));
      setMessage(restore ? "Organization restored. Restore applications independently." : "Organization retired and application credentials revoked.");
    } catch (error) { setMessage(readError(error)); }
    finally { setBoundaryAction(""); }
  }
  if (!application && ["Operators", "Policy", "Email", "Management API", "Sessions"].includes(section))
    return <ControlPlane organization={organization} section={section} setMessage={setMessage} />;
  if (!application && section === "Providers")
    return <ProviderSettings basePath={organization ? `/v1/control/organizations/${organization.id}` : "/v1/control/installation"} scope={organization ? "organization" : "installation"} setMessage={setMessage} />;
  if (!application)
    return (
      <>
        <PageSummary
          summary={organization ? <>Applications in <strong>{organization.name}</strong></> : <>Organizations and applications</>}
          help={organization
            ? "Applications are independent identity and integration boundaries inside this organization. Select one to manage its users, billing, and delivery."
            : "Organizations group applications and control-plane access. Applications are the identity, billing, entitlement, and delivery boundary used by other apps."}
        />
        {organization ? (
          <ApplicationPicker
            organization={organization}
            setApplication={setApplication}
            setMessage={setMessage}
            reloadBoundaries={reloadBoundaries}
            onOrganizationChanged={(updated) => {
              setOrganization(updated);
              setOrganizations(organizations.map((item) => item.id === updated.id ? updated : item));
            }}
          />
        ) : organizations.length === 0 ? (
          <Onboarding
            onCreated={(org, env) => {
              setOrganizations([org]);
              setApplications([{ ...env, organization_id: org.id }]);
              setOrganization(org);
              setApplication({ ...env, organization_id: org.id });
              void reloadBoundaries();
            }}
            setMessage={setMessage}
          />
        ) : (
          <>
            <OrganizationCreator setMessage={setMessage} onCreated={(created) => {
              const owned = { ...created, role: created.role || "owner" };
              setOrganizations([...organizations, owned]);
              setOrganization(owned);
              setApplication(null);
              void reloadBoundaries();
            }} />
            <section className="cards">
              {organizations.map((org) => (
                <article key={org.id}>
                  <span>{org.retired_at ? "retired" : org.role}</span>
                  <h3>{org.name}</h3>
                  <p>{org.slug}</p>
                  <ActionGroup label={`${org.name} organization actions`} className="card-actions">
                    {!org.retired_at && <IconButton label={`Open ${org.name}`} icon="open" disabled={boundaryAction !== ""} onClick={() => setOrganization(org)} />}
                    {org.retired_at
                      ? <IconButton label={`Restore ${org.name}`} icon="restore" loading={boundaryAction === `restore-${org.id}`} disabled={boundaryAction !== ""} onClick={() => void setOrganizationRetirement(org, true)} />
                      : <IconButton label={`Retire ${org.name}`} icon="archive" tone="danger" loading={boundaryAction === `archive-${org.id}`} disabled={boundaryAction !== ""} onClick={() => void setOrganizationRetirement(org, false)} />}
                  </ActionGroup>
                </article>
              ))}
            </section>
          </>
        )}
      </>
    );
  if (section === "Overview") return <Dashboard application={application} />;
  if (section === "Settings") return <ApplicationSettings application={application} setMessage={setMessage} onChanged={(updated) => {
    setApplication(updated);
    setApplications(applications.map((item) => item.id === updated.id ? updated : item));
    void reloadBoundaries();
  }} />;
  if (section === "Providers") return <ProviderSettings basePath={`/v1/control/applications/${application.id}`} scope="application" setMessage={setMessage} />;
  if (section === "Storage") return <StorageObjectManager basePath={`/v1/control/applications/${application.id}`} allowUploads setMessage={setMessage} />;
  if (!selectedResource) return <div className="empty">No resources are configured for this module.</div>;
  if (loading)
    return <LoadingState label={`Loading ${section.toLowerCase()}`} />;
  return (
    <>
      <div className="resource-tabs">
        {sectionResources.map((resource) => (
          <button className={resource.path === selectedResource.path ? "active" : ""} key={resource.path} onClick={() => setResourcePath(resource.path)}>
            {resource.label}
          </button>
        ))}
      </div>
      <div className="resource-view" key={selectedResource.path}>
        {section === "Audit" && <AuditExport application={application} setMessage={setMessage} />}
        {selectedResource.path === "event-types" && <EventTypeCreator application={application} setMessage={setMessage} onCreated={() => setRefresh((value) => value + 1)} />}
        {selectedResource.path === "webhooks" && <WebhookCreator application={application} setMessage={setMessage} onCreated={() => setRefresh((value) => value + 1)} />}
        {selectedResource.path === "notification-templates" && <NotificationTemplateCreator application={application} setMessage={setMessage} onCreated={() => setRefresh((value) => value + 1)} />}
        {selectedResource.create && <CreateResource application={application} resource={selectedResource} setMessage={setMessage} onCreated={() => setRefresh((value) => value + 1)} />}
        <section className="table">
          <div className="table-head"><span>{selectedResource.label}</span><div><span>{items.length} records</span><IconButton label={`Refresh ${selectedResource.label.toLowerCase()}`} icon="refresh" loading={loading} onClick={() => setRefresh((value) => value + 1)} /></div></div>
          {items.length === 0 ? <div className="table-empty">No records yet.</div> : items.map((item, index) => (
            <ResourceRow key={String(item.id ?? index)} item={item} resource={selectedResource.path} application={application} setMessage={setMessage} onInspect={() => inspect(item)} onChanged={() => setRefresh((value) => value + 1)} />
          ))}
        </section>
        {detail && <DetailPanel detail={detail} resource={selectedResource.path} application={application} setMessage={setMessage} onClose={closeDetail} onChanged={() => { setRefresh((value) => value + 1); void inspect(detail); }} />}
      </div>
    </>
  );
}

function CreateResource({ application, resource, setMessage, onCreated }: { application: Application; resource: Resource; setMessage: (value: string) => void; onCreated: () => void }) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [fieldValues, setFieldValues] = useState<Record<string, string>>({});
  if (!resource.create) return null;
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    const target = event.currentTarget;
    const form = new FormData(target);
    const body: Record<string, unknown> = {};
    for (const field of resource.create!.fields) {
      const raw = form.get(field.name);
      if (field.type === "checkbox") body[field.name] = raw === "on";
      else if (field.type === "number") body[field.name] = raw ? Number(raw) : undefined;
      else if (["permissions", "redirect_uris", "allowed_grants", "allowed_scopes", "role_keys", "event_filters"].includes(field.name))
        body[field.name] = String(raw ?? "").split(",").map((value) => value.trim()).filter(Boolean);
      else if (raw !== "") body[field.name] = raw;
    }
    try {
      const result = await api.request<Record<string, unknown>>("POST", `/v1/control/applications/${application.id}/${resource.path}`, body, { idempotencyKey: crypto.randomUUID() });
      const returnedSecret = result?.secret ?? result?.client_secret ?? result?.invitation_token;
      setMessage(returnedSecret ? `Created. Store this one-time credential now: ${String(returnedSecret)}` : `${resource.create!.label} completed.`);
      target.reset();
      setFieldValues({});
      setOpen(false);
      onCreated();
    } catch (error) {
      setMessage(readError(error));
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className={`create-panel ${open ? "open" : ""}`}>
      <button className="create-toggle" onClick={() => setOpen((value) => { if (value) setFieldValues({}); return !value; })}>{open ? "Close" : resource.create.label}</button>
      {open && <form onSubmit={submit}>
        <div className="create-fields">{resource.create.fields.map((field) => {
          const visible = !field.showWhen || (fieldValues[field.showWhen.field] ?? resource.create!.fields.find((candidate) => candidate.name === field.showWhen!.field)?.options?.[0]?.value) === field.showWhen.value;
          if (!visible) return null;
          return <label key={field.name}>{field.label}
            {field.options ? <select name={field.name} required={field.required} value={fieldValues[field.name] ?? field.options[0]?.value ?? ""} onChange={(event) => setFieldValues((values) => ({ ...values, [field.name]: event.target.value }))}>{field.options.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}</select> : field.type === "textarea" ? <textarea name={field.name} required={field.required} placeholder={field.placeholder} /> : field.type === "checkbox" ? <input name={field.name} type="checkbox" defaultChecked /> : <input name={field.name} type={field.type ?? "text"} required={field.required} defaultValue={field.placeholder} />}
          </label>;
        })}</div>
        <button disabled={busy}>{busy ? "Working..." : resource.create.label}</button>
      </form>}
    </section>
  );
}

function ResourceRow({ item, resource, application, setMessage, onInspect, onChanged }: { item: Record<string, unknown>; resource: string; application: Application; setMessage: (value: string) => void; onInspect: () => Promise<void>; onChanged: () => void }) {
  const [pendingAction, setPendingAction] = useState("");
  const id = String(item.id ?? "");
  const actions: { label: string; icon?: AdminIconName; tone?: "default" | "danger" | "success"; method?: "POST" | "DELETE"; suffix: string; body?: unknown }[] = [];
  if (resource === "users") actions.push(
    { label: "Verify organization", icon: "verify", tone: "success", suffix: `users/${id}/verify-organization`, body: {} },
    { label: item.status === "suspended" ? "Restore user" : "Suspend user", icon: item.status === "suspended" ? "restore" : "suspend", tone: item.status === "suspended" ? "default" : "danger", suffix: `users/${id}/${item.status === "suspended" ? "restore" : "suspend"}`, body: { reason: "operator action" } },
  );
  if (resource === "billing/providers") actions.push({ label: "Verify provider", icon: "verify", tone: "success", suffix: `billing/providers/${id}/verify`, body: {} }, { label: "Reconcile provider", icon: "refresh", suffix: `billing/providers/${id}/reconciliation-runs`, body: {} });
  if (resource === "billing/subscriptions" && item.status !== "canceled") actions.push({ label: "Cancel at period end", suffix: `billing/subscriptions/${id}/cancel`, body: { at_period_end: true } });
  if (resource === "local-entitlement-requests" && item.status === "pending") actions.push(
    { label: "Approve request", icon: "approve", tone: "success", suffix: `local-entitlement-requests/${id}/approve`, body: {} },
    { label: "Reject request", icon: "reject", tone: "danger", suffix: `local-entitlement-requests/${id}/reject`, body: { reason: "operator rejected" } },
  );
  if (resource === "local-entitlement-requests" && ["rejected", "canceled"].includes(String(item.status))) actions.push({ label: "Reopen request", icon: "restore", suffix: `local-entitlement-requests/${id}/reopen`, body: { reason: "operator reopened for review" } });
  if (resource === "entitlements") actions.push({ label: item.revoked_at ? "Restore entitlement" : "Revoke entitlement", icon: item.revoked_at ? "restore" : "revoke", tone: item.revoked_at ? "default" : "danger", suffix: `entitlements/${id}/${item.revoked_at ? "restore" : "revoke"}`, body: { reason: item.revoked_at ? "operator restored" : "operator revoked" } });
  if (resource === "notification-templates" && !item.inherited) actions.push({ label: item.status === "draft" ? "Publish template" : "Archive template", icon: item.status === "draft" ? "publish" : "archive", tone: item.status === "draft" ? "success" : "danger", suffix: `notification-templates/${id}/${item.status === "draft" ? "publish" : "archive"}`, body: {} });
  if (resource === "notifications" && ["failed", "dead"].includes(String(item.status))) actions.push({ label: "Retry notification", icon: "refresh", suffix: `notifications/${id}/retry`, body: {} });
  if (resource === "webhook-deliveries" && item.status !== "delivered") actions.push({ label: "Replay webhook", icon: "replay", suffix: `webhook-deliveries/${id}/replay`, body: {} });
  if (resource === "billing/provider-events") actions.push({ label: "Replay provider event", icon: "replay", suffix: `billing/provider-events/${id}/replay`, body: {} });
  if (resource === "sender-identities" && !item.is_default) actions.push({ label: "Make default sender", icon: "star", suffix: `sender-identities/${id}/default`, body: {} });
  if (resource === "roles" && !item.built_in) actions.push({ label: "Delete role", icon: "trash", tone: "danger", method: "DELETE", suffix: `roles/${id}` });
  if (resource === "role-assignments") actions.push({ label: "Remove role assignment", icon: "remove", tone: "danger", method: "DELETE", suffix: `role-assignments/${id}` });
  if (resource === "workspaces") actions.push({ label: "Retire workspace", icon: "archive", tone: "danger", method: "DELETE", suffix: `workspaces/${id}` });
  if (resource === "webhooks" && !item.disabled_at) actions.push(
    { label: "Send test webhook", icon: "send", suffix: `webhooks/${id}/test`, body: {} },
    { label: "Rotate webhook secret", icon: "key-rotate", suffix: `webhooks/${id}/rotate-secret`, body: {} },
    { label: "Disable webhook", icon: "disable", tone: "danger", method: "DELETE", suffix: `webhooks/${id}` },
  );
  if (resource === "event-types" && item.source === "application" && item.status === "active") actions.push({ label: "Archive event type", icon: "archive", tone: "danger", method: "DELETE", suffix: `event-types/${id}` });
  async function act(action: (typeof actions)[number]) {
    setPendingAction(action.label);
    try {
      const result = await api.request<Record<string, unknown>>(action.method ?? "POST", `/v1/control/applications/${application.id}/${action.suffix}`, action.body ?? {}, { idempotencyKey: crypto.randomUUID() });
      const returnedSecret = result?.secret;
      setMessage(returnedSecret ? `Store this one-time webhook secret now: ${String(returnedSecret)}` : result ? JSON.stringify(result) : `${action.label} completed.`);
      onChanged();
    } catch (error) { setMessage(readError(error)); }
    finally { setPendingAction(""); }
  }
  async function inspect() {
    setPendingAction("Details");
    try { await onInspect(); }
    finally { setPendingAction(""); }
  }
  const title = resource === "notification-templates"
    ? `${String(item.key)} · ${String(item.locale ?? "en")}`
    : String(item.name ?? item.email ?? item.key ?? item.event_type ?? item.provider_event_id ?? item.recipient ?? item.id);
  const detail = resource === "notification-templates"
    ? `${String(item.status ?? "")} · ${String(item.scope ?? "application")}${item.inherited ? " · inherited" : ""}`
    : String(item.status ?? item.scope ?? item.type ?? item.currency ?? "");
  return <article><div><strong>{title}</strong><small>{detail}</small></div><div className="row-actions">{resourceDetailPath(resource, id) && <IconButton label="Details" icon="details" loading={pendingAction === "Details"} disabled={pendingAction !== ""} onClick={() => void inspect()} />}{actions.map((action) => action.icon
    ? <IconButton key={action.label} label={action.label} icon={action.icon} tone={action.tone} loading={pendingAction === action.label} disabled={pendingAction !== ""} onClick={() => void act(action)} />
    : <button disabled={pendingAction !== ""} key={action.label} onClick={() => void act(action)}>{pendingAction === action.label ? `${action.label}...` : action.label}</button>)}<code>{id}</code></div></article>;
}

function LoadingState({ label }: { label: string }) {
  return <div className="empty loading-state"><span className="mini-loader" /><strong>{label}</strong><small>Waiting for the control plane</small></div>;
}

function AdminIcon({ name }: { name: AdminIconName }) {
  const paths: Record<AdminIconName, ReactNode> = {
    open: <><path d="M5 12h14" /><path d="m13 6 6 6-6 6" /></>,
    archive: <><rect x="3" y="4" width="18" height="4" rx="1" /><path d="M5 8v11h14V8" /><path d="M9 12h6" /></>,
    restore: <><path d="M3 12a9 9 0 1 0 3-6.7L3 8" /><path d="M3 3v5h5" /></>,
    details: <><path d="M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6S2 12 2 12Z" /><circle cx="12" cy="12" r="2.5" /></>,
    refresh: <><path d="M20 7v5h-5" /><path d="M4 17v-5h5" /><path d="M6.1 9A7 7 0 0 1 18.7 7L20 12M4 12l1.3 5A7 7 0 0 0 17.9 15" /></>,
    replay: <><path d="M4 10a8 8 0 1 1 2.3 7.7" /><path d="M4 4v6h6" /><path d="m10 9 6 3-6 3Z" /></>,
    trash: <><path d="M4 7h16" /><path d="m9 7 1-3h4l1 3" /><path d="m6 7 1 13h10l1-13" /><path d="M10 11v5M14 11v5" /></>,
    remove: <><circle cx="12" cy="12" r="9" /><path d="M8 12h8" /></>,
    revoke: <><path d="M12 3 5 6v5c0 4.6 2.8 8.2 7 10 4.2-1.8 7-5.4 7-10V6l-7-3Z" /><path d="m9 9 6 6m0-6-6 6" /></>,
    disable: <><path d="M12 2v10" /><path d="M6.3 5.7a8 8 0 1 0 11.4 0" /></>,
    suspend: <><circle cx="12" cy="12" r="9" /><path d="M10 9v6M14 9v6" /></>,
    approve: <><circle cx="12" cy="12" r="9" /><path d="m8 12 2.7 2.7L16.5 9" /></>,
    reject: <><circle cx="12" cy="12" r="9" /><path d="m9 9 6 6m0-6-6 6" /></>,
    verify: <><path d="m12 3 2 2.1 2.9-.1.1 2.9L19 10l-2 2.1-.1 2.9-2.9-.1-2 2.1-2-2.1-2.9.1-.1-2.9L5 10l2-2.1.1-2.9 2.9.1L12 3Z" /><path d="m9.2 10.2 1.8 1.9 3.8-4" /></>,
    send: <><path d="m3 11 18-8-8 18-2-8-8-2Z" /><path d="m11 13 4-4" /></>,
    "key-rotate": <><circle cx="8" cy="15" r="3" /><path d="m10.2 12.8 7.3-7.3 2 2-1.5 1.5 1.5 1.5-2 2-1.5-1.5-3.8 3.8" /><path d="M4 6a8 8 0 0 1 9-2" /><path d="m12 2 2 2-2 2" /></>,
    star: <path d="m12 3 2.7 5.5 6.1.9-4.4 4.3 1 6.1-5.4-2.9-5.4 2.9 1-6.1-4.4-4.3 6.1-.9L12 3Z" />,
    publish: <><path d="M12 16V4" /><path d="m7 9 5-5 5 5" /><path d="M5 14v6h14v-6" /></>,
    edit: <><path d="m4 20 4.5-1 10-10-3.5-3.5-10 10L4 20Z" /><path d="m13.5 7 3.5 3.5" /></>,
    download: <><path d="M12 4v11" /><path d="m7 11 5 5 5-5" /><path d="M5 20h14" /></>,
  };
  return <svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">{paths[name]}</svg>;
}

function IconButton({ label, icon, loading = false, tone = "default", disabled = false, onClick }: {
  label: string;
  icon: AdminIconName;
  loading?: boolean;
  tone?: "default" | "danger" | "success";
  disabled?: boolean;
  onClick: () => void;
}) {
  return <button
    type="button"
    className={`icon-button ${tone === "default" ? "" : tone}`.trim()}
    aria-label={loading ? `${label} in progress` : label}
    aria-busy={loading}
    data-tooltip={label}
    title={label}
    disabled={disabled || loading}
    onClick={onClick}
  >{loading ? <span className="icon-button-spinner" aria-hidden="true" /> : <AdminIcon name={icon} />}</button>;
}

function ActionGroup({ label, className = "", children }: { label: string; className?: string; children: ReactNode }) {
  return <div className={`action-group ${className}`.trim()} role="group" aria-label={label}>{children}</div>;
}

function PageSummary({ summary, help, action }: { summary: ReactNode; help: ReactNode; action?: ReactNode }) {
  return <section className="page-summary">
    <div>{summary}</div>
    {action}
    <details className="page-help">
      <summary aria-label="About this page">?</summary>
      <div>{help}</div>
    </details>
  </section>;
}

function resourceDetailPath(resource: string, id: string) {
  const supported = new Set([
    "users", "roles", "workspaces", "products", "entitlements", "local-entitlement-requests", "event-types", "events", "audit-logs",
    "notifications", "notification-templates", "notification-providers", "webhooks", "webhook-deliveries", "billing/providers",
    "billing/subscriptions", "billing/invoices", "billing/payments", "billing/refunds",
    "billing/disputes", "billing/reconciliation-runs",
  ]);
  return id && supported.has(resource) ? `${resource}/${id}` : null;
}

function DetailPanel({ detail, resource, application, setMessage, onClose, onChanged }: {
  detail: Record<string, unknown>;
  resource: string;
  application: Application;
  setMessage: (value: string) => void;
  onClose: () => void;
  onChanged: () => void;
}) {
  const id = String(detail.id ?? "");
  return <div className="detail-backdrop" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && onClose()}><section className={`detail-panel ${resource === "notification-templates" ? "template-detail-panel" : ""}`} role="dialog" aria-modal="true" aria-label={`${resource} detail`}>
    <header><div><p className="eyebrow">RESOURCE DETAIL</p><h2>{String(detail.name ?? detail.email ?? detail.key ?? detail.type ?? id)}</h2></div><button className="outline" onClick={onClose}>Close</button></header>
    {resource === "products" && <ProductEntitlementEditor key={String(detail.version ?? 1)} product={detail} application={application} setMessage={setMessage} onChanged={onChanged} />}
    {resource === "products" && <PriceCreator productID={id} application={application} setMessage={setMessage} onChanged={onChanged} />}
    {resource === "roles" && <RoleEditor role={detail} application={application} setMessage={setMessage} onChanged={onChanged} />}
    {resource === "workspaces" && <WorkspaceMembers workspaceID={id} application={application} setMessage={setMessage} />}
    {resource === "users" && <UserAdministration user={detail} application={application} setMessage={setMessage} onChanged={onChanged} />}
    {resource === "notification-providers" && <ProviderTest providerID={id} application={application} setMessage={setMessage} />}
    {resource === "notification-templates" && <NotificationTemplateEditor template={detail} application={application} setMessage={setMessage} onChanged={onChanged} />}
    {resource === "webhooks" && <WebhookEditor webhook={detail} application={application} setMessage={setMessage} onChanged={onChanged} />}
    {resource === "event-types" && <EventTypeEditor definition={detail} application={application} setMessage={setMessage} onChanged={onChanged} />}
    {resource !== "notification-templates" && <pre>{JSON.stringify(detail, null, 2)}</pre>}
  </section></div>;
}

function RoleEditor({ role, application, setMessage, onChanged }: { role: Record<string, unknown>; application: Application; setMessage: (value: string) => void; onChanged: () => void }) {
  if (role.built_in) return <p>Built-in roles are immutable.</p>;
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      await api.request("PATCH", `/v1/control/applications/${application.id}/roles/${String(role.id)}`, {
        name: form.get("name"),
        permissions: String(form.get("permissions") ?? "").split(",").map((value) => value.trim()).filter(Boolean),
      });
      setMessage("Role updated.");
      onChanged();
    } catch (error) { setMessage(readError(error)); }
  }
  return <form className="detail-form" onSubmit={(event) => void submit(event)}><strong>Update custom role</strong><label><span>Name</span><input required name="name" defaultValue={String(role.name ?? "")} /></label><label className="full-field"><span>Permissions, comma separated</span><textarea required name="permissions" defaultValue={Array.isArray(role.permissions) ? role.permissions.join(", ") : ""} /></label><button>Update role</button></form>;
}

function useEventTypes(application: Application, setMessage: (value: string) => void) {
  const [definitions, setDefinitions] = useState<EventTypeDefinition[]>([]);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    api.request<Page<EventTypeDefinition>>("GET", `/v1/control/applications/${application.id}/event-types`)
      .then((value) => setDefinitions(value.items))
      .catch((error) => setMessage(readError(error)))
      .finally(() => setLoading(false));
  }, [application.id, setMessage]);
  return { definitions, loading };
}

function EventTypeCreator({ application, setMessage, onCreated }: { application: Application; setMessage: (value: string) => void; onCreated: () => void }) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const target = event.currentTarget;
    const form = new FormData(target);
    setBusy(true);
    try {
      const dataSchema = JSON.parse(String(form.get("data_schema") || "{}"));
      const exampleData = JSON.parse(String(form.get("example_data") || "{}"));
      if (!dataSchema || Array.isArray(dataSchema) || typeof dataSchema !== "object") throw new Error("The data schema must be a JSON object.");
      if (!exampleData || Array.isArray(exampleData) || typeof exampleData !== "object") throw new Error("The example data must be a JSON object.");
      await api.request("POST", `/v1/control/applications/${application.id}/event-types`, {
        name: String(form.get("name") ?? "").trim(),
        description: String(form.get("description") ?? "").trim(),
        schema_version: String(form.get("schema_version") || "1.0"),
        data_schema: dataSchema,
        example_subject: String(form.get("example_subject") ?? "").trim(),
        example_data: exampleData,
      });
      target.reset();
      setOpen(false);
      setMessage("Custom event type registered. Applications can publish it after receiving events:publish permission.");
      onCreated();
    } catch (error) { setMessage(readError(error)); }
    finally { setBusy(false); }
  }
  return <section className={`create-panel ${open ? "open" : ""}`}><button className="create-toggle" onClick={() => setOpen((value) => !value)}>{open ? "Close" : "Register custom event"}</button>{open && <form onSubmit={(event) => void submit(event)}><p>Declare and demonstrate the contract before applications publish it or webhooks subscribe to it. Major versions are breaking; minor versions are additive.</p><div className="create-fields"><label>Event type<input required name="name" placeholder="vehicle.created" pattern="[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)+" /></label><label>Schema version<input required name="schema_version" defaultValue="1.0" pattern="[1-9][0-9]*\.[0-9]+" /></label><label>Description<textarea name="description" placeholder="A vehicle was created." /></label><label>Example subject<input required name="example_subject" placeholder="vehicle/veh_123" /></label><label className="full-field">Data schema (JSON)<textarea required name="data_schema" defaultValue={'{\n  "type": "object",\n  "properties": {\n    "vehicle_id": { "type": "string" }\n  },\n  "required": ["vehicle_id"],\n  "additionalProperties": false\n}'} /></label><label className="full-field">Example data (JSON)<textarea required name="example_data" defaultValue={'{\n  "vehicle_id": "veh_123"\n}'} /></label></div><button disabled={busy}>{busy ? "Registering..." : "Register custom event"}</button></form>}</section>;
}

function EventTypeEditor({ definition, application, setMessage, onChanged }: { definition: Record<string, unknown>; application: Application; setMessage: (value: string) => void; onChanged: () => void }) {
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      const dataSchema = JSON.parse(String(form.get("data_schema") || "{}"));
      const exampleData = JSON.parse(String(form.get("example_data") || "{}"));
      if (!dataSchema || Array.isArray(dataSchema) || typeof dataSchema !== "object") throw new Error("The data schema must be a JSON object.");
      if (!exampleData || Array.isArray(exampleData) || typeof exampleData !== "object") throw new Error("The example data must be a JSON object.");
      const version = Number(definition.version ?? 1);
      await api.request("PATCH", `/v1/control/applications/${application.id}/event-types/${String(definition.id)}`, {
        description: String(form.get("description") ?? "").trim(), schema_version: form.get("schema_version"),
        data_schema: dataSchema, example_subject: String(form.get("example_subject") ?? "").trim(), example_data: exampleData, status: form.get("status"),
      }, { headers: { "If-Match": `"v${version.toString(16)}"` } });
      setMessage("Custom event type updated.");
      onChanged();
    } catch (error) { setMessage(readError(error)); }
  }
  async function copyExample() {
    try {
      await navigator.clipboard.writeText(JSON.stringify(definition.example_event ?? {}, null, 2));
      setMessage("Webhook example copied.");
    } catch { setMessage(`${errorMessagePrefix}The webhook example could not be copied.`); }
  }
  const contract = <section className="event-contract-view"><header><div><span>{String(definition.source ?? "application")} contract</span><h3>{String(definition.name)}</h3><p>{String(definition.description || "No description")}</p></div><div className="contract-version"><strong>v{String(definition.schema_version ?? "1.0")}</strong><small>Major breaking · minor additive</small></div></header><div className="contract-columns"><div><div className="contract-code-head"><strong>Webhook example</strong><button type="button" className="outline" onClick={() => void copyExample()}>Copy example</button></div><pre>{JSON.stringify(definition.example_event ?? {}, null, 2)}</pre></div><div><strong>Data JSON Schema</strong><pre>{JSON.stringify(definition.data_schema ?? {}, null, 2)}</pre></div></div></section>;
  if (definition.source === "platform93") return contract;
  return <>{contract}<form className="detail-form" onSubmit={(event) => void submit(event)}><strong>Update custom event contract</strong><label><span>Description</span><textarea name="description" defaultValue={String(definition.description ?? "")} /></label><label><span>Schema version</span><input required name="schema_version" pattern="[1-9][0-9]*\.[0-9]+" defaultValue={String(definition.schema_version ?? "1.0")} /><small>Change this whenever the schema changes. Increment the major number for breaking changes.</small></label><label><span>Example subject</span><input required name="example_subject" defaultValue={String(definition.example_subject ?? "")} /></label><label><span>Status</span><select name="status" defaultValue={String(definition.status ?? "active")}><option value="active">Active</option><option value="archived">Archived</option></select></label><label className="full-field"><span>Data schema (JSON)</span><textarea required name="data_schema" defaultValue={JSON.stringify(definition.data_schema ?? {}, null, 2)} /></label><label className="full-field"><span>Example data (JSON)</span><textarea required name="example_data" defaultValue={JSON.stringify(definition.example_data ?? {}, null, 2)} /></label><button>Update event contract</button></form></>;
}

function EventFilterSelector({ definitions, initial = [] }: { definitions: EventTypeDefinition[]; initial?: string[] }) {
  const [allEvents, setAllEvents] = useState(initial.length === 0);
  return <fieldset className="event-filter-selector"><legend>Subscribed event types</legend><label className="event-filter-all"><input type="checkbox" checked={allEvents} onChange={(event) => setAllEvents(event.target.checked)} /> Subscribe to every active event type</label><p>Leave “every event” selected for a catch-all endpoint, or choose exact event contracts below.</p><div>{definitions.filter((definition) => definition.status === "active").map((definition) => <label key={definition.id}><input disabled={allEvents} name="event_filters" type="checkbox" value={definition.name} defaultChecked={!allEvents && initial.includes(definition.name)} /><span><strong>{definition.name} · v{definition.schema_version}</strong><small>{definition.description || `${definition.source} event`} · {definition.source} · {definition.event_count ?? 0} observed</small></span></label>)}</div></fieldset>;
}

function WebhookCreator({ application, setMessage, onCreated }: { application: Application; setMessage: (value: string) => void; onCreated: () => void }) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const { definitions, loading } = useEventTypes(application, setMessage);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const target = event.currentTarget;
    const form = new FormData(target);
    setBusy(true);
    try {
      const result = await api.request<Record<string, unknown>>("POST", `/v1/control/applications/${application.id}/webhooks`, {
        uri: form.get("uri"), event_filters: form.getAll("event_filters").map(String),
      });
      target.reset();
      setOpen(false);
      setMessage(`Webhook created. Store this one-time secret now: ${String(result.secret)}`);
      onCreated();
    } catch (error) { setMessage(readError(error)); }
    finally { setBusy(false); }
  }
  return <section className={`create-panel ${open ? "open" : ""}`}><button className="create-toggle" onClick={() => setOpen((value) => !value)}>{open ? "Close" : "Create webhook"}</button>{open && <form onSubmit={(event) => void submit(event)}><div className="create-fields"><label>HTTPS endpoint<input required name="uri" type="url" placeholder="https://example.com/webhooks/platform93" /></label></div>{loading ? <LoadingState label="Loading event types" /> : <EventFilterSelector definitions={definitions} />}<button disabled={busy || loading}>{busy ? "Creating..." : "Create webhook"}</button></form>}</section>;
}

function WebhookEditor({ webhook, application, setMessage, onChanged }: { webhook: Record<string, unknown>; application: Application; setMessage: (value: string) => void; onChanged: () => void }) {
  const { definitions, loading } = useEventTypes(application, setMessage);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      await api.request("PATCH", `/v1/control/applications/${application.id}/webhooks/${String(webhook.id)}`, {
        uri: form.get("uri"),
        event_filters: form.getAll("event_filters").map(String),
        enabled: form.get("enabled") === "on",
      });
      setMessage("Webhook endpoint updated.");
      onChanged();
    } catch (error) { setMessage(readError(error)); }
  }
  return <form className="detail-form" onSubmit={(event) => void submit(event)}><strong>Update webhook endpoint</strong><label><span>Endpoint URL</span><input required name="uri" type="url" defaultValue={String(webhook.uri ?? "")} /></label><label className="checkbox-field"><input name="enabled" type="checkbox" defaultChecked={!webhook.disabled_at} /> Enabled</label><div className="full-field">{loading ? <LoadingState label="Loading event types" /> : <EventFilterSelector definitions={definitions} initial={Array.isArray(webhook.event_filters) ? webhook.event_filters.map(String) : []} />}</div><button disabled={loading}>Update webhook</button></form>;
}

function WorkspaceMembers({ workspaceID, application, setMessage }: { workspaceID: string; application: Application; setMessage: (value: string) => void }) {
  const [members, setMembers] = useState<Record<string, unknown>[]>([]);
  const [refresh, setRefresh] = useState(0);
  useEffect(() => {
    api.request<Page<Record<string, unknown>>>("GET", `/v1/control/applications/${application.id}/workspaces/${workspaceID}/members`)
      .then((value) => setMembers(value.items)).catch((error) => setMessage(readError(error)));
  }, [application.id, workspaceID, refresh, setMessage]);
  async function replace(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const target = event.currentTarget;
    const form = new FormData(target);
    try {
      await api.request("PUT", `/v1/control/applications/${application.id}/workspaces/${workspaceID}/members/${String(form.get("user_id"))}`, { role_keys: String(form.get("role_keys") ?? "").split(",").map((value) => value.trim()).filter(Boolean) });
      target.reset();
      setMessage("Workspace member roles updated.");
      setRefresh((value) => value + 1);
    } catch (error) { setMessage(readError(error)); }
  }
  async function remove(userID: string) {
    try {
      await api.request("DELETE", `/v1/control/applications/${application.id}/workspaces/${workspaceID}/members/${userID}`);
      setMessage("Workspace member removed.");
      setRefresh((value) => value + 1);
    } catch (error) { setMessage(readError(error)); }
  }
  async function transfer(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      await api.request("POST", `/v1/control/applications/${application.id}/workspaces/${workspaceID}/owner-transfer`, { new_owner_user_id: form.get("new_owner_user_id"), previous_owner_disposition: form.get("previous_owner_disposition") });
      setMessage("Workspace ownership transferred without changing its billing or entitlements.");
      setRefresh((value) => value + 1);
    } catch (error) { setMessage(readError(error)); }
  }
  return <><form className="detail-form" onSubmit={(event) => void replace(event)}><strong>Add or replace workspace member roles</strong><label><span>User ID</span><input required name="user_id" /></label><label><span>Role keys, comma separated</span><input required name="role_keys" placeholder="e.g. workspace_member" /></label><button>Apply roles</button></form><form className="detail-form" onSubmit={(event) => void transfer(event)}><strong>Recover workspace ownership</strong><label><span>New owner user ID</span><input required name="new_owner_user_id" /></label><label><span>Previous owner</span><select name="previous_owner_disposition" defaultValue="member"><option value="member">Keep previous owner as member</option><option value="remove">Remove previous owner</option></select></label><button>Transfer ownership</button></form><ControlTable title="Workspace members" items={members} renderActions={(item) => item.owner ? null : <button onClick={() => void remove(String(item.user_id))}>Remove</button>} /></>;
}

function UserAdministration({ user, application, setMessage, onChanged }: { user: Record<string, unknown>; application: Application; setMessage: (value: string) => void; onChanged: () => void }) {
  const userID = String(user.id);
  const [sessions, setSessions] = useState<Record<string, unknown>[]>([]);
  const [addresses, setAddresses] = useState<Record<string, unknown>[]>([]);
  const [refresh, setRefresh] = useState(0);
  useEffect(() => {
    Promise.all([
      api.request<Page<Record<string, unknown>>>("GET", `/v1/control/applications/${application.id}/users/${userID}/sessions`),
      api.request<Page<Record<string, unknown>>>("GET", `/v1/control/applications/${application.id}/users/${userID}/addresses`),
    ]).then(([sessionPage, addressPage]) => { setSessions(sessionPage.items); setAddresses(addressPage.items); })
      .catch((error) => setMessage(readError(error)));
  }, [application.id, userID, refresh, setMessage]);
  async function revokeAll() {
    try {
      await api.request("POST", `/v1/control/applications/${application.id}/users/${userID}/sessions/revoke`, { reason: "operator revoked all user sessions" });
      setMessage("All sessions for this user were revoked.");
      setRefresh((value) => value + 1);
    } catch (error) { setMessage(readError(error)); }
  }
  async function updateLocale(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const locale = String(new FormData(event.currentTarget).get("locale") ?? "").trim();
    try {
      const version = Number(user.version ?? 1);
      await api.request("PATCH", `/v1/control/applications/${application.id}/users/${userID}`, { locale }, { headers: { "If-Match": `"v${version.toString(16)}"` } });
      setMessage(locale ? `User locale set to ${locale}. Future emails will prefer this localization.` : "User locale preference cleared. Future emails will use template fallback order.");
      onChanged();
    } catch (error) { setMessage(readError(error)); }
  }
  return <><form className="detail-form user-locale-form" onSubmit={(event) => void updateLocale(event)}><strong>Email localization</strong><p className="full-field">Use a BCP 47 language tag such as <code>de</code>, <code>de-CH</code>, or <code>en-GB</code>. Leave empty to use template fallback order.</p><label className="full-field"><span>Preferred locale</span><input name="locale" defaultValue={String(user.locale ?? "")} placeholder="de-CH" maxLength={35} /></label><button>Save locale</button></form><div className="detail-actions"><button onClick={() => void revokeAll()}>Revoke all user sessions</button></div><ControlTable title="User sessions" items={sessions} renderActions={() => null} /><ControlTable title="Billing addresses" items={addresses} renderActions={() => null} /></>;
}

function validateFreeFormInput(format: FreeFormFormat, raw: string): string {
  if (!raw.trim() || format === "text") return "";
  if (format === "json") {
    try {
      JSON.parse(raw);
      return "";
    } catch (error) {
      return error instanceof SyntaxError ? error.message : "Enter valid JSON.";
    }
  }
  const parsed = Papa.parse<string[]>(raw, { skipEmptyLines: "greedy" });
  if (parsed.errors.length > 0) {
    const issue = parsed.errors[0]!;
    return `CSV row ${issue.row === undefined ? 1 : issue.row + 1}: ${issue.message}`;
  }
  const rows = parsed.data.filter((row) => row.length > 0);
  const expectedColumns = rows[0]?.length ?? 0;
  const inconsistentRow = rows.findIndex((row) => row.length !== expectedColumns);
  return inconsistentRow === -1 ? "" : `CSV row ${inconsistentRow + 1} has ${rows[inconsistentRow]!.length} columns; expected ${expectedColumns}.`;
}

function freeFormEditorValue(format: FreeFormFormat, value: unknown): string {
  if (value === undefined) return "";
  if (format !== "json" && typeof value === "string") return value;
  return JSON.stringify(value, null, 2) ?? "";
}

function FreeFormValueEditor({ feature, value }: { feature: CatalogFeature; value: unknown }) {
  const format = feature.free_form_format ?? "json";
  const [raw, setRaw] = useState(() => freeFormEditorValue(format, value));
  const error = validateFreeFormInput(format, raw);
  const status = !raw.trim() ? "Optional · leave empty to exclude" : error ? error : `Valid ${format === "json" ? "JSON" : format === "csv" ? "CSV" : "raw text"}`;
  return <label className={`full-field structured-value-field ${error ? "invalid" : raw.trim() ? "valid" : ""}`}>
    <span>{feature.name} ({feature.key})</span>
    <div className="structured-value-heading"><strong>{format === "text" ? "Raw text" : format.toUpperCase()}</strong><small>{status}</small></div>
    <textarea
      name={`feature:${feature.id}`}
      value={raw}
      aria-invalid={Boolean(error)}
      placeholder={format === "json" ? "Enter any valid JSON value" : format === "csv" ? "name,limit\nBasic,5" : "Enter raw text"}
      ref={(element) => element?.setCustomValidity(error)}
      onChange={(event) => setRaw(event.target.value)}
    />
  </label>;
}

function ProductEntitlementEditor({ product, application, setMessage, onChanged }: { product: Record<string, unknown>; application: Application; setMessage: (value: string) => void; onChanged: () => void }) {
  const [features, setFeatures] = useState<CatalogFeature[]>([]);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    api.request<Page<CatalogFeature>>("GET", `/v1/control/applications/${application.id}/features`)
      .then((value) => setFeatures(value.items))
      .catch((error) => setMessage(readError(error)))
      .finally(() => setLoading(false));
  }, [application.id, setMessage]);
  const assigned = new Map((Array.isArray(product.features) ? product.features : []).map((item) => {
    const value = item as Record<string, unknown>;
    return [String(value.feature_id), value];
  }));
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      const entitlementConfig = JSON.parse(String(form.get("entitlement_config") || "{}"));
      if (!entitlementConfig || Array.isArray(entitlementConfig) || typeof entitlementConfig !== "object") throw new Error("Entitlement configuration must be a JSON object.");
      const values: Record<string, unknown>[] = [];
      for (const feature of features) {
        const raw = String(form.get(`feature:${feature.id}`) ?? "");
        if (!raw.trim()) continue;
        if (feature.value_type === "boolean") values.push({ feature_id: feature.id, boolean_value: raw === "true" });
        if (feature.value_type === "quantity") {
          const quantity = Number(raw);
          if (!Number.isSafeInteger(quantity) || quantity < 0) throw new Error(`${feature.name} must be a non-negative whole number.`);
          values.push({ feature_id: feature.id, quantity_value: quantity });
        }
        if (feature.value_type === "free_form") {
          const format = feature.free_form_format ?? "json";
          const validationError = validateFreeFormInput(format, raw);
          if (validationError) throw new Error(`${feature.name}: ${validationError}`);
          values.push({ feature_id: feature.id, free_form_value: format === "json" ? JSON.parse(raw) : raw });
        }
      }
      const version = Number(product.version ?? 1);
      await api.request("PATCH", `/v1/control/applications/${application.id}/products/${String(product.id)}`, {
        entitlement_config: entitlementConfig,
        features: values,
      }, { headers: { "If-Match": `"v${version.toString(16)}"` } });
      setMessage("Product entitlement defaults updated. New prices will snapshot these values.");
      onChanged();
    } catch (error) { setMessage(readError(error)); }
  }
  return <form className="detail-form product-entitlements" onSubmit={(event) => void submit(event)}><strong>Product entitlement defaults</strong><p className="full-field">Define access by feature key, not product name. Every new immutable price snapshots these defaults; existing prices and subscriptions remain unchanged.</p><label className="full-field"><span>Entitlement configuration (JSON)</span><textarea name="entitlement_config" defaultValue={JSON.stringify(product.entitlement_config ?? {}, null, 2)} /></label>{loading ? <span>Loading feature definitions...</span> : features.length === 0 ? <p className="full-field">Create application features first, then assign their values here.</p> : features.map((feature) => { const current = assigned.get(feature.id); if (feature.value_type === "free_form") return <FreeFormValueEditor key={feature.id} feature={feature} value={current?.free_form_value} />; return <label key={feature.id}><span>{feature.name} ({feature.key})</span>{feature.value_type === "boolean" ? <select name={`feature:${feature.id}`} defaultValue={current?.boolean_value === undefined ? "" : String(current.boolean_value)}><option value="">Not included</option><option value="true">Enabled</option><option value="false">Disabled</option></select> : <input name={`feature:${feature.id}`} type="number" min="0" defaultValue={current?.quantity_value === undefined ? "" : String(current.quantity_value)} placeholder="Not included" />}</label>; })}<button>Save entitlement defaults</button></form>;
}

function PriceCreator({ productID, application, setMessage, onChanged }: { productID: string; application: Application; setMessage: (value: string) => void; onChanged: () => void }) {
  const [mode, setMode] = useState("recurring");
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const target = event.currentTarget;
    const form = new FormData(target);
    const mode = String(form.get("mode"));
    try {
      await api.request("POST", `/v1/control/applications/${application.id}/products/${productID}/prices`, {
        key: form.get("key"), mode, amount_minor: Number(form.get("amount_minor")), currency: form.get("currency"),
        currency_exponent: 2, interval_unit: mode === "recurring" ? form.get("interval_unit") : undefined,
        interval_count: mode === "recurring" ? Number(form.get("interval_count")) : undefined,
        validity_seconds: mode === "local" ? Number(form.get("validity_seconds")) : undefined,
        grace_seconds: 0, tax_behavior: form.get("tax_behavior"), checkout_config: {},
      });
      target.reset();
      setMode("recurring");
      setMessage("Immutable price version created.");
      onChanged();
    } catch (error) { setMessage(readError(error)); }
  }
  return <form className="detail-form" onSubmit={(event) => void submit(event)}><strong>Create immutable price</strong><p className="full-field">This price will snapshot the product entitlement defaults above.</p><label><span>Price key</span><input required name="key" placeholder="e.g. monthly-standard" /></label><label><span>Price mode</span><select name="mode" value={mode} onChange={(event) => setMode(event.target.value)}><option value="recurring">Recurring</option><option value="one_time">One time</option><option value="local">Local entitlement</option></select></label><label><span>Amount in minor units</span><input required name="amount_minor" min="0" type="number" placeholder="e.g. 1990" /><small>For EUR, 1990 means EUR 19.90.</small></label><label><span>Currency</span><input required name="currency" minLength={3} maxLength={3} defaultValue="EUR" /></label><label><span>Tax behavior</span><select name="tax_behavior" defaultValue="inclusive"><option value="inclusive">Tax inclusive</option><option value="exclusive">Tax exclusive</option><option value="unspecified">Unspecified</option></select></label>{mode === "recurring" && <><label><span>Billing interval</span><select name="interval_unit" defaultValue="month"><option>day</option><option>week</option><option>month</option><option>year</option></select></label><label><span>Interval count</span><input name="interval_count" min="1" type="number" defaultValue="1" /></label></>}{mode === "local" && <label><span>Local validity in seconds</span><input required name="validity_seconds" min="1" type="number" placeholder="e.g. 2592000" /></label>}<button>Create price</button></form>;
}

function ProviderTest({ providerID, application, setMessage }: { providerID: string; application: Application; setMessage: (value: string) => void }) {
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      const result = await api.request<Record<string, unknown>>("POST", `/v1/control/applications/${application.id}/notification-providers/${providerID}/test`, { recipient: form.get("recipient") }, { idempotencyKey: crypto.randomUUID() });
      setMessage(`SMTP test queued as notification ${String(result.notification_id)}.`);
    } catch (error) { setMessage(readError(error)); }
  }
  return <form className="detail-form" onSubmit={(event) => void submit(event)}><strong>Test delivery</strong><label><span>Recipient email</span><input required name="recipient" type="email" placeholder="recipient@example.com" /></label><button>Queue SMTP test</button></form>;
}

function useNotificationTemplateVariables(application: Application, setMessage: (value: string) => void, basePath = `/v1/control/applications/${application.id}`) {
  const [variables, setVariables] = useState<TemplateVariableDefinition[]>([]);
  useEffect(() => {
    api.request<Page<TemplateVariableDefinition>>("GET", `${basePath}/notification-template-variables`)
      .then((result) => setVariables(result.items))
      .catch((error) => setMessage(readError(error)));
  }, [application.id, basePath, setMessage]);
  return variables;
}

function NotificationTemplateCreator({ application, setMessage, onCreated, basePath = `/v1/control/applications/${application.id}` }: { application: Application; setMessage: (value: string) => void; onCreated: () => void; basePath?: string }) {
  const [open, setOpen] = useState(false);
  const variables = useNotificationTemplateVariables(application, setMessage, basePath);
  async function create(body: Record<string, unknown>) {
    try {
      await api.request("POST", `${basePath}/notification-templates`, body);
      setMessage("Notification template draft created.");
      setOpen(false);
      onCreated();
    } catch (error) { setMessage(readError(error)); }
  }
  return <section className={`create-panel template-create-panel ${open ? "open" : ""}`}>
    <button className="create-toggle" onClick={() => setOpen((value) => !value)}>{open ? "Close composer" : "Create template"}</button>
    {open && <NotificationTemplateComposer application={application} variables={variables} submitLabel="Create draft" onSubmit={create} />}
  </section>;
}

function NotificationTemplateEditor({ template, application, setMessage, onChanged, basePath = `/v1/control/applications/${application.id}` }: { template: Record<string, unknown>; application: Application; setMessage: (value: string) => void; onChanged: () => void; basePath?: string }) {
  const variables = useNotificationTemplateVariables(application, setMessage, basePath);
  const [localizing, setLocalizing] = useState(false);
  async function update(body: Record<string, unknown>) {
    try {
      const result = await api.request<Record<string, unknown>>("PATCH", `${basePath}/notification-templates/${String(template.id)}`, body);
      setMessage(`New immutable draft version ${String(result.version)} created. Close this panel to select it.`);
      onChanged();
    } catch (error) { setMessage(readError(error)); }
  }
  async function createLocalization(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const locale = String(new FormData(event.currentTarget).get("locale") ?? "").trim();
    try {
      const result = await api.request<Record<string, unknown>>("POST", `${basePath}/notification-templates`, {
        key: template.key, locale, category: template.category,
        subject_template: template.subject_template, text_template: template.text_template,
        html_template: template.html_template ?? "", variable_schema: template.variable_schema ?? {},
      });
      setMessage(`Localization ${String(result.locale)} created as a draft. Open it to translate and publish it.`);
      setLocalizing(false);
      onChanged();
    } catch (error) { setMessage(readError(error)); }
  }
  const availableLocales = Array.isArray(template.available_locales) ? template.available_locales.map(String) : [String(template.locale ?? "en")];
  return <><section className="template-localization-panel"><div><p className="eyebrow">LOCALIZATION SET</p><h3>{String(template.key)}</h3><p>Delivery tries the user locale, its parent language, English, then the next published locale. Application variants override installation variants for the same locale.</p><div className="locale-chips">{availableLocales.map((locale) => <span key={locale}>{locale}</span>)}</div></div><button type="button" className="outline" onClick={() => setLocalizing((value) => !value)}>{localizing ? "Cancel localization" : "Add localization"}</button>{localizing && <form onSubmit={(event) => void createLocalization(event)}><label><span>New locale</span><input required name="locale" maxLength={35} placeholder="de-CH" /></label><button>Create translation draft</button></form>}</section><NotificationTemplateComposer application={application} variables={variables} initial={template} submitLabel="Save as new draft version" onSubmit={update} /></>;
}

function customVariablesFromSchema(raw: unknown): CustomTemplateVariable[] {
  if (!raw || typeof raw !== "object") return [];
  const schema = raw as { properties?: Record<string, Record<string, unknown>>; required?: unknown[] };
  const required = new Set((schema.required ?? []).filter((value): value is string => typeof value === "string"));
  return Object.entries(schema.properties ?? {}).map(([key, definition]) => ({
    key,
    label: String(definition.title ?? key),
    type: (["string", "integer", "number", "boolean"].includes(String(definition.type)) ? definition.type : "string") as CustomTemplateVariable["type"],
    sample: String(definition.example ?? ""),
    required: required.has(key),
  }));
}

function customVariableSchema(variables: CustomTemplateVariable[]) {
  return {
    properties: Object.fromEntries(variables.map((variable) => [variable.key, {
      type: variable.type,
      title: variable.label,
      description: `Application-provided template variable: ${variable.label}.`,
      example: templateSampleValue(variable),
    }])),
    required: variables.filter((variable) => variable.required).map((variable) => variable.key),
  };
}

function templateSampleValue(variable: Pick<CustomTemplateVariable, "type" | "sample">): unknown {
  if (variable.type === "boolean") return variable.sample === "true";
  if (variable.type === "integer") return Number.parseInt(variable.sample || "0", 10);
  if (variable.type === "number") return Number(variable.sample || "0");
  return variable.sample;
}

function renderTemplatePreview(template: string, values: Record<string, unknown>, escapeHTML = false) {
  return template.replace(/{{\s*([A-Za-z][A-Za-z0-9_.-]{0,100})\s*}}/g, (_token, key: string) => {
    const raw = values[key] === undefined ? `{{${key}}}` : String(values[key]);
    return escapeHTML ? raw.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#039;") : raw;
  });
}

function emailPreviewDocument(body: string) {
  return `<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src https:; style-src 'unsafe-inline'"><style>body{margin:0;padding:28px;color:#101623;background:#fff;font:16px/1.55 system-ui,sans-serif}img{max-width:100%;height:auto}a{color:#0a7b55}h1,h2,h3{line-height:1.1}hr{border:0;border-top:1px solid #dce3ec}</style></head><body>${body}</body></html>`;
}

function sanitizeEditorHTML(value: string) {
  if (typeof document === "undefined") return value;
  const wrapper = document.createElement("div");
  wrapper.innerHTML = value;
  wrapper.querySelectorAll("script,iframe,object,embed,form,input,button,style,link,meta").forEach((node) => node.remove());
  wrapper.querySelectorAll("*").forEach((node) => {
    for (const attribute of Array.from(node.attributes)) {
      const name = attribute.name.toLowerCase();
      const attributeValue = attribute.value.trim().toLowerCase();
      if (name.startsWith("on") || name === "srcdoc" || ((name === "href" || name === "src") && (attributeValue.startsWith("javascript:") || attributeValue.startsWith("data:text/html")))) node.removeAttribute(attribute.name);
    }
    if (node instanceof HTMLImageElement && (!node.src.startsWith("https://") || node.hasAttribute("srcset"))) node.remove();
  });
  return wrapper.innerHTML;
}

function TemplateImagePicker({ application, onInsert }: { application: Application; onInsert: (markup: string) => void }) {
  const basePath = application.id === "installation" ? "/v1/control/installation" : `/v1/control/applications/${application.id}`;
  const [managedAvailable, setManagedAvailable] = useState(false);
  const [assets, setAssets] = useState<StorageObject[]>([]);
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState("");
  const [refresh, setRefresh] = useState(0);
  useEffect(() => {
    Promise.all([
      api.request<Page<Record<string, unknown>>>("GET", `${basePath}/storage/providers`),
      api.request<Page<StorageObject>>("GET", `${basePath}/storage/objects?visibility=public`),
    ]).then(([providers, objects]) => {
      setManagedAvailable(providers.items.some((provider) => provider.effective_for_public === true));
      setAssets(objects.items.filter((object) => object.status === "ready" && object.public_url && object.metadata?.purpose === "email_image"));
    }).catch(() => {
      setManagedAvailable(false);
      setAssets([]);
    });
  }, [basePath, refresh]);
  function insert(url: string, alt: string, objectID?: string) {
    const identifier = objectID ? ` data-p93-object-id="${escapeHTMLAttribute(objectID)}"` : "";
    onInsert(`<img src="${escapeHTMLAttribute(url)}" alt="${escapeHTMLAttribute(alt)}"${identifier}>`);
    setStatus("Image inserted into the email body.");
  }
  async function upload(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const target = event.currentTarget;
    const form = new FormData(target);
    const file = form.get("file");
    const alt = String(form.get("alt") ?? "").trim();
    if (!(file instanceof File) || !["image/png", "image/jpeg", "image/gif"].includes(file.type)) {
      setStatus("Choose a PNG, JPEG, or GIF image.");
      return;
    }
    setBusy(true);
    setStatus("");
    try {
      const authorization = await api.request<StorageUploadAuthorization>("POST", `${basePath}/storage/uploads`, {
        filename: file.name, content_type: file.type, size_bytes: file.size, visibility: "public", purpose: "email_image",
      }, { idempotencyKey: crypto.randomUUID() });
      const headers = new Headers(authorization.required_headers);
      headers.delete("content-length");
      const uploaded = await globalThis.fetch(authorization.upload_url, { method: "PUT", headers, body: file });
      if (!uploaded.ok) throw new Error(`S3 returned HTTP ${uploaded.status}; verify bucket CORS.`);
      const object = await api.request<StorageObject>("POST", `${basePath}/storage/uploads/${authorization.object.id}/complete`);
      if (!object.public_url) throw new Error("The verified public object did not return a public URL.");
      insert(object.public_url, alt || file.name, object.id);
      target.reset();
      setRefresh((value) => value + 1);
    } catch (error) { setStatus(toastBody(readError(error))); }
    finally { setBusy(false); }
  }
  function insertExternal(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const raw = String(form.get("url") ?? "").trim();
    try {
      const parsed = new URL(raw);
      if (parsed.protocol !== "https:") throw new Error("not HTTPS");
      insert(parsed.href, String(form.get("alt") ?? ""));
      event.currentTarget.reset();
    } catch { setStatus("External images require an absolute HTTPS URL."); }
  }
  return <details className="template-image-picker"><summary>Image</summary><div className="template-image-popover">
    <strong>Email image</strong><p>Public images load in email clients. External HTTPS URLs are always available.</p>
    {managedAvailable ? <form onSubmit={(event) => void upload(event)}><label>Managed image<input required name="file" type="file" accept="image/png,image/jpeg,image/gif" /></label><label>Alternative text<input name="alt" /></label><button disabled={busy}>{busy ? "Uploading..." : "Upload and insert"}</button></form> : <div className="provider-empty">Configure and verify an effective public storage bucket to upload managed images.</div>}
    {assets.length > 0 && <div className="template-asset-library">{assets.map((asset) => <button type="button" key={asset.id} onClick={() => insert(String(asset.public_url), asset.filename, asset.id)}><img src={String(asset.public_url)} alt="" /><span>{asset.filename}</span></button>)}</div>}
    <form onSubmit={insertExternal}><label>External HTTPS URL<input required name="url" type="url" placeholder="https://assets.example.com/logo.png" /></label><label>Alternative text<input name="alt" /></label><button>Insert URL</button></form>
    {status && <small role="status">{status}</small>}
  </div></details>;
}

function escapeHTMLAttribute(value: string) {
  return value.replaceAll("&", "&amp;").replaceAll('"', "&quot;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
}

function NotificationTemplateComposer({ application, variables, initial, submitLabel, onSubmit }: {
  application: Application;
  variables: TemplateVariableDefinition[];
  initial?: Record<string, unknown>;
  submitLabel: string;
  onSubmit: (body: Record<string, unknown>) => Promise<void>;
}) {
  const [key, setKey] = useState(String(initial?.key ?? ""));
  const [locale, setLocale] = useState(String(initial?.locale ?? "en"));
  const [category, setCategory] = useState(String(initial?.category ?? "transactional"));
  const [subject, setSubject] = useState(String(initial?.subject_template ?? "Welcome, {{first_name}}"));
  const [textBody, setTextBody] = useState(String(initial?.text_template ?? "Hello {{first_name}},\n\nWelcome to {{application_name}}."));
  const [htmlBody, setHTMLBody] = useState(String(initial?.html_template ?? "<h1>Welcome, {{first_name}}</h1><p>Thanks for joining <strong>{{application_name}}</strong>.</p>"));
  const [customVariables, setCustomVariables] = useState(() => customVariablesFromSchema(initial?.variable_schema));
  const [sourceMode, setSourceMode] = useState(false);
  const [busy, setBusy] = useState(false);
  const [activeField, setActiveField] = useState<"subject" | "text" | "html">("subject");
  const subjectRef = useRef<HTMLInputElement>(null);
  const textRef = useRef<HTMLTextAreaElement>(null);
  const richRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!sourceMode && richRef.current && richRef.current.innerHTML !== sanitizeEditorHTML(htmlBody)) richRef.current.innerHTML = sanitizeEditorHTML(htmlBody);
  }, [htmlBody, sourceMode]);
  const sampleValues = Object.fromEntries([
    ...variables.map((variable) => [variable.key, variable.sample]),
    ...customVariables.map((variable) => [variable.key, templateSampleValue(variable)]),
    ["application_id", application.id], ["application_name", application.name], ["application_slug", application.slug],
  ]);
  const allVariables = [
    ...variables,
    ...customVariables.map((variable) => ({ key: variable.key, label: variable.label, description: application.id === "installation" ? "Provided by the Platform93 system flow when the message is queued." : "Provided by the application or Platform93 system flow when the message is queued.", type: variable.type, availability: "custom" as const, sample: templateSampleValue(variable) })),
  ];
  function insertCode(code: string) {
    const token = `{{${code}}}`;
    if (activeField === "subject" && subjectRef.current) {
      const input = subjectRef.current;
      const start = input.selectionStart ?? subject.length;
      const end = input.selectionEnd ?? start;
      setSubject(subject.slice(0, start) + token + subject.slice(end));
      requestAnimationFrame(() => { input.focus(); input.setSelectionRange(start + token.length, start + token.length); });
      return;
    }
    if (activeField === "text" && textRef.current) {
      const input = textRef.current;
      const start = input.selectionStart ?? textBody.length;
      const end = input.selectionEnd ?? start;
      setTextBody(textBody.slice(0, start) + token + textBody.slice(end));
      requestAnimationFrame(() => { input.focus(); input.setSelectionRange(start + token.length, start + token.length); });
      return;
    }
    if (sourceMode) {
      setHTMLBody((value) => value + token);
      return;
    }
    richRef.current?.focus();
    document.execCommand("insertText", false, token);
    setHTMLBody(richRef.current?.innerHTML ?? htmlBody);
  }
  function formatHTML(command: string, value?: string) {
    richRef.current?.focus();
    document.execCommand(command, false, value);
    setHTMLBody(richRef.current?.innerHTML ?? htmlBody);
  }
  function insertImage(markup: string) {
    if (sourceMode) {
      setHTMLBody((value) => value + markup);
      return;
    }
    richRef.current?.focus();
    document.execCommand("insertHTML", false, markup);
    setHTMLBody(richRef.current?.innerHTML ?? htmlBody);
  }
  function addCustomVariable(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const target = event.currentTarget;
    const form = new FormData(target);
    const customKey = String(form.get("key") ?? "").trim();
    if (!/^[A-Za-z][A-Za-z0-9_.-]{0,100}$/.test(customKey) || allVariables.some((variable) => variable.key === customKey)) return;
    setCustomVariables((current) => [...current, { key: customKey, label: String(form.get("label") || customKey), type: String(form.get("type")) as CustomTemplateVariable["type"], sample: String(form.get("sample") ?? ""), required: form.get("required") === "on" }]);
    target.reset();
  }
  async function submit() {
    setBusy(true);
    try {
      await onSubmit({ key, locale, category, subject_template: subject, text_template: textBody, html_template: htmlBody, variable_schema: customVariableSchema(customVariables) });
    } finally { setBusy(false); }
  }
  const renderedHTML = renderTemplatePreview(htmlBody, sampleValues, true);
  return <div className="template-composer">
    <header className="template-composer-head"><div><p className="eyebrow">MESSAGE DESIGNER</p><h3>{initial ? `Edit ${key}` : "Compose a notification"}</h3><p>Build the email and plain-text fallback together. Codes are replaced only when the notification is queued.</p></div><span className="template-version">{initial ? `VERSION ${String(initial.version)}` : "NEW DRAFT"}</span></header>
    <div className="template-meta">
      <label><span>Template key</span><input required disabled={Boolean(initial)} value={key} onChange={(event) => setKey(event.target.value)} placeholder="welcome_email" /></label>
      <label><span>Locale</span><input required disabled={Boolean(initial)} value={locale} maxLength={35} onChange={(event) => setLocale(event.target.value)} placeholder="de-CH" /><small>BCP 47 language tag</small></label>
      <label><span>Category</span><select value={category} onChange={(event) => setCategory(event.target.value)}><option value="security">Security</option><option value="transactional">Transactional</option><option value="billing">Billing</option><option value="product">Product</option><option value="marketing">Marketing</option></select></label>
    </div>
    <div className="template-workbench">
      <div className="template-editors">
        <label className={`template-subject ${activeField === "subject" ? "active" : ""}`}><span>Subject</span><input ref={subjectRef} required value={subject} onFocus={() => setActiveField("subject")} onChange={(event) => setSubject(event.target.value)} /></label>
        <section className={`rich-editor-shell ${activeField === "html" ? "active" : ""}`}>
          <div className="rich-editor-label"><span>Email body</span><div><button type="button" className={!sourceMode ? "active" : ""} onClick={() => setSourceMode(false)}>Visual</button><button type="button" className={sourceMode ? "active" : ""} onClick={() => setSourceMode(true)}>HTML</button></div></div>
          {!sourceMode && <div className="editor-toolbar" aria-label="Email formatting controls"><button type="button" onMouseDown={(event) => event.preventDefault()} onClick={() => formatHTML("formatBlock", "p")}>P</button><button type="button" onMouseDown={(event) => event.preventDefault()} onClick={() => formatHTML("formatBlock", "h2")}>H2</button><button type="button" onMouseDown={(event) => event.preventDefault()} onClick={() => formatHTML("bold")}><strong>B</strong></button><button type="button" onMouseDown={(event) => event.preventDefault()} onClick={() => formatHTML("italic")}><em>I</em></button><button type="button" onMouseDown={(event) => event.preventDefault()} onClick={() => formatHTML("insertUnorderedList")}>List</button><button type="button" onMouseDown={(event) => event.preventDefault()} onClick={() => formatHTML("insertHorizontalRule")}>Rule</button><TemplateImagePicker application={application} onInsert={insertImage} /></div>}
          {sourceMode ? <textarea aria-label="HTML source" value={htmlBody} onFocus={() => setActiveField("html")} onChange={(event) => setHTMLBody(event.target.value)} /> : <div ref={richRef} className="rich-editor" contentEditable suppressContentEditableWarning onFocus={() => setActiveField("html")} onInput={(event) => setHTMLBody(event.currentTarget.innerHTML)} onPaste={(event) => { event.preventDefault(); document.execCommand("insertText", false, event.clipboardData.getData("text/plain")); }} />}
        </section>
        <label className={`template-text ${activeField === "text" ? "active" : ""}`}><span>Plain-text fallback</span><textarea ref={textRef} required value={textBody} onFocus={() => setActiveField("text")} onChange={(event) => setTextBody(event.target.value)} /></label>
      </div>
      <aside className="template-codebook"><div><p className="eyebrow">AVAILABLE CODES</p><h4>Insert into {activeField === "html" ? "email body" : activeField}</h4><p>Click a code to place it at the cursor. User codes require <code>user_id</code> when sending.</p></div><div className="code-list">{allVariables.map((variable) => <button type="button" key={variable.key} onClick={() => insertCode(variable.key)}><span><strong>{variable.label}</strong><code>{`{{${variable.key}}}`}</code></span><small>{variable.description}</small><em>{variable.availability === "always" ? "Always available" : variable.availability === "user" ? "Requires user_id" : "Application supplied"} · Example: {String(variable.sample)}</em></button>)}</div>
        <form className="custom-code-form" onSubmit={addCustomVariable}><strong>Add template code</strong><input required name="key" placeholder="order_number" /><input required name="label" placeholder="Order number" /><select name="type" defaultValue="string"><option value="string">Text</option><option value="integer">Whole number</option><option value="number">Number</option><option value="boolean">True / false</option></select><input name="sample" placeholder="Example value" /><label><input type="checkbox" name="required" /> Required</label><button type="submit">Add code</button></form>
        {customVariables.length > 0 && <div className="custom-code-summary">{customVariables.map((variable) => <span key={variable.key}><code>{variable.key}</code><IconButton label={`Remove ${variable.label}`} icon="remove" tone="danger" onClick={() => setCustomVariables((current) => current.filter((item) => item.key !== variable.key))} /></span>)}</div>}
      </aside>
    </div>
    <section className="template-preview-stage"><div className="preview-heading"><div><p className="eyebrow">LIVE PREVIEW</p><h4>{renderTemplatePreview(subject, sampleValues)}</h4></div><span>Sample data · no message sent</span></div><iframe title="Email preview" sandbox="" srcDoc={emailPreviewDocument(renderedHTML)} /><details><summary>Plain-text preview</summary><pre>{renderTemplatePreview(textBody, sampleValues)}</pre></details></section>
    <footer className="template-composer-actions"><p><strong>Codes remain escaped in HTML.</strong> Scripts, iframes, JavaScript URLs, and undeclared custom codes are rejected by the API.</p><button type="button" disabled={busy || !key || !locale || !subject || !textBody} onClick={() => void submit()}>{busy ? "Saving draft..." : submitLabel}</button></footer>
  </div>;
}

function AuditExport({ application, setMessage }: { application: Application; setMessage: (value: string) => void }) {
  async function create() {
    try {
      const result = await api.request<Record<string, unknown>>("POST", `/v1/control/applications/${application.id}/audit-exports`, {});
      setMessage(`Encrypted audit export ${String(result.id)} contains ${String(result.record_count)} records and expires at ${String(result.expires_at)}.`);
    } catch (error) { setMessage(readError(error)); }
  }
  return <section className="create-panel"><button className="create-toggle" onClick={() => void create()}>Create one-hour encrypted audit export</button></section>;
}

function Onboarding({
  onCreated,
  setMessage,
}: {
  onCreated: (organization: Organization, application: Application) => void;
  setMessage: (value: string) => void;
}) {
  const [busy, setBusy] = useState(false);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    const form = new FormData(event.currentTarget);
    try {
      const organization = await api.request<Organization>(
        "POST",
        "/v1/control/organizations",
        {
          name: form.get("organization_name"),
          slug: form.get("organization_slug"),
        },
      );
      const application = await api.request<Application>(
        "POST",
        `/v1/control/organizations/${organization.id}/applications`,
        {
          name: form.get("application_name"),
          slug: form.get("application_slug"),
        },
      );
      setMessage("Organization and application created.");
      onCreated({ ...organization, role: "owner" }, application);
    } catch (error) {
      setMessage(readError(error));
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="table">
      <div className="table-head">
        <span>Create the first boundary</span>
      </div>
      <form onSubmit={submit} className="onboarding">
        <div className="fields">
          <label>
            Organization name
            <input name="organization_name" required />
          </label>
          <label>
            Organization slug
            <input
              name="organization_slug"
              required
              pattern="[a-z][a-z0-9-]{2,62}"
            />
          </label>
          <label>
            Application name
            <input name="application_name" required />
          </label>
          <label>
            Application slug
            <input
              name="application_slug"
              required
              pattern="[a-z][a-z0-9-]{2,62}"
            />
          </label>
        </div>
        <button disabled={busy}>
          {busy
            ? "Creating..."
            : "Create organization and application"}
        </button>
      </form>
    </section>
  );
}

function OrganizationCreator({ onCreated, setMessage }: { onCreated: (organization: Organization) => void; setMessage: (value: string) => void }) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    const form = new FormData(event.currentTarget);
    try {
      const organization = await api.request<Organization>("POST", "/v1/control/organizations", { name: form.get("name"), slug: form.get("slug") });
      setMessage(`Organization ${organization.name} created. Add its first application next.`);
      onCreated(organization);
    } catch (error) {
      setMessage(readError(error));
    } finally {
      setBusy(false);
    }
  }
  return <section className={`create-panel boundary-create ${open ? "open" : ""}`}>
    <button className="create-toggle" onClick={() => setOpen((value) => !value)}>{open ? "Close" : "Add organization"}</button>
    {open && <form onSubmit={(event) => void submit(event)}><p>Create an independent organization boundary. Applications are added after opening it.</p><div className="create-fields"><label>Organization name<input required name="name" maxLength={255} placeholder="Acme GmbH" /></label><label>Organization slug<input required name="slug" pattern="[a-z][a-z0-9-]{2,62}" placeholder="acme-gmbh" /></label></div><button disabled={busy}>{busy ? "Creating organization..." : "Create organization"}</button></form>}
  </section>;
}

function Dashboard({ application }: { application: Application }) {
  const [statistics, setStatistics] = useState<Record<string, unknown> | null>(null);
  const [error, setError] = useState("");
  const [refresh, setRefresh] = useState(0);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    let active = true;
    setLoading(true);
    api.request<Record<string, unknown>>("GET", `/v1/control/applications/${application.id}/statistics`).then((statisticsValue) => {
      if (!active) return;
      setStatistics(statisticsValue);
      setError("");
    }).catch((reason) => active && setError(readError(reason))).finally(() => active && setLoading(false));
    return () => { active = false; };
  }, [application.id, refresh]);
  const users = statistics?.users as Record<string, unknown> | undefined;
  return (
    <>
      <PageSummary
        summary={<><span>OIDC issuer</span><code>{application.issuer}</code></>}
        help="This application is an isolated identity and integration boundary. Its users, workspaces, catalog, billing, entitlements, providers, and events are scoped independently."
        action={<IconButton label="Refresh metrics" icon="refresh" loading={loading} onClick={() => setRefresh((value) => value + 1)} />}
      />
      <section className="metric-grid">
        <article>
          <span>Active users</span>
          <strong>{statistics ? String(users?.active ?? 0) : "..."}</strong>
          <p>{statistics ? `${String(users?.suspended ?? 0)} suspended` : "Loading identity counts"}</p>
        </article>
        <article>
          <span>Active entitlements</span>
          <strong>{statistics ? String(statistics.active_entitlements ?? 0) : "..."}</strong>
          <p>{statistics ? `${String(statistics.pending_local_requests ?? 0)} local requests pending` : "Loading access counts"}</p>
        </article>
        <article>
          <span>Live subscriptions</span>
          <strong>{statistics ? String(statistics.live_subscriptions ?? 0) : "..."}</strong>
          <p>Trialing, active, or past due</p>
        </article>
        <article>
          <span>Workspaces</span>
          <strong>{statistics ? String(statistics.workspaces ?? 0) : "..."}</strong>
          <p>{statistics ? `${String(statistics.active_products ?? 0)} active products` : "Loading catalog counts"}</p>
        </article>
        <article>
          <span>Delivery failures</span>
          <strong>{statistics ? String(Number(statistics.notification_failures ?? 0) + Number(statistics.webhook_failures ?? 0)) : "..."}</strong>
          <p>Notification and webhook dead letters</p>
        </article>
        <article>
          <span>Events / 24h</span>
          <strong>{statistics ? String(statistics.events_last_24_hours ?? 0) : "..."}</strong>
          <p>Transactional domain activity</p>
        </article>
      </section>
      {error && <p className="error">{toastBody(error)}</p>}
    </>
  );
}

function ApplicationSettings({ application, setMessage, onChanged }: { application: Application; setMessage: (value: string) => void; onChanged: (application: Application) => void }) {
  const [current, setCurrent] = useState<Application | null>(null);
  const [renaming, setRenaming] = useState(false);
  useEffect(() => {
    let active = true;
    setCurrent(null);
    api.request<Application>("GET", `/v1/control/applications/${application.id}`)
      .then((value) => active && setCurrent(value))
      .catch((error) => active && setMessage(readError(error)));
    return () => { active = false; };
  }, [application.id, setMessage]);
  function changed(updated: Application) {
    setCurrent(updated);
    onChanged(updated);
  }
  async function rename(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!current?.organization_id) return;
    setRenaming(true);
    const name = String(new FormData(event.currentTarget).get("name") ?? "").trim();
    try {
      await api.request("PATCH", `/v1/control/organizations/${current.organization_id}/applications/${current.id}`, { name }, { headers: { "If-Match": `"v${Number(current.version ?? 1).toString(16)}"` } });
      changed({ ...current, name, version: Number(current.version ?? 1) + 1 });
      setMessage("Application renamed.");
    } catch (error) {
      setMessage(readError(error));
    } finally {
      setRenaming(false);
    }
  }
  if (!current) return <LoadingState label="Loading application settings" />;
  return <>
    <PageSummary summary="Runtime configuration and access policy" help="Rename the application, publish safe client-visible JSON, and control registration, passwordless access, personal API keys, and delegation. External services are configured under Providers." />
    <section className="boundary-settings"><div><p className="eyebrow">IDENTITY</p><h3>Name and stable key</h3><p>The UUID and slug remain stable for integrations. Renaming changes only the display name.</p></div><form key={`${current.id}-${current.name}`} onSubmit={(event) => void rename(event)}><label>Application name<input required maxLength={255} name="name" defaultValue={current.name} /></label><label>Stable slug<input disabled value={current.slug} /></label><button disabled={renaming}>{renaming ? "Renaming..." : "Rename application"}</button></form></section>
    <ApplicationConfigurationSettings application={current} setMessage={setMessage} onChanged={changed} />
  </>;
}

type InternalApplicationConfig = {
  registration_mode: "public" | "invite_only";
  password_enabled: boolean;
  passwordless_enabled: boolean;
  personal_api_keys_enabled: boolean;
  delegation_enabled: boolean;
};

const defaultInternalApplicationConfig: InternalApplicationConfig = {
  registration_mode: "public",
  password_enabled: true,
  passwordless_enabled: true,
  personal_api_keys_enabled: false,
  delegation_enabled: false,
};

function ApplicationConfigurationSettings({ application, setMessage, onChanged }: { application: Application; setMessage: (value: string) => void; onChanged: (value: Application) => void }) {
  const [publicJSON, setPublicJSON] = useState(() => JSON.stringify(application.public_config ?? {}, null, 2));
  const [publicError, setPublicError] = useState("");
  const [internal, setInternal] = useState<InternalApplicationConfig>(() => ({ ...defaultInternalApplicationConfig, ...(application.internal_config ?? {}) } as InternalApplicationConfig));
  const [busy, setBusy] = useState<"public" | "internal" | "">("");
  useEffect(() => {
    setPublicJSON(JSON.stringify(application.public_config ?? {}, null, 2));
    setPublicError("");
    setInternal({ ...defaultInternalApplicationConfig, ...(application.internal_config ?? {}) } as InternalApplicationConfig);
  }, [application.id, application.version, application.public_config, application.internal_config]);
  function updatePublicJSON(value: string) {
    setPublicJSON(value);
    try {
      const parsed = JSON.parse(value) as unknown;
      setPublicError(parsed && typeof parsed === "object" && !Array.isArray(parsed) ? "" : "Public configuration must be a JSON object.");
    } catch {
      setPublicError("Enter valid JSON before saving.");
    }
  }
  async function reloadApplication() {
    const updated = await api.request<Application>("GET", `/v1/control/applications/${application.id}`);
    onChanged(updated);
  }
  async function savePublic(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    updatePublicJSON(publicJSON);
    let config: unknown;
    try { config = JSON.parse(publicJSON); } catch { return; }
    if (!config || typeof config !== "object" || Array.isArray(config)) return;
    setBusy("public");
    try {
      await api.request("PATCH", `/v1/control/applications/${application.id}/public-config`, config, { headers: { "If-Match": `"v${Number(application.version ?? 1).toString(16)}"` } });
      await reloadApplication();
      setMessage("Public application configuration saved.");
    } catch (error) { setMessage(readError(error)); }
    finally { setBusy(""); }
  }
  async function saveInternal(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy("internal");
    try {
      await api.request("PATCH", `/v1/control/applications/${application.id}/internal-config`, internal, { headers: { "If-Match": `"v${Number(application.version ?? 1).toString(16)}"` } });
      await reloadApplication();
      setMessage("Application access policy saved and enforced.");
    } catch (error) { setMessage(readError(error)); }
    finally { setBusy(""); }
  }
  const toggle = (key: keyof Omit<InternalApplicationConfig, "registration_mode">) => setInternal((value) => ({ ...value, [key]: !value[key] }));
  const publicConfigURL = `${api.baseUrl}/v1/applications/${encodeURIComponent(application.id)}/public-config`;
  return <section className="application-configuration">
    <header><p className="eyebrow">APPLICATION CONFIGURATION</p><h3>Runtime and access policy</h3><p>Public configuration is safe runtime data for clients. Internal configuration is enforced by Platform93 and is never returned as a raw object to unauthenticated callers.</p></header>
    <div className="application-config-grid">
      <form onSubmit={(event) => void savePublic(event)}>
        <div><span>PUBLIC CONFIG</span><h4>Client-visible JSON</h4></div>
        <div className="public-config-access">
          <span>UNAUTHENTICATED RUNTIME ENDPOINT</span>
          <a href={publicConfigURL} target="_blank" rel="noreferrer">{publicConfigURL}</a>
          <code>client.application().publicConfig()</code>
          <small>The response includes runtime authentication settings. Your JSON is returned under <code>public_config</code>.</small>
        </div>
        <p className="config-warning"><strong>Public and unauthenticated.</strong> Never store credentials, tokens, or private operational data here.</p>
        <label>JSON object<textarea spellCheck={false} rows={13} value={publicJSON} onChange={(event) => updatePublicJSON(event.target.value)} aria-invalid={Boolean(publicError)} /></label>
        {publicError && <small className="field-error">{publicError}</small>}
        <button disabled={busy !== "" || Boolean(publicError)}>{busy === "public" ? "Saving public config..." : "Save public config"}</button>
      </form>
      <form onSubmit={(event) => void saveInternal(event)}>
        <div><span>INTERNAL CONFIG</span><h4>Authentication and access</h4></div>
        <label className="select-setting">Registration<select value={internal.registration_mode} onChange={(event) => setInternal((value) => ({ ...value, registration_mode: event.target.value as InternalApplicationConfig["registration_mode"] }))}><option value="public">Public registration</option><option value="invite_only">Invite or pre-provision only</option></select><small>Invite-only blocks all public account-creation paths. Existing and administrator-created users can still sign in.</small></label>
        <label className="toggle-setting"><input type="checkbox" checked={internal.password_enabled} onChange={() => toggle("password_enabled")} /><span><strong>Password authentication</strong><small>Allow users with a password identity to sign in.</small></span></label>
        <label className="toggle-setting"><input type="checkbox" checked={internal.passwordless_enabled} onChange={() => toggle("passwordless_enabled")} /><span><strong>Email codes and magic links</strong><small>Allow passwordless email challenges for existing users and public signup when enabled.</small></span></label>
        <label className="toggle-setting"><input type="checkbox" checked={internal.personal_api_keys_enabled} onChange={() => toggle("personal_api_keys_enabled")} /><span><strong>Personal API keys</strong><small>Users can create opaque keys carrying their live application permissions. Disabling revokes active keys.</small></span></label>
        <label className="toggle-setting"><input type="checkbox" checked={internal.delegation_enabled} onChange={() => toggle("delegation_enabled")} /><span><strong>Operator delegation</strong><small>Allow audited, short-lived delegated application-user access. Disabling revokes active delegations.</small></span></label>
        <button disabled={busy !== ""}>{busy === "internal" ? "Applying policy..." : "Save access policy"}</button>
      </form>
    </div>
  </section>;
}

function ApplicationPicker({ organization, setApplication, setMessage, reloadBoundaries, onOrganizationChanged }: {
  organization: Organization;
  setApplication: (value: Application) => void;
  setMessage: (value: string) => void;
  reloadBoundaries: () => Promise<void>;
  onOrganizationChanged: (value: Organization) => void;
}) {
  const [applications, setApplications] = useState<Application[]>([]);
  const [loading, setLoading] = useState(true);
  const [renaming, setRenaming] = useState(false);
  const [refresh, setRefresh] = useState(0);
  const [applicationAction, setApplicationAction] = useState("");
  useEffect(() => {
    let active = true;
    setLoading(true);
    api.request<Page<Application>>("GET", `/v1/control/organizations/${organization.id}/applications?include_retired=true`)
      .then((value) => active && setApplications(value.items.map((item) => ({ ...item, organization_id: organization.id }))))
      .catch((error) => setMessage(readError(error)))
      .finally(() => active && setLoading(false));
    return () => { active = false; };
  }, [organization.id, refresh, setMessage]);

  async function createApplication(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const target = event.currentTarget;
    const form = new FormData(target);
    try {
      const value = await api.request<Application>("POST", `/v1/control/organizations/${organization.id}/applications`, { name: form.get("name"), slug: form.get("slug") });
      target.reset();
      setMessage("Application created.");
      await reloadBoundaries();
      setApplication({ ...value, organization_id: organization.id });
    } catch (error) { setMessage(readError(error)); }
  }

  async function renameOrganization(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setRenaming(true);
    const name = String(new FormData(event.currentTarget).get("name") ?? "").trim();
    try {
      await api.request("PATCH", `/v1/control/organizations/${organization.id}`, { name }, { headers: { "If-Match": `"v${Number(organization.version ?? 1).toString(16)}"` } });
      onOrganizationChanged({ ...organization, name, version: Number(organization.version ?? 1) + 1 });
      setMessage("Organization renamed.");
      await reloadBoundaries();
    } catch (error) {
      setMessage(readError(error));
    } finally {
      setRenaming(false);
    }
  }

  async function setApplicationRetirement(applicationID: string, restore: boolean) {
    const actionKey = `${restore ? "restore" : "archive"}-${applicationID}`;
    setApplicationAction(actionKey);
    try {
      await api.request(restore ? "POST" : "DELETE", `/v1/control/organizations/${organization.id}/applications/${applicationID}${restore ? "/restore" : ""}`);
      setMessage(restore ? "Application restored. Previously revoked credentials remain revoked." : "Application retired and live credentials revoked.");
      setRefresh((value) => value + 1);
      await reloadBoundaries();
    } catch (error) { setMessage(readError(error)); }
    finally { setApplicationAction(""); }
  }

  return <section className="boundary-picker">
    <div className="picker-head"><div><p className="eyebrow">ORGANIZATION</p><h3>{organization.name}</h3></div></div>
    <section className="boundary-settings"><div><p className="eyebrow">ORGANIZATION SETTINGS</p><h3>Identity</h3><p>The slug remains stable for application configuration. Renaming changes only the display name.</p></div><form onSubmit={(event) => void renameOrganization(event)}><label>Organization name<input required maxLength={255} name="name" defaultValue={organization.name} /></label><label>Stable slug<input disabled value={organization.slug} /></label><button disabled={renaming}>{renaming ? "Renaming..." : "Rename organization"}</button></form></section>
    {loading ? <div className="empty">Loading applications...</div> : <div className="application-list">{applications.map((item) => <article className={item.retired_at ? "retired" : ""} key={item.id}><div><strong>{item.name}</strong><small>{item.retired_at ? "Retired application" : item.slug}</small></div><ActionGroup label={`${item.name} application actions`}>
      {!item.retired_at && <IconButton label={`Open ${item.name}`} icon="open" disabled={applicationAction !== ""} onClick={() => setApplication(item)} />}
      {item.retired_at
        ? <IconButton label={`Restore ${item.name}`} icon="restore" loading={applicationAction === `restore-${item.id}`} disabled={applicationAction !== ""} onClick={() => void setApplicationRetirement(item.id, true)} />
        : <IconButton label={`Retire ${item.name}`} icon="archive" tone="danger" loading={applicationAction === `archive-${item.id}`} disabled={applicationAction !== ""} onClick={() => void setApplicationRetirement(item.id, false)} />}
    </ActionGroup></article>)}</div>}
    <form className="inline-create" onSubmit={(event) => void createApplication(event)}><strong>New application</strong><input required name="name" placeholder="Application name" /><input required name="slug" pattern="[a-z][a-z0-9-]{2,62}" placeholder="application-slug" /><button>Create application</button></form>
  </section>;
}

function ControlPlane({ organization, section, setMessage }: {
  organization: Organization | null;
  section: string;
  setMessage: (value: string) => void;
}) {
  const [members, setMembers] = useState<Record<string, unknown>[]>([]);
  const [invitations, setInvitations] = useState<Record<string, unknown>[]>([]);
  const [sessions, setSessions] = useState<Record<string, unknown>[]>([]);
  const [installationOperators, setInstallationOperators] = useState<Record<string, unknown>[]>([]);
  const [installationAccess, setInstallationAccess] = useState<"loading" | "available" | "unavailable">("loading");
  const [refresh, setRefresh] = useState(0);
  useEffect(() => {
    if (section !== "Sessions") return;
    api.request<Page<Record<string, unknown>>>("GET", "/v1/control/auth/sessions")
      .then((page) => setSessions(page.items))
      .catch((error) => setMessage(readError(error)));
  }, [section, refresh, setMessage]);
  useEffect(() => {
    if (section !== "Operators" || organization) return;
    setInstallationAccess("loading");
    api.request<Page<Record<string, unknown>>>("GET", "/v1/control/installation/operators").then((operatorPage) => {
      setInstallationOperators(operatorPage.items);
      setInstallationAccess("available");
    }).catch((error) => {
      if (error instanceof Platform93Error && error.problem.status === 403) setInstallationAccess("unavailable");
      else setMessage(readError(error));
    });
  }, [organization, section, refresh, setMessage]);
  useEffect(() => {
    if (!organization || section !== "Operators") {
      setMembers([]);
      setInvitations([]);
      return;
    }
    Promise.all([
      api.request<Page<Record<string, unknown>>>("GET", `/v1/control/organizations/${organization.id}/members`),
      api.request<Page<Record<string, unknown>>>("GET", `/v1/control/organizations/${organization.id}/invitations`),
    ]).then(([memberPage, invitationPage]) => {
      setMembers(memberPage.items);
      setInvitations(invitationPage.items);
    }).catch((error) => setMessage(readError(error)));
  }, [organization, section, refresh, setMessage]);

  async function invite(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!organization) return;
    const target = event.currentTarget;
    const form = new FormData(target);
    try {
      const result = await api.request<Record<string, unknown>>("POST", `/v1/control/organizations/${organization.id}/invitations`, { email: form.get("email"), role: form.get("role"), expires_in: 604800 });
      setMessage(`Invitation queued. One-time credential: ${String(result.invitation_token)}`);
      target.reset();
      setRefresh((value) => value + 1);
    } catch (error) { setMessage(readError(error)); }
  }

  async function action(method: "POST" | "DELETE" | "PATCH", path: string, body?: unknown) {
    try {
      const result = await api.request<Record<string, unknown> | undefined>(method, path, body);
      setMessage(result?.invitation_token ? `New one-time credential: ${String(result.invitation_token)}` : `Operation completed (${method}).`);
      setRefresh((value) => value + 1);
    } catch (error) { setMessage(readError(error)); }
  }

  async function createInstallationOperator(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const target = event.currentTarget;
    const form = new FormData(target);
    try {
      await api.request("POST", "/v1/control/installation/operators", { email: form.get("email"), display_name: form.get("display_name"), role: form.get("role") });
      target.reset();
      setMessage("Installation operator created. They can sign in by email after installation SMTP is configured and verified.");
      setRefresh((value) => value + 1);
    } catch (error) { setMessage(readError(error)); }
  }

  if (section === "Operators") return <>
    <PageSummary summary={organization ? `Control access to ${organization.name}` : "Installation control access"} help={organization ? "Organization operators can govern its applications without becoming application users." : "Installation operators govern the deployment. Their control-plane identities remain separate from every application user."} />
    {!organization && (installationAccess === "loading" ? <LoadingState label="Loading installation operators" /> : installationAccess === "unavailable" ? <div className="empty">Installation operators are visible only to installation operators.</div> : <section className="control-scope">
      <div className="scope-heading"><p className="eyebrow">WHOLE INSTALLATION</p><h3>Installation operators</h3><p>Add an operator directly. This does not create an application user.</p></div>
      <section className="create-panel open"><form onSubmit={(event) => void createInstallationOperator(event)}><div className="create-fields"><label>Email<input required name="email" type="email" /></label><label>Display name<input name="display_name" /></label><label>Role<select name="role" defaultValue="auditor"><option>auditor</option><option>admin</option><option>owner</option></select></label></div><button>Add installation operator</button></form></section>
      <ControlTable title="Installation operators" items={installationOperators} renderActions={(item) => <>{["auditor", "admin", "owner"].filter((role) => role !== item.role).map((role) => <button key={role} onClick={() => void action("PATCH", `/v1/control/installation/operators/${String(item.id)}`, { role })}>Make {role}</button>)}<IconButton label="Remove installation role" icon="remove" tone="danger" onClick={() => void action("DELETE", `/v1/control/installation/operators/${String(item.id)}`)} /></>} />
    </section>)}
    {organization && <section className="control-scope">
      <div className="scope-heading"><p className="eyebrow">ONE ORGANIZATION</p><h3>Organization operators</h3><p>Invite owners, admins, auditors, or members. They do not become application users.</p></div>
      <section className="create-panel open"><form onSubmit={(event) => void invite(event)}><strong>Invite to {organization.name}</strong><div className="create-fields"><label>Email<input required name="email" type="email" /></label><label>Role<select name="role" defaultValue="member"><option>member</option><option>auditor</option><option>admin</option><option>owner</option></select></label></div><button>Invite organization operator</button></form></section>
      <ControlTable title={`${organization.name} operators`} items={members} renderActions={(item) => <>{["member", "auditor", "admin", "owner"].filter((role) => role !== item.role).map((role) => <button key={role} onClick={() => void action("PATCH", `/v1/control/organizations/${organization.id}/members/${String(item.id)}`, { role })}>Make {role}</button>)}<IconButton label="Remove organization member" icon="remove" tone="danger" onClick={() => void action("DELETE", `/v1/control/organizations/${organization.id}/members/${String(item.id)}`)} /></>} />
      <ControlTable title="Organization invitations" items={invitations} renderActions={(item) => item.status === "pending" ? <><IconButton label="Resend invitation" icon="send" onClick={() => void action("POST", `/v1/control/organizations/${organization.id}/invitations/${String(item.id)}/resend`, {})} /><IconButton label="Revoke invitation" icon="revoke" tone="danger" onClick={() => void action("DELETE", `/v1/control/organizations/${organization.id}/invitations/${String(item.id)}`)} /></> : null} />
    </section>}
  </>;
  if (section === "Policy" && organization) return <><PageSummary summary={`Limits and capabilities for ${organization.name}`} help="Installation operators define organization capacity and which capabilities its applications may expose. Organization operators can inspect this policy but cannot raise their own limits." /><OrganizationPolicySettings organization={organization} setMessage={setMessage} /></>;
  if (section === "Management API" && !organization) return <><PageSummary summary="External organization provisioning" help="The management API is a separate machine-only control boundary for provisioning organizations without granting access to this administrator interface." /><ManagementAPISettings setMessage={setMessage} /></>;
  if (section === "Email" && !organization) return <><PageSummary summary="Installation email defaults" help="These templates send control-plane messages and provide defaults for applications that have not published an application-specific override." /><InstallationTemplateSettings setMessage={setMessage} /></>;
  if (section === "Sessions") return <>
    <PageSummary summary="Active sessions for this operator account" help="Operator sessions belong to your control-plane identity and are independent of the currently selected organization or application." />
    <section className="control-scope"><ControlTable title="Your operator sessions" items={sessions} renderActions={(item) => item.revoked_at ? null : <IconButton label="Revoke session" icon="revoke" tone="danger" onClick={() => void action("DELETE", `/v1/control/auth/sessions/${String(item.id)}`)} />} /><button className="danger-action" onClick={() => void action("POST", "/v1/control/auth/logout-all", {})}>Log out every operator session</button></section>
  </>;
  return <div className="empty">This control page is unavailable in the selected context.</div>;
}

const organizationPolicySettings: { key: string; label: string; detail: string }[] = [
  { key: "public_registration", label: "Public registration", detail: "Applications may accept self-service sign-up." },
  { key: "password_authentication", label: "Password authentication", detail: "Applications may enable password sign-in." },
  { key: "passwordless_authentication", label: "Passwordless authentication", detail: "Applications may send email codes and magic links." },
  { key: "personal_api_keys", label: "Personal API keys", detail: "Application users may create personal access keys." },
  { key: "delegation", label: "Operator delegation", detail: "Organization administrators may create short-lived delegated sessions." },
  { key: "organization_provider_overrides", label: "Organization provider overrides", detail: "This organization may override installation SMTP, Stripe, Google, and Apple providers." },
  { key: "application_provider_overrides", label: "Application provider overrides", detail: "Applications may override inherited organization or installation providers." },
  { key: "custom_events", label: "Custom events", detail: "Applications may register and publish their own event contracts." },
  { key: "webhooks", label: "Outgoing webhooks", detail: "Applications may create outbound webhook endpoints." },
];

function OrganizationPolicySettings({ organization, setMessage }: { organization: Organization; setMessage: (value: string) => void }) {
  const [policy, setPolicy] = useState<OrganizationPolicy | null>(null);
  const [busy, setBusy] = useState(false);
  const canEdit = organization.role === "installation:owner" || organization.role === "installation:admin";
  useEffect(() => {
    api.request<OrganizationPolicy>("GET", `/v1/control/organizations/${organization.id}/policy`)
      .then(setPolicy)
      .catch((error) => setMessage(readError(error)));
  }, [organization.id, setMessage]);
  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!policy || !canEdit) return;
    const form = new FormData(event.currentTarget);
    const optionalLimit = (name: string) => {
      const raw = String(form.get(name) ?? "").trim();
      return raw === "" ? null : Number(raw);
    };
    const enabledSettings = Object.fromEntries(organizationPolicySettings.map(({ key }) => [key, form.get(key) === "on"]));
    setBusy(true);
    try {
      await api.request("PUT", `/v1/control/installation/organizations/${organization.id}/policy`, {
        max_applications: optionalLimit("max_applications"),
        max_users: optionalLimit("max_users"),
        enabled_settings: enabledSettings,
      }, { headers: { "If-Match": `"v${policy.version.toString(16)}"` } });
      const updated = await api.request<OrganizationPolicy>("GET", `/v1/control/organizations/${organization.id}/policy`);
      setPolicy(updated);
      setMessage(`Governance policy for ${organization.name} updated. Restrictions are enforced immediately.`);
    } catch (error) { setMessage(readError(error)); }
    finally { setBusy(false); }
  }
  if (!policy) return <LoadingState label="Loading organization governance policy" />;
  return <section className="governance-panel">
    <header><div><p className="eyebrow">INSTALLATION GOVERNANCE</p><h3>Limits and capabilities</h3></div><span className={canEdit ? "policy-owner" : "policy-locked"}>{canEdit ? "Control-plane managed" : "Read only"}</span></header>
    <p>These limits belong to the installation. Organization operators can inspect them but cannot change or bypass them.</p>
    <form key={policy.version} onSubmit={(event) => void save(event)}>
      <div className="policy-limits"><label>Maximum applications<input disabled={!canEdit} min="0" name="max_applications" type="number" defaultValue={policy.max_applications ?? ""} placeholder="Unlimited" /><small>{policy.usage.applications} currently active</small></label><label>Maximum users<input disabled={!canEdit} min="0" name="max_users" type="number" defaultValue={policy.max_users ?? ""} placeholder="Unlimited" /><small>{policy.usage.users} currently provisioned across applications</small></label></div>
      <div className="policy-settings">{organizationPolicySettings.map((setting) => <label key={setting.key}><input disabled={!canEdit} type="checkbox" name={setting.key} defaultChecked={policy.enabled_settings[setting.key] !== false} /><span><strong>{setting.label}</strong><small>{setting.detail}</small></span></label>)}</div>
      {canEdit && <button disabled={busy}>{busy ? "Applying policy..." : "Save installation policy"}</button>}
    </form>
  </section>;
}

function ManagementAPISettings({ setMessage }: { setMessage: (value: string) => void }) {
  const [status, setStatus] = useState<ManagementAPIStatus | null>(null);
  const [clients, setClients] = useState<Record<string, unknown>[]>([]);
  const [busy, setBusy] = useState("");
  const [refresh, setRefresh] = useState(0);
  useEffect(() => {
    Promise.all([
      api.request<ManagementAPIStatus>("GET", "/v1/control/installation/management-api"),
      api.request<Page<Record<string, unknown>>>("GET", "/v1/control/installation/management-clients"),
    ]).then(([managementStatus, page]) => { setStatus(managementStatus); setClients(page.items); })
      .catch((error) => setMessage(readError(error)));
  }, [refresh, setMessage]);
  async function toggle() {
    if (!status) return;
    setBusy("toggle");
    try {
      const updated = await api.request<{ enabled: boolean }>("PATCH", "/v1/control/installation/management-api", { enabled: !status.enabled });
      setStatus({ ...status, enabled: updated.enabled });
      setMessage(updated.enabled ? "Organization management API activated." : "Organization management API disabled. Existing management tokens are rejected immediately.");
    } catch (error) { setMessage(readError(error)); }
    finally { setBusy(""); }
  }
  async function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const target = event.currentTarget;
    const form = new FormData(target);
    setBusy("create");
    try {
      const result = await api.request<Record<string, unknown>>("POST", "/v1/control/installation/management-clients", { client_id: form.get("client_id"), name: form.get("name") });
      target.reset();
      setMessage(`Management client created. Store this secret now; it is shown once: ${String(result.client_secret)}`);
      setRefresh((value) => value + 1);
    } catch (error) { setMessage(readError(error)); }
    finally { setBusy(""); }
  }
  async function clientAction(method: "POST" | "DELETE", clientID: string) {
    setBusy(clientID);
    try {
      const result = await api.request<Record<string, unknown> | undefined>(method, `/v1/control/installation/management-clients/${clientID}${method === "POST" ? "/rotate-secret" : ""}`, method === "POST" ? {} : undefined);
      setMessage(result?.client_secret ? `Management secret rotated. Store it now; it is shown once: ${String(result.client_secret)}` : "Management client disabled. Its tokens are rejected immediately.");
      setRefresh((value) => value + 1);
    } catch (error) { setMessage(readError(error)); }
    finally { setBusy(""); }
  }
  if (!status) return <LoadingState label="Loading organization management API" />;
  return <section className="management-api-panel">
    <header><div><p className="eyebrow">EXTERNAL PROVISIONING</p><h3>Organization management API</h3><p>A separate machine-only control boundary for provisioning systems. Credentials cannot sign into this admin.</p></div>{status.can_manage ? <button disabled={busy !== ""} onClick={() => void toggle()}>{busy === "toggle" ? "Updating..." : status.enabled ? "Disable API" : "Activate API"}</button> : <span className="policy-locked">Read only</span>}</header>
    <div className="management-endpoints"><code>POST {status.token_endpoint}</code><code>{status.api_base}/organizations</code><span>{status.enabled ? "Accepting management tokens" : "Disabled at installation level"}</span></div>
    {status.can_manage && <form className="inline-create" onSubmit={(event) => void create(event)}><strong>New provisioning client</strong><input required name="client_id" placeholder="provisioning-production" /><input required name="name" placeholder="Provisioning service" /><button disabled={busy !== ""}>{busy === "create" ? "Creating..." : "Create client"}</button></form>}
    <ControlTable title="Management clients" items={clients} renderActions={(item) => !status.can_manage || item.disabled_at ? null : <><IconButton label="Rotate client secret" icon="key-rotate" loading={busy === item.id} disabled={busy !== ""} onClick={() => void clientAction("POST", String(item.id))} /><IconButton label="Disable management client" icon="disable" tone="danger" disabled={busy !== ""} onClick={() => void clientAction("DELETE", String(item.id))} /></>} />
  </section>;
}

const installationTemplateContext: Application = {
  id: "installation",
  name: "Platform93",
  slug: "platform93",
  issuer: "",
};

function InstallationTemplateSettings({ setMessage }: { setMessage: (value: string) => void }) {
  const basePath = "/v1/control/installation";
  const [templates, setTemplates] = useState<Record<string, unknown>[]>([]);
  const [selected, setSelected] = useState<Record<string, unknown> | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState("");
  const [refresh, setRefresh] = useState(0);
  useEffect(() => {
    setLoading(true);
    api.request<Page<Record<string, unknown>>>("GET", `${basePath}/notification-templates`)
      .then((page) => setTemplates(page.items))
      .catch((error) => setMessage(readError(error)))
      .finally(() => setLoading(false));
  }, [refresh, setMessage]);
  async function inspect(template: Record<string, unknown>) {
    setBusy(String(template.id));
    try {
      setSelected(await api.request<Record<string, unknown>>("GET", `${basePath}/notification-templates/${String(template.id)}`));
    } catch (error) { setMessage(readError(error)); }
    finally { setBusy(""); }
  }
  async function publish(template: Record<string, unknown>) {
    setBusy(String(template.id));
    try {
      await api.request("POST", `${basePath}/notification-templates/${String(template.id)}/publish`, {});
      setMessage(`${String(template.key)} is now the installation default. Applications without an override inherit it immediately.`);
      setSelected(null);
      setRefresh((value) => value + 1);
    } catch (error) { setMessage(readError(error)); }
    finally { setBusy(""); }
  }
  return <section className="installation-templates">
    <div className="scope-heading"><p className="eyebrow">DEFAULT EMAILS</p><h3>Installation email templates</h3><p>These published versions send Platform93 operator emails and are inherited by every application until that application publishes its own override.</p></div>
    {loading ? <LoadingState label="Loading installation email templates" /> : <section className="table"><div className="table-head"><span>Default templates</span><span>{templates.length} versions</span></div>{templates.map((template) => <article key={String(template.id)}><div><strong>{String(template.key)}</strong><small>{String(template.status)} · version {String(template.version)}{template.system_managed ? " · built in" : ""}</small></div><div className="row-actions"><IconButton label="Edit template" icon="edit" loading={busy === template.id} disabled={busy !== ""} onClick={() => void inspect(template)} />{template.status === "draft" && <IconButton label="Publish template" icon="publish" tone="success" disabled={busy !== ""} onClick={() => void publish(template)} />}</div></article>)}</section>}
    {selected && <div className="detail-backdrop" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && setSelected(null)}><section className="detail-panel template-detail-panel" role="dialog" aria-modal="true" aria-label="Installation email template"><header><div><p className="eyebrow">INSTALLATION DEFAULT</p><h2>{String(selected.key)}</h2></div><button className="outline" onClick={() => setSelected(null)}>Close</button></header><NotificationTemplateEditor template={selected} application={installationTemplateContext} basePath={basePath} setMessage={setMessage} onChanged={() => { setSelected(null); setRefresh((value) => value + 1); }} /></section></div>}
  </section>;
}

function ApplicationFlowSettings({ basePath, setMessage }: { basePath: string; setMessage: (value: string) => void }) {
  const [application, setApplication] = useState<Application | null>(null);
  const [clients, setClients] = useState<Record<string, unknown>[]>([]);
  const [busy, setBusy] = useState(false);
  const [refresh, setRefresh] = useState(0);
  useEffect(() => {
    Promise.all([
      api.request<Application>("GET", basePath),
      api.request<Page<Record<string, unknown>>>("GET", `${basePath}/clients`),
    ]).then(([current, clientPage]) => {
      setApplication(current);
      setClients(clientPage.items.filter((client) => client.client_type === "public" && Array.isArray(client.allowed_grants) && client.allowed_grants.includes("authorization_code")));
    }).catch((error) => setMessage(readError(error)));
  }, [basePath, refresh, setMessage]);
  const auth = application?.auth_config ?? {};
  const flows = (auth.flows && typeof auth.flows === "object" ? auth.flows : {}) as Record<string, unknown>;
  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!application) return;
    const form = new FormData(event.currentTarget);
    setBusy(true);
    try {
      await api.request("PATCH", `${basePath}/auth-config`, { flows: {
        oauth_client_id: form.get("oauth_client_id"),
        sign_in_redirect_uri: form.get("sign_in_redirect_uri"),
        invitation_redirect_uri: form.get("invitation_redirect_uri"),
      } }, { headers: { "If-Match": `"v${Number(application.version ?? 1).toString(16)}"` } });
      setMessage("Application sign-in and invitation redirects saved. OAuth authorization uses S256 PKCE with the selected public client.");
      setRefresh((value) => value + 1);
    } catch (error) { setMessage(readError(error)); }
    finally { setBusy(false); }
  }
  return <section className="application-flow-settings">
    <header><div><span>AUTH FLOW</span><h4>Application redirects</h4></div><p>Email links return to the sign-in callback. The browser SDK then creates an OAuth authorization request with a generated verifier and S256 challenge.</p></header>
    {clients.length === 0 ? <div className="provider-empty">Create a public OAuth client with the authorization_code grant before configuring redirects.</div> : <form key={`${application?.version ?? 0}-${refresh}`} onSubmit={(event) => void save(event)}>
      <label>Public OAuth client<select required name="oauth_client_id" defaultValue={String(flows.oauth_client_id ?? "")}><option value="" disabled>Select a client</option>{clients.map((client) => <option key={String(client.id)} value={String(client.client_id)}>{String(client.name)} · {String(client.client_id)}</option>)}</select></label>
      <label>Sign-in redirect URI<input required name="sign_in_redirect_uri" type="url" defaultValue={String(flows.sign_in_redirect_uri ?? "")} placeholder="https://app.example/auth/callback" /><small>Must exactly match a registered redirect URI on the selected client.</small></label>
      <label>Invitation redirect URI<input required name="invitation_redirect_uri" type="url" defaultValue={String(flows.invitation_redirect_uri ?? "")} placeholder="https://app.example/invitations/accept" /><small>Receives one-time workspace invitation credentials and must share the sign-in origin.</small></label>
      <button disabled={busy}>{busy ? "Saving flow..." : "Save application flow"}</button>
    </form>}
  </section>;
}

function ProviderSettings({ basePath, scope, setMessage }: { basePath: string; scope: "installation" | "organization" | "application"; setMessage: (value: string) => void }) {
  const [authProviders, setAuthProviders] = useState<Record<string, unknown>[]>([]);
  const [smtpProviders, setSMTPProviders] = useState<Record<string, unknown>[]>([]);
  const [billingProviders, setBillingProviders] = useState<Record<string, unknown>[]>([]);
  const [storageProviders, setStorageProviders] = useState<Record<string, unknown>[]>([]);
  const [refresh, setRefresh] = useState(0);
  const [busy, setBusy] = useState("");
  const canInherit = scope !== "application";
  useEffect(() => {
    Promise.all([
      api.request<Page<Record<string, unknown>>>("GET", `${basePath}/auth/providers`),
      api.request<Page<Record<string, unknown>>>("GET", `${basePath}/notification-providers`),
      api.request<Page<Record<string, unknown>>>("GET", `${basePath}/billing/providers`),
      api.request<Page<Record<string, unknown>>>("GET", `${basePath}/storage/providers`),
    ]).then(([auth, smtp, billing, storage]) => {
      setAuthProviders(auth.items);
      setSMTPProviders(smtp.items);
      setBillingProviders(billing.items);
      setStorageProviders(storage.items);
    }).catch((error) => setMessage(readError(error)));
  }, [basePath, refresh, setMessage]);
  async function submitProvider(event: FormEvent<HTMLFormElement>, kind: "google" | "apple" | "smtp" | "stripe" | "storage") {
    event.preventDefault();
    const target = event.currentTarget;
    const form = new FormData(target);
    setBusy(kind);
    try {
      if (kind === "google") await api.request("PUT", `${basePath}/auth/providers/google`, { client_id: form.get("client_id"), client_secret: form.get("client_secret"), inheritable: form.get("inheritable") === "on" });
      if (kind === "apple") await api.request("PUT", `${basePath}/auth/providers/apple`, { client_id: form.get("client_id"), team_id: form.get("team_id"), key_id: form.get("key_id"), private_key_pem: form.get("private_key_pem"), inheritable: form.get("inheritable") === "on" });
      if (kind === "smtp") await api.request("POST", `${basePath}/notification-providers`, { ...smtpProviderInput(form), inheritable: form.get("inheritable") === "on" });
      if (kind === "stripe") await api.request("POST", `${basePath}/billing/providers`, { provider: "stripe", secret: form.get("secret"), webhook_secret: form.get("webhook_secret"), api_version: "2026-04-22.dahlia", inheritable: form.get("inheritable") === "on" });
      if (kind === "storage") await api.request("POST", `${basePath}/storage/providers`, storageProviderInput(form, scope));
      target.reset();
      setMessage(`${kind === "smtp" ? "SMTP" : kind === "stripe" ? "Stripe" : kind === "storage" ? "S3-compatible storage" : `${titleCase(kind)} login`} provider saved at the ${scope} scope.`);
      setRefresh((value) => value + 1);
    } catch (error) { setMessage(readError(error)); }
    finally { setBusy(""); }
  }
  async function disable(kind: "auth" | "notification" | "billing" | "storage", provider: Record<string, unknown>) {
    const providerScope = String(provider.scope ?? scope);
    if (providerScope !== scope) {
      setMessage(`${errorMessagePrefix}This provider is inherited from ${providerScope}. Select that context to manage it.`);
      return;
    }
    const identity = kind === "auth" ? String(provider.provider) : String(provider.id);
    setBusy(`disable-${identity}`);
    try {
      const confirmation = kind === "storage" ? "?confirm_affected_objects=true" : "";
      if (kind === "storage" && !globalThis.confirm("Disable this storage provider? Platform93 operations will stop. Existing anonymous public URLs and unexpired private URLs cannot be revoked by this action.")) return;
      await api.request("DELETE", `${basePath}/${kind === "auth" ? "auth/providers" : kind === "notification" ? "notification-providers" : kind === "billing" ? "billing/providers" : "storage/providers"}/${identity}${confirmation}`);
      setMessage("Provider disabled. Children will resolve the next available inherited provider.");
      setRefresh((value) => value + 1);
    } catch (error) { setMessage(readError(error)); }
    finally { setBusy(""); }
  }
  async function verify(kind: "notification" | "billing" | "storage", provider: Record<string, unknown>) {
    const providerScope = String(provider.scope ?? scope);
    if (providerScope !== scope) {
      setMessage(`${errorMessagePrefix}This provider is inherited from ${providerScope}. Select that context to verify it.`);
      return;
    }
    const identity = String(provider.id);
    setBusy(`verify-${identity}`);
    try {
      await api.request("POST", `${basePath}/${kind === "notification" ? "notification-providers" : kind === "billing" ? "billing/providers" : "storage/providers"}/${identity}/verify`, {});
      setMessage(`${kind === "notification" ? "SMTP" : kind === "billing" ? "Stripe" : "Storage"} provider verified successfully.`);
      setRefresh((value) => value + 1);
    } catch (error) { setMessage(readError(error)); }
    finally { setBusy(""); }
  }
  async function enableStorage(provider: Record<string, unknown>) {
    if (String(provider.scope ?? scope) !== scope) {
      setMessage(`${errorMessagePrefix}This provider is inherited. Select its owning context to enable it.`);
      return;
    }
    const identity = String(provider.id);
    setBusy(`enable-${identity}`);
    try {
      await api.request("POST", `${basePath}/storage/providers/${identity}/enable`, {});
      setMessage("Storage provider enabled. Previously verified configuration is available again; changed configuration remains unverified.");
      setRefresh((value) => value + 1);
    } catch (error) { setMessage(readError(error)); }
    finally { setBusy(""); }
  }
  async function toggleInheritance(kind: "auth" | "notification" | "billing" | "storage", provider: Record<string, unknown>, inheritable: boolean) {
    const providerScope = String(provider.scope ?? scope);
    if (scope === "application" || providerScope !== scope) {
      setMessage(`${errorMessagePrefix}Select the provider's owning context to change its inheritance.`);
      return;
    }
    const identity = kind === "auth" ? String(provider.provider) : String(provider.id);
    setBusy(`inherit-${identity}`);
    try {
      await api.request("PATCH", `${basePath}/${kind === "auth" ? "auth/providers" : kind === "notification" ? "notification-providers" : kind === "billing" ? "billing/providers" : "storage/providers"}/${identity}`, { inheritable });
      setMessage(inheritable
        ? `${providerDisplayName(kind, provider)} is now ${scope === "installation" ? "a global default for organizations and applications" : "available to applications in this organization"}.`
        : `${providerDisplayName(kind, provider)} is now limited to the ${scope} scope.`);
      setRefresh((value) => value + 1);
    } catch (error) { setMessage(readError(error)); }
    finally { setBusy(""); }
  }
  const inheritanceField = () => canInherit ? <label className="provider-inheritance"><input name="inheritable" type="checkbox" defaultChecked /><span>{scope === "installation" ? "Use as global default for organizations and applications" : "Allow applications in this organization to inherit this provider"}</span></label> : null;
  return <section className="provider-settings control-scope">
    <div className="scope-heading"><p className="eyebrow">PROVIDER RESOLUTION</p><h3>{scope === "application" ? "Application integrations" : `${titleCase(scope)} providers`}</h3><p>Resolution order is application, organization, then installation. A local provider overrides inherited providers of the same type. Secrets are encrypted and never returned.</p></div>
    {scope === "application" && <ApplicationFlowSettings basePath={basePath} setMessage={setMessage} />}
    <div className="provider-columns">
      <section><header><span>01</span><div><h4>Authentication</h4><p>Social identity and account linking.</p></div></header><ProviderCards items={authProviders} currentScope={scope} busy={busy} onToggleInheritance={(item, value) => void toggleInheritance("auth", item, value)} onDisable={(item) => void disable("auth", item)} />
        <details><summary>Configure Google</summary><form onSubmit={(event) => void submitProvider(event, "google")}><label>OAuth client ID<input required name="client_id" /></label><label>OAuth client secret<input required name="client_secret" type="password" /></label>{inheritanceField()}<button disabled={busy !== ""}>{busy === "google" ? "Saving..." : "Save Google"}</button></form></details>
        <details><summary>Configure Apple</summary><form onSubmit={(event) => void submitProvider(event, "apple")}><label>Services ID / client ID<input required name="client_id" /></label><label>Team ID<input required name="team_id" /></label><label>Key ID<input required name="key_id" /></label><label>Sign in with Apple private key<textarea required name="private_key_pem" placeholder="-----BEGIN PRIVATE KEY-----" /></label>{inheritanceField()}<button disabled={busy !== ""}>{busy === "apple" ? "Saving..." : "Save Apple"}</button></form></details>
      </section>
      <section><header><span>02</span><div><h4>Email</h4><p>Transactional and security delivery.</p></div></header><ProviderCards items={smtpProviders} currentScope={scope} busy={busy} onToggleInheritance={(item, value) => void toggleInheritance("notification", item, value)} onVerify={(item) => void verify("notification", item)} onDisable={(item) => void disable("notification", item)} />
        <details><summary>Configure SMTP</summary><form onSubmit={(event) => void submitProvider(event, "smtp")}><label>Name<input required name="name" defaultValue={`${scope} SMTP`} /></label><label>Host<input required name="host" /></label><div className="provider-form-row"><label>Port<input required name="port" type="number" defaultValue="587" /></label><label>TLS<select name="tls_mode" defaultValue="starttls"><option value="starttls">STARTTLS</option><option value="implicit_tls">Implicit TLS</option></select></label></div><label>Username<input name="username" /></label><label>Password<input name="password" type="password" /></label><label>Sender email<input required name="sender_email" type="email" /></label><label>Sender name<input name="sender_name" defaultValue="Platform93" /></label>{inheritanceField()}<button disabled={busy !== ""}>{busy === "smtp" ? "Saving..." : "Save SMTP"}</button></form></details>
      </section>
      <section><header><span>03</span><div><h4>Billing</h4><p>Checkout, subscriptions, and tax.</p></div></header><ProviderCards items={billingProviders} currentScope={scope} busy={busy} onToggleInheritance={(item, value) => void toggleInheritance("billing", item, value)} onVerify={(item) => void verify("billing", item)} onDisable={(item) => void disable("billing", item)} />
        <details><summary>Configure Stripe</summary><form onSubmit={(event) => void submitProvider(event, "stripe")}><label>Secret key<input required name="secret" type="password" placeholder="sk_..." /></label><label>Webhook signing secret<input name="webhook_secret" type="password" placeholder="whsec_..." /></label>{inheritanceField()}<button disabled={busy !== ""}>{busy === "stripe" ? "Saving..." : "Save Stripe"}</button></form></details>
      </section>
      <section><header><span>04</span><div><h4>Object storage</h4><p>Light public and private S3-compatible files.</p></div></header><ProviderCards items={storageProviders} currentScope={scope} busy={busy} onToggleInheritance={(item, value) => void toggleInheritance("storage", item, value)} onVerify={(item) => void verify("storage", item)} onEnable={(item) => void enableStorage(item)} onDisable={(item) => void disable("storage", item)} />
        <details><summary>Configure S3-compatible storage</summary><form onSubmit={(event) => void submitProvider(event, "storage")}><label>Name<input required name="name" defaultValue={`${titleCase(scope)} storage`} /></label><label>Endpoint<input required name="endpoint" type="url" placeholder="https://nbg1.your-objectstorage.com" /></label><label>Region<input required name="region" placeholder="nbg1" /></label><div className="provider-form-row"><label>Access key ID<input required name="access_key_id" /></label><label>Secret access key<input required name="secret_access_key" type="password" /></label></div><label>Public bucket<input name="public_bucket" placeholder="platform93-public" /><small>Required for managed email images and permanent public URLs.</small></label><label>Private bucket<input name="private_bucket" placeholder="platform93-private" /></label><label>Public base URL<input name="public_base_url" type="url" placeholder="https://assets.example.com" /><small>Optional proxy or custom-domain base URL.</small></label><div className="provider-form-row"><label>Max object bytes<input name="max_object_bytes" type="number" min="1" defaultValue="26214400" /></label><label>Application quota bytes<input name="max_application_bytes" type="number" min="1" defaultValue="10737418240" /></label></div><div className="provider-form-row"><label>Email image bytes<input name="max_email_image_bytes" type="number" min="1" defaultValue="2097152" /></label><label>Application object count<input name="max_application_objects" type="number" min="1" defaultValue="100000" /></label></div><label className="provider-inheritance"><input name="force_path_style" type="checkbox" /><span>Use path-style bucket URLs (commonly required by MinIO)</span></label>{scope === "installation" && <label className="provider-inheritance"><input name="allow_private_endpoint" type="checkbox" /><span>Explicitly allow an HTTP or private-network endpoint</span></label>}{inheritanceField()}<p className="provider-warning">Use existing dedicated buckets. Verification writes and removes a probe, confirms public anonymous reads, and rejects anonymous private reads. Browser uploads also require bucket CORS.</p><button disabled={busy !== ""}>{busy === "storage" ? "Saving..." : "Save storage"}</button></form></details>
      </section>
    </div>
    <StorageObjectManager basePath={basePath} allowUploads={scope !== "organization"} compact setMessage={setMessage} />
  </section>;
}

function ProviderCards({ items, currentScope, busy, onToggleInheritance, onVerify, onEnable, onDisable }: { items: Record<string, unknown>[]; currentScope: string; busy: string; onToggleInheritance?: (item: Record<string, unknown>, inheritable: boolean) => void; onVerify?: (item: Record<string, unknown>) => void; onEnable?: (item: Record<string, unknown>) => void; onDisable: (item: Record<string, unknown>) => void }) {
  if (items.length === 0) return <div className="provider-empty">No provider resolves at this scope.</div>;
  return <div className="provider-cards">{items.map((item, index) => {
    const scope = String(item.scope ?? currentScope);
    const identity = String(item.id ?? item.provider);
    const local = scope === currentScope;
    const disabled = Boolean(item.disabled_at);
    const name = String(item.name ?? item.provider);
    return <article key={String(item.id ?? `${item.provider}-${index}`)}>
      <div><strong>{name}</strong><span className={`provider-source ${local ? "local" : "inherited"}`}>{local ? `${titleCase(scope)} provider` : `Inherited from ${scope}`}</span></div>
      <code>{String(item.client_id ?? item.sender_email ?? item.public_id ?? "configured")}</code>
      <small>{item.verified_at && !disabled ? "Verified" : item.status ? `Status: ${String(item.status)}` : item.inheritable ? "Available to children" : scope === "application" ? "Application only" : "This scope only"}</small>
      {local && currentScope !== "application" && onToggleInheritance && !disabled && <label className="provider-global-toggle"><input type="checkbox" checked={Boolean(item.inheritable)} disabled={busy !== ""} onChange={(event) => onToggleInheritance(item, event.currentTarget.checked)} /><span>{busy === `inherit-${identity}` ? "Updating availability..." : currentScope === "installation" ? "Global default for organizations and applications" : "Available to applications in this organization"}</span></label>}
      {local && !disabled && <ActionGroup label={`${name} provider actions`} className="provider-card-actions">
        {onVerify && <IconButton label={`Verify ${name}`} icon="verify" tone="success" loading={busy === `verify-${identity}`} disabled={busy !== ""} onClick={() => onVerify(item)} />}
        <IconButton label={`Disable ${name}`} icon="disable" tone="danger" loading={busy === `disable-${identity}`} disabled={busy !== ""} onClick={() => onDisable(item)} />
      </ActionGroup>}
      {local && disabled && onEnable && <ActionGroup label={`${name} provider actions`} className="provider-card-actions"><IconButton label={`Enable ${name}`} icon="disable" loading={busy === `enable-${identity}`} disabled={busy !== ""} onClick={() => onEnable(item)} /></ActionGroup>}
    </article>;
  })}</div>;
}

function StorageObjectManager({ basePath, allowUploads, compact = false, setMessage }: { basePath: string; allowUploads: boolean; compact?: boolean; setMessage: (value: string) => void }) {
  const [objects, setObjects] = useState<StorageObject[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState("");
  const [refresh, setRefresh] = useState(0);
  useEffect(() => {
    setLoading(true);
    api.request<Page<StorageObject>>("GET", `${basePath}/storage/objects`)
      .then((page) => setObjects(page.items))
      .catch((error) => setMessage(readError(error)))
      .finally(() => setLoading(false));
  }, [basePath, refresh, setMessage]);
  async function upload(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const target = event.currentTarget;
    const form = new FormData(target);
    const file = form.get("file");
    if (!(file instanceof File) || file.size === 0) return;
    const visibility = String(form.get("visibility")) as "public" | "private";
    const purpose = form.get("purpose") === "email_image" ? "email_image" : undefined;
    setBusy("upload");
    try {
      const authorization = await api.request<StorageUploadAuthorization>("POST", `${basePath}/storage/uploads`, {
        filename: file.name, content_type: file.type || "application/octet-stream", size_bytes: file.size, visibility, purpose,
      }, { idempotencyKey: crypto.randomUUID() });
      const headers = new Headers(authorization.required_headers);
      headers.delete("content-length");
      const uploadResponse = await globalThis.fetch(authorization.upload_url, { method: "PUT", headers, body: file });
      if (!uploadResponse.ok) throw new Error(`S3 upload returned HTTP ${uploadResponse.status}. Verify bucket CORS and provider permissions.`);
      await api.request("POST", `${basePath}/storage/uploads/${authorization.object.id}/complete`);
      target.reset();
      setMessage(`${file.name} uploaded and verified.`);
      setRefresh((value) => value + 1);
    } catch (error) { setMessage(readError(error)); }
    finally { setBusy(""); }
  }
  async function download(object: StorageObject) {
    setBusy(`download-${object.id}`);
    try {
      const result = await api.request<{ url: string }>("POST", `${basePath}/storage/objects/${object.id}/download`);
      globalThis.open(result.url, "_blank", "noopener,noreferrer");
    } catch (error) { setMessage(readError(error)); }
    finally { setBusy(""); }
  }
  async function remove(object: StorageObject) {
    if (!globalThis.confirm(`Delete ${object.filename}? Referenced email images cannot be deleted without a forced audited operation.`)) return;
    setBusy(`delete-${object.id}`);
    try {
      await api.request("DELETE", `${basePath}/storage/objects/${object.id}`);
      setMessage(`${object.filename} deletion queued.`);
      setRefresh((value) => value + 1);
    } catch (error) { setMessage(readError(error)); }
    finally { setBusy(""); }
  }
  return <section className={`storage-manager ${compact ? "compact" : "control-scope"}`}>
    <div className="scope-heading"><p className="eyebrow">LIGHT OBJECT STORAGE</p><h3>Stored objects</h3><p>Use this for assets and modest application files, not as a primary database or high-throughput media pipeline. Private downloads are authorized and expire; public URLs are anonymous and permanent.</p></div>
    {allowUploads && <form className="storage-upload" onSubmit={(event) => void upload(event)}><label>File<input required name="file" type="file" /></label><label>Visibility<select name="visibility" defaultValue="private"><option value="private">Private</option><option value="public">Public</option></select></label><label>Purpose<select name="purpose" defaultValue="general"><option value="general">General object</option><option value="email_image">Email image (PNG, JPEG, GIF)</option></select></label><button disabled={busy !== ""}>{busy === "upload" ? "Uploading and verifying..." : "Upload object"}</button></form>}
    {loading ? <LoadingState label="Loading stored objects" /> : <div className="storage-object-list">{objects.length === 0 ? <div className="provider-empty">No objects have been reserved or uploaded at this scope.</div> : objects.map((object) => <article key={object.id}><div><strong>{object.filename}</strong><span>{object.visibility} · {object.status}</span></div><small>{object.owner_type}{object.owner_id ? ` · ${object.owner_id}` : ""} · {formatBytes(object.size_bytes)} · {object.content_type}</small><code>{object.id}</code><ActionGroup label={`${object.filename} object actions`}>{object.public_url && <a href={object.public_url} target="_blank" rel="noreferrer">Public URL</a>}<IconButton label={`Open ${object.filename}`} icon="download" loading={busy === `download-${object.id}`} disabled={busy !== "" || object.status !== "ready"} onClick={() => void download(object)} /><IconButton label={`Delete ${object.filename}`} icon="trash" tone="danger" loading={busy === `delete-${object.id}`} disabled={busy !== "" || object.status === "deleting"} onClick={() => void remove(object)} /></ActionGroup></article>)}</div>}
  </section>;
}

function formatBytes(value: number) {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KiB`;
  if (value < 1024 * 1024 * 1024) return `${(value / 1024 / 1024).toFixed(1)} MiB`;
  return `${(value / 1024 / 1024 / 1024).toFixed(1)} GiB`;
}

function providerDisplayName(kind: "auth" | "notification" | "billing" | "storage", provider: Record<string, unknown>) {
  if (kind === "notification") return "SMTP";
  if (kind === "billing") return "Stripe";
  if (kind === "storage") return "Storage";
  return `${titleCase(String(provider.provider))} login`;
}

function ControlTable({ title, items, renderActions }: { title: string; items: Record<string, unknown>[]; renderActions: (item: Record<string, unknown>) => ReactNode }) {
  return <section className="table"><div className="table-head"><span>{title}</span><span>{items.length} records</span></div>{items.length === 0 ? <div className="table-empty">No records yet.</div> : items.map((item, index) => <article key={String(item.id ?? index)}><div><strong>{String(item.display_name ?? item.email ?? item.user_agent ?? item.id)}</strong><small>{String(item.role ?? item.status ?? item.ip_address ?? "")}</small></div><div className="row-actions">{renderActions(item)}<code>{String(item.id ?? "")}</code></div></article>)}</section>;
}

function Toast({ message, onDismiss }: { message: string; onDismiss: () => void }) {
  const failed = message.startsWith(errorMessagePrefix);
  const dismissRef = useRef(onDismiss);
  dismissRef.current = onDismiss;
  useEffect(() => {
    if (failed) return;
    const timeout = window.setTimeout(() => dismissRef.current(), 4000);
    return () => window.clearTimeout(timeout);
  }, [failed, message]);
  return <div className={`toast ${failed ? "toast-error" : "toast-success"}`} role={failed ? "alert" : "status"} aria-live={failed ? "assertive" : "polite"}>
    <div><strong>{failed ? "Request failed" : "Completed"}</strong><span>{toastBody(message)}</span></div>
    <button onClick={onDismiss} aria-label="Dismiss notification">Dismiss</button>
  </div>;
}

function toastBody(message: string) {
  return message.startsWith(errorMessagePrefix) ? message.slice(errorMessagePrefix.length) : message;
}

function titleCase(value: string) {
  return value.charAt(0).toUpperCase() + value.slice(1);
}

function readError(error: unknown) {
  if (error instanceof Platform93Error) {
    const problem = error.problem;
    const detail = problem.detail ?? problem.title ?? error.message;
    const context = [`code ${problem.code}`, `HTTP ${problem.status}`];
    if (problem.request_id) context.push(`request ${problem.request_id}`);
    return `${errorMessagePrefix}${detail} (${context.join(", ")})`;
  }
  if (error instanceof Error) {
    return `${errorMessagePrefix}The request could not be completed: ${error.message}`;
  }
  return `${errorMessagePrefix}The request failed for an unknown reason. Check the service logs and try again.`;
}
function smtpInput(form: FormData) {
  return {
    name: "Installation SMTP",
    host: form.get("host"),
    port: Number(form.get("port") ?? 587),
    username: form.get("username"),
    password: form.get("password"),
    tls_mode: form.get("tls_mode"),
    sender_email: form.get("sender_email"),
    sender_name: "Platform93",
  };
}

function smtpProviderInput(form: FormData) {
  return {
    name: form.get("name"),
    host: form.get("host"),
    port: Number(form.get("port") ?? 587),
    username: form.get("username"),
    password: form.get("password"),
    tls_mode: form.get("tls_mode"),
    sender_email: form.get("sender_email"),
    sender_name: form.get("sender_name"),
  };
}

function storageProviderInput(form: FormData, scope: "installation" | "organization" | "application") {
  const optional = (name: string) => String(form.get(name) ?? "").trim() || undefined;
  return {
    name: form.get("name"), endpoint: form.get("endpoint"), region: form.get("region"), access_key_id: form.get("access_key_id"),
    secret_access_key: form.get("secret_access_key"), force_path_style: form.get("force_path_style") === "on",
    public_bucket: optional("public_bucket"), private_bucket: optional("private_bucket"), public_base_url: optional("public_base_url"),
    inheritable: form.get("inheritable") === "on", allow_private_endpoint: scope === "installation" && form.get("allow_private_endpoint") === "on",
    max_object_bytes: Number(form.get("max_object_bytes")), max_email_image_bytes: Number(form.get("max_email_image_bytes")),
    max_application_bytes: Number(form.get("max_application_bytes")), max_application_objects: Number(form.get("max_application_objects")),
  };
}
