import type { Platform93Client, CreateInvitation, InvitationExchange } from "./index.js";
import type * as Contract from "./generated/types.gen.js";

export type ManagedUserCreate = Contract.ApplicationManagedUserCreate;
export type ManagedUserUpdate = Contract.ApplicationManagedUserUpdate;
export type ManagedUserAttributes = Contract.ApplicationManagedAttributesUpdate;
export type ManagedRoleAssignment = Contract.ApplicationUserRoleAssignment;
export type InvitationDeliveryResult = Contract.InvitationDeliveryResult;
export type InvitationRotationResult = Contract.InvitationRotationResult;
export type InvitationAuthenticationChallenge = Contract.InvitationAuthenticationChallenge;
export type UserAdministrationAction = "suspend" | "restore" | "verify-email" | "unverify-email" | "verify-organization" | "unverify-organization" | "sessions/revoke";
export type AdministrationSearch = { query?: string; cursor?: string; limit?: number };

/** Uses the supplied application-user or explicitly scoped machine token only. */
export class ApplicationAdministrationClient {
  constructor(private readonly client: Platform93Client, private readonly applicationId: string) {}
  private path(value: string) { return `/v1/applications/${encodeURIComponent(this.applicationId)}${value}`; }
  private search(path: string, options: AdministrationSearch & { user_id?: string }) {
    const query = new URLSearchParams();
    for (const [key, value] of Object.entries(options)) {
      if (value !== undefined) query.set(key, String(value));
    }
    return this.path(path) + (query.size ? `?${query}` : "");
  }
  listUsers(search: { query?: string; cursor?: string; limit?: number } = {}) {
    const query = new URLSearchParams(Object.entries(search).map(([key, value]) => [key, String(value)]));
    return this.client.request<Contract.UserPage>("GET", this.path(`/users?${query}`));
  }
  getUser(id: string) { return this.client.request<Contract.User>("GET", this.path(`/users/${encodeURIComponent(id)}`)); }
  createUser(input: ManagedUserCreate, idempotencyKey: string) { return this.client.request<Contract.User>("POST", this.path("/users"), input, { idempotencyKey }); }
  updateUser(id: string, input: ManagedUserUpdate, etag: string) { return this.client.request<void>("PATCH", this.path(`/users/${encodeURIComponent(id)}`), input, { headers: { "If-Match": etag } }); }
  updateUserAttributes(id: string, input: ManagedUserAttributes, etag: string) { return this.client.request<void>("PATCH", this.path(`/users/${encodeURIComponent(id)}/attributes`), input, { headers: { "If-Match": etag } }); }
  changeUserState(id: string, action: UserAdministrationAction, reason: string, etag: string, idempotencyKey: string) {
    return this.client.request<void>("POST", this.path(`/users/${encodeURIComponent(id)}/${action}`), { reason }, { idempotencyKey, headers: { "If-Match": etag } });
  }
  listUserSessions(id: string, search: AdministrationSearch = {}) { return this.client.request<Contract.ApplicationManagedSessionPage>("GET", this.search(`/users/${encodeURIComponent(id)}/sessions`,search)); }
  listRoles(search: AdministrationSearch = {}) { return this.client.request<Contract.RolePage>("GET", this.search("/roles",search)); }
  listUserRoleAssignments(userId: string, search: AdministrationSearch = {}) { return this.client.request<Contract.ApplicationUserRoleAssignmentPage>("GET", this.search("/role-assignments", { ...search, user_id: userId })); }
  assignRole(input: ManagedRoleAssignment, userEtag: string, idempotencyKey: string) { return this.client.request<Contract.RoleAssignmentRecord>("POST", this.path("/role-assignments"), input, { idempotencyKey, headers: { "If-Match": userEtag } }); }
  removeRoleAssignment(id: string, reason: string, userEtag: string) { return this.client.request<void>("DELETE", this.path(`/role-assignments/${encodeURIComponent(id)}`), { reason }, { headers: { "If-Match": userEtag } }); }
  createInvitation(input: CreateInvitation, idempotencyKey: string) { return this.client.request<InvitationDeliveryResult>("POST", this.path("/invitations"), input, { idempotencyKey }); }
  listInvitations(search: AdministrationSearch = {}) { return this.client.request<Contract.ApplicationInvitationPage>("GET", this.search("/invitations",search)); }
  getInvitation(id: string) { return this.client.request<Contract.ApplicationInvitation>("GET", this.path(`/invitations/${encodeURIComponent(id)}`)); }
  rotateInvitation(id: string, input: { send_email?: boolean; reason: string }, etag: string, idempotencyKey: string) { return this.client.request<InvitationRotationResult>("POST", this.path(`/invitations/${encodeURIComponent(id)}/rotate`), input, { idempotencyKey, headers: { "If-Match": etag } }); }
  revokeInvitation(id: string, reason: string, etag: string) { return this.client.request<void>("DELETE", this.path(`/invitations/${encodeURIComponent(id)}`), { reason }, { headers: { "If-Match": etag } }); }
}

export type InvitationEmailProof = Pick<InvitationExchange, "authentication_challenge_id" | "authentication_code" | "authentication_link_token">;
