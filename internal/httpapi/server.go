package httpapi

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	pathpkg "path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/supaapps/platform93/internal/buildinfo"
	"github.com/supaapps/platform93/internal/identity"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/platform"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

var (
	httpRequests = promauto.NewCounterVec(prometheus.CounterOpts{Name: "platform93_http_requests_total", Help: "HTTP requests by route, method, and status."}, []string{"route", "method", "status"})
	httpDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{Name: "platform93_http_request_duration_seconds", Help: "HTTP request duration by route and method.", Buckets: prometheus.DefBuckets}, []string{"route", "method"})
)

var inlineScriptPattern = regexp.MustCompile(`(?s)<script(?:\s[^>]*)?>(.*?)</script>`)

type Server struct {
	app         *platform.App
	adminAssets string
}

func New(app *platform.App, adminAssets string) http.Handler {
	s := &Server{app: app, adminAssets: adminAssets}
	r := chi.NewRouter()
	// Do not trust forwarding headers until an explicit trusted-proxy boundary is configured.
	r.Use(middleware.Recoverer, s.requestContext, s.accessLog, s.securityHeaders, s.cors)
	r.Get("/healthz", s.health)
	r.Get("/readyz", s.ready)
	r.Get("/version", s.version)
	r.Handle("/metrics", promhttp.Handler())

	r.Route("/v1", func(r chi.Router) {
		r.Get("/setup/status", s.setupStatus)
		r.Post("/setup/bootstrap", s.bootstrap)
		r.With(s.requireSetup).Post("/setup/complete", s.completeSetup)
		r.With(s.requireSetup).Post("/setup/notification-providers", s.createInstallationNotificationProvider)
		r.Get("/auth/providers/google/callback", s.routeGoogleCallback)
		r.Post("/auth/providers/apple/callback", s.routeAppleCallback)
		r.Get("/auth/providers/{provider}/callback", s.routeSocialCallback)
		r.Get("/control/auth/methods", s.controlAuthMethods)
		r.Post("/control/auth/providers/{provider}/start", s.startControlProviderLogin)
		r.Post("/control/invitations/providers/{provider}/start", s.startControlInvitationProvider)
		r.Post("/control/auth/email/start", s.controlUserEmailStart)
		r.Post("/control/auth/email/verify", s.controlUserEmailVerify)
		r.Post("/control/auth/password", s.controlUserPasswordLogin)
		r.Post("/control/auth/token/refresh", s.refreshControlUserSession)
		r.Post("/control/auth/logout", s.controlUserLogout)
		r.Post("/control/invitations/accept", s.acceptOrganizationInvitation)
		r.Group(func(r chi.Router) {
			r.Use(s.requireControlUser)
			r.Get("/control/auth/sessions", s.listControlUserSessions)
			r.Get("/control/auth/me", s.getControlUserAccount)
			r.Patch("/control/auth/me", s.updateControlUserAccount)
			r.Put("/control/auth/password", s.changeControlUserPassword)
			r.Post("/control/auth/providers/{provider}/link", s.startControlProviderLink)
			r.Delete("/control/auth/identities/{identity_id}", s.unlinkControlUserIdentity)
			r.Delete("/control/auth/sessions/{session_id}", s.revokeControlUserSession)
			r.Post("/control/auth/logout-all", s.logoutAllControlUserSessions)
			r.Get("/control/organizations", s.listOrganizations)
			r.Get("/control/installation/management-api", s.getManagementAPIStatus)
			r.Patch("/control/installation/management-api", s.updateManagementAPIStatus)
			r.Get("/control/installation/management-clients", s.listManagementClients)
			r.Post("/control/installation/management-clients", s.createManagementClient)
			r.Post("/control/installation/management-clients/{management_client_id}/rotate-secret", s.rotateManagementClientSecret)
			r.Delete("/control/installation/management-clients/{management_client_id}", s.disableManagementClient)
			r.Get("/control/installation/users", s.listInstallationControlUsers)
			r.Patch("/control/installation/users/{control_user_id}", s.updateInstallationControlUser)
			r.Delete("/control/installation/users/{control_user_id}", s.deleteInstallationControlUser)
			r.Get("/control/installation/invitations", s.listInstallationControlUserInvitations)
			r.Post("/control/installation/invitations", s.createInstallationControlUserInvitation)
			r.Post("/control/installation/invitations/{invitation_id}/resend", s.resendInstallationControlUserInvitation)
			r.Delete("/control/installation/invitations/{invitation_id}", s.revokeInstallationControlUserInvitation)
			r.Get("/control/installation/auth-policy", s.getControlAuthPolicy)
			r.Patch("/control/installation/auth-policy", s.updateControlAuthPolicy)
			r.Post("/control/installation/notification-providers", s.createInstallationNotificationProvider)
			r.Get("/control/installation/notification-providers", s.listInstallationNotificationProviders)
			r.Get("/control/installation/notification-providers/{provider_id}", s.getInstallationNotificationProvider)
			r.Patch("/control/installation/notification-providers/{provider_id}", s.updateInstallationNotificationProvider)
			r.Post("/control/installation/notification-providers/{provider_id}/verify", s.verifyInstallationNotificationProvider)
			r.With(s.idempotent).Post("/control/installation/notification-providers/{provider_id}/test", s.testInstallationNotificationProvider)
			r.Delete("/control/installation/notification-providers/{provider_id}", s.disableInstallationNotificationProvider)
			r.Post("/control/installation/storage/providers", s.createInstallationStorageProvider)
			r.Get("/control/installation/storage/providers", s.listInstallationStorageProviders)
			r.Get("/control/installation/storage/providers/{provider_id}", s.getInstallationStorageProvider)
			r.Patch("/control/installation/storage/providers/{provider_id}", s.updateInstallationStorageProvider)
			r.Post("/control/installation/storage/providers/{provider_id}/verify", s.verifyInstallationStorageProvider)
			r.Post("/control/installation/storage/providers/{provider_id}/enable", s.enableInstallationStorageProvider)
			r.Delete("/control/installation/storage/providers/{provider_id}", s.disableInstallationStorageProvider)
			r.With(s.idempotent).Post("/control/installation/storage/uploads", s.createInstallationStorageUpload)
			r.Post("/control/installation/storage/uploads/{object_id}/complete", s.completeInstallationStorageUpload)
			r.Get("/control/installation/storage/objects", s.listInstallationStorageObjects)
			r.Get("/control/installation/storage/objects/{object_id}", s.getInstallationStorageObject)
			r.Post("/control/installation/storage/objects/{object_id}/download", s.downloadInstallationStorageObject)
			r.Delete("/control/installation/storage/objects/{object_id}", s.deleteInstallationStorageObject)
			r.Post("/control/installation/billing/providers", s.createInstallationBillingProvider)
			r.Get("/control/installation/billing/providers", s.listInstallationBillingProviders)
			r.Get("/control/installation/billing/providers/{provider_id}", s.getInstallationBillingProvider)
			r.Patch("/control/installation/billing/providers/{provider_id}", s.updateInstallationBillingProvider)
			r.Post("/control/installation/billing/providers/{provider_id}/verify", s.verifyInstallationBillingProvider)
			r.Delete("/control/installation/billing/providers/{provider_id}", s.disableInstallationBillingProvider)
			r.Get("/control/installation/auth/providers", s.listInstallationAuthProviders)
			r.Put("/control/installation/auth/providers/{provider}", s.configureInstallationAuthProvider)
			r.Patch("/control/installation/auth/providers/{provider}", s.updateInstallationAuthProvider)
			r.Delete("/control/installation/auth/providers/{provider}", s.disableInstallationAuthProvider)
			r.Post("/control/installation/notification-templates", s.createInstallationNotificationTemplate)
			r.Get("/control/installation/notification-templates", s.listInstallationNotificationTemplates)
			r.Get("/control/installation/notification-template-variables", s.listInstallationNotificationTemplateVariables)
			r.Get("/control/installation/notification-templates/{template_id}", s.getInstallationNotificationTemplate)
			r.Patch("/control/installation/notification-templates/{template_id}", s.updateInstallationNotificationTemplate)
			r.Post("/control/installation/notification-templates/{template_id}/preview", s.previewInstallationNotificationTemplate)
			r.Post("/control/installation/notification-templates/{template_id}/publish", s.publishInstallationNotificationTemplate)
			r.Post("/control/installation/notification-templates/{template_id}/archive", s.archiveInstallationNotificationTemplate)
			r.Post("/control/organizations", s.createOrganization)
			r.Get("/control/organizations/{organization_id}", s.getOrganization)
			r.Get("/control/organizations/{organization_id}/policy", s.getOrganizationPolicy)
			r.Put("/control/installation/organizations/{organization_id}/policy", s.updateOrganizationPolicy)
			r.Patch("/control/organizations/{organization_id}", s.updateOrganization)
			r.Delete("/control/organizations/{organization_id}", s.retireOrganization)
			r.Post("/control/organizations/{organization_id}/restore", s.restoreOrganization)
			r.Get("/control/organizations/{organization_id}/members", s.listOrganizationMembers)
			r.Patch("/control/organizations/{organization_id}/members/{member_id}", s.updateOrganizationMember)
			r.Delete("/control/organizations/{organization_id}/members/{member_id}", s.deleteOrganizationMember)
			r.Post("/control/organizations/{organization_id}/invitations", s.createOrganizationInvitation)
			r.Get("/control/organizations/{organization_id}/invitations", s.listOrganizationInvitations)
			r.Post("/control/organizations/{organization_id}/invitations/{invitation_id}/resend", s.resendOrganizationInvitation)
			r.Delete("/control/organizations/{organization_id}/invitations/{invitation_id}", s.revokeOrganizationInvitation)
			r.Get("/control/organizations/{organization_id}/audit-logs", s.listOrganizationAudit)
			r.Post("/control/organizations/{organization_id}/notification-providers", s.createOrganizationNotificationProvider)
			r.Get("/control/organizations/{organization_id}/notification-providers", s.listOrganizationNotificationProviders)
			r.Get("/control/organizations/{organization_id}/notification-providers/{provider_id}", s.getOrganizationNotificationProvider)
			r.Patch("/control/organizations/{organization_id}/notification-providers/{provider_id}", s.updateOrganizationNotificationProvider)
			r.Post("/control/organizations/{organization_id}/notification-providers/{provider_id}/verify", s.verifyOrganizationNotificationProvider)
			r.With(s.idempotent).Post("/control/organizations/{organization_id}/notification-providers/{provider_id}/test", s.testOrganizationNotificationProvider)
			r.Delete("/control/organizations/{organization_id}/notification-providers/{provider_id}", s.disableOrganizationNotificationProvider)
			r.Post("/control/organizations/{organization_id}/storage/providers", s.createOrganizationStorageProvider)
			r.Get("/control/organizations/{organization_id}/storage/providers", s.listOrganizationStorageProviders)
			r.Get("/control/organizations/{organization_id}/storage/providers/{provider_id}", s.getOrganizationStorageProvider)
			r.Patch("/control/organizations/{organization_id}/storage/providers/{provider_id}", s.updateOrganizationStorageProvider)
			r.Post("/control/organizations/{organization_id}/storage/providers/{provider_id}/verify", s.verifyOrganizationStorageProvider)
			r.Post("/control/organizations/{organization_id}/storage/providers/{provider_id}/enable", s.enableOrganizationStorageProvider)
			r.Delete("/control/organizations/{organization_id}/storage/providers/{provider_id}", s.disableOrganizationStorageProvider)
			r.Get("/control/organizations/{organization_id}/storage/objects", s.listOrganizationStorageObjects)
			r.Get("/control/organizations/{organization_id}/storage/objects/{object_id}", s.getOrganizationStorageObject)
			r.Post("/control/organizations/{organization_id}/storage/objects/{object_id}/download", s.downloadOrganizationStorageObject)
			r.Delete("/control/organizations/{organization_id}/storage/objects/{object_id}", s.deleteOrganizationStorageObject)
			r.Post("/control/organizations/{organization_id}/billing/providers", s.createOrganizationBillingProvider)
			r.Get("/control/organizations/{organization_id}/billing/providers", s.listOrganizationBillingProviders)
			r.Get("/control/organizations/{organization_id}/billing/providers/{provider_id}", s.getOrganizationBillingProvider)
			r.Patch("/control/organizations/{organization_id}/billing/providers/{provider_id}", s.updateOrganizationBillingProvider)
			r.Post("/control/organizations/{organization_id}/billing/providers/{provider_id}/verify", s.verifyOrganizationBillingProvider)
			r.Delete("/control/organizations/{organization_id}/billing/providers/{provider_id}", s.disableOrganizationBillingProvider)
			r.Get("/control/organizations/{organization_id}/auth/providers", s.listOrganizationAuthProviders)
			r.Put("/control/organizations/{organization_id}/auth/providers/{provider}", s.configureOrganizationAuthProvider)
			r.Patch("/control/organizations/{organization_id}/auth/providers/{provider}", s.updateOrganizationAuthProvider)
			r.Delete("/control/organizations/{organization_id}/auth/providers/{provider}", s.disableOrganizationAuthProvider)
			r.Post("/control/organizations/{organization_id}/applications", s.createApplication)
			r.Get("/control/organizations/{organization_id}/applications", s.listApplications)
			r.Patch("/control/organizations/{organization_id}/applications/{application_resource_id}", s.updateApplication)
			r.Delete("/control/organizations/{organization_id}/applications/{application_resource_id}", s.retireApplication)
			r.Post("/control/organizations/{organization_id}/applications/{application_resource_id}/restore", s.restoreApplication)
			r.Get("/control/applications/{application_id}", s.getApplication)
			r.Get("/control/applications/{application_id}/statistics", s.applicationStatistics)
			r.Patch("/control/applications/{application_id}/public-config", s.updatePublicApplicationConfig)
			r.Patch("/control/applications/{application_id}/internal-config", s.updateInternalApplicationConfig)
			r.Patch("/control/applications/{application_id}/auth-config", s.updateAuthConfig)
			r.Put("/control/applications/{application_id}/auth/providers/google", s.configureGoogleProvider)
			r.Put("/control/applications/{application_id}/auth/providers/apple", s.configureAppleProvider)
			r.Put("/control/applications/{application_id}/auth/providers/{provider}", s.configureApplicationAuthProvider)
			r.Get("/control/applications/{application_id}/auth/providers", s.listApplicationAuthProviders)
			r.Delete("/control/applications/{application_id}/auth/providers/{provider}", s.disableApplicationAuthProvider)
			r.Post("/control/applications/{application_id}/domains", s.createApplicationDomain)
			r.Get("/control/applications/{application_id}/domains", s.listApplicationDomains)
			r.Post("/control/applications/{application_id}/domains/{domain_id}/verify", s.verifyApplicationDomain)
			r.Delete("/control/applications/{application_id}/domains/{domain_id}", s.deleteApplicationDomain)
			r.Post("/control/applications/{application_id}/clients", s.createClient)
			r.Get("/control/applications/{application_id}/clients", s.listClients)
			r.Get("/control/applications/{application_id}/clients/{client_id}", s.getClient)
			r.Patch("/control/applications/{application_id}/clients/{client_id}", s.updateClient)
			r.Post("/control/applications/{application_id}/clients/{client_id}/rotate-secret", s.rotateClientSecret)
			r.Delete("/control/applications/{application_id}/clients/{client_id}", s.disableClient)
			r.Get("/control/installation/signing-keys", s.listSigningKeys)
			r.Post("/control/installation/signing-keys/rotate", s.rotateSigningKey)
			r.Post("/control/applications/{application_id}/roles", s.createRole)
			r.Get("/control/applications/{application_id}/roles", s.listRoles)
			r.Get("/control/applications/{application_id}/roles/{role_id}", s.getRole)
			r.Patch("/control/applications/{application_id}/roles/{role_id}", s.updateRole)
			r.Delete("/control/applications/{application_id}/roles/{role_id}", s.deleteRole)
			r.Post("/control/applications/{application_id}/workspaces", s.createWorkspace)
			r.Get("/control/applications/{application_id}/workspaces", s.listWorkspaces)
			r.Get("/control/applications/{application_id}/workspaces/{workspace_id}", s.getWorkspace)
			r.Patch("/control/applications/{application_id}/workspaces/{workspace_id}", s.updateWorkspace)
			r.Delete("/control/applications/{application_id}/workspaces/{workspace_id}", s.deleteWorkspace)
			r.Post("/control/applications/{application_id}/workspaces/{workspace_id}/owner-transfer", s.transferWorkspaceOwnership)
			r.Get("/control/applications/{application_id}/workspaces/{workspace_id}/members", s.listWorkspaceMembers)
			r.Put("/control/applications/{application_id}/workspaces/{workspace_id}/members/{user_id}", s.replaceWorkspaceMemberRoles)
			r.Delete("/control/applications/{application_id}/workspaces/{workspace_id}/members/{user_id}", s.deleteWorkspaceMember)
			r.Post("/control/applications/{application_id}/role-assignments", s.assignRole)
			r.Get("/control/applications/{application_id}/role-assignments", s.listRoleAssignments)
			r.Delete("/control/applications/{application_id}/role-assignments/{assignment_id}", s.deleteRoleAssignment)
			r.With(s.idempotent).Post("/control/applications/{application_id}/permission-grants", s.createPermissionGrant)
			r.Get("/control/applications/{application_id}/permission-grants", s.listPermissionGrants)
			r.Get("/control/applications/{application_id}/permission-grants/effective", s.effectivePermissionAccess)
			r.Get("/control/applications/{application_id}/permission-grants/{grant_id}", s.getPermissionGrant)
			r.Delete("/control/applications/{application_id}/permission-grants/{grant_id}", s.revokePermissionGrant)
			r.Post("/control/applications/{application_id}/delegations", s.createDelegation)
			r.Get("/control/applications/{application_id}/delegations", s.listDelegations)
			r.Get("/control/applications/{application_id}/delegations/{delegation_id}", s.getDelegation)
			r.Post("/control/applications/{application_id}/delegations/{delegation_id}/revoke", s.revokeDelegation)
			r.Post("/control/applications/{application_id}/invitations", s.createControlInvitation)
			r.Get("/control/applications/{application_id}/invitations", s.listInvitations)
			r.Post("/control/applications/{application_id}/invitations/{invitation_id}/resend", s.resendInvitation)
			r.Get("/control/applications/{application_id}/invitations/{invitation_id}", s.getInvitation)
			r.Delete("/control/applications/{application_id}/invitations/{invitation_id}", s.revokeInvitation)
			r.Post("/control/applications/{application_id}/users", s.adminCreateUser)
			r.Get("/control/applications/{application_id}/users", s.adminListUsers)
			r.Get("/control/applications/{application_id}/users/{user_id}", s.adminGetUser)
			r.Patch("/control/applications/{application_id}/users/{user_id}", s.adminUpdateUser)
			r.Post("/control/applications/{application_id}/users/{user_id}/suspend", s.adminSuspendUser)
			r.Post("/control/applications/{application_id}/users/{user_id}/restore", s.adminRestoreUser)
			r.Post("/control/applications/{application_id}/users/{user_id}/verify-email", s.adminVerifyUserEmail)
			r.Post("/control/applications/{application_id}/users/{user_id}/unverify-email", s.adminUnverifyUserEmail)
			r.Post("/control/applications/{application_id}/users/{user_id}/verify-organization", s.adminVerifyUserOrganization)
			r.Post("/control/applications/{application_id}/users/{user_id}/unverify-organization", s.adminUnverifyUserOrganization)
			r.Get("/control/applications/{application_id}/users/{user_id}/sessions", s.adminListUserSessions)
			r.Post("/control/applications/{application_id}/users/{user_id}/sessions/revoke", s.adminRevokeUserSessions)
			r.Get("/control/applications/{application_id}/users/{user_id}/addresses", s.adminListUserAddresses)
			r.Get("/control/applications/{application_id}/oauth-consents", s.adminListOAuthConsents)
			r.Post("/control/applications/{application_id}/oauth-consents/{user_id}/{client_id}/revoke", s.adminRevokeOAuthConsent)
			r.Post("/control/applications/{application_id}/features", s.createFeature)
			r.Get("/control/applications/{application_id}/features", s.listFeatures)
			r.Post("/control/applications/{application_id}/products", s.createProduct)
			r.Get("/control/applications/{application_id}/products", s.listProducts)
			r.Get("/control/applications/{application_id}/products/{product_id}", s.getProduct)
			r.Patch("/control/applications/{application_id}/products/{product_id}", s.updateProduct)
			r.Post("/control/applications/{application_id}/products/{product_id}/prices", s.createPrice)
			r.Get("/control/applications/{application_id}/products/{product_id}/prices", s.listPrices)
			r.Post("/control/applications/{application_id}/entitlements", s.createEntitlement)
			r.Get("/control/applications/{application_id}/entitlements", s.listEntitlements)
			r.Get("/control/applications/{application_id}/entitlements/{entitlement_id}", s.getEntitlement)
			r.Post("/control/applications/{application_id}/entitlements/{entitlement_id}/adjust", s.adjustEntitlement)
			r.Post("/control/applications/{application_id}/entitlements/{entitlement_id}/revoke", s.revokeEntitlement)
			r.Post("/control/applications/{application_id}/entitlements/{entitlement_id}/restore", s.restoreEntitlement)
			r.Post("/control/applications/{application_id}/local-entitlement-requests/{request_id}/approve", s.approveLocalRequest)
			r.Post("/control/applications/{application_id}/local-entitlement-requests/{request_id}/reject", s.rejectLocalRequest)
			r.Post("/control/applications/{application_id}/local-entitlement-requests/{request_id}/reopen", s.reopenLocalRequest)
			r.Get("/control/applications/{application_id}/local-entitlement-requests", s.adminListLocalRequests)
			r.Get("/control/applications/{application_id}/local-entitlement-requests/{request_id}", s.adminGetLocalRequest)
			r.Post("/control/applications/{application_id}/billing/providers", s.createBillingProvider)
			r.Get("/control/applications/{application_id}/billing/providers", s.listBillingProviders)
			r.Get("/control/applications/{application_id}/billing/providers/{provider_id}", s.getBillingProvider)
			r.Patch("/control/applications/{application_id}/billing/providers/{provider_id}", s.updateBillingProvider)
			r.Post("/control/applications/{application_id}/billing/providers/{provider_id}/verify", s.verifyBillingProvider)
			r.Delete("/control/applications/{application_id}/billing/providers/{provider_id}", s.disableBillingProvider)
			r.Get("/control/applications/{application_id}/billing/subscriptions", s.listSubscriptions)
			r.Get("/control/applications/{application_id}/billing/subscriptions/{subscription_id}", s.getSubscription)
			r.With(s.idempotent).Post("/control/applications/{application_id}/billing/subscriptions/{subscription_id}/cancel", s.cancelSubscription)
			r.With(s.idempotent).Post("/control/applications/{application_id}/billing/subscriptions/{subscription_id}/resume", s.resumeSubscription)
			r.With(s.idempotent).Post("/control/applications/{application_id}/billing/subscriptions/{subscription_id}/change-price", s.changeSubscriptionPrice)
			r.Get("/control/applications/{application_id}/billing/invoices", s.listInvoices)
			r.Get("/control/applications/{application_id}/billing/invoices/{invoice_id}", s.getInvoice)
			r.Get("/control/applications/{application_id}/billing/payments", s.listPayments)
			r.Get("/control/applications/{application_id}/billing/payments/{payment_id}", s.getPayment)
			r.With(s.idempotent).Post("/control/applications/{application_id}/billing/payments/{payment_id}/refunds", s.createRefund)
			r.Get("/control/applications/{application_id}/billing/refunds", s.listRefunds)
			r.Get("/control/applications/{application_id}/billing/refunds/{refund_id}", s.getRefund)
			r.Get("/control/applications/{application_id}/billing/disputes", s.listDisputes)
			r.Get("/control/applications/{application_id}/billing/disputes/{dispute_id}", s.getDispute)
			r.Get("/control/applications/{application_id}/billing/statistics", s.billingStatistics)
			r.Get("/control/applications/{application_id}/billing/provider-events", s.listProviderEvents)
			r.Post("/control/applications/{application_id}/billing/provider-events/{event_id}/replay", s.replayProviderEvent)
			r.With(s.idempotent).Post("/control/applications/{application_id}/billing/providers/{provider_id}/reconciliation-runs", s.createReconciliationRun)
			r.Get("/control/applications/{application_id}/billing/reconciliation-runs", s.listReconciliationRuns)
			r.Get("/control/applications/{application_id}/billing/reconciliation-runs/{run_id}", s.getReconciliationRun)
			r.Get("/control/applications/{application_id}/events", s.listEvents)
			r.Get("/control/applications/{application_id}/events/{event_id}", s.getEvent)
			r.Post("/control/applications/{application_id}/event-types", s.createEventType)
			r.Get("/control/applications/{application_id}/event-types", s.listEventTypes)
			r.Get("/control/applications/{application_id}/event-types/{event_type_id}", s.getEventType)
			r.Patch("/control/applications/{application_id}/event-types/{event_type_id}", s.updateEventType)
			r.Delete("/control/applications/{application_id}/event-types/{event_type_id}", s.archiveEventType)
			r.Get("/control/applications/{application_id}/audit-logs", s.listAudit)
			r.Get("/control/applications/{application_id}/audit-logs/{audit_id}", s.getAudit)
			r.Post("/control/applications/{application_id}/audit-exports", s.createAuditExport)
			r.Get("/control/applications/{application_id}/audit-exports/{export_id}", s.getAuditExport)
			r.Post("/control/applications/{application_id}/webhooks", s.createWebhook)
			r.Get("/control/applications/{application_id}/webhooks", s.listWebhooks)
			r.Get("/control/applications/{application_id}/webhooks/{webhook_id}", s.getWebhook)
			r.Patch("/control/applications/{application_id}/webhooks/{webhook_id}", s.updateWebhook)
			r.With(s.idempotent).Post("/control/applications/{application_id}/webhooks/{webhook_id}/test", s.testWebhook)
			r.Post("/control/applications/{application_id}/webhooks/{webhook_id}/rotate-secret", s.rotateWebhookSecret)
			r.Delete("/control/applications/{application_id}/webhooks/{webhook_id}", s.disableWebhook)
			r.Get("/control/applications/{application_id}/webhook-deliveries", s.listWebhookDeliveries)
			r.Get("/control/applications/{application_id}/webhook-deliveries/{delivery_id}", s.getWebhookDelivery)
			r.Post("/control/applications/{application_id}/webhook-deliveries/{delivery_id}/replay", s.replayWebhookDelivery)
			r.Post("/control/applications/{application_id}/notification-providers", s.createNotificationProvider)
			r.Get("/control/applications/{application_id}/notification-providers", s.listNotificationProviders)
			r.Get("/control/applications/{application_id}/notification-providers/{provider_id}", s.getNotificationProvider)
			r.Patch("/control/applications/{application_id}/notification-providers/{provider_id}", s.updateNotificationProvider)
			r.Post("/control/applications/{application_id}/notification-providers/{provider_id}/verify", s.verifyNotificationProvider)
			r.With(s.idempotent).Post("/control/applications/{application_id}/notification-providers/{provider_id}/test", s.testNotificationProvider)
			r.Delete("/control/applications/{application_id}/notification-providers/{provider_id}", s.disableNotificationProvider)
			r.Post("/control/applications/{application_id}/storage/providers", s.createApplicationStorageProvider)
			r.Get("/control/applications/{application_id}/storage/providers", s.listApplicationStorageProviders)
			r.Get("/control/applications/{application_id}/storage/providers/{provider_id}", s.getApplicationStorageProvider)
			r.Patch("/control/applications/{application_id}/storage/providers/{provider_id}", s.updateApplicationStorageProvider)
			r.Post("/control/applications/{application_id}/storage/providers/{provider_id}/verify", s.verifyApplicationStorageProvider)
			r.Post("/control/applications/{application_id}/storage/providers/{provider_id}/enable", s.enableApplicationStorageProvider)
			r.Delete("/control/applications/{application_id}/storage/providers/{provider_id}", s.disableApplicationStorageProvider)
			r.With(s.idempotent).Post("/control/applications/{application_id}/storage/uploads", s.createControlApplicationStorageUpload)
			r.Post("/control/applications/{application_id}/storage/uploads/{object_id}/complete", s.completeControlApplicationStorageUpload)
			r.Get("/control/applications/{application_id}/storage/objects", s.listControlApplicationStorageObjects)
			r.Get("/control/applications/{application_id}/storage/objects/{object_id}", s.getControlApplicationStorageObject)
			r.Post("/control/applications/{application_id}/storage/objects/{object_id}/download", s.downloadControlApplicationStorageObject)
			r.Delete("/control/applications/{application_id}/storage/objects/{object_id}", s.deleteControlApplicationStorageObject)
			r.Post("/control/applications/{application_id}/sender-identities", s.createSenderIdentity)
			r.Get("/control/applications/{application_id}/sender-identities", s.listSenderIdentities)
			r.Post("/control/applications/{application_id}/sender-identities/{sender_id}/default", s.setDefaultSenderIdentity)
			r.Post("/control/applications/{application_id}/notification-templates", s.createNotificationTemplate)
			r.Get("/control/applications/{application_id}/notification-templates", s.listNotificationTemplates)
			r.Get("/control/applications/{application_id}/notification-template-variables", s.listNotificationTemplateVariables)
			r.Get("/control/applications/{application_id}/notification-templates/{template_id}", s.getNotificationTemplate)
			r.Patch("/control/applications/{application_id}/notification-templates/{template_id}", s.updateNotificationTemplate)
			r.Post("/control/applications/{application_id}/notification-templates/{template_id}/preview", s.previewNotificationTemplate)
			r.Post("/control/applications/{application_id}/notification-templates/{template_id}/publish", s.publishNotificationTemplate)
			r.Post("/control/applications/{application_id}/notification-templates/{template_id}/archive", s.archiveNotificationTemplate)
			r.Get("/control/applications/{application_id}/notifications", s.listNotifications)
			r.Get("/control/applications/{application_id}/notifications/statistics", s.notificationStatistics)
			r.Get("/control/applications/{application_id}/notifications/{notification_id}", s.getNotification)
			r.Post("/control/applications/{application_id}/notifications/{notification_id}/retry", s.retryNotification)
		})

		r.Get("/applications/{application_id}/public-config", s.publicConfig)
		r.Get("/applications/{application_id}/catalog/products", s.publicCatalog)
		r.Post("/applications/{application_id}/auth/password/sign-up", s.passwordSignUp)
		r.Post("/applications/{application_id}/auth/password/sign-in", s.passwordSignIn)
		r.Post("/applications/{application_id}/auth/methods", s.authMethods)
		r.Post("/applications/{application_id}/auth/token/refresh", s.refreshToken)
		r.Post("/applications/{application_id}/auth/email/start", s.emailStart)
		r.Post("/applications/{application_id}/auth/email/verify", s.emailVerify)
		r.Post("/applications/{application_id}/auth/password/reset/start", s.passwordResetStart)
		r.Post("/applications/{application_id}/auth/password/reset/verify", s.passwordResetVerify)
		r.Get("/applications/{application_id}/auth/providers", s.listAuthProviders)
		r.Post("/applications/{application_id}/auth/providers/google/start", s.startGoogleAuth)
		r.Post("/applications/{application_id}/auth/providers/google/exchange", s.exchangeGoogleAuth)
		r.Post("/applications/{application_id}/auth/providers/apple/start", s.startAppleAuth)
		r.Post("/applications/{application_id}/auth/providers/apple/exchange", s.exchangeAppleAuth)
		r.Post("/applications/{application_id}/auth/providers/{provider}/start", s.startSocialAuth)
		r.Post("/applications/{application_id}/auth/providers/{provider}/exchange", s.exchangeSocialAuth)
		r.Post("/applications/{application_id}/auth/external-email/start", s.startExternalEmailEnrollment)
		r.Post("/applications/{application_id}/auth/external-email/verify", s.verifyExternalEmailEnrollment)
		r.Post("/applications/{application_id}/auth/mfa/verify", s.verifyMFA)
		r.Post("/applications/{application_id}/auth/mfa/webauthn/options", s.beginWebAuthnAuthentication)
		r.Post("/applications/{application_id}/auth/mfa/webauthn/verify", s.finishWebAuthnAuthentication)
		r.Post("/applications/{application_id}/auth/invitations/exchange", s.exchangeInvitation)
		r.Post("/applications/{application_id}/auth/invitations/token", s.redeemInvitationAuthorizationCode)
		r.Post("/applications/{application_id}/auth/invitations/providers/{provider}/start", s.startApplicationInvitationProvider)
		r.Post("/applications/{application_id}/delegations/{delegation_id}/exchange", s.exchangeDelegation)
		r.With(s.requireApplicationActor, s.idempotent).Post("/applications/{application_id}/events", s.publishCustomEvent)
		r.With(s.requireApplicationActor, s.idempotent).Post("/applications/{application_id}/notifications", s.queueMachineNotification)
		r.With(s.requireApplicationActor).Post("/applications/{application_id}/invitations", s.createApplicationInvitation)
		r.With(s.requireApplicationActor).Get("/applications/{application_id}/invitations", s.listInvitations)
		r.With(s.requireApplicationActor).Post("/applications/{application_id}/invitations/{invitation_id}/resend", s.resendInvitation)
		r.With(s.requireApplicationActor).Get("/applications/{application_id}/invitations/{invitation_id}", s.getInvitation)
		r.With(s.requireApplicationActor).Delete("/applications/{application_id}/invitations/{invitation_id}", s.revokeInvitation)
		r.With(s.requireApplicationActor).Get("/applications/{application_id}/users", s.serviceListUsers)
		r.With(s.requireApplicationActor).Get("/applications/{application_id}/users/{user_id}", s.serviceGetUser)
		r.With(s.requireApplicationActor).Get("/applications/{application_id}/workspaces", s.serviceListWorkspaces)
		r.With(s.requireApplicationActor).Get("/applications/{application_id}/service/workspaces/{workspace_id}", s.serviceGetWorkspace)
		r.With(s.requireApplicationActor).Get("/applications/{application_id}/service/workspaces/{workspace_id}/access", s.serviceWorkspaceAccess)
		r.With(s.requireApplicationActor).Get("/applications/{application_id}/subjects/{subject_type}/{subject_id}/entitlements", s.serviceSubjectEntitlements)
		r.With(s.requireApplicationActor).Get("/applications/{application_id}/subjects/{subject_type}/{subject_id}/billing", s.serviceSubjectBilling)
		r.With(s.requireApplicationActor, s.idempotent).Post("/applications/{application_id}/permission-grants", s.createPermissionGrant)
		r.With(s.requireApplicationActor).Get("/applications/{application_id}/permission-grants", s.listPermissionGrants)
		r.With(s.requireApplicationActor).Get("/applications/{application_id}/permission-grants/effective", s.effectivePermissionAccess)
		r.With(s.requireApplicationActor).Get("/applications/{application_id}/permission-grants/{grant_id}", s.getPermissionGrant)
		r.With(s.requireApplicationActor).Delete("/applications/{application_id}/permission-grants/{grant_id}", s.revokePermissionGrant)
		r.With(s.requireApplicationActor).Get("/applications/{application_id}/storage/objects", s.listApplicationStorageObjects)
		r.With(s.requireApplicationActor, s.idempotent).Post("/applications/{application_id}/storage/uploads", s.createApplicationStorageUpload)
		r.With(s.requireApplicationActor).Post("/applications/{application_id}/storage/uploads/{object_id}/complete", s.completeApplicationStorageUpload)
		r.With(s.requireApplicationActor).Get("/applications/{application_id}/storage/objects/{object_id}", s.getApplicationStorageObject)
		r.With(s.requireApplicationActor).Post("/applications/{application_id}/storage/objects/{object_id}/download", s.downloadApplicationStorageObject)
		r.With(s.requireApplicationActor).Delete("/applications/{application_id}/storage/objects/{object_id}", s.deleteApplicationStorageObject)
		r.With(s.requireApplicationActor).Get("/applications/{application_id}/workspaces/{workspace_id}/storage/objects", s.listWorkspaceStorageObjects)
		r.With(s.requireApplicationActor, s.idempotent).Post("/applications/{application_id}/workspaces/{workspace_id}/storage/uploads", s.createWorkspaceStorageUpload)
		r.With(s.requireApplicationActor).Post("/applications/{application_id}/workspaces/{workspace_id}/storage/uploads/{object_id}/complete", s.completeWorkspaceStorageUpload)
		r.With(s.requireApplicationActor).Get("/applications/{application_id}/workspaces/{workspace_id}/storage/objects/{object_id}", s.getWorkspaceStorageObject)
		r.With(s.requireApplicationActor).Post("/applications/{application_id}/workspaces/{workspace_id}/storage/objects/{object_id}/download", s.downloadWorkspaceStorageObject)
		r.With(s.requireApplicationActor).Delete("/applications/{application_id}/workspaces/{workspace_id}/storage/objects/{object_id}", s.deleteWorkspaceStorageObject)
		r.Group(func(r chi.Router) {
			r.Use(s.requireUser)
			r.Get("/applications/{application_id}/me", s.me)
			r.Get("/applications/{application_id}/me/storage/objects", s.listMyStorageObjects)
			r.With(s.idempotent).Post("/applications/{application_id}/me/storage/uploads", s.createMyStorageUpload)
			r.Post("/applications/{application_id}/me/storage/uploads/{object_id}/complete", s.completeMyStorageUpload)
			r.Get("/applications/{application_id}/me/storage/objects/{object_id}", s.getMyStorageObject)
			r.Post("/applications/{application_id}/me/storage/objects/{object_id}/download", s.downloadMyStorageObject)
			r.Delete("/applications/{application_id}/me/storage/objects/{object_id}", s.deleteMyStorageObject)
			r.Post("/applications/{application_id}/auth/logout", s.logoutCurrentSession)
			r.Patch("/applications/{application_id}/me", s.updateMe)
			r.Post("/applications/{application_id}/me/email-verification/start", s.emailVerificationStart)
			r.Post("/applications/{application_id}/me/email-verification/verify", s.emailVerificationVerify)
			r.With(s.requireRecentAuth).Post("/applications/{application_id}/me/email-change/start", s.emailChangeStart)
			r.With(s.requireRecentAuth).Post("/applications/{application_id}/me/email-change/verify", s.emailChangeVerify)
			r.With(s.requireRecentAuth).Post("/applications/{application_id}/me/password/change", s.passwordChange)
			r.Get("/applications/{application_id}/me/export", s.exportMyAccount)
			r.With(s.requireRecentAuth).Post("/applications/{application_id}/me/anonymize", s.anonymizeMyAccount)
			r.With(s.requireRecentAuth).Delete("/applications/{application_id}/me", s.deleteMyAccount)
			r.Get("/applications/{application_id}/me/mfa/methods", s.listMFAMethods)
			r.With(s.requireRecentAuth).Post("/applications/{application_id}/me/mfa/totp", s.startTOTPEnrollment)
			r.With(s.requireRecentAuth).Post("/applications/{application_id}/me/mfa/totp/{method_id}/activate", s.activateTOTPEnrollment)
			r.With(s.requireRecentAuth).Post("/applications/{application_id}/me/mfa/webauthn/options", s.beginWebAuthnRegistration)
			r.With(s.requireRecentAuth).Post("/applications/{application_id}/me/mfa/webauthn/verify", s.finishWebAuthnRegistration)
			r.With(s.requireRecentAuth).Delete("/applications/{application_id}/me/mfa/methods/{method_id}", s.disableMFAMethod)
			r.With(s.requireRecentAuth).Post("/applications/{application_id}/me/mfa/recovery-codes/regenerate", s.regenerateRecoveryCodes)
			r.With(s.requireRecentAuth).Post("/applications/{application_id}/me/auth/providers/google/link", s.startGoogleLink)
			r.With(s.requireRecentAuth).Post("/applications/{application_id}/me/auth/providers/apple/link", s.startAppleLink)
			r.With(s.requireRecentAuth).Post("/applications/{application_id}/me/auth/providers/{provider}/link", s.startSocialLink)
			r.Get("/applications/{application_id}/me/auth/identities", s.listMyIdentities)
			r.With(s.requireRecentAuth).Delete("/applications/{application_id}/me/auth/identities/{identity_id}", s.unlinkMyIdentity)
			r.Get("/applications/{application_id}/me/sessions", s.listMySessions)
			r.Delete("/applications/{application_id}/me/sessions/{session_id}", s.revokeMySession)
			r.Post("/applications/{application_id}/me/logout-all", s.logoutAll)
			r.Get("/applications/{application_id}/me/api-keys", s.listAPIKeys)
			r.Post("/applications/{application_id}/me/api-keys", s.createAPIKey)
			r.Delete("/applications/{application_id}/me/api-keys/{key_id}", s.revokeAPIKey)
			r.Get("/applications/{application_id}/me/addresses", s.listAddresses)
			r.Post("/applications/{application_id}/me/addresses", s.createAddress)
			r.Patch("/applications/{application_id}/me/addresses/{address_id}", s.updateAddress)
			r.Post("/applications/{application_id}/me/addresses/{address_id}/activate", s.activateAddress)
			r.Delete("/applications/{application_id}/me/addresses/{address_id}", s.deleteAddress)
			r.Get("/applications/{application_id}/me/billing-profile", s.getBillingProfile)
			r.Patch("/applications/{application_id}/me/billing-profile", s.updateBillingProfile)
			r.Get("/applications/{application_id}/me/workspaces", s.listMyWorkspaces)
			r.Post("/applications/{application_id}/me/workspaces", s.createWorkspace)
			r.Get("/applications/{application_id}/workspaces/{workspace_id}", s.getWorkspace)
			r.Patch("/applications/{application_id}/workspaces/{workspace_id}", s.updateWorkspace)
			r.Delete("/applications/{application_id}/workspaces/{workspace_id}", s.deleteWorkspace)
			r.Get("/applications/{application_id}/workspaces/{workspace_id}/members", s.listWorkspaceMembers)
			r.Put("/applications/{application_id}/workspaces/{workspace_id}/members/{user_id}", s.replaceWorkspaceMemberRoles)
			r.Delete("/applications/{application_id}/workspaces/{workspace_id}/members/{user_id}", s.deleteWorkspaceMember)
			r.With(s.requireRecentAuth).Post("/applications/{application_id}/workspaces/{workspace_id}/owner-transfer", s.transferWorkspaceOwnership)
			r.Delete("/applications/{application_id}/workspaces/{workspace_id}/membership", s.leaveWorkspace)
			r.Get("/applications/{application_id}/workspaces/{workspace_id}/billing-profile", s.getBillingProfile)
			r.Patch("/applications/{application_id}/workspaces/{workspace_id}/billing-profile", s.updateBillingProfile)
			r.Get("/applications/{application_id}/workspaces/{workspace_id}/addresses", s.listAddresses)
			r.Post("/applications/{application_id}/workspaces/{workspace_id}/addresses", s.createAddress)
			r.Patch("/applications/{application_id}/workspaces/{workspace_id}/addresses/{address_id}", s.updateAddress)
			r.Post("/applications/{application_id}/workspaces/{workspace_id}/addresses/{address_id}/activate", s.activateAddress)
			r.Delete("/applications/{application_id}/workspaces/{workspace_id}/addresses/{address_id}", s.deleteAddress)
			r.Post("/applications/{application_id}/workspaces/{workspace_id}/invitations", s.createWorkspaceInvitation)
			r.Get("/applications/{application_id}/workspaces/{workspace_id}/invitations", s.listInvitations)
			r.Post("/applications/{application_id}/workspaces/{workspace_id}/invitations/{invitation_id}/resend", s.resendInvitation)
			r.Delete("/applications/{application_id}/workspaces/{workspace_id}/invitations/{invitation_id}", s.revokeInvitation)
			r.Get("/applications/{application_id}/workspaces/{workspace_id}/access", s.listWorkspaceAccess)
			r.With(s.idempotent).Post("/applications/{application_id}/workspaces/{workspace_id}/permission-grants", s.createPermissionGrant)
			r.Get("/applications/{application_id}/workspaces/{workspace_id}/permission-grants", s.listPermissionGrants)
			r.Get("/applications/{application_id}/workspaces/{workspace_id}/permission-grants/{grant_id}", s.getPermissionGrant)
			r.Delete("/applications/{application_id}/workspaces/{workspace_id}/permission-grants/{grant_id}", s.revokePermissionGrant)
			r.Get("/applications/{application_id}/me/workspace-invitations", s.listMyInvitations)
			r.Post("/applications/{application_id}/me/permissions/check", s.checkPermissions)
			r.Get("/applications/{application_id}/me/oauth-consents", s.listMyOAuthConsents)
			r.Delete("/applications/{application_id}/me/oauth-consents/{client_id}", s.revokeMyOAuthConsent)
			r.With(s.idempotent).Post("/applications/{application_id}/local-entitlement-checkouts", s.createLocalCheckout)
			r.Get("/applications/{application_id}/me/local-entitlement-requests", s.listMyLocalRequests)
			r.Get("/applications/{application_id}/me/local-entitlement-requests/{request_id}", s.getMyLocalRequest)
			r.Post("/applications/{application_id}/me/local-entitlement-requests/{request_id}/cancel", s.cancelLocalRequest)
			r.Get("/applications/{application_id}/me/entitlements", s.listMyEntitlements)
			r.With(s.idempotent).Post("/applications/{application_id}/billing/checkout-sessions", s.createCheckoutSession)
			r.Get("/applications/{application_id}/billing/checkout-sessions/{session_id}", s.getCheckoutSession)
			r.With(s.idempotent).Post("/applications/{application_id}/billing/portal-sessions", s.createPortalSession)
			r.Get("/applications/{application_id}/me/billing", s.myBillingSummary)
			r.Get("/applications/{application_id}/me/subscriptions", s.listMySubscriptions)
			r.Get("/applications/{application_id}/me/invoices", s.listMyInvoices)
			r.Get("/applications/{application_id}/me/payments", s.listMyPayments)
			r.Get("/applications/{application_id}/me/notification-preferences", s.listMyNotificationPreferences)
			r.Put("/applications/{application_id}/me/notification-preferences/{category}", s.updateMyNotificationPreference)
		})
		r.Group(func(r chi.Router) {
			r.Use(s.requireManagementClient)
			r.Get("/management/organizations", s.managementListOrganizations)
			r.Post("/management/organizations", s.managementCreateOrganization)
			r.Get("/management/organizations/{organization_id}", s.getOrganization)
			r.Patch("/management/organizations/{organization_id}", s.updateOrganization)
			r.Delete("/management/organizations/{organization_id}", s.retireOrganization)
			r.Post("/management/organizations/{organization_id}/restore", s.restoreOrganization)
			r.Get("/management/organizations/{organization_id}/policy", s.getOrganizationPolicy)
			r.Put("/management/organizations/{organization_id}/policy", s.updateOrganizationPolicy)
			r.Get("/management/organizations/{organization_id}/applications", s.listApplications)
			r.Post("/management/organizations/{organization_id}/applications", s.createApplication)
			r.Patch("/management/organizations/{organization_id}/applications/{application_resource_id}", s.updateApplication)
			r.Delete("/management/organizations/{organization_id}/applications/{application_resource_id}", s.retireApplication)
			r.Post("/management/organizations/{organization_id}/applications/{application_resource_id}/restore", s.restoreApplication)
		})
	})

	r.Get("/oidc/.well-known/openid-configuration", s.discovery)
	r.Get("/oidc/jwks.json", s.jwks)
	r.With(s.resolveOAuthApplication).Get("/oidc/authorize", s.oauthAuthorizeInteraction)
	r.With(s.resolveOAuthApplication, s.requireUser).Post("/oidc/authorize", s.oauthAuthorizeDecision)
	r.With(s.resolveOAuthApplication).Post("/oidc/token", s.oauthToken)
	r.With(s.resolveOAuthApplication).Post("/oidc/revoke", s.oauthRevoke)
	r.With(s.resolveOAuthApplication).Post("/oidc/introspect", s.oauthIntrospect)
	r.With(s.resolveOAuthApplication).Get("/oidc/userinfo", s.oauthUserinfo)
	r.Post("/provider-webhooks/stripe/{connection_public_id}", s.stripeWebhook)
	r.Handle("/*", s.adminHandler())
	return otelhttp.NewHandler(r, "platform93.http")
}

func (s *Server) requestContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := strings.TrimSpace(r.Header.Get("X-Request-ID"))
		if requestID == "" || len(requestID) > 128 {
			requestID = kernel.NewID().String()
		}
		w.Header().Set("X-Request-ID", requestID)
		next.ServeHTTP(w, r.WithContext(kernel.WithRequestID(r.Context(), requestID)))
	})
}

func (s *Server) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		recorder := &statusResponseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r)
		route := chi.RouteContext(r.Context()).RoutePattern()
		if route == "" {
			route = "unmatched"
		}
		duration := time.Since(start)
		httpRequests.WithLabelValues(route, r.Method, strconv.Itoa(recorder.status)).Inc()
		httpDuration.WithLabelValues(route, r.Method).Observe(duration.Seconds())
		slog.Info("http request", "request_id", kernel.RequestID(r.Context()), "method", r.Method,
			"route", route, "status", recorder.status, "duration_ms", duration.Milliseconds())
	})
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'")
		if strings.HasPrefix(s.app.PublicURL, "https://") {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		if strings.HasPrefix(r.URL.Path, "/v1/control/") || strings.HasPrefix(r.URL.Path, "/v1/setup/") {
			w.Header().Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireControlUser(next http.Handler) http.Handler {
	return s.controlUserMiddleware(false, next)
}
func (s *Server) requireSetup(next http.Handler) http.Handler {
	return s.controlUserMiddleware(true, next)
}

func (s *Server) controlUserMiddleware(setup bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		credential := ""
		fromCookie := false
		authorization := strings.TrimSpace(r.Header.Get("Authorization"))
		if strings.HasPrefix(strings.ToLower(authorization), "bearer ") {
			credential = strings.TrimSpace(authorization[7:])
		} else if cookie, cookieErr := r.Cookie("p93_control_access"); cookieErr == nil {
			credential, fromCookie = cookie.Value, true
		}
		if credential == "" {
			kernel.WriteProblem(w, r, http.StatusUnauthorized, "control_user_access_required", "A Platform user access JWT is required.")
			return
		}
		claims, err := identity.Verify(credential, func(kid string) (*rsa.PublicKey, error) {
			return s.app.ResolvePublicKey(r.Context(), kid)
		}, s.app.Issuer(), s.app.ControlAudience(), s.app.Now())
		if err != nil || claims.ActorType != "control_user" || setup && claims.TokenKind != "setup" || !setup && claims.TokenKind != "control" {
			kernel.WriteProblem(w, r, http.StatusUnauthorized, "invalid_control_user_session", "The Platform user session is invalid or expired.")
			return
		}
		var live bool
		err = s.app.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM control_user_sessions s JOIN control_users o ON o.id=s.control_user_id
WHERE s.id=$1 AND s.control_user_id=$2 AND s.kind=$3 AND s.revoked_at IS NULL AND s.expires_at>now() AND o.status='active')`,
			claims.SessionID, claims.Subject, claims.TokenKind).Scan(&live)
		if err != nil || !live {
			kernel.WriteProblem(w, r, http.StatusUnauthorized, "invalid_control_user_session", "The Platform user session is invalid or revoked.")
			return
		}
		actor := kernel.Actor{Type: "control_user", ID: claims.Subject, SessionID: claims.SessionID, Permissions: strings.Fields(claims.Scope)}
		_, _ = s.app.DB.Exec(r.Context(), `UPDATE control_user_sessions SET last_used_at=now(),ip_address=$1,user_agent=$2
WHERE id=$3 AND last_used_at<now()-interval '5 minutes'`, requestIPAddress(r), truncate(r.UserAgent(), 500), actor.SessionID)
		if fromCookie && !setup && r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			origin := strings.TrimRight(r.Header.Get("Origin"), "/")
			if origin == "" || !allowedControlOrigin(origin, s.app.PublicURL) {
				kernel.WriteProblem(w, r, http.StatusForbidden, "origin_not_allowed", "The request origin is not allowed.")
				return
			}
		}
		if !setup {
			var organizationID *string
			installationRole, hasInstallationRole := s.installationRole(r.WithContext(kernel.WithActor(r.Context(), actor)))
			if applicationID := chi.URLParam(r, "application_id"); applicationID != "" {
				var ownerOrganizationID string
				err = s.app.DB.QueryRow(r.Context(), `SELECT organization_id FROM applications WHERE id=$1 AND deleted_at IS NULL`, applicationID).Scan(&ownerOrganizationID)
				if err != nil {
					kernel.WriteProblem(w, r, http.StatusNotFound, "application_not_found", "The application was not found.")
					return
				}
				var membershipRole string
				_ = s.app.DB.QueryRow(r.Context(), `SELECT role FROM organization_memberships
WHERE organization_id=$1 AND control_user_id=$2`, ownerOrganizationID, actor.ID).Scan(&membershipRole)
				readOnly := r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions
				canRead := hasInstallationRole || membershipRole != ""
				canWrite := hasInstallationRole && (installationRole == "owner" || installationRole == "admin") || membershipRole == "owner" || membershipRole == "admin"
				if !canRead {
					kernel.WriteProblem(w, r, http.StatusNotFound, "application_not_found", "The application was not found.")
					return
				}
				if !readOnly && !canWrite {
					kernel.WriteProblem(w, r, http.StatusForbidden, "control_user_permission_required", "An organization owner or administrator is required for this operation.")
					return
				}
				organizationID = &ownerOrganizationID
			}
			request := r.WithContext(kernel.WithActor(r.Context(), actor))
			if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
				recorder := &statusResponseWriter{ResponseWriter: w, status: http.StatusOK}
				next.ServeHTTP(recorder, request)
				if recorder.status >= 200 && recorder.status < 300 {
					var application any
					if value := chi.URLParam(r, "application_id"); value != "" {
						application = value
					}
					if organizationID == nil {
						if value := chi.URLParam(r, "organization_id"); value != "" {
							organizationID = &value
						}
					}
					_, auditErr := s.app.DB.Exec(r.Context(), `INSERT INTO audit_records
(id,organization_id,application_id,actor_type,actor_id,action,target_type,reason,request_id,changes)
VALUES ($1,$2,$3,'control_user',$4,$5,'http_route',$6,$7,jsonb_build_object('method',$8::text,'path',$9::text))`,
						kernel.NewID(), organizationID, application, actor.ID, "http."+strings.ToLower(r.Method), truncate(r.Header.Get("X-Audit-Reason"), 500), kernel.RequestID(r.Context()), r.Method, r.URL.Path)
					if auditErr != nil {
						slog.Error("control user audit record failed", "request_id", kernel.RequestID(r.Context()), "error", auditErr)
					}
				}
				return
			}
		}
		next.ServeHTTP(w, r.WithContext(kernel.WithActor(r.Context(), actor)))
	})
}

func allowedControlOrigin(origin, publicURL string) bool {
	if origin == strings.TrimRight(publicURL, "/") {
		return true
	}
	originURL, originErr := url.Parse(origin)
	public, publicErr := url.Parse(publicURL)
	if originErr != nil || publicErr != nil || originURL.Scheme != "http" || public.Scheme != "http" || originURL.Port() != public.Port() {
		return false
	}
	return loopbackHost(originURL.Hostname()) && loopbackHost(public.Hostname())
}

func loopbackHost(host string) bool {
	return strings.EqualFold(host, "localhost") || net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback()
}

type statusResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusResponseWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (s *Server) requireUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		applicationID, err := uuid.Parse(chi.URLParam(r, "application_id"))
		if err != nil {
			kernel.WriteProblem(w, r, http.StatusBadRequest, "invalid_application_id", "The application identifier is invalid.")
			return
		}
		authorization := strings.TrimSpace(r.Header.Get("Authorization"))
		if !strings.HasPrefix(strings.ToLower(authorization), "bearer ") {
			kernel.WriteProblem(w, r, http.StatusUnauthorized, "access_token_required", "A bearer credential is required.")
			return
		}
		credential := strings.TrimSpace(authorization[7:])
		if strings.HasPrefix(credential, "p93_pat_") {
			var actor kernel.Actor
			var scopes []string
			err = s.app.DB.QueryRow(r.Context(), `SELECT k.user_id,k.id FROM personal_api_keys k
JOIN users u ON u.id=k.user_id JOIN applications a ON a.id=k.application_id WHERE k.application_id=$1 AND k.token_digest=$2
			AND k.revoked_at IS NULL AND k.expires_at>now() AND u.status='active'
			AND COALESCE((a.internal_config->>'personal_api_keys_enabled')::boolean,false)`, applicationID, s.app.Vault.Digest(credential)).Scan(&actor.ID, &actor.SessionID)
			if err == nil {
				_ = s.app.DB.QueryRow(r.Context(), "SELECT scopes FROM personal_api_keys WHERE id=$1", actor.SessionID).Scan(&scopes)
				_, _ = s.app.DB.Exec(r.Context(), "UPDATE personal_api_keys SET last_used_at=now() WHERE id=$1", actor.SessionID)
				actor.Type, actor.ApplicationID = "user_api_key", applicationID.String()
				actor.Permissions = reducePermissions(s.permissions(r, applicationID, actor.ID), scopes)
				next.ServeHTTP(w, r.WithContext(kernel.WithActor(r.Context(), actor)))
				return
			}
		}
		var applicationActive bool
		if err = s.app.DB.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM applications WHERE id=$1 AND deleted_at IS NULL)", applicationID).Scan(&applicationActive); err != nil || !applicationActive {
			kernel.WriteProblem(w, r, http.StatusUnauthorized, "invalid_access_token", "The access token is invalid.")
			return
		}
		claims, err := identity.Verify(credential, func(kid string) (*rsa.PublicKey, error) {
			return s.app.ResolvePublicKey(r.Context(), kid)
		}, s.app.Issuer(), s.app.ApplicationAudience(applicationID), s.app.Now())
		if err != nil || claims.ApplicationID != applicationID.String() || claims.TokenKind != "access" || claims.ActorType != "user" {
			kernel.WriteProblem(w, r, http.StatusUnauthorized, "invalid_access_token", "The access token is invalid or expired.")
			return
		}
		var live bool
		err = s.app.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM user_sessions s JOIN users u ON u.id=s.user_id
WHERE s.id=$1 AND s.user_id=$2 AND s.application_id=$3 AND s.revoked_at IS NULL AND s.expires_at>now() AND u.status='active'
AND (s.delegation_id IS NULL OR EXISTS(SELECT 1 FROM delegations d WHERE d.id=s.delegation_id AND d.exchanged_at IS NOT NULL
AND d.revoked_at IS NULL AND d.expires_at>now())))`,
			claims.SessionID, claims.Subject, applicationID).Scan(&live)
		if err != nil || !live {
			kernel.WriteProblem(w, r, http.StatusUnauthorized, "inactive_user_session", "The user session is no longer active.")
			return
		}
		if claims.ClientID != "" {
			var consentLive bool
			err = s.app.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM oauth_consents c JOIN clients cl ON cl.id=c.client_id
WHERE c.application_id=$1 AND c.user_id=$2 AND cl.client_id=$3 AND cl.disabled_at IS NULL AND c.revoked_at IS NULL)`,
				applicationID, claims.Subject, claims.ClientID).Scan(&consentLive)
			if err != nil || !consentLive {
				kernel.WriteProblem(w, r, http.StatusUnauthorized, "oauth_consent_inactive", "The OAuth consent is no longer active.")
				return
			}
		}
		permissions := strings.Fields(claims.Scope)
		delegatedBy := ""
		if claims.Actor != nil {
			var delegatedPermissions []string
			var controlUserID string
			err = s.app.DB.QueryRow(r.Context(), `SELECT d.permissions,d.control_user_id FROM user_sessions us
JOIN delegations d ON d.id=us.delegation_id WHERE us.id=$1 AND us.user_id=$2 AND d.application_id=$3`,
				claims.SessionID, claims.Subject, applicationID).Scan(&delegatedPermissions, &controlUserID)
			if err != nil || claims.Actor.Type != "control_user" || claims.Actor.Subject != controlUserID {
				kernel.WriteProblem(w, r, http.StatusUnauthorized, "invalid_delegated_session", "The delegated session is invalid.")
				return
			}
			permissions = allowedDelegatedPermissions(permissions, delegatedPermissions)
			delegatedBy = controlUserID
		}
		actor := kernel.Actor{Type: "user", ID: claims.Subject, ApplicationID: claims.ApplicationID, SessionID: claims.SessionID,
			Permissions: permissions, DelegatedBy: delegatedBy}
		next.ServeHTTP(w, r.WithContext(kernel.WithActor(r.Context(), actor)))
	})
}

// requireApplicationActor accepts ordinary application users and OAuth machine clients.
// User authentication remains in requireUser so its session, consent, and delegation
// checks stay identical for every user-facing route.
func (s *Server) requireApplicationActor(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization := strings.TrimSpace(r.Header.Get("Authorization"))
		if !strings.HasPrefix(strings.ToLower(authorization), "bearer ") {
			s.requireUser(next).ServeHTTP(w, r)
			return
		}
		credential := strings.TrimSpace(authorization[7:])
		if strings.HasPrefix(credential, "p93_pat_") {
			s.requireUser(next).ServeHTTP(w, r)
			return
		}
		applicationID, err := uuid.Parse(chi.URLParam(r, "application_id"))
		if err != nil {
			kernel.WriteProblem(w, r, http.StatusBadRequest, "invalid_application_id", "The application identifier is invalid.")
			return
		}
		claims, err := identity.Verify(credential, func(kid string) (*rsa.PublicKey, error) {
			return s.app.ResolvePublicKey(r.Context(), kid)
		}, s.app.Issuer(), s.app.ApplicationAudience(applicationID), s.app.Now())
		if err != nil || claims.ApplicationID != applicationID.String() || claims.TokenKind != "machine" || claims.ActorType != "client" || claims.Subject == "" {
			s.requireUser(next).ServeHTTP(w, r)
			return
		}
		if claims.ClientID != "" && claims.ClientID != claims.Subject {
			kernel.WriteProblem(w, r, http.StatusUnauthorized, "invalid_machine_token", "The machine token client identity is inconsistent.")
			return
		}
		var clientDatabaseID string
		err = s.app.DB.QueryRow(r.Context(), `SELECT c.id FROM clients c JOIN applications a ON a.id=c.application_id
WHERE c.application_id=$1 AND c.client_id=$2 AND c.disabled_at IS NULL AND a.deleted_at IS NULL`, applicationID, claims.Subject).Scan(&clientDatabaseID)
		if err != nil {
			kernel.WriteProblem(w, r, http.StatusUnauthorized, "inactive_machine_client", "The machine client is disabled or unavailable.")
			return
		}
		current := kernel.Actor{Type: "client", ID: clientDatabaseID, ApplicationID: applicationID.String(), Permissions: strings.Fields(claims.Scope)}
		next.ServeHTTP(w, r.WithContext(kernel.WithActor(r.Context(), current)))
	})
}

func allowedDelegatedPermissions(live, delegated []string) []string {
	result := make([]string, 0, len(delegated))
	for _, wanted := range delegated {
		for _, granted := range live {
			if permissionMatches(granted, wanted) {
				result = append(result, wanted)
				break
			}
		}
	}
	return result
}

func containsAllowedScope(live []string, requested string) bool {
	for _, granted := range live {
		if permissionMatches(granted, requested) {
			return true
		}
	}
	return false
}

func reducePermissions(permissions, scopes []string) []string {
	if len(scopes) == 0 {
		return permissions
	}
	result := make([]string, 0, len(permissions))
	for _, permission := range permissions {
		for _, scope := range scopes {
			if permissionMatches(scope, permission) {
				result = append(result, permission)
				break
			}
		}
	}
	return result
}

func (s *Server) adminHandler() http.Handler {
	if info, err := os.Stat(s.adminAssets); err != nil || !info.IsDir() {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		})
	}
	assets := os.DirFS(s.adminAssets)
	files := http.FileServerFS(assets)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assetPath := strings.TrimPrefix(pathpkg.Clean("/"+r.URL.Path), "/")
		if assetPath == "" {
			assetPath = "."
		}
		if !fs.ValidPath(assetPath) {
			http.NotFound(w, r)
			return
		}
		if info, err := fs.Stat(assets, assetPath); err == nil && !info.IsDir() {
			if strings.EqualFold(pathpkg.Ext(assetPath), ".html") {
				s.serveAdminHTML(w, r, assets, assetPath)
				return
			}
			files.ServeHTTP(w, r)
			return
		}
		index := pathpkg.Join(assetPath, "index.html")
		if _, err := fs.Stat(assets, index); err == nil {
			s.serveAdminHTML(w, r, assets, index)
			return
		}
		s.serveAdminHTML(w, r, assets, "index.html")
	})
}

func (s *Server) serveAdminHTML(w http.ResponseWriter, r *http.Request, assets fs.FS, assetPath string) {
	content, err := fs.ReadFile(assets, assetPath)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	hashes := make([]string, 0, 8)
	for _, match := range inlineScriptPattern.FindAllSubmatch(content, -1) {
		if len(match) != 2 || len(match[1]) == 0 {
			continue
		}
		digest := sha256.Sum256(match[1])
		hashes = append(hashes, "'sha256-"+base64.StdEncoding.EncodeToString(digest[:])+"'")
	}
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' "+strings.Join(hashes, " ")+"; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	kernel.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	if err := s.app.DB.Ping(r.Context()); err != nil {
		kernel.WriteProblem(w, r, http.StatusServiceUnavailable, "database_unavailable", "The database is unavailable.")
		return
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}
func (s *Server) version(w http.ResponseWriter, _ *http.Request) {
	kernel.WriteJSON(w, http.StatusOK, map[string]string{"version": buildinfo.Version, "commit": buildinfo.Commit, "built_at": buildinfo.Date, "schema": "1"})
}

func applicationID(r *http.Request) (uuid.UUID, error) {
	return uuid.Parse(chi.URLParam(r, "application_id"))
}

func actor(r *http.Request) kernel.Actor {
	value, _ := kernel.ActorFrom(r.Context())
	return value
}

func decodeMap(value []byte) map[string]any {
	result := map[string]any{}
	_ = json.Unmarshal(value, &result)
	return result
}

func decodeJSONValue(value []byte) any {
	var result any
	_ = json.Unmarshal(value, &result)
	return result
}

func rollback(tx interface{ Rollback(context.Context) error }, ctx context.Context) {
	_ = tx.Rollback(ctx)
}
