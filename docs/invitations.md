# Application And Workspace Invitations

Platform93 uses one application invitation model. An invitation can create basic
application access, assign application roles, and optionally add the recipient to
one workspace with workspace roles. It works independently of whether public
registration is enabled.

`internal_config.user_invitations_enabled` controls invitations created by
application users and defaults to `false`. When enabled, workspace owners and
members with the workspace invitation-management permission can invite recipients
to that workspace and assign workspace roles. Control-plane administrators and
machine clients with invitation-management permission are not affected by this
toggle. Disabling it does not revoke pending invitations.

Invitation links are sent to the application's configured
`auth_config.flows.invitation_redirect_uri`. The browser application uses
`@supaapps/platform93-auth` to parse the link or collect the email and eight-character
code. The package generates an S256 PKCE pair, exchanges the invitation, and redeems
the returned one-time authorization code. Acceptance verifies the email, creates or
reuses the application user, and applies roles and workspace membership atomically.

Backend automation uses an OAuth machine client with
`/applications/{application_id}/invitations/manage`, or the corresponding workspace
permission. Workspace owners can list active members and pending recipients through:

```text
GET /v1/applications/{application_id}/workspaces/{workspace_id}/access
```

Resend rotates both credentials, invalidates prior links/codes, extends expiry, and
is limited to once per 60 seconds. Pending invitations expire after seven days by
default; callers may choose between five minutes and thirty days.
