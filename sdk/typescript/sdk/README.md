# @supaapps/platform93-sdk

Generated TypeScript client and typed API primitives for Platform93.

```bash
npm install @supaapps/platform93-sdk
```

See the [Platform93 repository](https://github.com/supaapps/platform93) for API and
self-hosting documentation.

## Generated request types

OpenAPI properties marked `writeOnly` are omitted from generated read projections.
Use the operation data body or its `Writable` model for low-level generated requests.
For example, the external email enrollment POST body is
`StartExternalEmailEnrollmentData["body"]`, which resolves to
`ExternalEmailEnrollmentStartWritable`. The primary `Platform93Client` methods expose
curated request types directly.

## Administrative Google provisioning

With a Platform user control token, call
`client.provisionGoogleUser(applicationId, input, idempotencyKey)` to create a user
and link a trusted Google subject without sending an invitation or email. Supply
`google_sub`, `reason`, and exactly one of `user` (new profile with required email)
or `user_id` (existing active application user). This is not a browser or machine
client capability. See [silent provisioning](https://github.com/supaapps/platform93/blob/main/docs/google-account-provisioning.md)
for collision handling, event behavior, and trust requirements.
