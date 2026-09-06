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
