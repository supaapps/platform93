# Optional Object Storage

Platform93 can use an existing S3-compatible provider for light object storage.
Typical uses are email images, avatars, documents, temporary exports, and modest
application files. PostgreSQL remains the only required service. Object storage is
not an application database, shared filesystem, backup target, media pipeline, or
replacement for a dedicated high-throughput storage service.

## Provider Resolution

Providers can be configured at installation, organization, or application scope.
Installation and organization providers are available to children only when their
inheritance toggle is enabled. Public and private buckets resolve independently in
application, organization, installation order, so an application may use a local
public bucket while inheriting private storage.

Every object is permanently pinned to the provider and bucket selected when its
upload was authorized. Replacing a provider changes new uploads only. Disabling a
provider blocks Platform93 uploads, completion, downloads, and deletion for its
objects until it is enabled again. Anonymous public URLs and private URLs already
issued by S3 cannot be revoked by disabling Platform93 configuration.

Providers require an endpoint, region, access key, secret key, and at least one
pre-created bucket. Path-style addressing supports MinIO and providers that do not
use bucket subdomains. `public_base_url` can point to an HTTPS CDN or custom domain
whose path maps to the root of the configured public bucket.

Verification performs a write, authenticated read, anonymous read, and deletion in
each configured bucket. The public bucket must permit anonymous object reads and the
private bucket must reject them. Credentials are encrypted, write-only, omitted from
events, and redacted from API and audit responses.

Private-network and plain HTTP endpoints are rejected by default. An installation
owner can explicitly allow one on an installation provider. Child scopes cannot
make this exception. Prefer HTTPS even on private networks.

## Browser CORS

Platform93 authorizes ten-minute, single-PUT uploads and clients transfer bytes
directly to S3. Configure every upload bucket to allow the administrator and
application origins. A minimal S3-compatible CORS policy is:

```json
[
  {
    "AllowedOrigins": ["https://platform.example.com", "https://app.example.com"],
    "AllowedMethods": ["PUT", "GET", "HEAD"],
    "AllowedHeaders": ["content-type", "content-length", "x-amz-*"],
    "ExposeHeaders": ["ETag"],
    "MaxAgeSeconds": 3600
  }
]
```

Do not use `*` origins when authenticated application pages can upload private
content. Bucket policy, not CORS, controls anonymous public reads.

For a Hetzner Object Storage provider, use the HTTPS endpoint and region shown for
the bucket, such as `https://nbg1.your-objectstorage.com` with region `nbg1`.
Use virtual-host addressing unless the provider configuration requires path style.
Buckets should be dedicated to Platform93 because object keys and lifecycle state
are managed by Platform93.

## Ownership And URLs

Objects are owned by an application, user, or workspace. Installation-owned objects
exist only for global email-template assets. Callers never choose raw object keys;
Platform93 generates immutable organization/application/owner namespaces.

User routes always bind the owner to the authenticated user. Workspace routes use
the existing workspace permission paths. Application OAuth clients can use
application or authorized workspace routes, but cannot access `/me/storage`.

Public objects expose a permanent URL and are anonymously accessible. The declared
MIME type is retained, so administrators must treat general public uploads as
potentially executable content and should use a separate asset domain. Private
downloads require a live Platform93 authorization check and return a five-minute
presigned URL.

Upload creation requires `Idempotency-Key`, filename, MIME type, byte size, and
visibility. The SDK flow is reserve, direct PUT, complete:

```ts
const storage = client.application();
const authorization = await storage.createStorageUpload({
  filename: file.name,
  content_type: file.type,
  size_bytes: file.size,
  visibility: "private",
}, crypto.randomUUID());

await storage.putStorageUpload(authorization, file);
const object = await storage.completeStorageUpload(authorization.object.id);
```

Completion verifies size and MIME metadata using S3 HEAD before making the object
ready. Pending reservations expire after one hour. Deletion is asynchronous and
idempotent; disabled providers retain deletion work until they are re-enabled.

## Limits And Email Images

Defaults are 25 MiB per object, 2 MiB per managed email image, 10 GiB per
application, and 100,000 active/reserved objects per application. Provider owners
can adjust these limits. Quotas are reserved transactionally before presigning so
concurrent workers and API pods cannot over-allocate an application.

The template editor enables its managed image library when an effective public
bucket exists. Managed images must be PNG, JPEG, or GIF, and Platform93 verifies
their signatures at completion. External absolute HTTPS image URLs remain allowed
without storage. Template versions record managed-object references; referenced
objects cannot be deleted unless an administrator supplies an explicit force flag
and audit reason.

PostgreSQL-backed notification attachments are unchanged.

## Deployment

No Helm or Compose service is required. API and worker pods need DNS and outbound
access to the configured endpoint. The chart permits HTTPS port 443 by default. Add
custom ports such as MinIO `9000` to `networkPolicy.storagePorts` when the chart's
NetworkPolicy is enabled.
