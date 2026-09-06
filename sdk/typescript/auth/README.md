# @supaapps/platform93-auth

Headless browser authentication primitives for Platform93, with in-memory tokens by
default and explicit storage or BFF adapters.

Provider PKCE verifiers are separate from tokens. In browsers they use short-lived,
application-namespaced `sessionStorage` so full-page OAuth redirects can complete;
other runtimes use an injectable in-memory authorization-state store.

```bash
npm install @supaapps/platform93-auth
```

See the [Platform93 repository](https://github.com/supaapps/platform93) for complete
authentication flows.
