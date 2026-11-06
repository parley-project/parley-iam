# parley-iam

Identity and access management building blocks for Parley: principals and groups,
credentials, permissions, protected resources, and the `UserRegistry` interface an
application implements to supply them.

**Status: design sketch.** This branch exists so the design can be read as code. It is
not wired into any server and the names and shapes may change.

- Java 11 or later
- No runtime dependencies
- Apache License 2.0

## What's included

| Type | Purpose |
|---|---|
| `EntityId`, `Entity` | The unique id every principal, group and resource is given when it is created; never changes, never reused. |
| `ParleyPrincipal`, `BasicParleyPrincipal` | Who someone is (a person, a key, a group), read-only, with attributes the implementation names. |
| `BuiltInGroups` | `anyone` and `authenticated`, whose membership the framework decides. |
| `ProtectedResource` | What a permission is about; the application defines it. Has a type, a name and an owner. |
| `ParleyPermission`, `BasicParleyPermission` | A permission name on a resource; `implies` says whether a held permission covers a needed one. |
| `StandardPermissions` | The names `read`, `write`, `delete`, `grant`, `admin`. |
| `Requester` | Who is asking, with the connection's facts (address, TLS, port, transport, login methods). |
| `Credential` and its kinds | What a client offers: password, token, certificate, proof, vouched. |
| `StoredCredential`, `StoredCredentialType`, `ProofVerifier` | A stored secret for a proof, and the protocol's own check of it. |
| `AuthenticationResult`, `AuthorizationResult` | How a login or a permission check ended. |
| `UserRegistry` | The application's answer to "who is this, what groups, what permissions". Read-only. |
| `BasicUserRegistry` | The default registry: principals, groups, PBKDF2 password logins and grants in memory, with methods for the application to change them. Use it as it is, fill it from a file or database, or extend it. |
| `Authorizer`, `BasicAuthorizer` | Decides a permission check; the basic one asks a `UserRegistry`. Replaceable. |

Not in the sketch yet: the login policy (failure counting, delays, lockout) and the waiting
part for proofs, which the design places in this module too.
