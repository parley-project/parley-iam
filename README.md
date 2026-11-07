# parley-iam

Identity and access management for Parley: principals and groups, credentials, permissions,
protected resources, and the `UserRegistry` interface an application implements to supply them.
parley-net's servers log users in and check permissions with these types.

- Java 11 or later
- No runtime dependencies
- Apache License 2.0

## What's included

| Type | Purpose |
|---|---|
| `UserRegistry` | The application's users. It checks the credentials it can check itself, hands out a stored secret for a proof, finds principals by name or id, and answers the permission check (`checkPermission`: ALLOWED, DENIED or UNAVAILABLE). The framework only reads it. |
| `BasicUserRegistry` | A registry kept in memory: principals, groups (which may nest), PBKDF2 password logins and grants, with methods for the application to change them. It allows a permission when the principal or one of its groups holds one that covers it. Use it as it is, fill it from a file or database, or extend it. |
| `Requester` | Who is asking, with the connection's facts (address, local port, TLS, transport, server name, login methods used so far). Only the framework's session logs a requester in. |
| `Credential` and its kinds | What a client offers: `PasswordCredential`, `TokenCredential`, `CertificateCredential`, `ProofCredential`, `VouchedCredential`. |
| `StoredCredential`, `StoredCredentialType`, `ProofVerifier` | A stored secret for a proof (SCRAM, APOP, SSH keys, TSIG), and the protocol's own check of it. |
| `AuthenticationResult`, `AuthorizationResult` | How a login ended (AUTHENTICATED, REFUSED, UNSUPPORTED, UNAVAILABLE) and how a permission check ended (ALLOWED, DENIED, UNAVAILABLE), each with a reason for the log. |
| `UserRegistryUnavailableException` | The registry can't answer now (a database is down, say). |
| `ParleyPrincipal`, `BasicParleyPrincipal` | Who someone is (a person, a key, a group), read-only, with attributes the implementation names. |
| `ParleyPermission`, `BasicParleyPermission` | A permission name, optionally on one resource; `implies` says whether a held permission covers a needed one, for registries that compare them. |
| `StandardPermissions` | The names `read`, `write`, `delete`, `grant`, `admin`. |
| `ProtectedResource` | What a permission is about; the application defines it. Has a type, a name and an owner. |
| `EntityId`, `Entity` | The unique id a principal, group or resource is given when it is created; it never changes and is never reused. |

## How the framework uses it

parley-net's servers (`Server`, `NioServer`) do the parts that are the same for every protocol:

1. A session logs in only through its own `authenticate(credential)`. A proof (SCRAM, APOP, SSH
   keys) is run by the server: it gets the stored secret from the registry, then runs the protocol's
   `ProofVerifier` without holding the registry while it waits on the client. An unknown user gets a
   made-up secret, so the exchange fails the same way.
2. Every command that needs a permission is checked before it runs, by asking the registry's
   `checkPermission`. The server never compares permissions itself.
3. Login limits (failures per connection, the delay before a refused login is answered, the time
   allowed to log in) are applied by the server with the application's values.
4. Using a part that needs a registry with none configured is an error naming the missing setting,
   not a refused login or a denied permission.

What a permission covers, how groups combine, who owns what and how users are managed are the
registry's and the application's to decide.
