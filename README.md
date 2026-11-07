# parley-iam

Identity and access management for Parley: principals and groups, credentials, permissions,
protected resources, and the `UserRegistry` interface an application implements to supply them.
parley-net's servers log users in and check permissions with these types.

- Java 11 or later
- No runtime dependencies
- Apache License 2.0

## Packages

The main package, `us.bringardner.parley.iam`, is the contract: the interfaces and value classes an
application programs against and that the servers use. The default implementations and the fixed
vocabulary are in sub-packages, one per subject. The main package uses none of its sub-packages.

| Package | Holds |
|---|---|
| `us.bringardner.parley.iam` | `UserRegistry`, `PrincipalManager`, `PermissionManager`, `PrincipalChanges`, `ParleyPrincipal`, `ParleyPermission`, `Credential`, `StoredCredential`, `StoredCredentialType`, `ProofVerifier`, `Requester`, `AuthenticationResult`, `AuthorizationResult`, `ProtectedResource`, `Entity`, `EntityId`, `UserRegistryUnavailableException` |
| `...iam.credential` | The kinds of credential a client offers: `PasswordCredential`, `TokenCredential`, `CertificateCredential`, `ProofCredential`, `VouchedCredential` |
| `...iam.permission` | `BasicParleyPermission`, `StandardPermissions` |
| `...iam.principal` | `BasicParleyPrincipal` |
| `...iam.registry` | `BasicUserRegistry` |

## What's included

| Type | Purpose |
|---|---|
| `UserRegistry` | The application's users. It checks the credentials it can check itself, hands out a stored secret for a proof, finds principals by name or id, gives group membership from either end (`findGroups(principal)`, directly or through other groups, and `findMembers(group)`, direct members; the registry is the authority for membership), and answers the permission check (`checkPermission`: ALLOWED, DENIED or UNAVAILABLE). The framework only reads it. |
| `PrincipalManager` | Optional (an application checks with `instanceof`): create and delete users and groups, set attributes, add and remove members, set or remove a password, turn a user off and on (`setEnabled`; a turned-off user can't log in, holds nothing and isn't found, except by `findPrincipals`), and list by name (`findPrincipals(prefix, kind, limit)`). The methods don't check who is asking: that is the application's decision. |
| `PermissionManager` | Optional, separate from `PrincipalManager` so an application can keep its users in one place and its grants in another: `grant`, `revoke`, `findGrants` (the holder's own grants, not its groups'), and `supportsGrant(toGroup, onResource)`, so an application offers only what the registry can keep. A registry refuses a grant it can't keep. |
| `PrincipalChanges` | A change set: steps naming principals by name (so a step can name one an earlier step creates), applied with `PrincipalManager.apply(changes)`: every step or none, in one write. A step that can't work fails with an `IllegalArgumentException` naming it, and nothing is changed. Grant steps need a registry that is also a `PermissionManager`. `clear()` wipes the passwords the set holds. The single-step methods stay, each a change of its own. |
| `BasicUserRegistry` | A registry kept in memory, and a `PrincipalManager` and `PermissionManager`: principals, groups (which may nest), PBKDF2 password logins and grants of every kind (a grant about a resource, or about the whole server, which holds on every resource). It allows a permission when the principal or one of its groups holds one that covers it, and applies a change set under its lock, putting everything back when a step fails. Use it as it is, fill it from a file or database, or extend it. |
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

## Registries in other modules

- parley-net's `FileUserRegistry`: a users file. It is a `PrincipalManager` and a `PermissionManager`:
  groups (`group: <name>` lines for groups with no members, and group attributes), turned-off users
  (`enabled=false`), grants to users about the whole server, and a change set applied as one rewrite of
  the file (none when a step fails).
- parley-net-acl-jdbc's `JdbcUserRegistry`: a database. It is a `PrincipalManager` and a
  `PermissionManager`: grants to users and groups about the whole server, and a change set applied in one
  transaction, rolled back when a step fails.
