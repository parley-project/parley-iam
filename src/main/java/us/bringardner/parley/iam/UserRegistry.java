/**
 * <PRE>
 *
 * Copyright 2026 <A href="http://bringardner.us/tony">Tony Bringardner</A>
 *
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       <A href="http://www.apache.org/licenses/LICENSE-2.0">http://www.apache.org/licenses/LICENSE-2.0</A>
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *  </PRE>
 *
 *
 *	@author Tony Bringardner
 *
 *
 */
package us.bringardner.parley.iam;

import java.io.Closeable;
import java.io.IOException;
import java.util.Collection;
import java.util.Set;

/**
 * The one place the framework asks about users: who they are, what secrets they have,
 * what groups they are in and what permissions they hold. It is implemented by the
 * application (a file, a database, LDAP, single sign-on), and everything it returns is
 * read-only to the framework. How principals, groups, attributes and grants are created
 * or changed is the implementation's business; this interface only reads.
 */
public interface UserRegistry extends Closeable {

    /**
     * Can every user who can log in use this kind of credential? A server offers a login
     * method only when the answer is yes, because a client that picks an offered method
     * often can't fall back to another.
     *
     * @param kind the credential class, for example {@code PasswordCredential.class}
     * @param stored for a proof, the kind of stored secret it needs; otherwise null
     */
    boolean supports(Class<? extends Credential> kind, StoredCredentialType stored);

    /**
     * Check a credential this registry checks itself: a password, a token, a certificate,
     * vouched. Proofs don't come here; the framework runs their verifier (see
     * {@link #findStoredCredential}). For an unknown user, take as long as for a known one.
     */
    AuthenticationResult authenticate(Credential credential);

    /**
     * For a proof: the user's stored secret of that kind, or null when the user has none.
     * Must be quick: no waiting on a client.
     */
    StoredCredential findStoredCredential(String user, StoredCredentialType type)
            throws UserRegistryUnavailableException;

    /** Told how a proof ended, for a registry that records logins. The default does nothing. */
    default void recordOutcome(String user, AuthenticationResult result) {
    }

    /**
     * Look a principal up by any name it goes by (an alias, another case).
     *
     * @return the principal, carrying its canonical name, or null when there is none
     */
    ParleyPrincipal findPrincipal(String name) throws UserRegistryUnavailableException;

    /** @return the principal with this id, or null when there is none */
    ParleyPrincipal findPrincipal(EntityId id) throws UserRegistryUnavailableException;

    /**
     * Every group the principal is in, including through other groups (Tony in sales,
     * sales in staff: both). The registry handles loops. An implementation without nested
     * groups returns direct groups only. Never includes the built-in groups.
     */
    Set<ParleyPrincipal> findGroups(ParleyPrincipal principal) throws UserRegistryUnavailableException;

    /**
     * The permissions this holder holds on this resource (or on the server as a whole when
     * the resource is null). The holder is a principal, one of its groups, or a built-in
     * group. The requester is passed so an implementation can apply conditions of its own
     * (only over TLS, only from these addresses); the framework applies none.
     *
     * @return the permissions held; empty when there are none
     */
    Collection<ParleyPermission> findPermissions(Requester requester, ParleyPrincipal holder,
            ProtectedResource resource) throws UserRegistryUnavailableException;

    /** Let go of connections and caches. The default does nothing. */
    @Override
    default void close() throws IOException {
    }
}
