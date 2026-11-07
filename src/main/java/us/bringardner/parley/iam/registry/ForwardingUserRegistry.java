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
package us.bringardner.parley.iam.registry;

import java.io.IOException;
import java.util.Objects;
import java.util.Set;

import us.bringardner.parley.iam.AuthenticationResult;
import us.bringardner.parley.iam.AuthorizationResult;
import us.bringardner.parley.iam.Credential;
import us.bringardner.parley.iam.EntityId;
import us.bringardner.parley.iam.ParleyPermission;
import us.bringardner.parley.iam.ParleyPrincipal;
import us.bringardner.parley.iam.ProtectedResource;
import us.bringardner.parley.iam.Requester;
import us.bringardner.parley.iam.StoredCredential;
import us.bringardner.parley.iam.StoredCredentialType;
import us.bringardner.parley.iam.UserRegistry;
import us.bringardner.parley.iam.UserRegistryUnavailableException;

/**
 * A registry that passes every {@link UserRegistry} method to another one. A wrapper extends it and
 * overrides only what differs: a registry whose permission checks are down, one that logs or
 * caches, a read-only view.
 * <p>
 * It is only a {@code UserRegistry}: even when the registry it wraps is also a
 * {@link us.bringardner.parley.iam.PrincipalManager PrincipalManager} or
 * {@link us.bringardner.parley.iam.PermissionManager PermissionManager}, this one isn't, so an
 * application that checks with {@code instanceof} sees only the reading part.
 * <p>
 * {@link #close()} closes the wrapped registry.
 *
 * @since 2.0.0
 */
public class ForwardingUserRegistry implements UserRegistry {

    private final UserRegistry delegate;

    /** @param delegate the registry every call goes to */
    public ForwardingUserRegistry(UserRegistry delegate) {
        this.delegate = Objects.requireNonNull(delegate, "delegate");
    }

    /** @return the registry every call goes to */
    protected UserRegistry delegate() {
        return delegate;
    }

    @Override
    public boolean supports(Class<? extends Credential> kind, StoredCredentialType stored) {
        return delegate.supports(kind, stored);
    }

    @Override
    public AuthenticationResult authenticate(Credential credential) {
        return delegate.authenticate(credential);
    }

    @Override
    public StoredCredential findStoredCredential(String user, StoredCredentialType type)
            throws UserRegistryUnavailableException {
        return delegate.findStoredCredential(user, type);
    }

    @Override
    public void recordOutcome(String user, AuthenticationResult result) {
        delegate.recordOutcome(user, result);
    }

    @Override
    public ParleyPrincipal findPrincipal(String name) throws UserRegistryUnavailableException {
        return delegate.findPrincipal(name);
    }

    @Override
    public ParleyPrincipal findPrincipal(EntityId id) throws UserRegistryUnavailableException {
        return delegate.findPrincipal(id);
    }

    @Override
    public Set<ParleyPrincipal> findGroups(ParleyPrincipal principal) throws UserRegistryUnavailableException {
        return delegate.findGroups(principal);
    }

    @Override
    public Set<ParleyPrincipal> findMembers(ParleyPrincipal group) throws UserRegistryUnavailableException {
        return delegate.findMembers(group);
    }

    @Override
    public AuthorizationResult checkPermission(Requester requester, ParleyPermission needed,
            ProtectedResource resource) {
        return delegate.checkPermission(requester, needed, resource);
    }

    @Override
    public void close() throws IOException {
        delegate.close();
    }
}
