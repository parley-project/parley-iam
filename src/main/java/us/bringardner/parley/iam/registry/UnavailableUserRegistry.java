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
 * A registry that can't answer anything, as one whose database is down: every login is
 * UNAVAILABLE, every lookup throws {@link UserRegistryUnavailableException}, every permission check
 * is UNAVAILABLE, all with the reason given. It says it supports every kind of credential, so a
 * server still offers them (SCRAM, APOP) and the client is told to try again later, not that its
 * password is wrong.
 *
 * @since 2.0.0
 */
public class UnavailableUserRegistry implements UserRegistry {

    private final String reason;

    /** @param reason why it can't answer, e.g. "the database is down" */
    public UnavailableUserRegistry(String reason) {
        this.reason = Objects.requireNonNull(reason, "reason");
    }

    /** @return why it can't answer */
    public String getReason() {
        return reason;
    }

    @Override
    public boolean supports(Class<? extends Credential> kind, StoredCredentialType stored) {
        return true;
    }

    @Override
    public AuthenticationResult authenticate(Credential credential) {
        return AuthenticationResult.unavailable(reason);
    }

    @Override
    public StoredCredential findStoredCredential(String user, StoredCredentialType type)
            throws UserRegistryUnavailableException {
        throw new UserRegistryUnavailableException(reason);
    }

    @Override
    public ParleyPrincipal findPrincipal(String name) throws UserRegistryUnavailableException {
        throw new UserRegistryUnavailableException(reason);
    }

    @Override
    public ParleyPrincipal findPrincipal(EntityId id) throws UserRegistryUnavailableException {
        throw new UserRegistryUnavailableException(reason);
    }

    @Override
    public Set<ParleyPrincipal> findGroups(ParleyPrincipal principal) throws UserRegistryUnavailableException {
        throw new UserRegistryUnavailableException(reason);
    }

    @Override
    public Set<ParleyPrincipal> findMembers(ParleyPrincipal group) throws UserRegistryUnavailableException {
        throw new UserRegistryUnavailableException(reason);
    }

    @Override
    public AuthorizationResult checkPermission(Requester requester, ParleyPermission needed,
            ProtectedResource resource) {
        return AuthorizationResult.unavailable(reason);
    }
}
