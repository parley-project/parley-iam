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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * A small registry for the tests, showing how little an implementation has to do.
 * It knows principals, direct group memberships and grants; it works out nested
 * groups itself. It checks no credentials.
 */
class InMemoryUserRegistry implements UserRegistry {

    private final Map<EntityId, ParleyPrincipal> principals = new HashMap<EntityId, ParleyPrincipal>();
    private final Map<EntityId, Set<ParleyPrincipal>> directGroups = new HashMap<EntityId, Set<ParleyPrincipal>>();
    private final Map<EntityId, List<ParleyPermission>> grants = new HashMap<EntityId, List<ParleyPermission>>();
    boolean unavailable;

    void add(ParleyPrincipal principal) {
        principals.put(principal.getId(), principal);
    }

    void addMember(ParleyPrincipal group, ParleyPrincipal member) {
        Set<ParleyPrincipal> groups = directGroups.get(member.getId());
        if (groups == null) {
            groups = new LinkedHashSet<ParleyPrincipal>();
            directGroups.put(member.getId(), groups);
        }
        groups.add(group);
    }

    void grant(ParleyPrincipal holder, ParleyPermission permission) {
        List<ParleyPermission> held = grants.get(holder.getId());
        if (held == null) {
            held = new ArrayList<ParleyPermission>();
            grants.put(holder.getId(), held);
        }
        held.add(permission);
    }

    @Override
    public boolean supports(Class<? extends Credential> kind, StoredCredentialType stored) {
        return false;
    }

    @Override
    public AuthenticationResult authenticate(Credential credential) {
        return AuthenticationResult.unsupported("the test registry checks no credentials");
    }

    @Override
    public StoredCredential findStoredCredential(String user, StoredCredentialType type) {
        return null;
    }

    @Override
    public ParleyPrincipal findPrincipal(String name) {
        for (ParleyPrincipal principal : principals.values()) {
            if (principal.getName().equalsIgnoreCase(name)) {
                return principal;
            }
        }
        return null;
    }

    @Override
    public ParleyPrincipal findPrincipal(EntityId id) {
        return principals.get(id);
    }

    @Override
    public Set<ParleyPrincipal> findGroups(ParleyPrincipal principal) throws UserRegistryUnavailableException {
        failIfUnavailable();
        Set<ParleyPrincipal> found = new LinkedHashSet<ParleyPrincipal>();
        collectGroups(principal, found);
        return found;
    }

    /** Adds every group of the principal, following groups of groups; a group already found stops a loop. */
    private void collectGroups(ParleyPrincipal principal, Set<ParleyPrincipal> found) {
        Set<ParleyPrincipal> groups = directGroups.get(principal.getId());
        if (groups == null) {
            return;
        }
        for (ParleyPrincipal group : groups) {
            if (found.add(group)) {
                collectGroups(group, found);
            }
        }
    }

    @Override
    public Collection<ParleyPermission> findPermissions(Requester requester, ParleyPrincipal holder,
            ProtectedResource resource) throws UserRegistryUnavailableException {
        failIfUnavailable();
        List<ParleyPermission> held = grants.get(holder.getId());
        if (held == null) {
            return Collections.emptyList();
        }
        return held;
    }

    private void failIfUnavailable() throws UserRegistryUnavailableException {
        if (unavailable) {
            throw new UserRegistryUnavailableException("the test database is down");
        }
    }
}
