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
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * The default {@link Authorizer}, asking one {@link UserRegistry}:
 * <ol>
 * <li>The resource's owner is allowed, and so is a member of a group that owns it.</li>
 * <li>Otherwise the requester is allowed when {@code anyone}, {@code authenticated} (when
 * logged in), the principal or one of its groups holds a permission that implies the
 * needed one.</li>
 * <li>Otherwise it is denied.</li>
 * </ol>
 * The first match decides and gives the reason. A registry that can't answer gives
 * UNAVAILABLE, never DENIED.
 */
public class BasicAuthorizer implements Authorizer {

    private final UserRegistry registry;

    /** @param registry where principals, groups and permissions come from */
    public BasicAuthorizer(UserRegistry registry) {
        this.registry = Objects.requireNonNull(registry, "registry");
    }

    @Override
    public AuthorizationResult check(Requester requester, ParleyPermission needed, ProtectedResource resource) {
        try {
            ParleyPrincipal principal = requester.getPrincipal();
            Set<ParleyPrincipal> groups = null;
            if (principal != null) {
                groups = registry.findGroups(principal);
            }

            // 1. The owner, or a member of the group that owns it
            if (resource != null && principal != null) {
                EntityId owner = resource.getOwnerId();
                if (owner.equals(principal.getId())) {
                    return AuthorizationResult.allowed(principal.getName() + " owns " + resource.getName());
                }
                for (ParleyPrincipal group : groups) {
                    if (owner.equals(group.getId())) {
                        return AuthorizationResult.allowed(principal.getName() + " is in "
                                + group.getName() + ", which owns " + resource.getName());
                    }
                }
            }

            // 2. Holders in order: anyone, authenticated, the principal, its groups
            List<ParleyPrincipal> holders = new ArrayList<ParleyPrincipal>();
            holders.add(BuiltInGroups.ANYONE);
            if (principal != null) {
                holders.add(BuiltInGroups.AUTHENTICATED);
                holders.add(principal);
                holders.addAll(groups);
            }
            for (ParleyPrincipal holder : holders) {
                Collection<ParleyPermission> held = registry.findPermissions(requester, holder, resource);
                for (ParleyPermission permission : held) {
                    if (permission.implies(needed)) {
                        return AuthorizationResult.allowed(holder.getName() + " holds " + permission);
                    }
                }
            }

            // 3. Nothing matched
            String who = "nobody logged in";
            if (principal != null) {
                who = principal.getName();
            }
            return AuthorizationResult.denied(who + " holds nothing that covers " + needed);
        } catch (UserRegistryUnavailableException e) {
            return AuthorizationResult.unavailable(e.getMessage());
        }
    }
}
