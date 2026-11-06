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

import java.util.Set;

/**
 * A {@link UserRegistry} whose grants an application can manage: permissions given to a user or
 * a group, about one resource or about the server as a whole, and taken away again. It is
 * separate from {@link PrincipalManager}, since an application may manage its users in one place
 * and its grants in another.
 * <p>
 * It is optional: an application that manages grants checks for it
 * ({@code registry instanceof PermissionManager}). A grant can be about anything that has or
 * needs a permission (a {@link ParleyPermission} with or without a resource); each registry keeps
 * what it can, refuses the rest with {@link IllegalArgumentException}, and says beforehand what it
 * keeps ({@link #supportsGrant}), so an application offers only what will work. A registry that
 * can't change its grants only sometimes (a file registry read from a class path resource
 * instead of a file) throws {@link UnsupportedOperationException} from the changing methods.
 * <p>
 * Whether a held permission covers a needed one is still the registry's answer, in
 * {@link #checkPermission}. A change goes to the registry's store, so every registry reading
 * that store sees it. These methods don't check who is asking: who may grant what is the
 * application's decision; it can ask {@link #checkPermission} first.
 */
public interface PermissionManager extends UserRegistry {

    /**
     * Does this registry keep this kind of grant? An application asks before it offers a grant,
     * as a server asks {@link #supports} before it offers a login method.
     *
     * @param toGroup true for a grant to a group, false for one to a user
     * @param onResource true for a grant about one resource, false for one about the server as a whole
     * @return true when {@link #grant} keeps such grants
     */
    boolean supportsGrant(boolean toGroup, boolean onResource);

    /**
     * Give a user or group a permission.
     *
     * @param holder a user or group of this registry
     * @param permission the permission, about a resource or about the server as a whole
     * @return true when it is new; false when the holder had it already
     * @throws IllegalArgumentException when the holder isn't in this registry, or the registry
     *             doesn't keep that kind of grant ({@link #supportsGrant})
     * @throws UserRegistryUnavailableException when the store can't be read or changed now
     */
    boolean grant(ParleyPrincipal holder, ParleyPermission permission) throws UserRegistryUnavailableException;

    /**
     * Take a permission away from a user or group. What it holds through its groups stays.
     *
     * @param holder a user or group of this registry
     * @param permission the permission, as it was granted (name and resource)
     * @return true when the holder had it
     * @throws IllegalArgumentException when the holder isn't in this registry
     * @throws UserRegistryUnavailableException when the store can't be read or changed now
     */
    boolean revoke(ParleyPrincipal holder, ParleyPermission permission) throws UserRegistryUnavailableException;

    /**
     * The permissions granted to this user or group itself, not through its groups, for a
     * management page. A turned-off user's grants are listed too.
     *
     * @param holder a user or group of this registry
     * @return its grants; empty when it has none; never null
     * @throws IllegalArgumentException when the holder isn't in this registry
     * @throws UserRegistryUnavailableException when the store can't be read now
     */
    Set<ParleyPermission> findGrants(ParleyPrincipal holder) throws UserRegistryUnavailableException;
}
