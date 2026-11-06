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

/**
 * A {@link UserRegistry} whose groups an application can change: groups created and deleted,
 * members added and removed. It is optional: an application that manages groups checks for it
 * ({@code registry instanceof GroupManager}). A registry that can't change its groups doesn't
 * offer it; one that can only sometimes (a file registry read from a class path resource
 * instead of a file) throws {@link UnsupportedOperationException} from the changing methods.
 * <p>
 * A change goes to the registry's own store (memory, a file, a database), so it is seen by
 * every registry that reads that store: at once by this one, by others when they next read it.
 * <p>
 * These methods don't check who is asking. Who may change a group is the application's
 * decision; it can ask {@link #checkPermission} first.
 */
public interface GroupManager extends UserRegistry {

    /**
     * Make a group with no members.
     *
     * @param name the group's name
     * @return the new group
     * @throws IllegalArgumentException when the name is empty, can't be stored, or is taken by
     *             a user or a group
     * @throws UserRegistryUnavailableException when the store can't be read or changed now
     */
    ParleyPrincipal createGroup(String name) throws UserRegistryUnavailableException;

    /**
     * Delete a group: its members are no longer in it, and it is no longer in other groups.
     *
     * @param group a group of this registry
     * @return true when there was such a group
     * @throws UserRegistryUnavailableException when the store can't be read or changed now
     */
    boolean deleteGroup(ParleyPrincipal group) throws UserRegistryUnavailableException;

    /**
     * Put a user or another group in a group.
     *
     * @param group a group of this registry
     * @param member a user or group of this registry
     * @return true when it was added; false when it was already a direct member
     * @throws IllegalArgumentException when the group isn't a group of this registry, the member
     *             isn't in this registry, the member is the group or already holds it (a loop),
     *             or the registry doesn't take that kind of member (one whose groups don't nest
     *             takes users only)
     * @throws UserRegistryUnavailableException when the store can't be read or changed now
     */
    boolean addMember(ParleyPrincipal group, ParleyPrincipal member) throws UserRegistryUnavailableException;

    /**
     * Take a direct member out of a group. The group stays, even when it is left empty.
     *
     * @param group a group of this registry
     * @param member a direct member of it
     * @return true when it was a direct member
     * @throws UserRegistryUnavailableException when the store can't be read or changed now
     */
    boolean removeMember(ParleyPrincipal group, ParleyPrincipal member) throws UserRegistryUnavailableException;
}
