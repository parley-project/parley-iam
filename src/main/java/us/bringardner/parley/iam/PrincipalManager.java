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

import java.util.List;
import java.util.Set;

/**
 * A {@link UserRegistry} whose principals an application can manage: users and groups created,
 * changed and deleted, and members put in groups and taken out. Users and groups are managed
 * the same way, since a group is a principal like any other; the only difference is that a
 * group has members and a user can log in. Membership is one relationship, read from either end
 * ({@link #findGroups}, {@link #findMembers}).
 * <p>
 * It is optional: an application that manages principals checks for it
 * ({@code registry instanceof PrincipalManager}). A registry that can't change its principals
 * doesn't offer it; one that can only sometimes (a file registry read from a class path
 * resource instead of a file) throws {@link UnsupportedOperationException} from the changing
 * methods.
 * <p>
 * A change goes to the registry's own store (memory, a file, a database), so it is seen by
 * every registry that reads that store: at once by this one, by others when they next read it.
 * Changes that belong together go in one {@link PrincipalChanges}, made all together or not at
 * all by {@link #apply}; each single-step method is a change set of its own.
 * A principal is a read-only value, so a method that changes one returns it as it is now.
 * <p>
 * A user who is turned off ({@link #setEnabled}) can't log in, holds no permissions, isn't found
 * by {@link #findPrincipal} and isn't listed by {@link #findMembers}, as if it were gone. Only the
 * reads meant for a management page still show it: {@link #findPrincipals}, so it can be turned on
 * again, and {@link #findDirectGroups} (with a {@link PermissionManager}'s {@code findGrants}), so
 * an administrator can see and change what it keeps without turning it on.
 * <p>
 * These methods don't check who is asking. Who may change a principal is the application's
 * decision; it can ask {@link #checkPermission} first.
 */
public interface PrincipalManager extends UserRegistry {

    /**
     * Make every change in the set, in order, or none of them: either all the steps are made
     * and stored together, or the registry and its store are as they were. Use it for anything
     * that must happen together (adding a user with its password, attributes, groups and grants);
     * the single-step methods below are each a change set of one step.
     * <p>
     * A step that can't work (a name already taken, a principal that isn't there, a grant the
     * registry doesn't keep, a grant step in a registry that isn't a {@link PermissionManager})
     * fails with {@link IllegalArgumentException}, naming the step, and nothing is changed.
     *
     * @param changes the steps
     * @throws IllegalArgumentException when a step can't work; nothing was changed
     * @throws UserRegistryUnavailableException when the store can't be read or changed now; nothing was changed
     */
    void apply(PrincipalChanges changes) throws UserRegistryUnavailableException;

    /** Which principals {@link #findPrincipals} lists. */
    enum Kind {
        /** Users only */
        USER,
        /** Groups only */
        GROUP,
        /** Users and groups */
        ANY
    }

    /**
     * Make a user with no password (it can't log in until it has one), no groups and no
     * attributes, turned on.
     *
     * @param name the user's name
     * @return the new user
     * @throws IllegalArgumentException when the name is empty, can't be stored, or is taken by
     *             a user or a group
     * @throws UserRegistryUnavailableException when the store can't be read or changed now
     */
    ParleyPrincipal createUser(String name) throws UserRegistryUnavailableException;

    /**
     * Make a group with no members and no attributes.
     *
     * @param name the group's name
     * @return the new group
     * @throws IllegalArgumentException when the name is empty, can't be stored, or is taken by
     *             a user or a group
     * @throws UserRegistryUnavailableException when the store can't be read or changed now
     */
    ParleyPrincipal createGroup(String name) throws UserRegistryUnavailableException;

    /**
     * Delete a user or a group with everything this registry keeps for it: a user's password
     * and memberships, a group's members' memberships in it, its own memberships, attributes
     * and permissions. What the application keeps elsewhere (a mailbox, files it owns) is the
     * application's to deal with.
     *
     * @param principal a user or group of this registry
     * @return true when there was such a principal
     * @throws UserRegistryUnavailableException when the store can't be read or changed now
     */
    boolean deletePrincipal(ParleyPrincipal principal) throws UserRegistryUnavailableException;

    /**
     * Set or remove one of a principal's attributes. The application names its attributes; a
     * registry may keep some names for itself (the file registry's {@code groups}).
     *
     * @param principal a user or group of this registry
     * @param name the attribute's name
     * @param value its value; null removes it
     * @return the principal with the change
     * @throws IllegalArgumentException when the principal isn't in this registry, or the name
     *             or value can't be stored
     * @throws UserRegistryUnavailableException when the store can't be read or changed now
     */
    ParleyPrincipal setAttribute(ParleyPrincipal principal, String name, String value)
            throws UserRegistryUnavailableException;

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

    /**
     * Give a user a password, replacing any it had. The registry keeps whatever its logins need
     * (a hash, SCRAM credentials), never more than it must. The array is not kept; clear it when
     * done.
     *
     * @param user a user of this registry
     * @param password the new password, not empty
     * @throws IllegalArgumentException for a group (a group doesn't log in), a principal that
     *             isn't in this registry, or an empty password
     * @throws UserRegistryUnavailableException when the store can't be read or changed now
     */
    void setPassword(ParleyPrincipal user, char[] password) throws UserRegistryUnavailableException;

    /**
     * Take a user's password away, so it can't log in with one.
     *
     * @param user a user of this registry
     * @return true when it had one
     * @throws IllegalArgumentException for a group or a principal that isn't in this registry
     * @throws UserRegistryUnavailableException when the store can't be read or changed now
     */
    boolean removePassword(ParleyPrincipal user) throws UserRegistryUnavailableException;

    /**
     * Turn a user off without deleting it, or on again. A turned-off user keeps its password,
     * groups and attributes.
     *
     * @param user a user of this registry
     * @param enabled false to turn it off
     * @throws IllegalArgumentException for a group (a group doesn't log in) or a principal that
     *             isn't in this registry
     * @throws UserRegistryUnavailableException when the store can't be read or changed now
     */
    void setEnabled(ParleyPrincipal user, boolean enabled) throws UserRegistryUnavailableException;

    /**
     * The groups this user or group was put in directly, not the groups those are in, for a
     * management page. A turned-off user's groups are listed too, though {@link #findGroups}
     * gives none while it is off, so its groups can be seen and changed without turning it on.
     *
     * @param principal a user or group of this registry
     * @return its groups; empty when it is in none; never null
     * @throws IllegalArgumentException when the principal isn't in this registry
     * @throws UserRegistryUnavailableException when the store can't be read now
     * @since 2.0.0
     */
    Set<ParleyPrincipal> findDirectGroups(ParleyPrincipal principal) throws UserRegistryUnavailableException;

    /**
     * @param user a user of this registry
     * @return false when the user is turned off; true for a group
     * @throws IllegalArgumentException for a principal that isn't in this registry
     * @throws UserRegistryUnavailableException when the store can't be read now
     */
    boolean isEnabled(ParleyPrincipal user) throws UserRegistryUnavailableException;

    /**
     * List principals whose names start with a prefix, for a management page: sorted by name,
     * turned-off users included. Names are compared as the registry compares them (the basic
     * registry ignores case).
     *
     * @param prefix the start of the names; null or empty lists every principal
     * @param kind users, groups, or both
     * @param limit the most to list; 0 or less for no limit
     * @return the principals; never null
     * @throws UserRegistryUnavailableException when the store can't be read now
     */
    List<ParleyPrincipal> findPrincipals(String prefix, Kind kind, int limit) throws UserRegistryUnavailableException;
}
