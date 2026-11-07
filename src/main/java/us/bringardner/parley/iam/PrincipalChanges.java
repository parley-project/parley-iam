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
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Changes to users, groups and grants that a {@link PrincipalManager} makes all together or not
 * at all ({@link PrincipalManager#apply}): adding a user with its password, attributes, groups and
 * grants, say. The steps are made in the order they were added, and a step names its principals
 * by name, so it can name one an earlier step creates:
 * <pre>
 * PrincipalChanges changes = new PrincipalChanges()
 *         .createUser("tony@bringardner.us")
 *         .setPassword("tony@bringardner.us", password)
 *         .setAttribute("tony@bringardner.us", "maildrop", "bringardner.us/tony")
 *         .createGroup("sales@bringardner.us")
 *         .addMember("sales@bringardner.us", "tony@bringardner.us")
 *         .grant("tony@bringardner.us", new BasicParleyPermission(StandardPermissions.READ, null));
 * registry.apply(changes);
 * changes.clear(); // wipes the password
 * </pre>
 * The steps mean what the {@link PrincipalManager} and {@link PermissionManager} methods of the
 * same names mean; a step that finds nothing to change (adding a member already there, revoking
 * a permission not held, deleting a principal that isn't there) changes nothing and isn't an
 * error. A change set is not safe for use by several threads at once.
 */
public final class PrincipalChanges {

    /** What a step does. */
    public enum Action {
        CREATE_USER, CREATE_GROUP, DELETE, SET_ATTRIBUTE, ADD_MEMBER, REMOVE_MEMBER,
        SET_PASSWORD, REMOVE_PASSWORD, SET_ENABLED, GRANT, REVOKE
    }

    /** One step: an action and what it needs. Read by registries carrying out {@link PrincipalManager#apply}. */
    public static final class Step {
        private final Action action;
        private final String name;
        private final String other;
        private final String value;
        private final char[] password;
        private final boolean enabled;
        private final ParleyPermission permission;

        private Step(Action action, String name, String other, String value, char[] password, boolean enabled,
                ParleyPermission permission) {
            this.action = action;
            this.name = name;
            this.other = other;
            this.value = value;
            this.password = password;
            this.enabled = enabled;
            this.permission = permission;
        }

        /** @return what the step does */
        public Action getAction() {
            return action;
        }

        /**
         * @return the principal the step is about: the one created, deleted or changed, the group
         * for {@link Action#ADD_MEMBER} and {@link Action#REMOVE_MEMBER}, the holder for a grant
         */
        public String getName() {
            return name;
        }

        /** @return the member, for {@link Action#ADD_MEMBER} and {@link Action#REMOVE_MEMBER}; else null */
        public String getMember() {
            return other;
        }

        /** @return the attribute's name, for {@link Action#SET_ATTRIBUTE}; else null */
        public String getAttribute() {
            return action == Action.SET_ATTRIBUTE ? other : null;
        }

        /** @return the attribute's value (null removes it), for {@link Action#SET_ATTRIBUTE} */
        public String getValue() {
            return value;
        }

        /**
         * @return the new password, for {@link Action#SET_PASSWORD}: the change set's own copy
         * itself, not another copy, so that {@link PrincipalChanges#clear} wipes the only one
         */
        public char[] getPassword() {
            return password;
        }

        /** @return true to turn the user on, for {@link Action#SET_ENABLED} */
        public boolean isEnabled() {
            return enabled;
        }

        /** @return the permission, for {@link Action#GRANT} and {@link Action#REVOKE} */
        public ParleyPermission getPermission() {
            return permission;
        }

        @Override
        public String toString() {
            switch (action) {
                case ADD_MEMBER:
                case REMOVE_MEMBER:
                    return action + " " + other + " in " + name;
                case SET_ATTRIBUTE:
                    return action + " " + name + " " + other + "=" + value;
                case SET_ENABLED:
                    return action + " " + name + " " + enabled;
                case GRANT:
                case REVOKE:
                    return action + " " + permission + " to " + name;
                default:
                    return action + " " + name;
            }
        }
    }

    private final List<Step> steps = new ArrayList<Step>();

    private PrincipalChanges add(Action action, String name, String other, String value, char[] password,
            boolean enabled, ParleyPermission permission) {
        if (name == null || name.isEmpty()) {
            throw new IllegalArgumentException("A step needs the name of a principal");
        }
        steps.add(new Step(action, name, other, value, password, enabled, permission));
        return this;
    }

    private static String required(String what, String text) {
        if (text == null || text.isEmpty()) {
            throw new IllegalArgumentException("A step needs " + what);
        }
        return text;
    }

    /** Make a user with no password, groups or attributes, turned on. */
    public PrincipalChanges createUser(String name) {
        return add(Action.CREATE_USER, name, null, null, null, true, null);
    }

    /** Make a group with no members or attributes. */
    public PrincipalChanges createGroup(String name) {
        return add(Action.CREATE_GROUP, name, null, null, null, true, null);
    }

    /** Delete a user or group with everything the registry keeps for it. */
    public PrincipalChanges delete(String name) {
        return add(Action.DELETE, name, null, null, null, true, null);
    }

    /** Set an attribute of a user or group; a null value removes it. */
    public PrincipalChanges setAttribute(String name, String attribute, String value) {
        return add(Action.SET_ATTRIBUTE, name, required("an attribute name", attribute), value, null, true, null);
    }

    /** Put a user or group in a group. */
    public PrincipalChanges addMember(String group, String member) {
        return add(Action.ADD_MEMBER, group, required("a member", member), null, null, true, null);
    }

    /** Take a direct member out of a group. */
    public PrincipalChanges removeMember(String group, String member) {
        return add(Action.REMOVE_MEMBER, group, required("a member", member), null, null, true, null);
    }

    /**
     * Give a user a password. The change set keeps its own copy of the array, until
     * {@link #clear}.
     */
    public PrincipalChanges setPassword(String user, char[] password) {
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("A password can't be empty");
        }
        return add(Action.SET_PASSWORD, user, null, null, Arrays.copyOf(password, password.length), true, null);
    }

    /** Take a user's password away. */
    public PrincipalChanges removePassword(String user) {
        return add(Action.REMOVE_PASSWORD, user, null, null, null, true, null);
    }

    /** Turn a user off, or on again. */
    public PrincipalChanges setEnabled(String user, boolean enabled) {
        return add(Action.SET_ENABLED, user, null, null, null, enabled, null);
    }

    /** Give a user or group a permission (needs a registry that is also a {@link PermissionManager}). */
    public PrincipalChanges grant(String holder, ParleyPermission permission) {
        return add(Action.GRANT, holder, null, null, null, true, Objects.requireNonNull(permission, "permission"));
    }

    /** Take a permission away from a user or group (needs a {@link PermissionManager}). */
    public PrincipalChanges revoke(String holder, ParleyPermission permission) {
        return add(Action.REVOKE, holder, null, null, null, true, Objects.requireNonNull(permission, "permission"));
    }

    /** @return the steps, in order; read-only */
    public List<Step> getSteps() {
        return Collections.unmodifiableList(steps);
    }

    /** @return true when there are no steps */
    public boolean isEmpty() {
        return steps.isEmpty();
    }

    /** Wipe the passwords this change set holds; call it when the changes have been applied. */
    public void clear() {
        for (Step step : steps) {
            if (step.password != null) {
                Arrays.fill(step.password, '\0');
            }
        }
    }

    @Override
    public String toString() {
        return steps.toString();
    }
}
