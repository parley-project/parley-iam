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

import java.util.Locale;
import java.util.Objects;

/**
 * A permission: a name ("read", "write", "smtp.send") on a resource, or on the server as a
 * whole. The same type describes what an application needs before it acts and what a
 * principal holds; {@link #implies(ParleyPermission)} says whether a held one covers a
 * needed one. This is the idea of {@code java.security.Permission}, without its machinery.
 * <p>
 * Names are compared without regard to case ("read" and "Read" are the same permission),
 * using {@link Locale#ROOT} so the result never depends on the computer's language.
 * <p>
 * Each kind of resource decides what its permissions cover by overriding {@code implies}:
 * for example, read on a folder covering everything under it.
 */
public abstract class ParleyPermission {

    private final String name;
    private final EntityId resourceId;

    /**
     * @param name the permission's name, written however reads best
     * @param resourceId the resource it is about, or null for the server as a whole
     */
    protected ParleyPermission(String name, EntityId resourceId) {
        this.name = Objects.requireNonNull(name, "name");
        this.resourceId = resourceId;
    }

    /** @return the name as written */
    public final String getName() {
        return name;
    }

    /** @return the resource this permission is about, or null for the server as a whole */
    public final EntityId getResourceId() {
        return resourceId;
    }

    /**
     * Does holding this permission cover the needed one?
     *
     * @param needed the permission the application needs before it acts
     * @return true when this permission covers it
     */
    public abstract boolean implies(ParleyPermission needed);

    /**
     * @param other a name to compare with
     * @return true when this permission's name is the same as the other, ignoring case
     */
    protected final boolean hasName(String other) {
        return name.toLowerCase(Locale.ROOT).equals(other.toLowerCase(Locale.ROOT));
    }

    /**
     * @param needed another permission
     * @return true when both are about the same resource (or both about the whole server)
     */
    protected final boolean sameResource(ParleyPermission needed) {
        return Objects.equals(resourceId, needed.getResourceId());
    }

    /**
     * Two permissions are equal when they are the same class, have the same name (ignoring
     * case) and are about the same resource. Used to find a grant again, for example to revoke it.
     */
    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (other == null || other.getClass() != getClass()) {
            return false;
        }
        ParleyPermission that = (ParleyPermission) other;
        return hasName(that.name) && sameResource(that);
    }

    @Override
    public int hashCode() {
        return Objects.hash(name.toLowerCase(Locale.ROOT), resourceId);
    }

    @Override
    public String toString() {
        if (resourceId == null) {
            return name;
        }
        return name + " on " + resourceId;
    }
}
