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

import java.util.Objects;
import java.util.UUID;

/**
 * The unique id of an entity: a principal, a group or a resource.
 * <p>
 * An id is given when the entity is created, never changes and is never reused.
 * How it is made is the implementation's choice: a {@link UUID}, a database sequence,
 * or anything else with those two properties. Ownership and grants refer to the id;
 * names are for logging in and display, so renaming something changes nothing it
 * owns or was granted.
 * <p>
 * The framework only compares ids for equality; it never reads meaning into the value.
 */
public final class EntityId {

    private final String value;

    private EntityId(String value) {
        this.value = value;
    }

    /**
     * An id from its stored value, for example a UUID's text or a sequence number.
     *
     * @param value the value; not null or empty
     * @return the id
     */
    public static EntityId of(String value) {
        Objects.requireNonNull(value, "value");
        if (value.isEmpty()) {
            throw new IllegalArgumentException("An entity id can't be empty");
        }
        return new EntityId(value);
    }

    /**
     * A new id made from a random UUID, for implementations that have no id scheme of their own.
     *
     * @return a new id
     */
    public static EntityId random() {
        return new EntityId(UUID.randomUUID().toString());
    }

    /** @return the stored value */
    public String getValue() {
        return value;
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof EntityId)) {
            return false;
        }
        EntityId that = (EntityId) other;
        return value.equals(that.value);
    }

    @Override
    public int hashCode() {
        return value.hashCode();
    }

    @Override
    public String toString() {
        return value;
    }
}
