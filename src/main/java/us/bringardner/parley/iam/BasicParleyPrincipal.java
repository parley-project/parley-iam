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

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * The general-purpose, read-only {@link ParleyPrincipal}. Its attributes are copied when
 * it is made, so changing the map afterwards changes nothing.
 */
public final class BasicParleyPrincipal implements ParleyPrincipal {

    private final EntityId id;
    private final String name;
    private final boolean group;
    private final Map<String, Object> attributes;

    /**
     * @param id the principal's id
     * @param name its canonical name
     * @param group true for a group
     * @param attributes its attributes; null for none
     */
    public BasicParleyPrincipal(EntityId id, String name, boolean group, Map<String, ?> attributes) {
        this.id = Objects.requireNonNull(id, "id");
        this.name = Objects.requireNonNull(name, "name");
        this.group = group;
        if (attributes == null) {
            this.attributes = Collections.emptyMap();
        } else {
            this.attributes = Collections.unmodifiableMap(new LinkedHashMap<String, Object>(attributes));
        }
    }

    /** A person or key with no attributes. */
    public static BasicParleyPrincipal user(EntityId id, String name) {
        return new BasicParleyPrincipal(id, name, false, null);
    }

    /** A group with no attributes. */
    public static BasicParleyPrincipal group(EntityId id, String name) {
        return new BasicParleyPrincipal(id, name, true, null);
    }

    @Override
    public EntityId getId() {
        return id;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public boolean isGroup() {
        return group;
    }

    @Override
    public Object getAttribute(String attributeName) {
        return attributes.get(attributeName);
    }

    @Override
    public Set<String> getAttributeNames() {
        return attributes.keySet();
    }

    /** Two principals are the same principal when their ids are equal. */
    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof ParleyPrincipal)) {
            return false;
        }
        ParleyPrincipal that = (ParleyPrincipal) other;
        return id.equals(that.getId());
    }

    @Override
    public int hashCode() {
        return id.hashCode();
    }

    @Override
    public String toString() {
        return name + " (" + id + ")";
    }
}
