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

import java.security.Principal;
import java.util.Set;

/**
 * Who someone is: a person, a TSIG key, a JMX client, or a group.
 * <p>
 * A group is a principal like any other: it can hold permissions, own resources and
 * have attributes. Membership is the only relationship between principals, and the
 * {@link UserRegistry} answers it.
 * <p>
 * A principal is read-only. Creating, changing and deleting principals is done by the
 * application, not through this interface.
 */
public interface ParleyPrincipal extends Principal, Entity {

    /**
     * The one canonical name, decided by the registry. Used for logging in and display;
     * ownership and grants use {@link #getId()}.
     */
    @Override
    String getName();

    /** @return true when this principal is a group */
    boolean isGroup();

    /**
     * An attribute the implementation keeps for this principal (an FTP root, a maildrop).
     * The framework defines no attribute names: the code that uses an attribute names it.
     *
     * @param name the attribute's name
     * @return its value, or null when there is none
     */
    Object getAttribute(String name);

    /** @return the names of the attributes this principal has; empty when it has none */
    Set<String> getAttributeNames();
}
