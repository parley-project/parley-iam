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
package us.bringardner.parley.iam.permission;

import us.bringardner.parley.iam.ParleyPermission;

/**
 * The permission names every implementation is expected to understand. They are only
 * names: what each covers on a given kind of resource is decided by that resource's
 * {@link ParleyPermission#implies(ParleyPermission)}. Applications add names of their own;
 * a family prefix ({@code smtp.send}, {@code ssh.shell}) is recommended, not required.
 */
public final class StandardPermissions {

    /** See a resource's content and properties, and what it contains. */
    public static final String READ = "read";

    /** Change a resource's content or properties, and create things inside it. */
    public static final String WRITE = "write";

    /** Remove a resource or things inside it. */
    public static final String DELETE = "delete";

    /** Pass on what the holder holds on a resource, revoke grants on it and see its grants. */
    public static final String GRANT = "grant";

    /** Every permission on a resource; not ownership. */
    public static final String ADMIN = "admin";

    private StandardPermissions() {
    }
}
