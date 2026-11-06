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
 * The two groups every system has. Their membership is decided by the framework, never
 * stored: {@link #ANYONE} is every requester, logged in or not, and {@link #AUTHENTICATED}
 * is every logged-in requester. A registry never returns them as groups, but it may hold
 * grants to them (a grant to {@code anyone} means "no login needed for this").
 */
public final class BuiltInGroups {

    /** Every requester, logged in or not. */
    public static final ParleyPrincipal ANYONE =
            BasicParleyPrincipal.group(EntityId.of("parley:anyone"), "anyone");

    /** Every logged-in requester. */
    public static final ParleyPrincipal AUTHENTICATED =
            BasicParleyPrincipal.group(EntityId.of("parley:authenticated"), "authenticated");

    private BuiltInGroups() {
    }

    /** @return true when the principal is one of the two built-in groups */
    public static boolean isBuiltIn(ParleyPrincipal principal) {
        return ANYONE.equals(principal) || AUTHENTICATED.equals(principal);
    }
}
