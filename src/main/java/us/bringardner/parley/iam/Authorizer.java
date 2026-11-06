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
 * Decides whether a requester may do something. The framework ships
 * {@link BasicAuthorizer}; an application that decides differently (a policy engine,
 * a remote service, rules of its own) implements this interface instead.
 */
public interface Authorizer {

    /**
     * @param requester who is asking
     * @param needed the permission the application needs before it acts
     * @param resource what it is about, or null for the server as a whole
     * @return ALLOWED, DENIED or UNAVAILABLE, with a reason for the log
     */
    AuthorizationResult check(Requester requester, ParleyPermission needed, ProtectedResource resource);
}
