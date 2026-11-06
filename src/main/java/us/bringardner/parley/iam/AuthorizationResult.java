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
 * How a permission check ended. UNAVAILABLE keeps an outage from being reported as "denied".
 * The reason is for the log.
 */
public final class AuthorizationResult {

    /** The three outcomes. */
    public enum Status {
        ALLOWED, DENIED, UNAVAILABLE
    }

    private final Status status;
    private final String reason;

    private AuthorizationResult(Status status, String reason) {
        this.status = status;
        this.reason = reason;
    }

    public static AuthorizationResult allowed(String reason) {
        return new AuthorizationResult(Status.ALLOWED, reason);
    }

    public static AuthorizationResult denied(String reason) {
        return new AuthorizationResult(Status.DENIED, reason);
    }

    public static AuthorizationResult unavailable(String reason) {
        return new AuthorizationResult(Status.UNAVAILABLE, reason);
    }

    public Status getStatus() {
        return status;
    }

    /** @return true only when ALLOWED */
    public boolean isAllowed() {
        return status == Status.ALLOWED;
    }

    /** @return why, for the log */
    public String getReason() {
        return reason;
    }

    @Override
    public String toString() {
        return status + ": " + reason;
    }
}
