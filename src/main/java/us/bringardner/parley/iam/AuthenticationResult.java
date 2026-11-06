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

/**
 * How a login ended: one of four outcomes, never an exception. The reason is for the log
 * and is never sent to the client.
 */
public final class AuthenticationResult {

    /** The four outcomes. */
    public enum Status {
        /** The credential is good; the result carries the principal and the method used. */
        AUTHENTICATED,
        /** The credential is wrong, or the user is unknown. */
        REFUSED,
        /** This registry doesn't handle this kind of credential. */
        UNSUPPORTED,
        /** The registry can't answer now (its database is down); not counted as a failure. */
        UNAVAILABLE
    }

    private final Status status;
    private final ParleyPrincipal principal;
    private final String method;
    private final String reason;

    private AuthenticationResult(Status status, ParleyPrincipal principal, String method, String reason) {
        this.status = status;
        this.principal = principal;
        this.method = method;
        this.reason = reason;
    }

    /**
     * @param principal who logged in
     * @param method how, for example "password", "scram-sha-256", "publickey"
     */
    public static AuthenticationResult authenticated(ParleyPrincipal principal, String method) {
        Objects.requireNonNull(principal, "principal");
        Objects.requireNonNull(method, "method");
        return new AuthenticationResult(Status.AUTHENTICATED, principal, method, "authenticated");
    }

    public static AuthenticationResult refused(String reason) {
        return new AuthenticationResult(Status.REFUSED, null, null, reason);
    }

    public static AuthenticationResult unsupported(String reason) {
        return new AuthenticationResult(Status.UNSUPPORTED, null, null, reason);
    }

    public static AuthenticationResult unavailable(String reason) {
        return new AuthenticationResult(Status.UNAVAILABLE, null, null, reason);
    }

    public Status getStatus() {
        return status;
    }

    /** @return who logged in, or null unless AUTHENTICATED */
    public ParleyPrincipal getPrincipal() {
        return principal;
    }

    /** @return the login method, or null unless AUTHENTICATED */
    public String getMethod() {
        return method;
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
