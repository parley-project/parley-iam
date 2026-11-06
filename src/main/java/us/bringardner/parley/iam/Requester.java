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

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Who is asking: the principal (or nobody logged in) plus the facts about the connection
 * that an implementation may want to decide with: the client's address, the local port,
 * whether the connection uses TLS, TCP or UDP, the server's name, and the methods that
 * proved this login so far.
 * <p>
 * A requester is immutable. Logging in gives a new requester ({@link #loggedIn}), and only
 * a result of {@link AuthenticationResult.Status#AUTHENTICATED} can do that.
 * <p>
 * Who a session has logged in is the session's own requester, which only the session's
 * {@code authenticate} changes (rule 1, "one door for logging in"). A requester made
 * anywhere else logs no session in.
 */
public final class Requester {

    /** How the client is connected. */
    public enum Transport {
        TCP, UDP, OTHER
    }

    private final ParleyPrincipal principal;
    private final InetAddress clientAddress;
    private final int localPort;
    private final boolean secure;
    private final Transport transport;
    private final String serverName;
    private final List<String> methods;

    private Requester(ParleyPrincipal principal, InetAddress clientAddress, int localPort,
            boolean secure, Transport transport, String serverName, List<String> methods) {
        this.principal = principal;
        this.clientAddress = clientAddress;
        this.localPort = localPort;
        this.secure = secure;
        this.transport = Objects.requireNonNull(transport, "transport");
        this.serverName = Objects.requireNonNull(serverName, "serverName");
        this.methods = Collections.unmodifiableList(new ArrayList<String>(methods));
    }

    /**
     * A requester for a new connection, with nobody logged in.
     *
     * @param clientAddress the client's address, or null when the connection doesn't give one
     * @param localPort the port the client connected to, or 0 when there is none
     * @param secure true when the connection uses TLS
     * @param transport TCP, UDP or other
     * @param serverName the name of the server being asked
     * @return the requester
     */
    public static Requester connected(InetAddress clientAddress, int localPort, boolean secure,
            Transport transport, String serverName) {
        return new Requester(null, clientAddress, localPort, secure, transport, serverName,
                Collections.<String>emptyList());
    }

    /**
     * A requester with no connection facts, for example a JMX client, whose address the JDK
     * doesn't give.
     */
    public static Requester withoutAddress(String serverName) {
        return connected(null, 0, false, Transport.OTHER, serverName);
    }

    /**
     * The same connection after a successful login. Each login method used is added to
     * {@link #getMethods()}, so a login in several steps lists every step.
     * <p>
     * Only the framework's session calls this, from its {@code authenticate}, with the
     * result the server gave it; that is the one door for logging in (rule 1). It is public
     * only because the session is in another module (parley-net). Protocol and application
     * code never call it: they call the session's {@code authenticate}.
     *
     * @param result the result of a login; must be AUTHENTICATED
     * @return a new requester with the result's principal
     * @throws IllegalArgumentException when the result isn't AUTHENTICATED
     */
    public Requester loggedIn(AuthenticationResult result) {
        if (result.getStatus() != AuthenticationResult.Status.AUTHENTICATED) {
            throw new IllegalArgumentException("Only an AUTHENTICATED result logs a requester in");
        }
        List<String> allMethods = new ArrayList<String>(methods);
        allMethods.add(result.getMethod());
        return new Requester(result.getPrincipal(), clientAddress, localPort, secure, transport,
                serverName, allMethods);
    }

    /**
     * The same requester after the connection started or ended TLS (STARTTLS). Who is logged
     * in and how stay the same.
     *
     * @param secure true when the connection now uses TLS
     * @return this requester when nothing changed, otherwise a new one
     */
    public Requester withSecure(boolean secure) {
        if (secure == this.secure) {
            return this;
        }
        return new Requester(principal, clientAddress, localPort, secure, transport, serverName, methods);
    }

    /** @return the same connection with nobody logged in (logout, reset) */
    public Requester loggedOut() {
        return new Requester(null, clientAddress, localPort, secure, transport, serverName,
                Collections.<String>emptyList());
    }

    /** @return the logged-in principal, or null when nobody is logged in */
    public ParleyPrincipal getPrincipal() {
        return principal;
    }

    /** @return true when someone is logged in */
    public boolean isLoggedIn() {
        return principal != null;
    }

    /** @return the client's address, or null when the connection doesn't give one */
    public InetAddress getClientAddress() {
        return clientAddress;
    }

    /** @return the port the client connected to, or 0 */
    public int getLocalPort() {
        return localPort;
    }

    /** @return true when the connection uses TLS */
    public boolean isSecure() {
        return secure;
    }

    /** @return TCP, UDP or other */
    public Transport getTransport() {
        return transport;
    }

    /** @return the name of the server being asked */
    public String getServerName() {
        return serverName;
    }

    /** @return the login methods used so far, in order; empty when nobody is logged in */
    public List<String> getMethods() {
        return methods;
    }
}
