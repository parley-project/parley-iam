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
package us.bringardner.parley.iam.registry;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import us.bringardner.parley.iam.AuthenticationResult;
import us.bringardner.parley.iam.AuthorizationResult;
import us.bringardner.parley.iam.EntityId;
import us.bringardner.parley.iam.ParleyPermission;
import us.bringardner.parley.iam.ParleyPrincipal;
import us.bringardner.parley.iam.PermissionManager;
import us.bringardner.parley.iam.PrincipalManager;
import us.bringardner.parley.iam.ProtectedResource;
import us.bringardner.parley.iam.Requester;
import us.bringardner.parley.iam.StoredCredentialType;
import us.bringardner.parley.iam.UserRegistry;
import us.bringardner.parley.iam.UserRegistryUnavailableException;
import us.bringardner.parley.iam.credential.PasswordCredential;
import us.bringardner.parley.iam.credential.ProofCredential;
import us.bringardner.parley.iam.permission.BasicParleyPermission;
import us.bringardner.parley.iam.permission.StandardPermissions;
import us.bringardner.parley.iam.principal.BasicParleyPrincipal;

/** ForwardingUserRegistry and UnavailableUserRegistry. */
class WrappedRegistriesTest {

    private final Requester connected = Requester.connected(null, 143, true, Requester.Transport.TCP, "imap");
    private final ParleyPrincipal tony = new BasicParleyPrincipal(EntityId.of("user:tony"), "tony", false, new HashMap<>());
    private final ParleyPrincipal sales = new BasicParleyPrincipal(EntityId.of("group:sales"), "sales", true, new HashMap<>());
    private final ParleyPermission read = new BasicParleyPermission(StandardPermissions.READ, null);
    private BasicUserRegistry users;

    @BeforeEach
    void setUp() {
        users = new BasicUserRegistry(1000); // fewer iterations than the default, to keep the tests quick
        users.addPrincipal(tony);
        users.addPrincipal(sales);
        users.addMember(sales.getId(), tony.getId());
        users.setPassword(tony.getId(), "secret".toCharArray());
        users.grant(tony.getId(), read);
    }

    private PasswordCredential password(String user, String password) {
        return new PasswordCredential(user, password.toCharArray(), connected);
    }

    @Test
    void forwardingPassesEveryCallOn() throws Exception {
        UserRegistry wrapped = new ForwardingUserRegistry(users);
        AuthenticationResult in = wrapped.authenticate(password("tony", "secret"));
        assertEquals(AuthenticationResult.Status.AUTHENTICATED, in.getStatus());
        assertEquals(AuthenticationResult.Status.REFUSED, wrapped.authenticate(password("tony", "wrong")).getStatus());
        assertEquals(users.supports(PasswordCredential.class, null), wrapped.supports(PasswordCredential.class, null));
        assertSame(users.findPrincipal("tony"), wrapped.findPrincipal("tony"));
        assertSame(users.findPrincipal(tony.getId()), wrapped.findPrincipal(tony.getId()));
        assertSame(tony, wrapped.findUser("tony"));
        assertNull(wrapped.findUser("sales"), "a group isn't a user");
        assertEquals(users.findGroups(tony), wrapped.findGroups(tony));
        assertEquals(users.findMembers(sales), wrapped.findMembers(sales));
        assertEquals(AuthorizationResult.Status.ALLOWED,
                wrapped.checkPermission(connected.loggedIn(in), read, null).getStatus());
    }

    @Test
    void forwardingHidesTheManagers() {
        UserRegistry wrapped = new ForwardingUserRegistry(users);
        assertTrue(users instanceof PrincipalManager && users instanceof PermissionManager);
        assertFalse(wrapped instanceof PrincipalManager, "only the reading part");
        assertFalse(wrapped instanceof PermissionManager, "only the reading part");
    }

    @Test
    void aWrapperOverridesOnlyWhatDiffers() throws Exception {
        UserRegistry permissionsDown = new ForwardingUserRegistry(users) {
            @Override
            public AuthorizationResult checkPermission(Requester requester, ParleyPermission needed,
                    ProtectedResource resource) {
                return AuthorizationResult.unavailable("the database is down");
            }
        };
        AuthenticationResult in = permissionsDown.authenticate(password("tony", "secret"));
        assertEquals(AuthenticationResult.Status.AUTHENTICATED, in.getStatus(), "logins still work");
        assertEquals(AuthorizationResult.Status.UNAVAILABLE,
                permissionsDown.checkPermission(connected.loggedIn(in), read, null).getStatus());
    }

    @Test
    void closeClosesTheWrappedRegistry() throws Exception {
        AtomicInteger closed = new AtomicInteger();
        UserRegistry counting = new ForwardingUserRegistry(users) {
            @Override
            public void close() {
                closed.incrementAndGet();
            }
        };
        new ForwardingUserRegistry(counting).close();
        assertEquals(1, closed.get());
    }

    @Test
    void unavailableAnswersNothing() {
        UserRegistry down = new UnavailableUserRegistry("the database is down");
        assertTrue(down.supports(ProofCredential.class, StoredCredentialType.PLAIN_TEXT), "a server still offers every kind");
        AuthenticationResult login = down.authenticate(password("tony", "secret"));
        assertEquals(AuthenticationResult.Status.UNAVAILABLE, login.getStatus(), "not a wrong password");
        UserRegistryUnavailableException e = assertThrows(UserRegistryUnavailableException.class, () -> down.findPrincipal("tony"));
        assertEquals("the database is down", e.getMessage());
        assertThrows(UserRegistryUnavailableException.class, () -> down.findPrincipal(tony.getId()));
        assertThrows(UserRegistryUnavailableException.class, () -> down.findUser("tony"));
        assertThrows(UserRegistryUnavailableException.class, () -> down.findGroups(tony));
        assertThrows(UserRegistryUnavailableException.class, () -> down.findMembers(sales));
        assertThrows(UserRegistryUnavailableException.class, () -> down.findStoredCredential("tony", StoredCredentialType.PLAIN_TEXT));
        assertEquals(AuthorizationResult.Status.UNAVAILABLE, down.checkPermission(connected, read, null).getStatus());
    }
}
