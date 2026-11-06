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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

class BasicUserRegistryTest {

    private final ParleyPrincipal tony = BasicParleyPrincipal.user(EntityId.random(), "tony@bringardner.us");
    private final ParleyPrincipal sales = BasicParleyPrincipal.group(EntityId.random(), "sales");
    private final ParleyPrincipal staff = BasicParleyPrincipal.group(EntityId.random(), "staff");
    private final Requester connected = Requester.connected(null, 143, true, Requester.Transport.TCP, "imap");

    private BasicUserRegistry registry;

    @BeforeEach
    void setUp() {
        registry = new BasicUserRegistry(1000); // fewer iterations than the default, to keep the tests quick
        registry.addPrincipal(tony);
        registry.addPrincipal(sales);
        registry.addPrincipal(staff);
        registry.setPassword(tony.getId(), "secret".toCharArray());
    }

    private AuthenticationResult login(String user, String password) {
        return registry.authenticate(new PasswordCredential(user, password.toCharArray(), connected));
    }

    @Test
    void rightPasswordLogsIn() {
        AuthenticationResult result = login("tony@bringardner.us", "secret");
        assertEquals(AuthenticationResult.Status.AUTHENTICATED, result.getStatus());
        assertSame(tony, result.getPrincipal());
        assertEquals(BasicUserRegistry.PASSWORD_METHOD, result.getMethod());
    }

    @Test
    void nameIgnoresCase() {
        assertEquals(AuthenticationResult.Status.AUTHENTICATED, login("Tony@Bringardner.US", "secret").getStatus());
    }

    @Test
    void wrongPasswordIsRefused() {
        assertEquals(AuthenticationResult.Status.REFUSED, login("tony@bringardner.us", "guess").getStatus());
    }

    @Test
    void unknownUserIsRefused() {
        assertEquals(AuthenticationResult.Status.REFUSED, login("nobody", "secret").getStatus());
    }

    @Test
    void aGroupCantLogIn() {
        assertThrows(IllegalArgumentException.class, new Executable() {
            @Override
            public void execute() {
                registry.setPassword(sales.getId(), "secret".toCharArray());
            }
        });
        assertEquals(AuthenticationResult.Status.REFUSED, login("sales", "secret").getStatus());
    }

    @Test
    void otherCredentialsAreUnsupported() {
        TokenCredential token = new TokenCredential("abc", connected);
        assertEquals(AuthenticationResult.Status.UNSUPPORTED, registry.authenticate(token).getStatus());
        assertTrue(registry.supports(PasswordCredential.class, null));
        assertFalse(registry.supports(TokenCredential.class, null));
    }

    @Test
    void nestedGroupsAreFoundAndLoopsStop() throws Exception {
        registry.addMember(sales.getId(), tony.getId());
        registry.addMember(staff.getId(), sales.getId());
        registry.addMember(sales.getId(), staff.getId()); // a loop: sales in staff, staff in sales
        Set<ParleyPrincipal> groups = registry.findGroups(tony);
        assertEquals(2, groups.size());
        assertTrue(groups.contains(sales));
        assertTrue(groups.contains(staff));
    }

    @Test
    void anIdIsNeverReused() {
        registry.removePrincipal(tony.getId());
        final ParleyPrincipal again = BasicParleyPrincipal.user(tony.getId(), "someone-else");
        assertThrows(IllegalArgumentException.class, new Executable() {
            @Override
            public void execute() {
                registry.addPrincipal(again);
            }
        });
    }

    @Test
    void aNameCanBeUsedAgainWithANewId() throws Exception {
        registry.removePrincipal(tony.getId());
        ParleyPrincipal newTony = BasicParleyPrincipal.user(EntityId.random(), "tony@bringardner.us");
        registry.addPrincipal(newTony);
        assertEquals(newTony.getId(), registry.findPrincipal("tony@bringardner.us").getId());
        assertEquals(AuthenticationResult.Status.REFUSED, login("tony@bringardner.us", "secret").getStatus());
    }

    @Test
    void twoPrincipalsCantShareAName() {
        final ParleyPrincipal twin = BasicParleyPrincipal.user(EntityId.random(), "TONY@bringardner.us");
        assertThrows(IllegalArgumentException.class, new Executable() {
            @Override
            public void execute() {
                registry.addPrincipal(twin);
            }
        });
    }

    @Test
    void revokeRemovesAGrant() throws Exception {
        ParleyPermission read = new BasicParleyPermission(StandardPermissions.READ, null);
        registry.grant(tony.getId(), read);
        assertEquals(1, registry.findPermissions(connected, tony, null).size());
        assertTrue(registry.revoke(tony.getId(), new BasicParleyPermission("READ", null)));
        assertEquals(0, registry.findPermissions(connected, tony, null).size());
    }

    @Test
    void removingAPrincipalRemovesItsGrantsAndMemberships() throws Exception {
        registry.addMember(sales.getId(), tony.getId());
        registry.grant(sales.getId(), new BasicParleyPermission(StandardPermissions.READ, null));
        registry.removePrincipal(sales.getId());
        assertNull(registry.findPrincipal("sales"));
        assertEquals(0, registry.findGroups(tony).size());
        assertEquals(0, registry.findPermissions(connected, sales, null).size());
    }

    @Test
    void builtInGroupsCanHoldGrantsButCantBeAdded() throws Exception {
        registry.grant(BuiltInGroups.ANYONE.getId(), new BasicParleyPermission(StandardPermissions.READ, null));
        assertEquals(1, registry.findPermissions(connected, BuiltInGroups.ANYONE, null).size());
        assertThrows(IllegalArgumentException.class, new Executable() {
            @Override
            public void execute() {
                registry.addPrincipal(BuiltInGroups.ANYONE);
            }
        });
    }
}
