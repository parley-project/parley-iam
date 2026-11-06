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
        assertEquals(1, registry.findPermissions(tony).size());
        assertTrue(registry.revoke(tony.getId(), new BasicParleyPermission("READ", null)));
        assertEquals(0, registry.findPermissions(tony).size());
    }

    @Test
    void removingAPrincipalRemovesItsGrantsAndMemberships() throws Exception {
        registry.addMember(sales.getId(), tony.getId());
        registry.grant(sales.getId(), new BasicParleyPermission(StandardPermissions.READ, null));
        registry.removePrincipal(sales.getId());
        assertNull(registry.findPrincipal("sales"));
        assertEquals(0, registry.findGroups(tony).size());
        assertEquals(0, registry.findPermissions(sales).size());
    }

    @Test
    void checkPermissionAnswersForThePrincipalAndItsGroups() throws Exception {
        ParleyPermission read = new BasicParleyPermission(StandardPermissions.READ, null);
        ParleyPermission write = new BasicParleyPermission(StandardPermissions.WRITE, null);
        Requester tonyIn = connected.loggedIn(AuthenticationResult.authenticated(tony, "password"));
        assertEquals(AuthorizationResult.Status.DENIED, registry.checkPermission(tonyIn, read, null).getStatus());

        registry.addMember(sales.getId(), tony.getId());
        registry.grant(sales.getId(), read);
        assertEquals(AuthorizationResult.Status.ALLOWED, registry.checkPermission(tonyIn, read, null).getStatus(), "through a group");
        assertEquals(AuthorizationResult.Status.DENIED, registry.checkPermission(tonyIn, write, null).getStatus());

        registry.grant(tony.getId(), write);
        assertEquals(AuthorizationResult.Status.ALLOWED, registry.checkPermission(tonyIn, write, null).getStatus(), "held directly");
        assertEquals(AuthorizationResult.Status.DENIED, registry.checkPermission(connected, read, null).getStatus(), "nobody logged in");
    }
    @Test
    void groupsAreManagedThroughGroupManager() throws Exception {
        GroupManager groups = registry;
        ParleyPrincipal support = groups.createGroup("support");
        assertTrue(support.isGroup());
        assertSame(support, registry.findPrincipal("Support"));
        assertEquals(0, registry.findMembers(support).size(), "a new group is empty");

        assertTrue(groups.addMember(support, tony));
        assertFalse(groups.addMember(support, tony), "already a member");
        assertTrue(groups.addMember(staff, support), "groups nest");
        assertEquals(Set.of(support, staff), registry.findGroups(tony), "directly and through support");
        assertEquals(Set.of(tony), registry.findMembers(support));
        assertEquals(Set.of(support), registry.findMembers(staff), "direct members only");

        assertTrue(groups.removeMember(support, tony));
        assertFalse(groups.removeMember(support, tony));
        assertEquals(0, registry.findGroups(tony).size());
        assertSame(support, registry.findPrincipal("support"), "an empty group stays");

        assertTrue(groups.deleteGroup(support));
        assertFalse(groups.deleteGroup(support));
        assertNull(registry.findPrincipal("support"));
        assertEquals(0, registry.findMembers(staff).size(), "a deleted group is in no group");
    }

    @Test
    void groupChangesThatCantWorkAreRefused() throws Exception {
        final GroupManager groups = registry;
        registry.addMember(staff.getId(), sales.getId());
        final ParleyPrincipal stranger = BasicParleyPrincipal.group(EntityId.random(), "stranger");
        assertRefused(new Executable() {
            @Override
            public void execute() throws Throwable {
                groups.createGroup("Tony@Bringardner.us");
            }
        }, "the name of a user");
        assertRefused(new Executable() {
            @Override
            public void execute() throws Throwable {
                groups.createGroup(" ");
            }
        }, "no name");
        assertRefused(new Executable() {
            @Override
            public void execute() throws Throwable {
                groups.addMember(tony, sales);
            }
        }, "a user isn't a group");
        assertRefused(new Executable() {
            @Override
            public void execute() throws Throwable {
                groups.addMember(stranger, tony);
            }
        }, "a group of another registry");
        assertRefused(new Executable() {
            @Override
            public void execute() throws Throwable {
                groups.addMember(sales, stranger);
            }
        }, "a member of another registry");
        assertRefused(new Executable() {
            @Override
            public void execute() throws Throwable {
                groups.addMember(sales, sales);
            }
        }, "itself");
        assertRefused(new Executable() {
            @Override
            public void execute() throws Throwable {
                groups.addMember(sales, staff);
            }
        }, "a loop: sales is in staff");
        assertFalse(groups.deleteGroup(tony), "a user isn't deleted as a group");
        assertSame(tony, registry.findPrincipal("tony@bringardner.us"));
    }

    @Test
    void aRegistryWithoutGroupsFindsNone() throws Exception {
        UserRegistry plain = new UserRegistry() {
            @Override
            public boolean supports(Class<? extends Credential> kind, StoredCredentialType stored) {
                return false;
            }

            @Override
            public AuthenticationResult authenticate(Credential credential) {
                return AuthenticationResult.unsupported("none");
            }

            @Override
            public StoredCredential findStoredCredential(String user, StoredCredentialType type) {
                return null;
            }

            @Override
            public ParleyPrincipal findPrincipal(String name) {
                return null;
            }

            @Override
            public ParleyPrincipal findPrincipal(EntityId id) {
                return null;
            }

            @Override
            public AuthorizationResult checkPermission(Requester requester, ParleyPermission needed, ProtectedResource resource) {
                return AuthorizationResult.denied("none");
            }
        };
        assertEquals(0, plain.findGroups(tony).size());
        assertEquals(0, plain.findMembers(sales).size());
        assertFalse(plain instanceof GroupManager);
    }

    private static void assertRefused(Executable change, String why) {
        assertThrows(IllegalArgumentException.class, change, why);
    }
}
