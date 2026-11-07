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

import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import us.bringardner.parley.iam.AuthenticationResult;
import us.bringardner.parley.iam.AuthorizationResult;
import us.bringardner.parley.iam.Credential;
import us.bringardner.parley.iam.EntityId;
import us.bringardner.parley.iam.ParleyPermission;
import us.bringardner.parley.iam.ParleyPrincipal;
import us.bringardner.parley.iam.PermissionManager;
import us.bringardner.parley.iam.PrincipalChanges;
import us.bringardner.parley.iam.PrincipalManager;
import us.bringardner.parley.iam.ProtectedResource;
import us.bringardner.parley.iam.Requester;
import us.bringardner.parley.iam.StoredCredential;
import us.bringardner.parley.iam.StoredCredentialType;
import us.bringardner.parley.iam.UserRegistry;
import us.bringardner.parley.iam.credential.PasswordCredential;
import us.bringardner.parley.iam.credential.TokenCredential;
import us.bringardner.parley.iam.permission.BasicParleyPermission;
import us.bringardner.parley.iam.permission.StandardPermissions;
import us.bringardner.parley.iam.principal.BasicParleyPrincipal;

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
    void groupsAreManagedThroughPrincipalManager() throws Exception {
        PrincipalManager groups = registry;
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

        assertTrue(groups.deletePrincipal(support));
        assertFalse(groups.deletePrincipal(support));
        assertNull(registry.findPrincipal("support"));
        assertEquals(0, registry.findMembers(staff).size(), "a deleted group is in no group");
    }

    @Test
    void groupChangesThatCantWorkAreRefused() throws Exception {
        final PrincipalManager groups = registry;
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
        assertFalse(plain instanceof PrincipalManager);
    }

    @Test
    void usersAreManagedLikeGroups() throws Exception {
        PrincipalManager manager = registry;
        ParleyPrincipal jose = manager.createUser("jose@bringardner.us");
        assertFalse(jose.isGroup());
        assertEquals(AuthenticationResult.Status.REFUSED, login("jose@bringardner.us", "pw").getStatus(), "no password yet");

        manager.setPassword(jose, "pw".toCharArray());
        assertEquals(AuthenticationResult.Status.AUTHENTICATED, login("jose@bringardner.us", "pw").getStatus());
        assertTrue(manager.removePassword(jose));
        assertFalse(manager.removePassword(jose));
        assertEquals(AuthenticationResult.Status.REFUSED, login("jose@bringardner.us", "pw").getStatus());

        ParleyPrincipal changed = manager.setAttribute(jose, "maildrop", "jose");
        assertEquals("jose", changed.getAttribute("maildrop"));
        assertEquals("jose", registry.findPrincipal("jose@bringardner.us").getAttribute("maildrop"));
        assertEquals(jose, changed, "the same principal");
        ParleyPrincipal salesNow = manager.setAttribute(sales, "mailbox", "sales");
        assertEquals("sales", salesNow.getAttribute("mailbox"), "groups have attributes too");
        assertEquals(null, manager.setAttribute(jose, "maildrop", null).getAttribute("maildrop"));

        assertTrue(manager.deletePrincipal(jose));
        assertNull(registry.findPrincipal("jose@bringardner.us"));
        assertFalse(manager.deletePrincipal(jose));
    }

    @Test
    void aTurnedOffUserIsAsIfGone() throws Exception {
        PrincipalManager manager = registry;
        ParleyPermission read = new BasicParleyPermission(StandardPermissions.READ, null);
        registry.grant(tony.getId(), read);
        registry.addMember(sales.getId(), tony.getId());
        Requester tonyIn = connected.loggedIn(AuthenticationResult.authenticated(tony, "password"));

        manager.setEnabled(tony, false);
        assertFalse(manager.isEnabled(tony));
        assertTrue(manager.isEnabled(sales), "a group is always on");
        assertEquals(AuthenticationResult.Status.REFUSED, login("tony@bringardner.us", "secret").getStatus());
        assertEquals(AuthorizationResult.Status.DENIED, registry.checkPermission(tonyIn, read, null).getStatus(), "even a session from before");
        assertNull(registry.findPrincipal("tony@bringardner.us"));
        assertNull(registry.findPrincipal(tony.getId()));
        assertEquals(0, registry.findMembers(sales).size());
        assertEquals(0, registry.findGroups(tony).size());
        assertEquals(java.util.List.of(tony), manager.findPrincipals("tony", PrincipalManager.Kind.USER, 0), "listed, so it can be turned on");

        manager.setEnabled(tony, true);
        assertEquals(AuthenticationResult.Status.AUTHENTICATED, login("tony@bringardner.us", "secret").getStatus());
        assertEquals(Set.of(sales), registry.findGroups(tony), "its groups were kept");
    }

    @Test
    void principalsAreListedByName() throws Exception {
        PrincipalManager manager = registry;
        manager.createUser("Alice@bringardner.us");
        manager.createGroup("support");
        assertEquals(5, manager.findPrincipals(null, PrincipalManager.Kind.ANY, 0).size());
        assertEquals(java.util.List.of("Alice@bringardner.us", "tony@bringardner.us"),
                names(manager.findPrincipals("", PrincipalManager.Kind.USER, 0)), "sorted, case ignored");
        assertEquals(java.util.List.of("sales", "staff", "support"), names(manager.findPrincipals(null, PrincipalManager.Kind.GROUP, 0)));
        assertEquals(java.util.List.of("staff"), names(manager.findPrincipals("ST", PrincipalManager.Kind.ANY, 5)), "prefix, case ignored");
        assertEquals(java.util.List.of("sales"), names(manager.findPrincipals("s", PrincipalManager.Kind.ANY, 1)), "the limit");
    }

    @Test
    void userChangesThatCantWorkAreRefused() throws Exception {
        final PrincipalManager manager = registry;
        final ParleyPrincipal stranger = BasicParleyPrincipal.user(EntityId.random(), "stranger");
        assertRefused(new Executable() {
            @Override
            public void execute() throws Throwable {
                manager.createUser("SALES");
            }
        }, "the name of a group");
        assertRefused(new Executable() {
            @Override
            public void execute() throws Throwable {
                manager.setPassword(sales, "pw".toCharArray());
            }
        }, "a group doesn't log in");
        assertRefused(new Executable() {
            @Override
            public void execute() throws Throwable {
                manager.setPassword(tony, new char[0]);
            }
        }, "an empty password");
        assertRefused(new Executable() {
            @Override
            public void execute() throws Throwable {
                manager.setEnabled(sales, false);
            }
        }, "a group isn't turned off");
        assertRefused(new Executable() {
            @Override
            public void execute() throws Throwable {
                manager.setAttribute(stranger, "maildrop", "x");
            }
        }, "a principal of another registry");
    }

    private static java.util.List<String> names(java.util.List<ParleyPrincipal> principals) {
        java.util.List<String> ret = new java.util.ArrayList<String>();
        for (ParleyPrincipal p : principals) {
            ret.add(p.getName());
        }
        return ret;
    }

    @Test
    void grantsAreManagedThroughPermissionManager() throws Exception {
        PermissionManager manager = registry;
        final EntityId inbox = EntityId.random();
        final EntityId other = EntityId.random();
        ProtectedResource inboxResource = resource(inbox);
        ProtectedResource otherResource = resource(other);
        ParleyPermission write = new BasicParleyPermission(StandardPermissions.WRITE, null);
        ParleyPermission writeInbox = new BasicParleyPermission(StandardPermissions.WRITE, inbox);
        ParleyPermission read = new BasicParleyPermission(StandardPermissions.READ, null);
        Requester tonyIn = connected.loggedIn(AuthenticationResult.authenticated(tony, "password"));
        assertTrue(manager.supportsGrant(true, true));
        assertTrue(manager.supportsGrant(false, false));

        assertTrue(manager.grant(tony, writeInbox));
        assertFalse(manager.grant(tony, new BasicParleyPermission("WRITE", inbox)), "names ignore case: the same grant");
        assertEquals(AuthorizationResult.Status.ALLOWED, registry.checkPermission(tonyIn, write, inboxResource).getStatus(), "about that resource");
        assertEquals(AuthorizationResult.Status.ALLOWED, registry.checkPermission(tonyIn, writeInbox, null).getStatus(), "the needed permission names it");
        assertEquals(AuthorizationResult.Status.DENIED, registry.checkPermission(tonyIn, write, otherResource).getStatus(), "another resource");
        assertEquals(AuthorizationResult.Status.DENIED, registry.checkPermission(tonyIn, write, null).getStatus(), "the whole server");

        assertTrue(manager.grant(sales, read));
        registry.addMember(sales.getId(), tony.getId());
        assertEquals(AuthorizationResult.Status.ALLOWED, registry.checkPermission(tonyIn, read, otherResource).getStatus(),
                "a server-wide grant to a group holds on every resource");
        assertEquals(Set.of(writeInbox), manager.findGrants(tony), "its own grants, not its groups'");
        assertEquals(Set.of(read), manager.findGrants(sales));

        assertTrue(manager.revoke(tony, writeInbox));
        assertFalse(manager.revoke(tony, writeInbox));
        assertEquals(AuthorizationResult.Status.DENIED, registry.checkPermission(tonyIn, write, inboxResource).getStatus());
        assertEquals(0, manager.findGrants(tony).size());

        final ParleyPrincipal stranger = BasicParleyPrincipal.user(EntityId.random(), "stranger");
        assertRefused(new Executable() {
            @Override
            public void execute() throws Throwable {
                registry.grant(stranger, read);
            }
        }, "a principal of another registry");
    }

    private ProtectedResource resource(final EntityId id) {
        return new ProtectedResource() {
            @Override
            public EntityId getId() {
                return id;
            }

            @Override
            public String getType() {
                return "mailbox";
            }

            @Override
            public String getName() {
                return "INBOX";
            }

            @Override
            public EntityId getOwnerId() {
                return tony.getId();
            }
        };
    }

    @Test
    void aChangeSetIsMadeAllTogether() throws Exception {
        PrincipalChanges changes = new PrincipalChanges()
                .createUser("jose@bringardner.us")
                .setPassword("jose@bringardner.us", "pw".toCharArray())
                .setAttribute("jose@bringardner.us", "maildrop", "jose")
                .createGroup("support")
                .addMember("support", "jose@bringardner.us")
                .addMember("sales", "jose@bringardner.us")
                .grant("jose@bringardner.us", new BasicParleyPermission(StandardPermissions.READ, null));
        registry.apply(changes);
        changes.clear();
        assertEquals(0, changes.getSteps().get(1).getPassword()[0], "clear wipes the password");
        ParleyPrincipal jose = registry.findPrincipal("jose@bringardner.us");
        assertEquals("jose", jose.getAttribute("maildrop"));
        assertEquals(AuthenticationResult.Status.AUTHENTICATED, login("jose@bringardner.us", "pw").getStatus());
        assertEquals(2, registry.findGroups(jose).size());
        assertEquals(1, registry.findGrants(jose).size());
    }

    @Test
    void aChangeSetThatFailsChangesNothing() throws Exception {
        final PrincipalChanges changes = new PrincipalChanges()
                .createUser("jose@bringardner.us")
                .setPassword("jose@bringardner.us", "pw".toCharArray())
                .createGroup("support")
                .addMember("support", "jose@bringardner.us")
                .setPassword("tony@bringardner.us", "new".toCharArray())
                .addMember("nosuchgroup", "jose@bringardner.us");
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, new Executable() {
            @Override
            public void execute() throws Throwable {
                registry.apply(changes);
            }
        });
        assertTrue(e.getMessage().contains("nosuchgroup"), e.getMessage());
        assertNull(registry.findPrincipal("jose@bringardner.us"), "the user made by an earlier step is gone again");
        assertNull(registry.findPrincipal("support"));
        assertEquals(AuthenticationResult.Status.AUTHENTICATED, login("tony@bringardner.us", "secret").getStatus(), "the old password");
        assertEquals(3, registry.findPrincipals(null, PrincipalManager.Kind.ANY, 0).size());
    }

    private static void assertRefused(Executable change, String why) {
        assertThrows(IllegalArgumentException.class, change, why);
    }
}
