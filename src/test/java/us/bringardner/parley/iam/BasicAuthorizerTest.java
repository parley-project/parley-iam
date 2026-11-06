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
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

class BasicAuthorizerTest {

    /** A resource for the tests: a file with an owner. */
    static final class TestFile implements ProtectedResource {
        private final EntityId id = EntityId.random();
        private final String name;
        private final EntityId owner;

        TestFile(String name, ParleyPrincipal owner) {
            this.name = name;
            this.owner = owner.getId();
        }

        @Override
        public EntityId getId() {
            return id;
        }

        @Override
        public String getType() {
            return "file";
        }

        @Override
        public String getName() {
            return name;
        }

        @Override
        public EntityId getOwnerId() {
            return owner;
        }
    }

    private final ParleyPrincipal tony = BasicParleyPrincipal.user(EntityId.random(), "tony");
    private final ParleyPrincipal bob = BasicParleyPrincipal.user(EntityId.random(), "bob");
    private final ParleyPrincipal sales = BasicParleyPrincipal.group(EntityId.random(), "sales");
    private final ParleyPrincipal staff = BasicParleyPrincipal.group(EntityId.random(), "staff");

    private InMemoryUserRegistry registry;
    private BasicAuthorizer authorizer;
    private TestFile tonysFile;

    @BeforeEach
    void setUp() {
        registry = new InMemoryUserRegistry();
        registry.add(tony);
        registry.add(bob);
        registry.add(sales);
        registry.add(staff);
        registry.addMember(sales, bob);   // bob is in sales
        registry.addMember(staff, sales); // sales is in staff, so bob is in staff too
        authorizer = new BasicAuthorizer(registry);
        tonysFile = new TestFile("/tony/notes.txt", tony);
    }

    private Requester loggedIn(ParleyPrincipal principal) {
        Requester connected = Requester.connected(null, 21, true, Requester.Transport.TCP, "ftp");
        return connected.loggedIn(AuthenticationResult.authenticated(principal, "password"));
    }

    private ParleyPermission read(ProtectedResource resource) {
        return new BasicParleyPermission(StandardPermissions.READ, resource.getId());
    }

    private AuthorizationResult.Status check(Requester requester, ParleyPermission needed, ProtectedResource resource) {
        return authorizer.check(requester, needed, resource).getStatus();
    }

    @Test
    void ownerIsAllowedWithNoGrants() {
        assertEquals(AuthorizationResult.Status.ALLOWED, check(loggedIn(tony), read(tonysFile), tonysFile));
    }

    @Test
    void memberOfOwningGroupIsAllowed() {
        TestFile salesFile = new TestFile("/sales/plan.txt", staff);
        assertEquals(AuthorizationResult.Status.ALLOWED, check(loggedIn(bob), read(salesFile), salesFile));
    }

    @Test
    void othersAreDeniedWithoutAGrant() {
        assertEquals(AuthorizationResult.Status.DENIED, check(loggedIn(bob), read(tonysFile), tonysFile));
    }

    @Test
    void grantToTheUserAllows() {
        registry.grant(bob, read(tonysFile));
        assertEquals(AuthorizationResult.Status.ALLOWED, check(loggedIn(bob), read(tonysFile), tonysFile));
    }

    @Test
    void grantToAGroupOfAGroupAllows() {
        registry.grant(staff, read(tonysFile));
        assertEquals(AuthorizationResult.Status.ALLOWED, check(loggedIn(bob), read(tonysFile), tonysFile));
    }

    @Test
    void grantToAnyoneNeedsNoLogin() {
        registry.grant(BuiltInGroups.ANYONE, read(tonysFile));
        Requester nobody = Requester.connected(null, 21, false, Requester.Transport.TCP, "ftp");
        assertEquals(AuthorizationResult.Status.ALLOWED, check(nobody, read(tonysFile), tonysFile));
    }

    @Test
    void grantToAuthenticatedNeedsALogin() {
        registry.grant(BuiltInGroups.AUTHENTICATED, read(tonysFile));
        Requester nobody = Requester.connected(null, 21, false, Requester.Transport.TCP, "ftp");
        assertEquals(AuthorizationResult.Status.DENIED, check(nobody, read(tonysFile), tonysFile));
        assertEquals(AuthorizationResult.Status.ALLOWED, check(loggedIn(bob), read(tonysFile), tonysFile));
    }

    @Test
    void writeDoesNotImplyRead() {
        registry.grant(bob, new BasicParleyPermission(StandardPermissions.WRITE, tonysFile.getId()));
        assertEquals(AuthorizationResult.Status.DENIED, check(loggedIn(bob), read(tonysFile), tonysFile));
    }

    @Test
    void adminImpliesEverythingOnItsResource() {
        registry.grant(bob, new BasicParleyPermission(StandardPermissions.ADMIN, tonysFile.getId()));
        ParleyPermission send = new BasicParleyPermission("smtp.send", tonysFile.getId());
        assertEquals(AuthorizationResult.Status.ALLOWED, check(loggedIn(bob), send, tonysFile));
    }

    @Test
    void namesIgnoreCase() {
        registry.grant(bob, new BasicParleyPermission("Read", tonysFile.getId()));
        assertEquals(AuthorizationResult.Status.ALLOWED, check(loggedIn(bob), read(tonysFile), tonysFile));
    }

    @Test
    void aGrantOnAnotherResourceDoesNotCount() {
        TestFile other = new TestFile("/tony/other.txt", tony);
        registry.grant(bob, read(other));
        assertEquals(AuthorizationResult.Status.DENIED, check(loggedIn(bob), read(tonysFile), tonysFile));
    }

    @Test
    void anOutageIsUnavailableNotDenied() {
        registry.unavailable = true;
        assertEquals(AuthorizationResult.Status.UNAVAILABLE, check(loggedIn(bob), read(tonysFile), tonysFile));
    }

    @Test
    void onlyAnAuthenticatedResultLogsIn() {
        Requester connected = Requester.connected(null, 21, false, Requester.Transport.TCP, "ftp");
        assertThrows(IllegalArgumentException.class, new Executable() {
            @Override
            public void execute() {
                connected.loggedIn(AuthenticationResult.refused("wrong password"));
            }
        });
    }

    @Test
    void eachLoginMethodIsListed() {
        Requester first = loggedIn(tony);
        Requester second = first.loggedIn(AuthenticationResult.authenticated(tony, "totp"));
        assertEquals(2, second.getMethods().size());
        assertEquals("totp", second.getMethods().get(1));
    }
}
