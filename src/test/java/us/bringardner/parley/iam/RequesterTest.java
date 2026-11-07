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
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import us.bringardner.parley.iam.principal.BasicParleyPrincipal;

class RequesterTest {

    private final ParleyPrincipal tony = BasicParleyPrincipal.user(EntityId.random(), "tony");

    @Test
    void startingTlsKeepsTheLogin() {
        Requester plain = Requester.connected(null, 25, false, Requester.Transport.TCP, "smtp");
        Requester in = plain.loggedIn(AuthenticationResult.authenticated(tony, "password"));
        Requester secured = in.withSecure(true);
        assertTrue(secured.isSecure());
        assertSame(tony, secured.getPrincipal());
        assertEquals(in.getMethods(), secured.getMethods());
        assertEquals(25, secured.getLocalPort());
        assertFalse(in.isSecure(), "the old requester doesn't change");
        assertSame(secured, secured.withSecure(true), "nothing changed");
        assertFalse(secured.withSecure(false).isSecure());
    }
}
