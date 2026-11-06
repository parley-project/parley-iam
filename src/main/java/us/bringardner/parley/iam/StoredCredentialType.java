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

import java.util.Locale;
import java.util.Objects;

/**
 * Which kind of stored secret a proof needs: SCRAM keys, SSH public keys, a TSIG secret,
 * a plain-text secret. An open set: a protocol may name kinds of its own.
 */
public final class StoredCredentialType {

    public static final StoredCredentialType SCRAM_SHA_256 = new StoredCredentialType("scram-sha-256");
    public static final StoredCredentialType SSH_PUBLIC_KEYS = new StoredCredentialType("ssh-public-keys");
    public static final StoredCredentialType TSIG_SECRET = new StoredCredentialType("tsig-secret");
    public static final StoredCredentialType PLAIN_TEXT = new StoredCredentialType("plain-text");

    private final String name;

    /** @param name the kind's name, compared without regard to case */
    public StoredCredentialType(String name) {
        this.name = Objects.requireNonNull(name, "name").toLowerCase(Locale.ROOT);
    }

    /** @return the kind's name, in lower case */
    public String getName() {
        return name;
    }

    @Override
    public boolean equals(Object other) {
        if (!(other instanceof StoredCredentialType)) {
            return false;
        }
        StoredCredentialType that = (StoredCredentialType) other;
        return name.equals(that.name);
    }

    @Override
    public int hashCode() {
        return name.hashCode();
    }

    @Override
    public String toString() {
        return name;
    }
}
