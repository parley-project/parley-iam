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

/** A stored secret a registry hands out for a proof, of one {@link StoredCredentialType}. */
public final class StoredCredential {

    private final StoredCredentialType type;
    private final Object value;

    /**
     * @param type which kind it is
     * @param value the secret itself, in the form the protocol's verifier expects
     */
    public StoredCredential(StoredCredentialType type, Object value) {
        this.type = Objects.requireNonNull(type, "type");
        this.value = Objects.requireNonNull(value, "value");
    }

    /** @return which kind it is */
    public StoredCredentialType getType() {
        return type;
    }

    /** @return the secret itself */
    public Object getValue() {
        return value;
    }
}
