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

/**
 * A challenge and response: the client proves it knows a secret without sending it.
 * The proof names the kind of stored secret it needs and carries the protocol's check.
 */
public final class ProofCredential extends Credential {

    private final StoredCredentialType storedType;
    private final ProofVerifier verifier;

    public ProofCredential(String user, StoredCredentialType storedType, ProofVerifier verifier,
            Requester requester) {
        super(user, requester);
        this.storedType = storedType;
        this.verifier = verifier;
    }

    /** @return the kind of stored secret the verifier needs */
    public StoredCredentialType getStoredType() {
        return storedType;
    }

    /** @return the protocol's check */
    public ProofVerifier getVerifier() {
        return verifier;
    }
}
