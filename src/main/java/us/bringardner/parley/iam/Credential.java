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
 * What a client offers to prove who it is. The framework ships one kind per way of proving:
 * {@link us.bringardner.parley.iam.credential.PasswordCredential PasswordCredential},
 * {@link us.bringardner.parley.iam.credential.TokenCredential TokenCredential},
 * {@link us.bringardner.parley.iam.credential.CertificateCredential CertificateCredential},
 * {@link us.bringardner.parley.iam.credential.ProofCredential ProofCredential} and
 * {@link us.bringardner.parley.iam.credential.VouchedCredential VouchedCredential}, in
 * {@code us.bringardner.parley.iam.credential}.
 */
public abstract class Credential {

    private final String user;
    private final Requester requester;

    /**
     * @param user the user name the client gave, or null when the credential names the user
     *            itself (a token, a certificate)
     * @param requester who is offering it
     */
    protected Credential(String user, Requester requester) {
        this.user = user;
        this.requester = requester;
    }

    /** @return the user name the client gave, or null */
    public String getUser() {
        return user;
    }

    /** @return who is offering this credential */
    public Requester getRequester() {
        return requester;
    }
}
