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

import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/** A certificate chain (TLS client certificate, OpenSSH certificate). The certificate names the user. */
public final class CertificateCredential extends Credential {

    private final List<Certificate> chain;

    public CertificateCredential(Certificate[] chain, Requester requester) {
        super(null, requester);
        this.chain = Collections.unmodifiableList(Arrays.asList(chain.clone()));
    }

    /** @return the chain, the client's own certificate first */
    public List<Certificate> getChain() {
        return chain;
    }
}
