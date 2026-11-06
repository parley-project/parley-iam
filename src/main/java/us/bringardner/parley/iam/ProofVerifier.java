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

import java.io.IOException;

/**
 * A protocol's own check of a proof (SCRAM's exchange, an SSH signature, a TSIG MAC).
 * It may wait on the client; the framework never holds a registry's lock or connection
 * while it runs.
 */
public interface ProofVerifier {

    /**
     * @param stored the user's stored secret of the kind the proof asked for
     * @return true when the client proved it knows (or holds) the secret
     * @throws IOException when talking to the client fails
     */
    boolean verify(StoredCredential stored) throws IOException;
}
