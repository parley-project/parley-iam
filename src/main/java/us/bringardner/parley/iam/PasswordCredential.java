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

import java.util.Arrays;

/** A user name and a password, as SMTP AUTH PLAIN, IMAP LOGIN, FTP PASS or SSH send them. */
public final class PasswordCredential extends Credential {

    private final char[] password;

    public PasswordCredential(String user, char[] password, Requester requester) {
        super(user, requester);
        this.password = password.clone();
    }

    /** @return a copy of the password; clear it when done */
    public char[] getPassword() {
        return password.clone();
    }

    /** Overwrites the password held by this credential. */
    public void clear() {
        Arrays.fill(password, '\0');
    }
}
