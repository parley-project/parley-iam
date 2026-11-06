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
 * Something a permission is about: a file, a mailbox, a DNS name, a domain.
 * <p>
 * The application defines what a resource is and how resources nest; the framework only
 * needs its id, its type, its name and its owner. Every resource has an owner, a principal
 * (possibly a group) with full control.
 */
public interface ProtectedResource extends Entity {

    /** @return the kind of thing, for example "file", "mailbox", "dns-name", "domain" */
    String getType();

    /** @return which one, for example "/tony/notes.txt" or "tony@bringardner.us/INBOX" */
    String getName();

    /** @return the id of the principal that owns this resource; never null */
    EntityId getOwnerId();
}
