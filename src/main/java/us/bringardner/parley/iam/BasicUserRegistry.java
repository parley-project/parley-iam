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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * The general-purpose {@link UserRegistry}: principals, groups, passwords and grants held
 * in memory. An application can use it as it is, fill it from its own files or database,
 * or extend it.
 * <p>
 * The framework only reads it, through {@link UserRegistry}. The methods that change it are
 * for the application: users and groups through {@link PrincipalManager}, and
 * {@link #addPrincipal}, {@link #grant} and their opposites, which take ids.
 * <ul>
 * <li>Logins: passwords only, stored as PBKDF2 hashes (never the password itself). A group
 * can't log in. An unknown user takes as long to refuse as a known one.</li>
 * <li>Names: a principal is found by its name ignoring case; two principals can't share a
 * name.</li>
 * <li>Ids: an id is never reused, even after its principal is removed.</li>
 * <li>Groups: nested groups are followed, and a loop stops instead of running forever.</li>
 * <li>Safe to use from many threads at once.</li>
 * </ul>
 * A subclass backed by a file or a database may throw {@link UserRegistryUnavailableException}
 * from the find methods when it can't be reached.
 */
public class BasicUserRegistry implements PrincipalManager {

    /** The login method reported for a password login. */
    public static final String PASSWORD_METHOD = "password";

    private static final String HASH_ALGORITHM = "PBKDF2WithHmacSHA256";
    /** OWASP's recommended iteration count for PBKDF2-HMAC-SHA256 (2023). */
    private static final int DEFAULT_ITERATIONS = 600_000;
    private static final int SALT_BYTES = 16;
    private static final int HASH_BITS = 256;

    /** A stored password: the salt, the iteration count and the hash. */
    private static final class PasswordHash {
        final byte[] salt;
        final int iterations;
        final byte[] hash;

        PasswordHash(byte[] salt, int iterations, byte[] hash) {
            this.salt = salt;
            this.iterations = iterations;
            this.hash = hash;
        }
    }

    private final Object lock = new Object();
    private final SecureRandom random = new SecureRandom();
    private final int iterations;

    private final Map<EntityId, ParleyPrincipal> principals = new HashMap<EntityId, ParleyPrincipal>();
    /** Lower-case name to id. */
    private final Map<String, EntityId> names = new HashMap<String, EntityId>();
    /** Every id ever added, so none is used twice. */
    private final Set<EntityId> usedIds = new HashSet<EntityId>();
    /** Member id to the groups it is directly in. */
    private final Map<EntityId, Set<EntityId>> directGroups = new HashMap<EntityId, Set<EntityId>>();
    private final Map<EntityId, PasswordHash> passwords = new HashMap<EntityId, PasswordHash>();
    /** The users turned off. */
    private final Set<EntityId> disabled = new HashSet<EntityId>();
    /** Holder id (a principal or a group) to its grants. */
    private final Map<EntityId, Set<ParleyPermission>> grants = new HashMap<EntityId, Set<ParleyPermission>>();

    /** Sorts principals by name, ignoring case. */
    private static final java.util.Comparator<ParleyPrincipal> BY_NAME = new ByName();

    private static final class ByName implements java.util.Comparator<ParleyPrincipal>, java.io.Serializable {
        private static final long serialVersionUID = 1L;

        @Override
        public int compare(ParleyPrincipal a, ParleyPrincipal b) {
            return nameKey(a.getName()).compareTo(nameKey(b.getName()));
        }
    }

    /** Made up once, so refusing an unknown user costs the same as checking a known one. */
    private final PasswordHash unknownUserHash;

    /** A registry with the default iteration count for password hashes. */
    public BasicUserRegistry() {
        this(DEFAULT_ITERATIONS);
    }

    /**
     * @param iterations the PBKDF2 iteration count for new password hashes; lower only for tests
     */
    public BasicUserRegistry(int iterations) {
        if (iterations < 1) {
            throw new IllegalArgumentException("iterations must be at least 1");
        }
        this.iterations = iterations;
        this.unknownUserHash = makeHash("not a real password".toCharArray());
    }

    // ---- Changes, for the application -------------------------------------------------

    /**
     * Adds a principal or a group.
     *
     * @throws IllegalArgumentException when the id was used before or the name is taken
     */
    public void addPrincipal(ParleyPrincipal principal) {
        Objects.requireNonNull(principal, "principal");
        String key = nameKey(principal.getName());
        synchronized (lock) {
            if (usedIds.contains(principal.getId())) {
                throw new IllegalArgumentException("The id " + principal.getId() + " has already been used");
            }
            if (names.containsKey(key)) {
                throw new IllegalArgumentException("The name " + principal.getName() + " is taken");
            }
            usedIds.add(principal.getId());
            principals.put(principal.getId(), principal);
            names.put(key, principal.getId());
        }
    }

    /**
     * Removes a principal or group with its password, its memberships, its members' memberships
     * in it and its grants. Its id is never used again. Resources it owns are the application's
     * to deal with.
     *
     * @return true when it was there
     */
    public boolean removePrincipal(EntityId id) {
        synchronized (lock) {
            ParleyPrincipal removed = principals.remove(id);
            if (removed == null) {
                return false;
            }
            names.remove(nameKey(removed.getName()));
            passwords.remove(id);
            grants.remove(id);
            disabled.remove(id);
            directGroups.remove(id);
            for (Set<EntityId> groups : directGroups.values()) {
                groups.remove(id);
            }
            return true;
        }
    }

    /**
     * Puts a member (a principal or another group) in a group, by id. Unlike
     * {@link #addMember(ParleyPrincipal, ParleyPrincipal)} it doesn't refuse a loop (finding
     * groups stops at one).
     *
     * @throws IllegalArgumentException when either isn't in this registry or the group isn't a group
     */
    public void addMember(EntityId groupId, EntityId memberId) {
        synchronized (lock) {
            ParleyPrincipal group = principals.get(groupId);
            if (group == null || !group.isGroup()) {
                throw new IllegalArgumentException("No group with the id " + groupId);
            }
            if (!principals.containsKey(memberId)) {
                throw new IllegalArgumentException("No principal with the id " + memberId);
            }
            Set<EntityId> groups = directGroups.get(memberId);
            if (groups == null) {
                groups = new LinkedHashSet<EntityId>();
                directGroups.put(memberId, groups);
            }
            groups.add(groupId);
        }
    }

    /** @return true when the member was directly in the group */
    public boolean removeMember(EntityId groupId, EntityId memberId) {
        synchronized (lock) {
            Set<EntityId> groups = directGroups.get(memberId);
            return groups != null && groups.remove(groupId);
        }
    }

    /**
     * Sets a principal's password, stored as a PBKDF2 hash. The array is not kept; clear it
     * when done.
     *
     * @throws IllegalArgumentException when there is no such principal, or it is a group
     */
    public void setPassword(EntityId id, char[] password) {
        PasswordHash hash = makeHash(password); // slow on purpose, so done outside the lock
        synchronized (lock) {
            ParleyPrincipal principal = principals.get(id);
            if (principal == null || principal.isGroup()) {
                throw new IllegalArgumentException("No user with the id " + id);
            }
            passwords.put(id, hash);
        }
    }

    /** Removes a principal's password, so it can no longer log in with one. */
    public void removePassword(EntityId id) {
        synchronized (lock) {
            passwords.remove(id);
        }
    }

    /**
     * Gives a holder a permission. The holder is a principal or group in this registry.
     */
    public void grant(EntityId holderId, ParleyPermission permission) {
        Objects.requireNonNull(permission, "permission");
        synchronized (lock) {
            if (!isHolder(holderId)) {
                throw new IllegalArgumentException("No principal with the id " + holderId);
            }
            Set<ParleyPermission> held = grants.get(holderId);
            if (held == null) {
                held = new LinkedHashSet<ParleyPermission>();
                grants.put(holderId, held);
            }
            held.add(permission);
        }
    }

    /** @return true when the holder had that grant */
    public boolean revoke(EntityId holderId, ParleyPermission permission) {
        synchronized (lock) {
            Set<ParleyPermission> held = grants.get(holderId);
            return held != null && held.remove(permission);
        }
    }

    // ---- PrincipalManager, for the application -----------------------------------------

    /** A user with a new random id. */
    @Override
    public ParleyPrincipal createUser(String name) {
        checkName(name);
        ParleyPrincipal user = BasicParleyPrincipal.user(EntityId.random(), name);
        addPrincipal(user);
        return user;
    }

    /** A group with a new random id. */
    @Override
    public ParleyPrincipal createGroup(String name) {
        checkName(name);
        ParleyPrincipal group = BasicParleyPrincipal.group(EntityId.random(), name);
        addPrincipal(group);
        return group;
    }

    @Override
    public boolean deletePrincipal(ParleyPrincipal principal) {
        Objects.requireNonNull(principal, "principal");
        return removePrincipal(principal.getId());
    }

    @Override
    public ParleyPrincipal setAttribute(ParleyPrincipal principal, String name, String value) {
        Objects.requireNonNull(principal, "principal");
        if (name == null || name.trim().isEmpty()) {
            throw new IllegalArgumentException("An attribute needs a name");
        }
        synchronized (lock) {
            ParleyPrincipal stored = stored(principal);
            Map<String, Object> attributes = new LinkedHashMap<String, Object>();
            for (String key : stored.getAttributeNames()) {
                attributes.put(key, stored.getAttribute(key));
            }
            if (value == null) {
                attributes.remove(name);
            } else {
                attributes.put(name, value);
            }
            ParleyPrincipal changed = new BasicParleyPrincipal(stored.getId(), stored.getName(), stored.isGroup(), attributes);
            principals.put(changed.getId(), changed);
            return changed;
        }
    }

    @Override
    public void setPassword(ParleyPrincipal user, char[] password) {
        Objects.requireNonNull(user, "user");
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("A password can't be empty");
        }
        setPassword(user.getId(), password);
    }

    @Override
    public boolean removePassword(ParleyPrincipal user) {
        Objects.requireNonNull(user, "user");
        synchronized (lock) {
            storedUser(user);
            return passwords.remove(user.getId()) != null;
        }
    }

    @Override
    public void setEnabled(ParleyPrincipal user, boolean enabled) {
        Objects.requireNonNull(user, "user");
        synchronized (lock) {
            storedUser(user);
            if (enabled) {
                disabled.remove(user.getId());
            } else {
                disabled.add(user.getId());
            }
        }
    }

    @Override
    public boolean isEnabled(ParleyPrincipal user) {
        Objects.requireNonNull(user, "user");
        synchronized (lock) {
            return !disabled.contains(stored(user).getId());
        }
    }

    /** Names compared ignoring case, as everywhere in this registry. */
    @Override
    public List<ParleyPrincipal> findPrincipals(String prefix, Kind kind, int limit) {
        String start = prefix == null ? "" : nameKey(prefix);
        List<ParleyPrincipal> found = new ArrayList<ParleyPrincipal>();
        synchronized (lock) {
            for (ParleyPrincipal p : principals.values()) {
                boolean wanted = kind == null || kind == Kind.ANY || (kind == Kind.GROUP) == p.isGroup();
                if (wanted && nameKey(p.getName()).startsWith(start)) {
                    found.add(p);
                }
            }
        }
        found.sort(BY_NAME);
        if (limit > 0 && found.size() > limit) {
            return new ArrayList<ParleyPrincipal>(found.subList(0, limit));
        }
        return found;
    }

    /** Groups nest here, so the member may be a group, as long as that makes no loop. */
    @Override
    public boolean addMember(ParleyPrincipal group, ParleyPrincipal member) {
        Objects.requireNonNull(group, "group");
        Objects.requireNonNull(member, "member");
        synchronized (lock) {
            ParleyPrincipal storedGroup = principals.get(group.getId());
            if (storedGroup == null || !storedGroup.isGroup()) {
                throw new IllegalArgumentException("No group " + group.getName() + " in this registry");
            }
            if (!principals.containsKey(member.getId())) {
                throw new IllegalArgumentException("No principal " + member.getName() + " in this registry");
            }
            if (group.getId().equals(member.getId())) {
                throw new IllegalArgumentException("A group can't be a member of itself");
            }
            Set<ParleyPrincipal> groupsOfGroup = new LinkedHashSet<ParleyPrincipal>();
            collectGroups(group.getId(), new HashSet<EntityId>(), groupsOfGroup);
            for (ParleyPrincipal holder : groupsOfGroup) {
                if (holder.getId().equals(member.getId())) {
                    throw new IllegalArgumentException(group.getName() + " is already in " + member.getName()
                            + ", so " + member.getName() + " can't be in " + group.getName());
                }
            }
            Set<EntityId> groups = directGroups.get(member.getId());
            if (groups == null) {
                groups = new LinkedHashSet<EntityId>();
                directGroups.put(member.getId(), groups);
            }
            return groups.add(group.getId());
        }
    }

    @Override
    public boolean removeMember(ParleyPrincipal group, ParleyPrincipal member) {
        Objects.requireNonNull(group, "group");
        Objects.requireNonNull(member, "member");
        return removeMember(group.getId(), member.getId());
    }

    // ---- UserRegistry, for the framework ----------------------------------------------

    /** Passwords only. */
    @Override
    public boolean supports(Class<? extends Credential> kind, StoredCredentialType stored) {
        return kind == PasswordCredential.class && stored == null;
    }

    @Override
    public AuthenticationResult authenticate(Credential credential) {
        if (!(credential instanceof PasswordCredential)) {
            return AuthenticationResult.unsupported("BasicUserRegistry checks passwords only");
        }
        PasswordCredential passwordCredential = (PasswordCredential) credential;
        ParleyPrincipal principal = null;
        PasswordHash stored = null;
        if (passwordCredential.getUser() != null) {
            synchronized (lock) {
                EntityId id = names.get(nameKey(passwordCredential.getUser()));
                if (id != null) {
                    principal = principals.get(id);
                    stored = passwords.get(id);
                }
            }
        }
        boolean known = principal != null && stored != null && !principal.isGroup();
        boolean turnedOff;
        synchronized (lock) {
            turnedOff = principal != null && disabled.contains(principal.getId());
        }
        if (!known) {
            stored = unknownUserHash; // same work, so the time doesn't tell
        }

        char[] password = passwordCredential.getPassword();
        boolean matches;
        try {
            matches = matches(password, stored);
        } finally {
            Arrays.fill(password, '\0');
        }
        if (known && matches && !turnedOff) {
            return AuthenticationResult.authenticated(principal, PASSWORD_METHOD);
        }
        if (turnedOff) {
            return AuthenticationResult.refused(principal.getName() + " is turned off");
        }
        if (!known) {
            return AuthenticationResult.refused("no user " + passwordCredential.getUser() + " with a password");
        }
        return AuthenticationResult.refused("wrong password for " + principal.getName());
    }

    /** This registry stores no secrets for proofs. */
    @Override
    public StoredCredential findStoredCredential(String user, StoredCredentialType type)
            throws UserRegistryUnavailableException {
        return null;
    }

    @Override
    public ParleyPrincipal findPrincipal(String name) throws UserRegistryUnavailableException {
        if (name == null) {
            return null;
        }
        synchronized (lock) {
            EntityId id = names.get(nameKey(name));
            if (id == null || disabled.contains(id)) {
                return null;
            }
            return principals.get(id);
        }
    }

    /** A turned-off user isn't found. */
    @Override
    public ParleyPrincipal findPrincipal(EntityId id) throws UserRegistryUnavailableException {
        synchronized (lock) {
            return disabled.contains(id) ? null : principals.get(id);
        }
    }

    /**
     * Every group the principal is in, including through other groups (Tony in sales, sales
     * in staff: both). Loops are handled.
     */
    @Override
    public Set<ParleyPrincipal> findGroups(ParleyPrincipal principal) {
        Set<ParleyPrincipal> found = new LinkedHashSet<ParleyPrincipal>();
        if (principal == null) {
            return found;
        }
        synchronized (lock) {
            if (disabled.contains(principal.getId())) {
                return found; // as if it were gone
            }
            Set<EntityId> seen = new HashSet<EntityId>();
            collectGroups(principal.getId(), seen, found);
        }
        return found;
    }

    /** The principals put directly in this group, in no set order; turned-off users aren't listed. */
    @Override
    public Set<ParleyPrincipal> findMembers(ParleyPrincipal group) {
        Set<ParleyPrincipal> found = new LinkedHashSet<ParleyPrincipal>();
        if (group == null) {
            return found;
        }
        synchronized (lock) {
            for (Map.Entry<EntityId, Set<EntityId>> entry : directGroups.entrySet()) {
                if (entry.getValue().contains(group.getId()) && !disabled.contains(entry.getKey())) {
                    ParleyPrincipal member = principals.get(entry.getKey());
                    if (member != null) {
                        found.add(member);
                    }
                }
            }
        }
        return found;
    }

    /**
     * Allowed when the logged-in principal, or a group it is in, holds a permission that
     * covers the one needed ({@link ParleyPermission#implies}). Nobody logged in, and a user
     * turned off since it logged in, hold nothing.
     */
    @Override
    public AuthorizationResult checkPermission(Requester requester, ParleyPermission needed,
            ProtectedResource resource) {
        ParleyPrincipal principal = requester.getPrincipal();
        if (principal == null) {
            return AuthorizationResult.denied("nobody logged in");
        }
        synchronized (lock) {
            if (disabled.contains(principal.getId())) {
                return AuthorizationResult.denied(principal.getName() + " is turned off");
            }
        }
        List<ParleyPrincipal> holders = new ArrayList<ParleyPrincipal>();
        holders.add(principal);
        holders.addAll(findGroups(principal));
        for (ParleyPrincipal holder : holders) {
            for (ParleyPermission permission : findPermissions(holder)) {
                if (permission.implies(needed)) {
                    return AuthorizationResult.allowed(holder.getName() + " holds " + permission);
                }
            }
        }
        return AuthorizationResult.denied(principal.getName() + " holds nothing that covers " + needed);
    }

    /** @return every grant the holder has itself (not through its groups) */
    public Collection<ParleyPermission> findPermissions(ParleyPrincipal holder) {
        synchronized (lock) {
            Set<ParleyPermission> held = grants.get(holder.getId());
            if (held == null) {
                return new ArrayList<ParleyPermission>();
            }
            return new ArrayList<ParleyPermission>(held);
        }
    }

    // ---- Helpers ----------------------------------------------------------------------

    /** Adds the groups of one member, then theirs; an id already seen stops a loop. Called holding the lock. */
    private void collectGroups(EntityId memberId, Set<EntityId> seen, Set<ParleyPrincipal> found) {
        Set<EntityId> groups = directGroups.get(memberId);
        if (groups == null) {
            return;
        }
        for (EntityId groupId : new ArrayList<EntityId>(groups)) {
            if (seen.add(groupId)) {
                ParleyPrincipal group = principals.get(groupId);
                if (group != null) {
                    found.add(group);
                }
                collectGroups(groupId, seen, found);
            }
        }
    }

    /** @return the principal as stored here (by id); called holding the lock */
    private ParleyPrincipal stored(ParleyPrincipal principal) {
        ParleyPrincipal stored = principals.get(principal.getId());
        if (stored == null) {
            throw new IllegalArgumentException("No principal " + principal.getName() + " in this registry");
        }
        return stored;
    }

    /** @return the user as stored here; called holding the lock */
    private ParleyPrincipal storedUser(ParleyPrincipal user) {
        ParleyPrincipal stored = stored(user);
        if (stored.isGroup()) {
            throw new IllegalArgumentException(stored.getName() + " is a group, and a group doesn't log in");
        }
        return stored;
    }

    private static void checkName(String name) {
        if (name == null || name.trim().isEmpty()) {
            throw new IllegalArgumentException("A principal needs a name");
        }
    }

    /** Called holding the lock. */
    private boolean isHolder(EntityId id) {
        return principals.containsKey(id);
    }

    private static String nameKey(String name) {
        return name.toLowerCase(Locale.ROOT);
    }

    private PasswordHash makeHash(char[] password) {
        byte[] salt = new byte[SALT_BYTES];
        random.nextBytes(salt);
        return new PasswordHash(salt, iterations, pbkdf2(password, salt, iterations));
    }

    private static boolean matches(char[] password, PasswordHash stored) {
        byte[] candidate = pbkdf2(password, stored.salt, stored.iterations);
        return MessageDigest.isEqual(candidate, stored.hash); // takes the same time wherever they differ
    }

    private static byte[] pbkdf2(char[] password, byte[] salt, int iterations) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, HASH_BITS);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(HASH_ALGORITHM);
            return factory.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(HASH_ALGORITHM + " is part of every Java 11 runtime", e);
        } catch (InvalidKeySpecException e) {
            throw new IllegalStateException("Couldn't hash a password", e);
        } finally {
            spec.clearPassword();
        }
    }
}
