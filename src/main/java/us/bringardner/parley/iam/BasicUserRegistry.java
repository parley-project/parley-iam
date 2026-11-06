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
import java.util.LinkedHashSet;
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
 * The framework only reads it, through {@link UserRegistry}. The methods that change it
 * ({@link #addPrincipal}, {@link #addMember}, {@link #setPassword}, {@link #grant} and their
 * opposites) are for the application.
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
public class BasicUserRegistry implements UserRegistry {

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
    /** Holder id (a principal, a group or a built-in group) to its grants. */
    private final Map<EntityId, Set<ParleyPermission>> grants = new HashMap<EntityId, Set<ParleyPermission>>();

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
     * @throws IllegalArgumentException when the id was used before, the name is taken, or it is
     *             a built-in group
     */
    public void addPrincipal(ParleyPrincipal principal) {
        Objects.requireNonNull(principal, "principal");
        if (BuiltInGroups.isBuiltIn(principal)) {
            throw new IllegalArgumentException("The built-in groups can't be added");
        }
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
            directGroups.remove(id);
            for (Set<EntityId> groups : directGroups.values()) {
                groups.remove(id);
            }
            return true;
        }
    }

    /**
     * Puts a member (a principal or another group) in a group.
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
     * Gives a holder a permission. The holder is a principal or group in this registry, or
     * {@link BuiltInGroups#ANYONE} or {@link BuiltInGroups#AUTHENTICATED}.
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
        if (known && matches) {
            return AuthenticationResult.authenticated(principal, PASSWORD_METHOD);
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
            if (id == null) {
                return null;
            }
            return principals.get(id);
        }
    }

    @Override
    public ParleyPrincipal findPrincipal(EntityId id) throws UserRegistryUnavailableException {
        synchronized (lock) {
            return principals.get(id);
        }
    }

    @Override
    public Set<ParleyPrincipal> findGroups(ParleyPrincipal principal) throws UserRegistryUnavailableException {
        Set<ParleyPrincipal> found = new LinkedHashSet<ParleyPrincipal>();
        synchronized (lock) {
            Set<EntityId> seen = new HashSet<EntityId>();
            collectGroups(principal.getId(), seen, found);
        }
        return found;
    }

    /**
     * Every grant the holder has. The {@link Authorizer} decides with {@code implies} which of
     * them cover what is needed; a large registry would filter by resource here instead.
     */
    @Override
    public Collection<ParleyPermission> findPermissions(Requester requester, ParleyPrincipal holder,
            ProtectedResource resource) throws UserRegistryUnavailableException {
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

    /** Called holding the lock. */
    private boolean isHolder(EntityId id) {
        return principals.containsKey(id) || BuiltInGroups.ANYONE.getId().equals(id)
                || BuiltInGroups.AUTHENTICATED.getId().equals(id);
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
