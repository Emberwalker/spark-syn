package io.drakon.spark.syn;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import javax.annotation.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import spark.*;

/**
 * Syn - Guarding the halls (of a Spark app)
 */
@SuppressWarnings("WeakerAccess")
@ParametersAreNonnullByDefault
public class Syn {

    private static final Logger log = LoggerFactory.getLogger(Syn.class);
    private static final String SEPERATOR = ":/:";
    private static final String COOKIE_NAME = "syn-session";

    public static final int DEFAULT_ITERATIONS = 30000;
    public static final int DEFAULT_KEY_LEN = 256;
    public static final Duration DEFAULT_SESSION_LIFETIME = Duration.ofHours(6);

    private final String path;
    private final Route render;
    private final Route onAuthSuccess;
    private AuthProvider authProvider;
    private Duration sessionLifetime;
    private final boolean secure;
    private final int iterations;
    private final int keyLength;

    private final Map<String, UserAndTimeout> sessions = new HashMap<>();
    private final SecureRandom random = new SecureRandom();

    /**
     * Simple constructor.
     *
     * @param path The Spark path to mount the login routes on to e.g. /login
     * @param authProvider An auth provider to get/create user data.
     * @param secure Should the session cookie be marked Secure (HTTPS-only)?
     * @param render A standard Spark Route. Called to render the login page, as well as if auth fails. See README!
     * @param onAuthSuccess A standard Spark Route, which is called when authentication succeeds.
     */
    @SuppressWarnings("unused")
    public Syn(String path, AuthProvider authProvider, boolean secure, Route render, Route onAuthSuccess) {
        this.path = path;
        this.authProvider = authProvider;
        this.secure = secure;
        this.sessionLifetime = DEFAULT_SESSION_LIFETIME;
        this.iterations = DEFAULT_ITERATIONS;
        this.keyLength = DEFAULT_KEY_LEN;
        this.render = render;
        this.onAuthSuccess = onAuthSuccess;
    }

    /**
     * Advanced constructor - all the options! Defaults are available as static constants on this class.
     *
     * @param path The Spark path to mount the login routes on to e.g. /login
     * @param authProvider An auth provider to get/create user data.
     * @param sessionLifetime How long a user session should persist before being invalidated.
     * @param iterations How many PBKDF2 iterations should be performed.
     * @param keyLength PBKDF2 key length.
     * @param secure Should the session cookie be marked Secure (HTTPS-only)?
     * @param render A standard Spark Route. Called to render the login page, as well as if auth fails. See README!
     * @param onAuthSuccess A standard Spark Route, which is called when authentication succeeds.
     */
    @SuppressWarnings("unused")
    public Syn(String path, AuthProvider authProvider, Duration sessionLifetime, int iterations, int keyLength,
               boolean secure, Route render, Route onAuthSuccess) {
        if (sessionLifetime.getSeconds() >= Integer.MAX_VALUE)
            throw new IllegalArgumentException("Session lifetime in seconds is larger than MAX_INT!");
        this.path = path;
        this.authProvider = authProvider;
        this.sessionLifetime = sessionLifetime;
        this.secure = secure;
        this.iterations = iterations;
        this.keyLength = keyLength;
        this.render = render;
        this.onAuthSuccess = onAuthSuccess;
    }

    /**
     * Registers Syn with Spark. After this is called, Syn will apply a Before filter on all requests and setup login
     * routes.
     */
    @SuppressWarnings("unused")
    public void route() {
        Spark.before((req, res) -> {
            String cookie = req.cookie(COOKIE_NAME);
            if (cookie != null) {
                UserAndTimeout usr = sessions.get(cookie);
                if (usr != null) {
                    if (LocalDateTime.now().isAfter(usr.expires)) {
                        res.removeCookie(COOKIE_NAME);
                        sessions.remove(cookie);
                    } else {
                        req.attribute("user", usr.user);
                        return;
                    }
                } else res.removeCookie(COOKIE_NAME);
            }

            if (req.pathInfo().equals(path)) return;

            res.redirect(path, Redirect.Status.FOUND.intValue());
        });

        Spark.get(path, (req, res) -> {
            if (req.attribute("user") != null) return onAuthSuccess.handle(req, res); // Already auth'd
            return render.handle(req, res);
        });

        Spark.post(path, (req, res) -> {
            if (req.attribute("user") != null) return onAuthSuccess.handle(req, res); // Already auth'd

            String user = req.queryParams("syn-user");
            String password = req.queryParams("syn-password");
            if (user == null || user.equals("") || password == null || password.equals("")) {
                return failRoute(ErrorState.MISSING_FIELD, req, res);
            }

            String rawFromAuth = authProvider.getUser(user);
            if (rawFromAuth == null) return failRoute(ErrorState.NO_SUCH_USER, req, res);

            SaltAndHash userFile = new SaltAndHash(this, rawFromAuth);
            if (!userFile.checkIsEqual(password)) return failRoute(ErrorState.INVALID_CREDENTIALS, req, res);

            // User definitely legit.
            String sessKey = genRandomSessionKey();
            res.cookie(COOKIE_NAME, sessKey, (int)sessionLifetime.getSeconds(), secure, true);
            sessions.put(sessKey, new UserAndTimeout(user, LocalDateTime.now().plus(sessionLifetime)));
            req.attribute("user", user);

            return onAuthSuccess.handle(req, res);
        });
    }

    /**
     * Logs out the given user during a request. Cleans up Spark state and removes the users cookie.
     *
     * When Request/Response objects are unavilable, see {@see destroySession}.
     *
     * @param user User to logout.
     * @param req Spark Request object.
     * @param res Spark Response object.
     * @return True if a session was removed, else false.
     */
    public boolean logoutUser(String user, Request req, Response res) {
        res.removeCookie(COOKIE_NAME);
        req.attribute("user", null);
        return destroySession(user);
    }

    /**
     * Destroys any active sessions for the given user. You should prefer {@see logoutUser} where Request/Response
     * objects are available, as that method properly clears Spark state and the users cookie.
     *
     * @param user User to logout.
     * @return True if a session was removed, else false.
     */
    public boolean destroySession(String user) {
        return sessions.remove(user) != null;
    }

    /**
     * Creates a new user, and writes the new users hash/salt to the auth provider. Includes user-specified metadata
     * for the auth provider.
     *
     * @param username New users name/ID.
     * @param password New users password (unhashed).
     * @param metadata Custom metadata which is passed unchanged to the auth provider.
     */
    @SuppressWarnings("unused")
    public void createUser(String username, String password, @Nullable Object metadata) {
        SaltAndHash hashSalt = new SaltAndHash(this, password, genRandomSalt());
        authProvider.writeUser(username, hashSalt.toDBFormat(), metadata);
    }

    /**
     * Creates a new user, and writes the new users hash/salt to the auth provider.
     *
     * @param username New users name/ID.
     * @param password New users password (unhashed).
     */
    @SuppressWarnings("unused")
    public void createUser(String username, String password) {
        createUser(username, password, null);
    }

    /**
     * Change the authentication backend. THIS WILL CLEAR ALL CURRENT SESSIONS!
     *
     * @param authProvider The new auth provider.
     */
    @SuppressWarnings("unused")
    public void setAuthProvider(AuthProvider authProvider) {
        sessions.clear();
        this.authProvider = authProvider;
    }

    String genRandomSessionKey() {
        return genRandomString(128);
    }

    String genRandomSalt() {
        return genRandomString(64);
    }

    /** Generates a new random string. Based on https://stackoverflow.com/a/41156 */
    String genRandomString(int bytes) {
        byte[] arr = new byte[bytes];
        random.nextBytes(arr);
        return toHex(arr);
    }

    /**
     * Converts a byte array to hex form. From
     * https://howtodoinjava.com/security/how-to-generate-secure-password-hash-md5-sha-pbkdf2-bcrypt-examples/
     */
    static String toHex(byte[] array) {
        BigInteger bi = new BigInteger(1, array);
        String hex = bi.toString(16);
        int paddingLength = (array.length * 2) - hex.length();
        if (paddingLength > 0) {
            return String.format("%0" + paddingLength + "d", 0) + hex;
        } else {
            return hex;
        }
    }

    private static byte[] fromHex(String hex) {
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        return bytes;
    }

    /**
     * Sets attributes and an appropriate status before invoking the user-provided render bifunction.
     *
     * @param error Error type.
     * @param req Spark Request object.
     * @param res Spark Response object.
     * @return An object to return from the route.
     */
    private Object failRoute(ErrorState error, Request req, Response res) throws Exception {
        req.attribute("syn-error", error);
        res.status(401);// 401 Unauthorized
        return render.handle(req, res);
    }

    /**
     * Interface for providers, which can be queried by Syn for hash/salt entries for users.
     */
    @ParametersAreNonnullByDefault
    public interface AuthProvider {

        /**
         * Returns a hash/salt entry for a given user.
         *
         * @param user The user to find.
         * @return The hash/salt field, or null if the user doesn't exist.
         */
        String getUser(String user);

        /**
         * Write a user entry back to the data store. May be a NOOP if the store is read-only.
         *
         * @param user The user name/ID.
         * @param hashSaltField The hash/salt field value.
         * @param metadata User-provided metadata.
         */
        default void writeUser(String user, String hashSaltField, @Nullable Object metadata) {}

    }

    /**
     * Errors Syn can attach to a Request object on error, when calling the user-provided render bifunction.
     */
    public enum ErrorState {
        MISSING_FIELD,
        INVALID_CREDENTIALS,
        NO_SUCH_USER
    }

    /**
     * Container type for a hash + salt combination. Provides operations related to those values.
     */
    @ParametersAreNonnullByDefault
    private static class SaltAndHash {
        final Syn host;
        final String hash;
        final String salt;

        /**
         * Loads details from a provided auth hash/salt string.
         *
         * @param host The hosting Syn instance.
         * @param fromAuth The auth hash/salt string.
         */
        public SaltAndHash(Syn host, String fromAuth) {
            this.host = host;
            String[] parts = fromAuth.split(SEPERATOR);
            if (parts.length != 2) throw new IllegalArgumentException("Invalid format from auth source.");
            salt = parts[0].toLowerCase();
            hash = parts[1].toLowerCase();
        }

        /**
         * Hashes an unhashed password and stores the result along with the salt.
         *
         * @param host The hosting Syn instance.
         * @param unhashedPassword The unhashed password.
         * @param salt The salt. So salty.
         */
        public SaltAndHash(Syn host, String unhashedPassword, String salt) {
            this.host = host;
            this.hash = getHashedVersion(host, unhashedPassword, salt);
            this.salt = salt;
        }

        /**
         * Returns the hash/salt in a format suitable for sending back to an auth provider for storage.
         */
        public String toDBFormat() {
            return salt + SEPERATOR + hash;
        }

        /**
         * Check if provided password matches the one represented by this instance.
         *
         * @param password The unhashed password to check against.
         * @return True if correct, false otherwise.
         */
        public boolean checkIsEqual(String password) {
            String hashed = getHashedVersion(host, password, salt);
            return hashed.equals(hash);
        }

        /** Internal helper to hash a password with a salt. */
        private static String getHashedVersion(Syn host, String password, String salt) {
            return toHex(
                    hashPassword(password.toCharArray(), fromHex(salt), host.iterations, host.keyLength))
                    .toLowerCase();
        }

        /**
         * Hashes a password in accordance with OWASP recommendations. Code/docs from
         * https://www.owasp.org/index.php/Hashing_Java
         *
         * @param password Plaintext password.
         * @param salt Salt bytes (at least 32).
         * @param iterations Iterations of PBKDF2 (30,000 is a safe lower bound).
         * @param keyLength Key length (> 256 recommended)
         * @return Hashed bytes.
         */
        private static byte[] hashPassword(final char[] password, final byte[] salt, final int iterations,
                                           final int keyLength) {
            try {
                SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
                PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyLength);
                SecretKey key = skf.generateSecret(spec);
                return key.getEncoded();
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new RuntimeException(e);
            }
        }

    }

    @ParametersAreNonnullByDefault
    private static class UserAndTimeout {
        public final String user;
        public final LocalDateTime expires;

        public UserAndTimeout(String user, LocalDateTime expires) {
            this.user = user;
            this.expires = expires;
        }
    }

    public static void main(String[] argv) {
        if (argv.length == 0) {
            System.out.println("Provide a password as a parameter.");
            return;
        }

        StringBuilder buf = new StringBuilder();
        for (String s : argv) {
            buf.append(s);
        }
        String pass = buf.toString();

        Syn syn = new Syn("/", user -> null, false, (a, b) -> null, (a, b) -> null);
        String salt = syn.genRandomSalt();
        SaltAndHash saltAndHash = new SaltAndHash(syn, pass, salt);
        System.out.println(saltAndHash.toDBFormat());
    }

}
