package com.guardian;

import org.msgpack.core.MessageBufferPacker;
import org.msgpack.core.MessagePack;
import org.msgpack.core.MessageUnpacker;
import org.msgpack.value.Value;
import org.msgpack.value.ValueType;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.SocketAddress;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Java client SDK for the Guardian license daemon.
 *
 * <p>Communicates with the Guardian daemon over a Unix domain socket using a binary
 * protocol with msgpack-encoded payloads. The handshake authenticates the daemon via
 * Ed25519 signature verification and the client via HMAC-SHA256, then derives an
 * AES-256-GCM session key for all subsequent encrypted communication.</p>
 *
 * <h2>Wire Format</h2>
 * <pre>
 * [4 bytes uint32 big-endian total_length] [1 byte message_type] [N bytes msgpack payload]
 * where total_length = 1 + len(payload)
 * </pre>
 *
 * <h2>Usage</h2>
 * <pre>{@code
 * GuardianClient guardian = new GuardianClient.Builder()
 *     .module("my-module")
 *     .socketPath("/var/run/guardian/guardian.sock")
 *     .tokenPath("/etc/guardian/token")
 *     .checkInterval(Duration.ofMinutes(5))
 *     .onValid(details -> {
 *         System.out.println("License valid: " + details.getFeatures());
 *     })
 *     .onInvalid((details, error) -> {
 *         System.err.println("License invalid: " + error.getMessage());
 *         System.exit(1);
 *     })
 *     .build();
 *
 * guardian.start();
 * LicenseDetails details = guardian.forceCheck();
 * guardian.stop();
 * }</pre>
 *
 * @see Builder
 * @see LicenseDetails
 */
public class GuardianClient implements AutoCloseable {

    private static final Logger LOG = Logger.getLogger(GuardianClient.class.getName());

    /** Default Unix socket path for the Guardian daemon. */
    private static final String DEFAULT_SOCKET_PATH = "/var/run/guardian/guardian.sock";

    /** Default token file path. */
    private static final String DEFAULT_TOKEN_PATH = "/etc/guardian/token";

    /** Maximum allowed message size (1 MB), matching the Go daemon. */
    private static final int MAX_MESSAGE_SIZE = 1 << 20;

    /** AES-GCM initialization vector length in bytes. */
    private static final int GCM_IV_LENGTH = 12;

    /** AES-GCM authentication tag length in bits. */
    private static final int GCM_TAG_BITS = 128;

    /** Client nonce size in bytes for the handshake. */
    private static final int CLIENT_NONCE_SIZE = 32;

    /** Session key derivation suffix, matching the Go daemon. */
    private static final byte[] SESSION_KEY_SUFFIX = "guardian-session-v1".getBytes(StandardCharsets.UTF_8);

    // ---- Message type constants ----
    private static final byte MSG_GUARDIAN_HELLO   = 0x01;
    private static final byte MSG_SERVICE_AUTH     = 0x02;
    private static final byte MSG_AUTH_RESULT      = 0x03;
    private static final byte MSG_LICENSE_REQUEST  = 0x04;
    private static final byte MSG_LICENSE_RESPONSE = 0x05;
    private static final byte MSG_HEARTBEAT_PING   = 0x06;
    private static final byte MSG_HEARTBEAT_PONG   = 0x07;

    // ---- Ed25519 DER prefix for X.509 SubjectPublicKeyInfo encoding ----
    /**
     * ASN.1 DER prefix for an Ed25519 public key wrapped in X.509 SubjectPublicKeyInfo.
     * The raw 32-byte Ed25519 key is appended after this prefix.
     */
    private static final byte[] ED25519_X509_PREFIX = new byte[]{
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65,
            0x70, 0x03, 0x21, 0x00
    };

    // ---- Instance fields ----
    private final String module;
    private final String socketPath;
    private final String tokenPath;
    private final Duration checkInterval;
    private final ValidHandler onValid;
    private final InvalidHandler onInvalid;

    private final ReentrantLock lock = new ReentrantLock();
    private final SecureRandom secureRandom = new SecureRandom();

    private volatile boolean running;
    private SocketChannel socketChannel;
    private InputStream inputStream;
    private OutputStream outputStream;
    private byte[] sessionKey;
    private String sessionId;

    private ScheduledExecutorService scheduler;
    private ScheduledFuture<?> periodicTask;

    // Cached token file credentials
    private String serviceId;
    private byte[] token;
    private byte[] daemonPubKeyBytes;

    // -----------------------------------------------------------------------
    // Inner classes and interfaces
    // -----------------------------------------------------------------------

    /**
     * Holds the result of a license check, combining data from both
     * {@code LICENSE_RESPONSE} and the most recent {@code HEARTBEAT_PONG}.
     */
    public static class LicenseDetails {

        private final boolean valid;
        private final String module;
        private final String expiresAt;
        private final List<String> features;
        private final Map<String, Object> metadata;
        private final String hwStatus;
        private final String licenseStatus;
        private final int expiresInDays;

        /**
         * Constructs a new {@code LicenseDetails} instance.
         *
         * @param valid         whether the license is currently valid
         * @param module        the module name this license covers
         * @param expiresAt     ISO-8601 expiration timestamp
         * @param features      list of licensed feature flags
         * @param metadata      map of metadata key-value pairs
         * @param hwStatus      hardware binding status from the last heartbeat
         * @param licenseStatus license status string from the last heartbeat
         * @param expiresInDays number of days until license expiration
         */
        public LicenseDetails(boolean valid, String module, String expiresAt,
                              List<String> features, Map<String, Object> metadata,
                              String hwStatus, String licenseStatus, int expiresInDays) {
            this.valid = valid;
            this.module = module;
            this.expiresAt = expiresAt;
            this.features = features != null ? Collections.unmodifiableList(new ArrayList<>(features)) : Collections.emptyList();
            this.metadata = metadata != null ? Collections.unmodifiableMap(new HashMap<>(metadata)) : Collections.emptyMap();
            this.hwStatus = hwStatus;
            this.licenseStatus = licenseStatus;
            this.expiresInDays = expiresInDays;
        }

        /** Returns {@code true} if the license is valid. */
        public boolean isValid() { return valid; }

        /** Returns the module name this license covers. */
        public String getModule() { return module; }

        /** Returns the ISO-8601 expiration timestamp string. */
        public String getExpiresAt() { return expiresAt; }

        /** Returns an unmodifiable list of licensed feature flags. */
        public List<String> getFeatures() { return features; }

        /** Returns an unmodifiable map of module metadata. */
        public Map<String, Object> getMetadata() { return metadata; }

        /** Returns the hardware binding status from the last heartbeat. */
        public String getHwStatus() { return hwStatus; }

        /** Returns the license status string from the last heartbeat. */
        public String getLicenseStatus() { return licenseStatus; }

        /** Returns the number of days until the license expires. */
        public int getExpiresInDays() { return expiresInDays; }

        @Override
        public String toString() {
            return "LicenseDetails{" +
                    "valid=" + valid +
                    ", module='" + module + '\'' +
                    ", expiresAt='" + expiresAt + '\'' +
                    ", features=" + features +
                    ", metadata=" + metadata +
                    ", hwStatus='" + hwStatus + '\'' +
                    ", licenseStatus='" + licenseStatus + '\'' +
                    ", expiresInDays=" + expiresInDays +
                    '}';
        }
    }

    /**
     * Functional interface invoked when a license check succeeds and the license is valid.
     */
    @FunctionalInterface
    public interface ValidHandler {
        /**
         * Called when the license is confirmed valid.
         *
         * @param details the license details
         */
        void handle(LicenseDetails details);
    }

    /**
     * Functional interface invoked when a license check fails or the license is invalid.
     */
    @FunctionalInterface
    public interface InvalidHandler {
        /**
         * Called when the license is invalid or an error occurs during the check.
         *
         * @param details the license details (may contain partial information)
         * @param error   the exception describing the failure
         */
        void handle(LicenseDetails details, Exception error);
    }

    // -----------------------------------------------------------------------
    // Builder
    // -----------------------------------------------------------------------

    /**
     * Builder for constructing a {@link GuardianClient} instance.
     *
     * <p>At minimum, {@link #module(String)} must be set. Socket and token paths
     * default to standard locations but can be overridden. Environment variables
     * {@code GUARDIAN_SOCKET} and {@code GUARDIAN_TOKEN_PATH} are also consulted.</p>
     */
    public static class Builder {

        private String module;
        private String socketPath;
        private String tokenPath;
        private Duration checkInterval = Duration.ofMinutes(5);
        private ValidHandler onValid;
        private InvalidHandler onInvalid;

        /**
         * Sets the license module name to check. Required.
         *
         * @param module the module identifier
         * @return this builder
         */
        public Builder module(String module) {
            this.module = Objects.requireNonNull(module, "module must not be null");
            return this;
        }

        /**
         * Sets the Unix domain socket path for the Guardian daemon.
         * Defaults to {@code /var/run/guardian/guardian.sock} or the
         * {@code GUARDIAN_SOCKET} environment variable.
         *
         * @param socketPath absolute path to the daemon socket
         * @return this builder
         */
        public Builder socketPath(String socketPath) {
            this.socketPath = Objects.requireNonNull(socketPath, "socketPath must not be null");
            return this;
        }

        /**
         * Sets the path to the Guardian token file.
         * Defaults to {@code /etc/guardian/token} or the
         * {@code GUARDIAN_TOKEN_PATH} environment variable.
         *
         * @param tokenPath absolute path to the token file
         * @return this builder
         */
        public Builder tokenPath(String tokenPath) {
            this.tokenPath = Objects.requireNonNull(tokenPath, "tokenPath must not be null");
            return this;
        }

        /**
         * Sets the interval between periodic license and heartbeat checks.
         * Defaults to 5 minutes.
         *
         * @param interval the check interval
         * @return this builder
         */
        public Builder checkInterval(Duration interval) {
            this.checkInterval = Objects.requireNonNull(interval, "checkInterval must not be null");
            if (interval.isNegative() || interval.isZero()) {
                throw new IllegalArgumentException("checkInterval must be positive");
            }
            return this;
        }

        /**
         * Registers the callback invoked when a license check confirms the license is valid.
         *
         * @param handler the valid-license handler
         * @return this builder
         */
        public Builder onValid(ValidHandler handler) {
            this.onValid = Objects.requireNonNull(handler, "onValid handler must not be null");
            return this;
        }

        /**
         * Registers the callback invoked when a license check fails or the license is invalid.
         *
         * @param handler the invalid-license handler
         * @return this builder
         */
        public Builder onInvalid(InvalidHandler handler) {
            this.onInvalid = Objects.requireNonNull(handler, "onInvalid handler must not be null");
            return this;
        }

        /**
         * Builds and returns a new {@link GuardianClient}.
         *
         * @return the configured client (not yet connected)
         * @throws IllegalStateException if required fields are missing
         */
        public GuardianClient build() {
            if (module == null || module.isEmpty()) {
                throw new IllegalStateException("module is required");
            }

            String resolvedSocket = socketPath;
            if (resolvedSocket == null) {
                String envSocket = System.getenv("GUARDIAN_SOCKET");
                resolvedSocket = (envSocket != null && !envSocket.isEmpty()) ? envSocket : DEFAULT_SOCKET_PATH;
            }

            String resolvedToken = tokenPath;
            if (resolvedToken == null) {
                String envToken = System.getenv("GUARDIAN_TOKEN_PATH");
                resolvedToken = (envToken != null && !envToken.isEmpty()) ? envToken : DEFAULT_TOKEN_PATH;
            }

            return new GuardianClient(module, resolvedSocket, resolvedToken,
                    checkInterval, onValid, onInvalid);
        }
    }

    // -----------------------------------------------------------------------
    // Constructor (private -- use Builder)
    // -----------------------------------------------------------------------

    private GuardianClient(String module, String socketPath, String tokenPath,
                           Duration checkInterval, ValidHandler onValid, InvalidHandler onInvalid) {
        this.module = module;
        this.socketPath = socketPath;
        this.tokenPath = tokenPath;
        this.checkInterval = checkInterval;
        this.onValid = onValid;
        this.onInvalid = onInvalid;
    }

    // -----------------------------------------------------------------------
    // Lifecycle
    // -----------------------------------------------------------------------

    /**
     * Connects to the Guardian daemon, performs the authentication handshake,
     * runs an initial license check (invoking the appropriate callback), and
     * starts periodic heartbeat and license checks.
     *
     * @throws GuardianException if connection, authentication, or the initial check fails
     */
    public void start() throws GuardianException {
        lock.lock();
        try {
            if (running) {
                throw new GuardianException("Client is already running");
            }
            loadTokenFile();
            connect();
            handshake();
            running = true;

            // Initial license check
            performCheck();

            // Schedule periodic checks
            scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "guardian-client-scheduler");
                t.setDaemon(true);
                return t;
            });
            periodicTask = scheduler.scheduleAtFixedRate(
                    this::periodicCheck,
                    checkInterval.toMillis(),
                    checkInterval.toMillis(),
                    TimeUnit.MILLISECONDS
            );
        } catch (GuardianException e) {
            cleanupConnection();
            throw e;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Forces an immediate license check, bypassing the periodic schedule.
     * Also sends a heartbeat ping and merges the pong data into the returned details.
     *
     * @return the current license details
     * @throws GuardianException if the check fails
     */
    public LicenseDetails forceCheck() throws GuardianException {
        lock.lock();
        try {
            if (!running) {
                throw new GuardianException("Client is not running");
            }
            return performCheck();
        } finally {
            lock.unlock();
        }
    }

    /**
     * Stops periodic checking, disconnects from the daemon, and releases all resources.
     */
    public void stop() {
        lock.lock();
        try {
            running = false;
            if (periodicTask != null) {
                periodicTask.cancel(false);
                periodicTask = null;
            }
            if (scheduler != null) {
                scheduler.shutdownNow();
                scheduler = null;
            }
            cleanupConnection();
        } finally {
            lock.unlock();
        }
    }

    /**
     * Alias for {@link #stop()}, satisfying {@link AutoCloseable}.
     */
    @Override
    public void close() {
        stop();
    }

    // -----------------------------------------------------------------------
    // Token file parsing
    // -----------------------------------------------------------------------

    /**
     * Parses the Guardian token file to extract service credentials.
     * <p>
     * Token file format:
     * <pre>
     * SERVICE_ID=service_A
     * TOKEN=tok_&lt;hex_encoded_token&gt;
     * DAEMON_PUB=dpub_&lt;hex_encoded_ed25519_public_key&gt;
     * </pre>
     */
    private void loadTokenFile() throws GuardianException {
        Path path = Path.of(tokenPath);
        if (!Files.exists(path)) {
            throw new GuardianException("Token file not found: " + tokenPath);
        }

        try (BufferedReader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            String line;
            String parsedServiceId = null;
            byte[] parsedToken = null;
            byte[] parsedDaemonPub = null;

            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                int eq = line.indexOf('=');
                if (eq < 0) {
                    continue;
                }
                String key = line.substring(0, eq).trim();
                String value = line.substring(eq + 1).trim();

                switch (key) {
                    case "SERVICE_ID":
                        parsedServiceId = value;
                        break;
                    case "TOKEN":
                        String tokenHex = value.startsWith("tok_") ? value.substring(4) : value;
                        parsedToken = hexDecode(tokenHex);
                        break;
                    case "DAEMON_PUB":
                        String pubHex = value.startsWith("dpub_") ? value.substring(5) : value;
                        parsedDaemonPub = hexDecode(pubHex);
                        break;
                }
            }

            if (parsedServiceId == null || parsedServiceId.isEmpty()) {
                throw new GuardianException("Missing SERVICE_ID in token file");
            }
            if (parsedToken == null) {
                throw new GuardianException("Missing TOKEN in token file");
            }
            if (parsedDaemonPub == null) {
                throw new GuardianException("Missing DAEMON_PUB in token file");
            }

            this.serviceId = parsedServiceId;
            this.token = parsedToken;
            this.daemonPubKeyBytes = parsedDaemonPub;

        } catch (IOException e) {
            throw new GuardianException("Failed to read token file: " + tokenPath, e);
        }
    }

    // -----------------------------------------------------------------------
    // Connection management
    // -----------------------------------------------------------------------

    /**
     * Opens a Unix domain socket connection to the Guardian daemon.
     */
    private void connect() throws GuardianException {
        try {
            SocketAddress addr = UnixDomainSocketAddress.of(socketPath);
            socketChannel = SocketChannel.open(addr);
            socketChannel.configureBlocking(true);
            inputStream = Channels.newInputStream(socketChannel);
            outputStream = Channels.newOutputStream(socketChannel);
        } catch (IOException e) {
            throw new GuardianException("Failed to connect to Guardian daemon at " + socketPath, e);
        }
    }

    /**
     * Closes the socket and clears connection-related state.
     */
    private void cleanupConnection() {
        sessionKey = null;
        sessionId = null;
        closeQuietly(inputStream);
        closeQuietly(outputStream);
        if (socketChannel != null) {
            try {
                socketChannel.close();
            } catch (IOException ignored) {
                // best effort
            }
        }
        inputStream = null;
        outputStream = null;
        socketChannel = null;
    }

    /**
     * Reconnects to the daemon, performing a fresh handshake.
     */
    private void reconnect() throws GuardianException {
        cleanupConnection();
        connect();
        handshake();
    }

    // -----------------------------------------------------------------------
    // Handshake protocol
    // -----------------------------------------------------------------------

    /**
     * Performs the full authentication handshake with the Guardian daemon.
     *
     * <ol>
     *   <li>Read {@code GUARDIAN_HELLO} and verify the daemon's Ed25519 signature</li>
     *   <li>Generate a 32-byte client nonce</li>
     *   <li>Compute {@code HMAC-SHA256(guardian_nonce || client_nonce, token)}</li>
     *   <li>Send {@code SERVICE_AUTH} with service_id, client_nonce, and hmac</li>
     *   <li>Read {@code AUTH_RESULT} and verify status is "ok"</li>
     *   <li>Derive session key: {@code HMAC-SHA256(guardian_nonce || client_nonce, token || "guardian-session-v1")}</li>
     * </ol>
     */
    private void handshake() throws GuardianException {
        try {
            // Step 1: Read GUARDIAN_HELLO
            RawMessage hello = readMessage();
            if (hello.type != MSG_GUARDIAN_HELLO) {
                throw new GuardianException(
                        "Expected GUARDIAN_HELLO (0x01), got 0x" + String.format("%02x", hello.type));
            }

            Map<String, Object> helloFields = unpackMap(hello.payload);
            byte[] guardianNonce = toByteArray(helloFields.get("guardian_nonce"));
            byte[] signature = toByteArray(helloFields.get("signature"));

            if (guardianNonce == null || signature == null) {
                throw new GuardianException("Malformed GUARDIAN_HELLO: missing nonce or signature");
            }

            // Step 2: Verify daemon signature
            verifyEd25519(daemonPubKeyBytes, guardianNonce, signature);

            // Step 3: Generate client nonce and compute HMAC
            byte[] clientNonce = new byte[CLIENT_NONCE_SIZE];
            secureRandom.nextBytes(clientNonce);

            byte[] nonceConcat = concat(guardianNonce, clientNonce);
            byte[] hmac = hmacSha256(nonceConcat, token);

            // Step 4: Send SERVICE_AUTH
            byte[] authPayload = packServiceAuth(serviceId, clientNonce, hmac);
            writeMessage(MSG_SERVICE_AUTH, authPayload);

            // Step 5: Read AUTH_RESULT
            RawMessage result = readMessage();
            if (result.type != MSG_AUTH_RESULT) {
                throw new GuardianException(
                        "Expected AUTH_RESULT (0x03), got 0x" + String.format("%02x", result.type));
            }

            Map<String, Object> resultFields = unpackMap(result.payload);
            String status = (String) resultFields.get("status");
            String error = (String) resultFields.get("error");

            if (!"ok".equals(status)) {
                throw new GuardianException("Authentication failed: " +
                        (error != null ? error : "status=" + status));
            }
            this.sessionId = (String) resultFields.get("session_id");

            // Step 6: Derive session key
            byte[] keyMaterial = concat(token, SESSION_KEY_SUFFIX);
            this.sessionKey = hmacSha256(nonceConcat, keyMaterial);

            LOG.fine("Handshake completed successfully, session_id=" + sessionId);

        } catch (GuardianException e) {
            throw e;
        } catch (Exception e) {
            throw new GuardianException("Handshake failed", e);
        }
    }

    // -----------------------------------------------------------------------
    // License checking
    // -----------------------------------------------------------------------

    /**
     * Performs a license check followed by a heartbeat exchange. Invokes the
     * appropriate callback and returns the combined {@link LicenseDetails}.
     */
    private LicenseDetails performCheck() throws GuardianException {
        try {
            // Send LICENSE_REQUEST (encrypted)
            byte[] reqPayload = packLicenseRequest(module);
            writeEncryptedMessage(MSG_LICENSE_REQUEST, reqPayload);

            // Read LICENSE_RESPONSE (encrypted)
            RawMessage resp = readEncryptedMessage();
            if (resp.type != MSG_LICENSE_RESPONSE) {
                throw new GuardianException(
                        "Expected LICENSE_RESPONSE (0x05), got 0x" + String.format("%02x", resp.type));
            }

            Map<String, Object> licFields = unpackMap(resp.payload);
            boolean valid = Boolean.TRUE.equals(licFields.get("valid"));
            String respModule = (String) licFields.get("module");
            String expiresAt = (String) licFields.get("expires_at");
            List<String> features = toStringList(licFields.get("features"));
            Map<String, Object> metadata = toObjectMap(licFields.get("metadata"));
            String licError = (String) licFields.get("error");

            // Send HEARTBEAT_PING (encrypted)
            byte[] pingPayload = packHeartbeatPing(System.currentTimeMillis());
            writeEncryptedMessage(MSG_HEARTBEAT_PING, pingPayload);

            // Read HEARTBEAT_PONG (encrypted)
            RawMessage pong = readEncryptedMessage();
            String hwStatus = null;
            String licenseStatus = null;
            int expiresInDays = -1;

            if (pong.type == MSG_HEARTBEAT_PONG) {
                Map<String, Object> pongFields = unpackMap(pong.payload);
                hwStatus = (String) pongFields.get("hw_status");
                licenseStatus = (String) pongFields.get("license_status");
                Object expDays = pongFields.get("expires_in_days");
                if (expDays instanceof Number) {
                    expiresInDays = ((Number) expDays).intValue();
                }
            } else {
                LOG.warning("Expected HEARTBEAT_PONG (0x07), got 0x" + String.format("%02x", pong.type));
            }

            LicenseDetails details = new LicenseDetails(
                    valid, respModule, expiresAt, features, metadata,
                    hwStatus, licenseStatus, expiresInDays);

            // Invoke callbacks
            if (valid && licError == null) {
                if (onValid != null) {
                    onValid.handle(details);
                }
            } else {
                if (onInvalid != null) {
                    Exception cause = licError != null
                            ? new GuardianException("License error: " + licError)
                            : new GuardianException("License is not valid");
                    onInvalid.handle(details, cause);
                }
            }

            return details;

        } catch (GuardianException e) {
            throw e;
        } catch (Exception e) {
            throw new GuardianException("License check failed", e);
        }
    }

    /**
     * Periodic check task executed by the scheduler. Handles auto-reconnect
     * on connection failures.
     */
    private void periodicCheck() {
        lock.lock();
        try {
            if (!running) {
                return;
            }
            try {
                performCheck();
            } catch (GuardianException e) {
                LOG.log(Level.WARNING, "Periodic check failed, attempting reconnect", e);
                try {
                    reconnect();
                    performCheck();
                } catch (GuardianException reconnectEx) {
                    LOG.log(Level.SEVERE, "Reconnect and re-check failed", reconnectEx);
                    if (onInvalid != null) {
                        LicenseDetails errorDetails = new LicenseDetails(
                                false, module, null, null, null,
                                null, null, -1);
                        onInvalid.handle(errorDetails, reconnectEx);
                    }
                }
            }
        } finally {
            lock.unlock();
        }
    }

    // -----------------------------------------------------------------------
    // Wire protocol I/O
    // -----------------------------------------------------------------------

    /**
     * Holder for a raw wire-protocol message (type byte + msgpack payload).
     */
    private static class RawMessage {
        final byte type;
        final byte[] payload;

        RawMessage(byte type, byte[] payload) {
            this.type = type;
            this.payload = payload;
        }
    }

    /**
     * Reads a single framed message from the socket.
     * Wire format: {@code [4 bytes uint32 BE total_length][1 byte type][N bytes payload]}
     */
    private RawMessage readMessage() throws IOException {
        byte[] lenBuf = readExact(4);
        int totalLen = ByteBuffer.wrap(lenBuf).getInt();

        if (totalLen < 1) {
            throw new IOException("Message too short: " + totalLen + " bytes");
        }
        if (totalLen > MAX_MESSAGE_SIZE) {
            throw new IOException("Message too large: " + totalLen + " bytes (max " + MAX_MESSAGE_SIZE + ")");
        }

        byte[] typeBuf = readExact(1);
        byte msgType = typeBuf[0];

        int payloadLen = totalLen - 1;
        byte[] payload = payloadLen > 0 ? readExact(payloadLen) : new byte[0];

        return new RawMessage(msgType, payload);
    }

    /**
     * Writes a single framed message to the socket.
     *
     * @param msgType the message type byte
     * @param payload the msgpack-encoded payload bytes
     */
    private void writeMessage(byte msgType, byte[] payload) throws IOException {
        int totalLen = 1 + payload.length;
        if (totalLen > MAX_MESSAGE_SIZE) {
            throw new IOException("Message too large: " + totalLen + " bytes (max " + MAX_MESSAGE_SIZE + ")");
        }

        ByteBuffer header = ByteBuffer.allocate(5);
        header.putInt(totalLen);
        header.put(msgType);
        header.flip();

        outputStream.write(header.array());
        outputStream.write(payload);
        outputStream.flush();
    }

    /**
     * Writes an encrypted message. The msgpack payload is encrypted with AES-256-GCM
     * using the session key. The message type byte is written in the clear as part of
     * the wire frame header, matching the Go daemon's protocol.
     *
     * <p>Wire format: {@code [4-byte len][1-byte msgType][IV (12 bytes) || AES-GCM ciphertext]}</p>
     *
     * @param msgType the message type byte
     * @param payload the msgpack-encoded payload to encrypt
     */
    private void writeEncryptedMessage(byte msgType, byte[] payload) throws IOException, GuardianException {
        try {
            byte[] encrypted = aesGcmEncrypt(sessionKey, payload);
            writeMessage(msgType, encrypted);
        } catch (GeneralSecurityException e) {
            throw new GuardianException("Failed to encrypt message", e);
        }
    }

    /**
     * Reads and decrypts an encrypted message from the daemon.
     *
     * @return the decrypted raw message (type from wire header, decrypted msgpack payload)
     */
    private RawMessage readEncryptedMessage() throws IOException, GuardianException {
        RawMessage raw = readMessage();
        try {
            byte[] decrypted = aesGcmDecrypt(sessionKey, raw.payload);
            return new RawMessage(raw.type, decrypted);
        } catch (GeneralSecurityException e) {
            throw new GuardianException("Failed to decrypt message", e);
        }
    }

    /**
     * Reads exactly {@code n} bytes from the input stream, blocking as needed.
     *
     * @param n the number of bytes to read
     * @return a byte array of length {@code n}
     * @throws IOException if the stream ends before {@code n} bytes are read
     */
    private byte[] readExact(int n) throws IOException {
        byte[] buf = new byte[n];
        int offset = 0;
        while (offset < n) {
            int read = inputStream.read(buf, offset, n - offset);
            if (read < 0) {
                throw new IOException("Unexpected end of stream (read " + offset + " of " + n + " bytes)");
            }
            offset += read;
        }
        return buf;
    }

    // -----------------------------------------------------------------------
    // Msgpack serialization helpers
    // -----------------------------------------------------------------------

    /**
     * Packs a SERVICE_AUTH message payload into msgpack bytes.
     */
    private static byte[] packServiceAuth(String serviceId, byte[] clientNonce, byte[] hmac) throws IOException {
        try (MessageBufferPacker packer = MessagePack.newDefaultBufferPacker()) {
            packer.packMapHeader(3);
            packer.packString("service_id");
            packer.packString(serviceId);
            packer.packString("client_nonce");
            packer.packBinaryHeader(clientNonce.length);
            packer.writePayload(clientNonce);
            packer.packString("hmac");
            packer.packBinaryHeader(hmac.length);
            packer.writePayload(hmac);
            return packer.toByteArray();
        }
    }

    /**
     * Packs a LICENSE_REQUEST message payload into msgpack bytes.
     */
    private static byte[] packLicenseRequest(String module) throws IOException {
        try (MessageBufferPacker packer = MessagePack.newDefaultBufferPacker()) {
            packer.packMapHeader(1);
            packer.packString("module");
            packer.packString(module);
            return packer.toByteArray();
        }
    }

    /**
     * Packs a HEARTBEAT_PING message payload into msgpack bytes.
     */
    private static byte[] packHeartbeatPing(long timestamp) throws IOException {
        try (MessageBufferPacker packer = MessagePack.newDefaultBufferPacker()) {
            packer.packMapHeader(1);
            packer.packString("timestamp");
            packer.packLong(timestamp);
            return packer.toByteArray();
        }
    }

    /**
     * Unpacks a msgpack byte array into a {@code Map<String, Object>}.
     * Supports string, binary, boolean, integer, float, array, and map value types.
     */
    private static Map<String, Object> unpackMap(byte[] data) throws IOException {
        try (MessageUnpacker unpacker = MessagePack.newDefaultUnpacker(data)) {
            int size = unpacker.unpackMapHeader();
            Map<String, Object> map = new HashMap<>(size);
            for (int i = 0; i < size; i++) {
                String key = unpacker.unpackString();
                Value val = unpacker.unpackValue();
                map.put(key, valueToObject(val));
            }
            return map;
        }
    }

    /**
     * Converts a msgpack {@link Value} to a Java object.
     */
    private static Object valueToObject(Value val) {
        if (val == null || val.isNilValue()) {
            return null;
        }
        ValueType vt = val.getValueType();
        switch (vt) {
            case STRING:
                return val.asStringValue().asString();
            case BINARY:
                return val.asBinaryValue().asByteArray();
            case BOOLEAN:
                return val.asBooleanValue().getBoolean();
            case INTEGER:
                return val.asIntegerValue().toLong();
            case FLOAT:
                return val.asFloatValue().toDouble();
            case ARRAY: {
                List<Object> list = new ArrayList<>();
                for (Value item : val.asArrayValue()) {
                    list.add(valueToObject(item));
                }
                return list;
            }
            case MAP: {
                Map<String, Object> inner = new HashMap<>();
                for (Map.Entry<Value, Value> entry : val.asMapValue().entrySet()) {
                    String k = entry.getKey().isStringValue()
                            ? entry.getKey().asStringValue().asString()
                            : entry.getKey().toString();
                    inner.put(k, valueToObject(entry.getValue()));
                }
                return inner;
            }
            default:
                return val.toString();
        }
    }

    // -----------------------------------------------------------------------
    // Cryptographic operations
    // -----------------------------------------------------------------------

    /**
     * Verifies an Ed25519 signature over a message using the daemon's public key.
     *
     * @param publicKeyBytes raw 32-byte Ed25519 public key
     * @param message        the signed message
     * @param signatureBytes the Ed25519 signature to verify
     * @throws GuardianException if verification fails
     */
    private static void verifyEd25519(byte[] publicKeyBytes, byte[] message, byte[] signatureBytes)
            throws GuardianException {
        try {
            // Wrap the raw 32-byte Ed25519 key in X.509 SubjectPublicKeyInfo DER encoding
            byte[] x509Key = new byte[ED25519_X509_PREFIX.length + publicKeyBytes.length];
            System.arraycopy(ED25519_X509_PREFIX, 0, x509Key, 0, ED25519_X509_PREFIX.length);
            System.arraycopy(publicKeyBytes, 0, x509Key, ED25519_X509_PREFIX.length, publicKeyBytes.length);

            KeyFactory kf = KeyFactory.getInstance("Ed25519");
            PublicKey pubKey = kf.generatePublic(new X509EncodedKeySpec(x509Key));

            Signature sig = Signature.getInstance("Ed25519");
            sig.initVerify(pubKey);
            sig.update(message);

            if (!sig.verify(signatureBytes)) {
                throw new GuardianException(
                        "Invalid Guardian daemon signature -- possible impersonation");
            }
        } catch (GuardianException e) {
            throw e;
        } catch (GeneralSecurityException e) {
            throw new GuardianException("Ed25519 verification error", e);
        }
    }

    /**
     * Computes HMAC-SHA256.
     *
     * @param message the message bytes
     * @param key     the HMAC key
     * @return the 32-byte HMAC digest
     */
    private static byte[] hmacSha256(byte[] message, byte[] key) throws GuardianException {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(message);
        } catch (GeneralSecurityException e) {
            throw new GuardianException("HMAC-SHA256 computation failed", e);
        }
    }

    /**
     * Encrypts plaintext with AES-256-GCM using a random 12-byte IV.
     * Returns {@code IV || ciphertext+tag}.
     *
     * @param key       the 32-byte AES key
     * @param plaintext the data to encrypt
     * @return the IV prepended to the GCM ciphertext (including auth tag)
     */
    private byte[] aesGcmEncrypt(byte[] key, byte[] plaintext) throws GeneralSecurityException {
        byte[] iv = new byte[GCM_IV_LENGTH];
        secureRandom.nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE,
                new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(GCM_TAG_BITS, iv));
        byte[] ciphertext = cipher.doFinal(plaintext);

        // Prepend IV to ciphertext
        byte[] result = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(ciphertext, 0, result, iv.length, ciphertext.length);
        return result;
    }

    /**
     * Decrypts an AES-256-GCM blob where the first 12 bytes are the IV.
     *
     * @param key        the 32-byte AES key
     * @param ivAndCipher the IV (12 bytes) followed by GCM ciphertext+tag
     * @return the decrypted plaintext
     */
    private static byte[] aesGcmDecrypt(byte[] key, byte[] ivAndCipher) throws GeneralSecurityException {
        if (ivAndCipher.length < GCM_IV_LENGTH) {
            throw new GeneralSecurityException("Ciphertext too short for AES-GCM IV");
        }

        byte[] iv = new byte[GCM_IV_LENGTH];
        System.arraycopy(ivAndCipher, 0, iv, 0, GCM_IV_LENGTH);

        byte[] ciphertext = new byte[ivAndCipher.length - GCM_IV_LENGTH];
        System.arraycopy(ivAndCipher, GCM_IV_LENGTH, ciphertext, 0, ciphertext.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE,
                new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(GCM_TAG_BITS, iv));
        return cipher.doFinal(ciphertext);
    }

    // -----------------------------------------------------------------------
    // Utility methods
    // -----------------------------------------------------------------------

    /**
     * Decodes a hex-encoded string to a byte array.
     *
     * @param hex the hex string (must have even length)
     * @return the decoded bytes
     * @throws GuardianException if the hex string is malformed
     */
    private static byte[] hexDecode(String hex) throws GuardianException {
        if (hex.length() % 2 != 0) {
            throw new GuardianException("Invalid hex string (odd length): " + hex);
        }
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            int hi = Character.digit(hex.charAt(i * 2), 16);
            int lo = Character.digit(hex.charAt(i * 2 + 1), 16);
            if (hi < 0 || lo < 0) {
                throw new GuardianException("Invalid hex character at position " + (i * 2));
            }
            bytes[i] = (byte) ((hi << 4) | lo);
        }
        return bytes;
    }

    /**
     * Concatenates two byte arrays.
     */
    private static byte[] concat(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    /**
     * Converts a msgpack value to a byte array. Handles both binary values (byte[])
     * and raw Value objects.
     */
    private static byte[] toByteArray(Object obj) {
        if (obj instanceof byte[]) {
            return (byte[]) obj;
        }
        return null;
    }

    /**
     * Converts a msgpack value to a {@code List<String>}.
     */
    @SuppressWarnings("unchecked")
    private static List<String> toStringList(Object obj) {
        if (obj instanceof List) {
            List<?> raw = (List<?>) obj;
            List<String> result = new ArrayList<>(raw.size());
            for (Object item : raw) {
                result.add(item != null ? item.toString() : null);
            }
            return result;
        }
        return Collections.emptyList();
    }

    /**
     * Converts a msgpack value to a {@code Map<String, Object>}.
     */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> toObjectMap(Object obj) {
        if (obj instanceof Map) {
            return (Map<String, Object>) obj;
        }
        return Collections.emptyMap();
    }

    /**
     * Closes a {@link Closeable} without throwing.
     */
    private static void closeQuietly(Closeable closeable) {
        if (closeable != null) {
            try {
                closeable.close();
            } catch (IOException ignored) {
                // best effort
            }
        }
    }

    // -----------------------------------------------------------------------
    // Exception type
    // -----------------------------------------------------------------------

    /**
     * Exception type for all Guardian client errors, including protocol violations,
     * authentication failures, and connection problems.
     */
    public static class GuardianException extends Exception {

        /**
         * Constructs a {@code GuardianException} with a message.
         *
         * @param message the error message
         */
        public GuardianException(String message) {
            super(message);
        }

        /**
         * Constructs a {@code GuardianException} with a message and cause.
         *
         * @param message the error message
         * @param cause   the underlying cause
         */
        public GuardianException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
