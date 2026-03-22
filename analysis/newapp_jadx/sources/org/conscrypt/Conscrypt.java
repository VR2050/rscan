package org.conscrypt;

import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.Provider;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes3.dex */
public final class Conscrypt {
    private static final Version VERSION;

    public static class ProviderBuilder {
        private String defaultTlsProtocol;
        private String name;
        private boolean provideTrustManager;

        public Provider build() {
            return new OpenSSLProvider(this.name, this.provideTrustManager, this.defaultTlsProtocol);
        }

        public ProviderBuilder defaultTlsProtocol(String str) {
            this.defaultTlsProtocol = str;
            return this;
        }

        @Deprecated
        public ProviderBuilder provideTrustManager() {
            return provideTrustManager(true);
        }

        public ProviderBuilder setName(String str) {
            this.name = str;
            return this;
        }

        private ProviderBuilder() {
            this.name = Platform.getDefaultProviderName();
            this.provideTrustManager = Platform.provideTrustManagerByDefault();
            this.defaultTlsProtocol = NativeCrypto.SUPPORTED_PROTOCOL_TLSV1_3;
        }

        public ProviderBuilder provideTrustManager(boolean z) {
            this.provideTrustManager = z;
            return this;
        }
    }

    public static class Version {
        private final int major;
        private final int minor;
        private final int patch;

        public int major() {
            return this.major;
        }

        public int minor() {
            return this.minor;
        }

        public int patch() {
            return this.patch;
        }

        private Version(int i2, int i3, int i4) {
            this.major = i2;
            this.minor = i3;
            this.patch = i4;
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:8:0x004e A[ADDED_TO_REGION] */
    static {
        /*
            java.lang.String r0 = "-1"
            r1 = 0
            r2 = -1
            java.lang.Class<org.conscrypt.Conscrypt> r3 = org.conscrypt.Conscrypt.class
            java.lang.String r4 = "conscrypt.properties"
            java.io.InputStream r3 = r3.getResourceAsStream(r4)     // Catch: java.lang.Throwable -> L3f java.io.IOException -> L44
            if (r3 == 0) goto L39
            java.util.Properties r4 = new java.util.Properties     // Catch: java.lang.Throwable -> L36 java.io.IOException -> L45
            r4.<init>()     // Catch: java.lang.Throwable -> L36 java.io.IOException -> L45
            r4.load(r3)     // Catch: java.lang.Throwable -> L36 java.io.IOException -> L45
            java.lang.String r5 = "org.conscrypt.version.major"
            java.lang.String r5 = r4.getProperty(r5, r0)     // Catch: java.lang.Throwable -> L36 java.io.IOException -> L45
            int r5 = java.lang.Integer.parseInt(r5)     // Catch: java.lang.Throwable -> L36 java.io.IOException -> L45
            java.lang.String r6 = "org.conscrypt.version.minor"
            java.lang.String r6 = r4.getProperty(r6, r0)     // Catch: java.lang.Throwable -> L36 java.io.IOException -> L46
            int r6 = java.lang.Integer.parseInt(r6)     // Catch: java.lang.Throwable -> L36 java.io.IOException -> L46
            java.lang.String r7 = "org.conscrypt.version.patch"
            java.lang.String r0 = r4.getProperty(r7, r0)     // Catch: java.lang.Throwable -> L36 java.io.IOException -> L47
            int r0 = java.lang.Integer.parseInt(r0)     // Catch: java.lang.Throwable -> L36 java.io.IOException -> L47
            r2 = r5
            goto L3b
        L36:
            r0 = move-exception
            r1 = r3
            goto L40
        L39:
            r0 = -1
            r6 = -1
        L3b:
            org.conscrypt.p508io.IoUtils.closeQuietly(r3)
            goto L4c
        L3f:
            r0 = move-exception
        L40:
            org.conscrypt.p508io.IoUtils.closeQuietly(r1)
            throw r0
        L44:
            r3 = r1
        L45:
            r5 = -1
        L46:
            r6 = -1
        L47:
            org.conscrypt.p508io.IoUtils.closeQuietly(r3)
            r2 = r5
            r0 = -1
        L4c:
            if (r2 < 0) goto L5a
            if (r6 < 0) goto L5a
            if (r0 < 0) goto L5a
            org.conscrypt.Conscrypt$Version r3 = new org.conscrypt.Conscrypt$Version
            r3.<init>(r2, r6, r0)
            org.conscrypt.Conscrypt.VERSION = r3
            goto L5c
        L5a:
            org.conscrypt.Conscrypt.VERSION = r1
        L5c:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: org.conscrypt.Conscrypt.<clinit>():void");
    }

    private Conscrypt() {
    }

    public static void checkAvailability() {
        NativeCrypto.checkAvailability();
    }

    public static byte[] exportKeyingMaterial(SSLSocket sSLSocket, String str, byte[] bArr, int i2) {
        return toConscrypt(sSLSocket).exportKeyingMaterial(str, bArr, i2);
    }

    public static String getApplicationProtocol(SSLSocket sSLSocket) {
        return toConscrypt(sSLSocket).getApplicationProtocol();
    }

    public static String[] getApplicationProtocols(SSLSocket sSLSocket) {
        return toConscrypt(sSLSocket).getApplicationProtocols();
    }

    public static byte[] getChannelId(SSLSocket sSLSocket) {
        return toConscrypt(sSLSocket).getChannelId();
    }

    public static synchronized ConscryptHostnameVerifier getDefaultHostnameVerifier(TrustManager trustManager) {
        ConscryptHostnameVerifier defaultHostnameVerifier;
        synchronized (Conscrypt.class) {
            defaultHostnameVerifier = TrustManagerImpl.getDefaultHostnameVerifier();
        }
        return defaultHostnameVerifier;
    }

    public static X509TrustManager getDefaultX509TrustManager() {
        checkAvailability();
        return SSLParametersImpl.getDefaultX509TrustManager();
    }

    public static String getHostname(SSLSocket sSLSocket) {
        return toConscrypt(sSLSocket).getHostname();
    }

    public static String getHostnameOrIP(SSLSocket sSLSocket) {
        return toConscrypt(sSLSocket).getHostnameOrIP();
    }

    public static ConscryptHostnameVerifier getHostnameVerifier(TrustManager trustManager) {
        return toConscrypt(trustManager).getHostnameVerifier();
    }

    public static byte[] getTlsUnique(SSLSocket sSLSocket) {
        return toConscrypt(sSLSocket).getTlsUnique();
    }

    public static boolean isAvailable() {
        try {
            checkAvailability();
            return true;
        } catch (Throwable unused) {
            return false;
        }
    }

    public static boolean isConscrypt(Provider provider) {
        return provider instanceof OpenSSLProvider;
    }

    public static int maxEncryptedPacketLength() {
        return NativeConstants.SSL3_RT_MAX_PACKET_SIZE;
    }

    public static int maxSealOverhead(SSLEngine sSLEngine) {
        return toConscrypt(sSLEngine).maxSealOverhead();
    }

    public static SSLContextSpi newPreferredSSLContextSpi() {
        checkAvailability();
        return OpenSSLContextImpl.getPreferred();
    }

    public static Provider newProvider() {
        checkAvailability();
        return new OpenSSLProvider();
    }

    public static ProviderBuilder newProviderBuilder() {
        return new ProviderBuilder();
    }

    public static void setApplicationProtocolSelector(SSLSocket sSLSocket, ApplicationProtocolSelector applicationProtocolSelector) {
        toConscrypt(sSLSocket).setApplicationProtocolSelector(applicationProtocolSelector);
    }

    public static void setApplicationProtocols(SSLSocket sSLSocket, String[] strArr) {
        toConscrypt(sSLSocket).setApplicationProtocols(strArr);
    }

    public static void setBufferAllocator(SSLEngine sSLEngine, BufferAllocator bufferAllocator) {
        toConscrypt(sSLEngine).setBufferAllocator(bufferAllocator);
    }

    public static void setChannelIdEnabled(SSLSocket sSLSocket, boolean z) {
        toConscrypt(sSLSocket).setChannelIdEnabled(z);
    }

    public static void setChannelIdPrivateKey(SSLSocket sSLSocket, PrivateKey privateKey) {
        toConscrypt(sSLSocket).setChannelIdPrivateKey(privateKey);
    }

    public static void setClientSessionCache(SSLContext sSLContext, SSLClientSessionCache sSLClientSessionCache) {
        SSLSessionContext clientSessionContext = sSLContext.getClientSessionContext();
        if (clientSessionContext instanceof ClientSessionContext) {
            ((ClientSessionContext) clientSessionContext).setPersistentCache(sSLClientSessionCache);
        } else {
            StringBuilder m586H = C1499a.m586H("Not a conscrypt client context: ");
            m586H.append(clientSessionContext.getClass().getName());
            throw new IllegalArgumentException(m586H.toString());
        }
    }

    public static void setDefaultBufferAllocator(BufferAllocator bufferAllocator) {
        ConscryptEngine.setDefaultBufferAllocator(bufferAllocator);
    }

    public static synchronized void setDefaultHostnameVerifier(ConscryptHostnameVerifier conscryptHostnameVerifier) {
        synchronized (Conscrypt.class) {
            TrustManagerImpl.setDefaultHostnameVerifier(conscryptHostnameVerifier);
        }
    }

    public static void setHandshakeListener(SSLEngine sSLEngine, HandshakeListener handshakeListener) {
        toConscrypt(sSLEngine).setHandshakeListener(handshakeListener);
    }

    public static void setHostname(SSLSocket sSLSocket, String str) {
        toConscrypt(sSLSocket).setHostname(str);
    }

    public static void setHostnameVerifier(TrustManager trustManager, ConscryptHostnameVerifier conscryptHostnameVerifier) {
        toConscrypt(trustManager).setHostnameVerifier(conscryptHostnameVerifier);
    }

    public static void setServerSessionCache(SSLContext sSLContext, SSLServerSessionCache sSLServerSessionCache) {
        SSLSessionContext serverSessionContext = sSLContext.getServerSessionContext();
        if (serverSessionContext instanceof ServerSessionContext) {
            ((ServerSessionContext) serverSessionContext).setPersistentCache(sSLServerSessionCache);
        } else {
            StringBuilder m586H = C1499a.m586H("Not a conscrypt client context: ");
            m586H.append(serverSessionContext.getClass().getName());
            throw new IllegalArgumentException(m586H.toString());
        }
    }

    public static void setUseEngineSocket(SSLSocketFactory sSLSocketFactory, boolean z) {
        toConscrypt(sSLSocketFactory).setUseEngineSocket(z);
    }

    public static void setUseEngineSocketByDefault(boolean z) {
        OpenSSLSocketFactoryImpl.setUseEngineSocketByDefault(z);
        OpenSSLServerSocketFactoryImpl.setUseEngineSocketByDefault(z);
    }

    public static void setUseSessionTickets(SSLSocket sSLSocket, boolean z) {
        toConscrypt(sSLSocket).setUseSessionTickets(z);
    }

    private static OpenSSLSocketFactoryImpl toConscrypt(SSLSocketFactory sSLSocketFactory) {
        if (isConscrypt(sSLSocketFactory)) {
            return (OpenSSLSocketFactoryImpl) sSLSocketFactory;
        }
        StringBuilder m586H = C1499a.m586H("Not a conscrypt socket factory: ");
        m586H.append(sSLSocketFactory.getClass().getName());
        throw new IllegalArgumentException(m586H.toString());
    }

    public static SSLEngineResult unwrap(SSLEngine sSLEngine, ByteBuffer[] byteBufferArr, ByteBuffer[] byteBufferArr2) {
        return toConscrypt(sSLEngine).unwrap(byteBufferArr, byteBufferArr2);
    }

    public static Version version() {
        return VERSION;
    }

    public static byte[] exportKeyingMaterial(SSLEngine sSLEngine, String str, byte[] bArr, int i2) {
        return toConscrypt(sSLEngine).exportKeyingMaterial(str, bArr, i2);
    }

    public static String getApplicationProtocol(SSLEngine sSLEngine) {
        return toConscrypt(sSLEngine).getApplicationProtocol();
    }

    public static String[] getApplicationProtocols(SSLEngine sSLEngine) {
        return toConscrypt(sSLEngine).getApplicationProtocols();
    }

    public static byte[] getChannelId(SSLEngine sSLEngine) {
        return toConscrypt(sSLEngine).getChannelId();
    }

    public static String getHostname(SSLEngine sSLEngine) {
        return toConscrypt(sSLEngine).getHostname();
    }

    public static byte[] getTlsUnique(SSLEngine sSLEngine) {
        return toConscrypt(sSLEngine).getTlsUnique();
    }

    public static boolean isConscrypt(SSLContext sSLContext) {
        return sSLContext.getProvider() instanceof OpenSSLProvider;
    }

    public static void setApplicationProtocolSelector(SSLEngine sSLEngine, ApplicationProtocolSelector applicationProtocolSelector) {
        toConscrypt(sSLEngine).setApplicationProtocolSelector(applicationProtocolSelector);
    }

    public static void setApplicationProtocols(SSLEngine sSLEngine, String[] strArr) {
        toConscrypt(sSLEngine).setApplicationProtocols(strArr);
    }

    public static void setBufferAllocator(SSLSocket sSLSocket, BufferAllocator bufferAllocator) {
        AbstractConscryptSocket conscrypt = toConscrypt(sSLSocket);
        if (conscrypt instanceof ConscryptEngineSocket) {
            ((ConscryptEngineSocket) conscrypt).setBufferAllocator(bufferAllocator);
        }
    }

    public static void setChannelIdEnabled(SSLEngine sSLEngine, boolean z) {
        toConscrypt(sSLEngine).setChannelIdEnabled(z);
    }

    public static void setChannelIdPrivateKey(SSLEngine sSLEngine, PrivateKey privateKey) {
        toConscrypt(sSLEngine).setChannelIdPrivateKey(privateKey);
    }

    public static void setHostname(SSLEngine sSLEngine, String str) {
        toConscrypt(sSLEngine).setHostname(str);
    }

    public static void setUseEngineSocket(SSLServerSocketFactory sSLServerSocketFactory, boolean z) {
        toConscrypt(sSLServerSocketFactory).setUseEngineSocket(z);
    }

    public static void setUseSessionTickets(SSLEngine sSLEngine, boolean z) {
        toConscrypt(sSLEngine).setUseSessionTickets(z);
    }

    public static SSLEngineResult unwrap(SSLEngine sSLEngine, ByteBuffer[] byteBufferArr, int i2, int i3, ByteBuffer[] byteBufferArr2, int i4, int i5) {
        return toConscrypt(sSLEngine).unwrap(byteBufferArr, i2, i3, byteBufferArr2, i4, i5);
    }

    public static boolean isConscrypt(SSLSocketFactory sSLSocketFactory) {
        return sSLSocketFactory instanceof OpenSSLSocketFactoryImpl;
    }

    @Deprecated
    public static Provider newProvider(String str) {
        checkAvailability();
        return newProviderBuilder().setName(str).build();
    }

    public static boolean isConscrypt(SSLServerSocketFactory sSLServerSocketFactory) {
        return sSLServerSocketFactory instanceof OpenSSLServerSocketFactoryImpl;
    }

    public static boolean isConscrypt(SSLSocket sSLSocket) {
        return sSLSocket instanceof AbstractConscryptSocket;
    }

    private static OpenSSLServerSocketFactoryImpl toConscrypt(SSLServerSocketFactory sSLServerSocketFactory) {
        if (isConscrypt(sSLServerSocketFactory)) {
            return (OpenSSLServerSocketFactoryImpl) sSLServerSocketFactory;
        }
        StringBuilder m586H = C1499a.m586H("Not a conscrypt server socket factory: ");
        m586H.append(sSLServerSocketFactory.getClass().getName());
        throw new IllegalArgumentException(m586H.toString());
    }

    public static boolean isConscrypt(SSLEngine sSLEngine) {
        return sSLEngine instanceof AbstractConscryptEngine;
    }

    public static boolean isConscrypt(TrustManager trustManager) {
        return trustManager instanceof TrustManagerImpl;
    }

    private static AbstractConscryptSocket toConscrypt(SSLSocket sSLSocket) {
        if (isConscrypt(sSLSocket)) {
            return (AbstractConscryptSocket) sSLSocket;
        }
        StringBuilder m586H = C1499a.m586H("Not a conscrypt socket: ");
        m586H.append(sSLSocket.getClass().getName());
        throw new IllegalArgumentException(m586H.toString());
    }

    private static AbstractConscryptEngine toConscrypt(SSLEngine sSLEngine) {
        if (isConscrypt(sSLEngine)) {
            return (AbstractConscryptEngine) sSLEngine;
        }
        StringBuilder m586H = C1499a.m586H("Not a conscrypt engine: ");
        m586H.append(sSLEngine.getClass().getName());
        throw new IllegalArgumentException(m586H.toString());
    }

    private static TrustManagerImpl toConscrypt(TrustManager trustManager) {
        if (isConscrypt(trustManager)) {
            return (TrustManagerImpl) trustManager;
        }
        StringBuilder m586H = C1499a.m586H("Not a Conscrypt trust manager: ");
        m586H.append(trustManager.getClass().getName());
        throw new IllegalArgumentException(m586H.toString());
    }
}
