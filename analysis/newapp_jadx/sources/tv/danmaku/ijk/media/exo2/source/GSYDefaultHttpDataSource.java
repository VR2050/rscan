package tv.danmaku.ijk.media.exo2.source;

import android.net.Uri;
import androidx.annotation.Nullable;
import androidx.annotation.VisibleForTesting;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.net.HttpURLConnection;
import java.net.NoRouteToHostException;
import java.net.ProtocolException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p248o1.AbstractC2294h;
import p005b.p199l.p200a.p201a.p248o1.C2284c;
import p005b.p199l.p200a.p201a.p248o1.C2322n;
import p005b.p199l.p200a.p201a.p248o1.C2324p;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2333y;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p005b.p199l.p200a.p201a.p250p1.InterfaceC2362v;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* loaded from: classes3.dex */
public class GSYDefaultHttpDataSource extends AbstractC2294h implements InterfaceC2333y {
    public static final int DEFAULT_CONNECT_TIMEOUT_MILLIS = 8000;
    public static final int DEFAULT_READ_TIMEOUT_MILLIS = 8000;
    private static final int HTTP_STATUS_PERMANENT_REDIRECT = 308;
    private static final int HTTP_STATUS_TEMPORARY_REDIRECT = 307;
    private static final long MAX_BYTES_TO_DRAIN = 2048;
    private static final int MAX_REDIRECTS = 20;
    private static final String TAG = "DefaultHttpDataSource";
    private final boolean allowCrossProtocolRedirects;
    private long bytesRead;
    private long bytesSkipped;
    private long bytesToRead;
    private long bytesToSkip;
    private final int connectTimeoutMillis;

    @Nullable
    private HttpURLConnection connection;

    @Nullable
    private InterfaceC2362v<String> contentTypePredicate;

    @Nullable
    private C2324p dataSpec;

    @Nullable
    private final InterfaceC2333y.e defaultRequestProperties;

    @Nullable
    private InputStream inputStream;
    private boolean opened;
    private final int readTimeoutMillis;
    private final InterfaceC2333y.e requestProperties;
    private int responseCode;
    private final String userAgent;
    private static final Pattern CONTENT_RANGE_HEADER = Pattern.compile("^bytes (\\d+)-(\\d+)/(\\d+)$");
    private static final AtomicReference<byte[]> skipBufferReference = new AtomicReference<>();

    public GSYDefaultHttpDataSource(String str) {
        this(str, 8000, 8000);
    }

    private void closeConnectionQuietly() {
        HttpURLConnection httpURLConnection = this.connection;
        if (httpURLConnection != null) {
            try {
                httpURLConnection.disconnect();
            } catch (Exception unused) {
            }
            this.connection = null;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:24:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:6:0x001f  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private static long getContentLength(java.net.HttpURLConnection r6) {
        /*
            java.lang.String r0 = "Content-Length"
            java.lang.String r0 = r6.getHeaderField(r0)
            boolean r1 = android.text.TextUtils.isEmpty(r0)
            if (r1 != 0) goto L11
            long r0 = java.lang.Long.parseLong(r0)     // Catch: java.lang.NumberFormatException -> L11
            goto L13
        L11:
            r0 = -1
        L13:
            java.lang.String r2 = "Content-Range"
            java.lang.String r6 = r6.getHeaderField(r2)
            boolean r2 = android.text.TextUtils.isEmpty(r6)
            if (r2 != 0) goto L51
            java.util.regex.Pattern r2 = tv.danmaku.ijk.media.exo2.source.GSYDefaultHttpDataSource.CONTENT_RANGE_HEADER
            java.util.regex.Matcher r6 = r2.matcher(r6)
            boolean r2 = r6.find()
            if (r2 == 0) goto L51
            r2 = 2
            java.lang.String r2 = r6.group(r2)     // Catch: java.lang.NumberFormatException -> L51
            long r2 = java.lang.Long.parseLong(r2)     // Catch: java.lang.NumberFormatException -> L51
            r4 = 1
            java.lang.String r6 = r6.group(r4)     // Catch: java.lang.NumberFormatException -> L51
            long r4 = java.lang.Long.parseLong(r6)     // Catch: java.lang.NumberFormatException -> L51
            long r2 = r2 - r4
            r4 = 1
            long r2 = r2 + r4
            r4 = 0
            int r6 = (r0 > r4 ? 1 : (r0 == r4 ? 0 : -1))
            if (r6 >= 0) goto L49
            r0 = r2
            goto L51
        L49:
            int r6 = (r0 > r2 ? 1 : (r0 == r2 ? 0 : -1))
            if (r6 == 0) goto L51
            long r0 = java.lang.Math.max(r0, r2)     // Catch: java.lang.NumberFormatException -> L51
        L51:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: tv.danmaku.ijk.media.exo2.source.GSYDefaultHttpDataSource.getContentLength(java.net.HttpURLConnection):long");
    }

    private static URL handleRedirect(URL url, String str) {
        if (str == null) {
            throw new ProtocolException("Null location redirect");
        }
        URL url2 = new URL(url, str);
        String protocol = url2.getProtocol();
        if ("https".equals(protocol) || "http".equals(protocol)) {
            return url2;
        }
        throw new ProtocolException(C1499a.m637w("Unsupported protocol redirect: ", protocol));
    }

    private static boolean isCompressed(HttpURLConnection httpURLConnection) {
        return "gzip".equalsIgnoreCase(httpURLConnection.getHeaderField("Content-Encoding"));
    }

    private HttpURLConnection makeConnection(C2324p c2324p) {
        HttpURLConnection makeConnection;
        C2324p c2324p2 = c2324p;
        URL url = new URL(c2324p2.f5933a.toString());
        int i2 = c2324p2.f5934b;
        byte[] bArr = c2324p2.f5935c;
        long j2 = c2324p2.f5938f;
        long j3 = c2324p2.f5939g;
        boolean m2267b = c2324p2.m2267b(1);
        if (!this.allowCrossProtocolRedirects) {
            return makeConnection(url, i2, bArr, j2, j3, m2267b, true, c2324p2.f5936d);
        }
        int i3 = 0;
        while (true) {
            int i4 = i3 + 1;
            if (i3 > 20) {
                throw new NoRouteToHostException(C1499a.m626l("Too many redirects: ", i4));
            }
            long j4 = j3;
            long j5 = j2;
            makeConnection = makeConnection(url, i2, bArr, j2, j3, m2267b, false, c2324p2.f5936d);
            int responseCode = makeConnection.getResponseCode();
            String headerField = makeConnection.getHeaderField("Location");
            if ((i2 == 1 || i2 == 3) && (responseCode == 300 || responseCode == 301 || responseCode == 302 || responseCode == 303 || responseCode == HTTP_STATUS_TEMPORARY_REDIRECT || responseCode == HTTP_STATUS_PERMANENT_REDIRECT)) {
                makeConnection.disconnect();
                url = handleRedirect(url, headerField);
            } else {
                if (i2 != 2 || (responseCode != 300 && responseCode != 301 && responseCode != 302 && responseCode != 303)) {
                    break;
                }
                makeConnection.disconnect();
                url = handleRedirect(url, headerField);
                i2 = 1;
                bArr = null;
            }
            c2324p2 = c2324p;
            i3 = i4;
            j3 = j4;
            j2 = j5;
        }
        return makeConnection;
    }

    private static void maybeTerminateInputStream(HttpURLConnection httpURLConnection, long j2) {
        int i2 = C2344d0.f6035a;
        if (i2 == 19 || i2 == 20) {
            try {
                InputStream inputStream = httpURLConnection.getInputStream();
                if (j2 == -1) {
                    if (inputStream.read() == -1) {
                        return;
                    }
                } else if (j2 <= 2048) {
                    return;
                }
                String name = inputStream.getClass().getName();
                if ("com.android.okhttp.internal.http.HttpTransport$ChunkedInputStream".equals(name) || "com.android.okhttp.internal.http.HttpTransport$FixedLengthInputStream".equals(name)) {
                    Method declaredMethod = inputStream.getClass().getSuperclass().getDeclaredMethod("unexpectedEndOfInput", new Class[0]);
                    declaredMethod.setAccessible(true);
                    declaredMethod.invoke(inputStream, new Object[0]);
                }
            } catch (Exception unused) {
            }
        }
    }

    private int readInternal(byte[] bArr, int i2, int i3) {
        if (i3 == 0) {
            return 0;
        }
        long j2 = this.bytesToRead;
        if (j2 != -1) {
            long j3 = j2 - this.bytesRead;
            if (j3 == 0) {
                return -1;
            }
            i3 = (int) Math.min(i3, j3);
        }
        int read = this.inputStream.read(bArr, i2, i3);
        if (read == -1) {
            if (this.bytesToRead == -1) {
                return -1;
            }
            throw new EOFException();
        }
        this.bytesRead += read;
        bytesTransferred(read);
        return read;
    }

    private void skipInternal() {
        if (this.bytesSkipped == this.bytesToSkip) {
            return;
        }
        byte[] andSet = skipBufferReference.getAndSet(null);
        if (andSet == null) {
            andSet = new byte[4096];
        }
        while (true) {
            long j2 = this.bytesSkipped;
            long j3 = this.bytesToSkip;
            if (j2 == j3) {
                skipBufferReference.set(andSet);
                return;
            }
            int read = this.inputStream.read(andSet, 0, (int) Math.min(j3 - j2, andSet.length));
            if (Thread.currentThread().isInterrupted()) {
                throw new InterruptedIOException();
            }
            if (read == -1) {
                throw new EOFException();
            }
            this.bytesSkipped += read;
            bytesTransferred(read);
        }
    }

    public final long bytesRead() {
        return this.bytesRead;
    }

    public final long bytesRemaining() {
        long j2 = this.bytesToRead;
        return j2 == -1 ? j2 : j2 - this.bytesRead;
    }

    public final long bytesSkipped() {
        return this.bytesSkipped;
    }

    public void clearAllRequestProperties() {
        InterfaceC2333y.e eVar = this.requestProperties;
        synchronized (eVar) {
            eVar.f6019b = null;
            eVar.f6018a.clear();
        }
    }

    public void clearRequestProperty(String str) {
        Objects.requireNonNull(str);
        InterfaceC2333y.e eVar = this.requestProperties;
        synchronized (eVar) {
            eVar.f6019b = null;
            eVar.f6018a.remove(str);
        }
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public void close() {
        try {
            if (this.inputStream != null) {
                maybeTerminateInputStream(this.connection, bytesRemaining());
                try {
                    this.inputStream.close();
                } catch (IOException e2) {
                    throw new InterfaceC2333y.b(e2, this.dataSpec, 3);
                }
            }
        } finally {
            this.inputStream = null;
            closeConnectionQuietly();
            if (this.opened) {
                this.opened = false;
                transferEnded();
            }
        }
    }

    @Nullable
    public final HttpURLConnection getConnection() {
        return this.connection;
    }

    public int getResponseCode() {
        int i2;
        if (this.connection == null || (i2 = this.responseCode) <= 0) {
            return -1;
        }
        return i2;
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.AbstractC2294h, p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public Map<String, List<String>> getResponseHeaders() {
        HttpURLConnection httpURLConnection = this.connection;
        return httpURLConnection == null ? Collections.emptyMap() : httpURLConnection.getHeaderFields();
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    @Nullable
    public Uri getUri() {
        HttpURLConnection httpURLConnection = this.connection;
        if (httpURLConnection == null) {
            return null;
        }
        return Uri.parse(httpURLConnection.getURL().toString());
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public long open(C2324p c2324p) {
        this.dataSpec = c2324p;
        long j2 = 0;
        this.bytesRead = 0L;
        this.bytesSkipped = 0L;
        transferInitializing(c2324p);
        try {
            HttpURLConnection makeConnection = makeConnection(c2324p);
            this.connection = makeConnection;
            try {
                this.responseCode = makeConnection.getResponseCode();
                String responseMessage = this.connection.getResponseMessage();
                int i2 = this.responseCode;
                if (i2 < 200 || i2 > 299) {
                    Map<String, List<String>> headerFields = this.connection.getHeaderFields();
                    closeConnectionQuietly();
                    InterfaceC2333y.d dVar = new InterfaceC2333y.d(this.responseCode, responseMessage, headerFields, c2324p);
                    if (this.responseCode != 416) {
                        throw dVar;
                    }
                    dVar.initCause(new C2322n(0));
                    throw dVar;
                }
                String contentType = this.connection.getContentType();
                InterfaceC2362v<String> interfaceC2362v = this.contentTypePredicate;
                if (interfaceC2362v != null && !((C2284c) interfaceC2362v).m2191a(contentType)) {
                    closeConnectionQuietly();
                    throw new InterfaceC2333y.c(contentType, c2324p);
                }
                if (this.responseCode == 200) {
                    long j3 = c2324p.f5938f;
                    if (j3 != 0) {
                        j2 = j3;
                    }
                }
                this.bytesToSkip = j2;
                boolean isCompressed = isCompressed(this.connection);
                if (isCompressed) {
                    this.bytesToRead = c2324p.f5939g;
                } else {
                    long j4 = c2324p.f5939g;
                    if (j4 != -1) {
                        this.bytesToRead = j4;
                    } else {
                        long contentLength = getContentLength(this.connection);
                        this.bytesToRead = contentLength != -1 ? contentLength - this.bytesToSkip : -1L;
                    }
                }
                try {
                    this.inputStream = this.connection.getInputStream();
                    if (isCompressed) {
                        this.inputStream = new GZIPInputStream(this.inputStream);
                    }
                    this.opened = true;
                    transferStarted(c2324p);
                    return this.bytesToRead;
                } catch (IOException e2) {
                    closeConnectionQuietly();
                    throw new InterfaceC2333y.b(e2, c2324p, 1);
                }
            } catch (IOException e3) {
                closeConnectionQuietly();
                StringBuilder m586H = C1499a.m586H("Unable to connect to ");
                m586H.append(c2324p.f5933a.toString());
                throw new InterfaceC2333y.b(m586H.toString(), e3, c2324p, 1);
            }
        } catch (IOException e4) {
            StringBuilder m586H2 = C1499a.m586H("Unable to connect to ");
            m586H2.append(c2324p.f5933a.toString());
            throw new InterfaceC2333y.b(m586H2.toString(), e4, c2324p, 1);
        }
    }

    @VisibleForTesting
    public HttpURLConnection openConnection(URL url) {
        return (HttpURLConnection) url.openConnection();
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public int read(byte[] bArr, int i2, int i3) {
        try {
            skipInternal();
            return readInternal(bArr, i2, i3);
        } catch (IOException e2) {
            throw new InterfaceC2333y.b(e2, this.dataSpec, 2);
        }
    }

    public void setContentTypePredicate(@Nullable InterfaceC2362v<String> interfaceC2362v) {
        this.contentTypePredicate = interfaceC2362v;
    }

    public void setRequestProperty(String str, String str2) {
        Objects.requireNonNull(str);
        Objects.requireNonNull(str2);
        this.requestProperties.m2284b(str, str2);
    }

    public GSYDefaultHttpDataSource(String str, int i2, int i3) {
        this(str, i2, i3, false, null);
    }

    public GSYDefaultHttpDataSource(String str, int i2, int i3, boolean z, @Nullable InterfaceC2333y.e eVar) {
        super(true);
        C4195m.m4769H(str);
        this.userAgent = str;
        this.requestProperties = new InterfaceC2333y.e();
        this.connectTimeoutMillis = i2;
        this.readTimeoutMillis = i3;
        this.allowCrossProtocolRedirects = z;
        this.defaultRequestProperties = eVar;
    }

    @Deprecated
    public GSYDefaultHttpDataSource(String str, @Nullable InterfaceC2362v<String> interfaceC2362v) {
        this(str, interfaceC2362v, 8000, 8000);
    }

    @Deprecated
    public GSYDefaultHttpDataSource(String str, @Nullable InterfaceC2362v<String> interfaceC2362v, int i2, int i3) {
        this(str, interfaceC2362v, i2, i3, false, null);
    }

    @Deprecated
    public GSYDefaultHttpDataSource(String str, @Nullable InterfaceC2362v<String> interfaceC2362v, int i2, int i3, boolean z, @Nullable InterfaceC2333y.e eVar) {
        super(true);
        C4195m.m4769H(str);
        this.userAgent = str;
        this.contentTypePredicate = interfaceC2362v;
        this.requestProperties = new InterfaceC2333y.e();
        this.connectTimeoutMillis = i2;
        this.readTimeoutMillis = i3;
        this.allowCrossProtocolRedirects = z;
        this.defaultRequestProperties = eVar;
    }

    private HttpURLConnection makeConnection(URL url, int i2, byte[] bArr, long j2, long j3, boolean z, boolean z2, Map<String, String> map) {
        HttpURLConnection httpURLConnection;
        if (url.getProtocol().endsWith("https")) {
            HttpsURLConnection httpsURLConnection = (HttpsURLConnection) url.openConnection();
            httpsURLConnection.setHostnameVerifier(new HostnameVerifier() { // from class: tv.danmaku.ijk.media.exo2.source.GSYDefaultHttpDataSource.1
                @Override // javax.net.ssl.HostnameVerifier
                public boolean verify(String str, SSLSession sSLSession) {
                    return true;
                }
            });
            TrustManager[] trustManagerArr = {new X509TrustManager() { // from class: tv.danmaku.ijk.media.exo2.source.GSYDefaultHttpDataSource.2
                @Override // javax.net.ssl.X509TrustManager
                public void checkClientTrusted(X509Certificate[] x509CertificateArr, String str) {
                }

                @Override // javax.net.ssl.X509TrustManager
                public void checkServerTrusted(X509Certificate[] x509CertificateArr, String str) {
                }

                @Override // javax.net.ssl.X509TrustManager
                public X509Certificate[] getAcceptedIssuers() {
                    return null;
                }
            }};
            try {
                SSLContext sSLContext = SSLContext.getInstance("SSL");
                sSLContext.init(null, trustManagerArr, new SecureRandom());
                httpsURLConnection.setSSLSocketFactory(sSLContext.getSocketFactory());
                httpsURLConnection.setHostnameVerifier(new HostnameVerifier() { // from class: tv.danmaku.ijk.media.exo2.source.GSYDefaultHttpDataSource.3
                    @Override // javax.net.ssl.HostnameVerifier
                    public boolean verify(String str, SSLSession sSLSession) {
                        return true;
                    }
                });
                httpURLConnection = httpsURLConnection;
            } catch (KeyManagementException e2) {
                e2.printStackTrace();
                httpURLConnection = httpsURLConnection;
            } catch (NoSuchAlgorithmException e3) {
                e3.printStackTrace();
                httpURLConnection = httpsURLConnection;
            }
        } else {
            httpURLConnection = (HttpURLConnection) url.openConnection();
        }
        httpURLConnection.setConnectTimeout(this.connectTimeoutMillis);
        httpURLConnection.setReadTimeout(this.readTimeoutMillis);
        HashMap hashMap = new HashMap();
        InterfaceC2333y.e eVar = this.defaultRequestProperties;
        if (eVar != null) {
            hashMap.putAll(eVar.m2283a());
        }
        hashMap.putAll(this.requestProperties.m2283a());
        hashMap.putAll(map);
        for (Map.Entry entry : hashMap.entrySet()) {
            httpURLConnection.setRequestProperty((String) entry.getKey(), (String) entry.getValue());
        }
        if (j2 != 0 || j3 != -1) {
            String m631q = C1499a.m631q("bytes=", j2, "-");
            if (j3 != -1) {
                StringBuilder m586H = C1499a.m586H(m631q);
                m586H.append((j2 + j3) - 1);
                m631q = m586H.toString();
            }
            httpURLConnection.setRequestProperty("Range", m631q);
        }
        httpURLConnection.setRequestProperty("User-Agent", this.userAgent);
        httpURLConnection.setRequestProperty("Accept-Encoding", z ? "gzip" : "identity");
        httpURLConnection.setInstanceFollowRedirects(z2);
        httpURLConnection.setDoOutput(bArr != null);
        httpURLConnection.setRequestMethod(C2324p.m2266a(i2));
        if (bArr != null) {
            httpURLConnection.setFixedLengthStreamingMode(bArr.length);
            httpURLConnection.connect();
            OutputStream outputStream = httpURLConnection.getOutputStream();
            outputStream.write(bArr);
            outputStream.close();
        } else {
            httpURLConnection.connect();
        }
        return httpURLConnection;
    }
}
