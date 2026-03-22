package p005b.p199l.p200a.p201a.p248o1;

import android.net.Uri;
import androidx.annotation.Nullable;
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
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2333y;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p403d.p404a.p405a.p407b.p408a.C4195m;
import tv.danmaku.ijk.media.player.IjkMediaMeta;

/* renamed from: b.l.a.a.o1.u */
/* loaded from: classes.dex */
public class C2329u extends AbstractC2294h implements InterfaceC2333y {

    /* renamed from: a */
    public static final Pattern f5990a = Pattern.compile("^bytes (\\d+)-(\\d+)/(\\d+)$");

    /* renamed from: b */
    public static final AtomicReference<byte[]> f5991b = new AtomicReference<>();

    /* renamed from: c */
    public final boolean f5992c;

    /* renamed from: d */
    public final int f5993d;

    /* renamed from: e */
    public final int f5994e;

    /* renamed from: f */
    public final String f5995f;

    /* renamed from: g */
    @Nullable
    public final InterfaceC2333y.e f5996g;

    /* renamed from: h */
    public final InterfaceC2333y.e f5997h;

    /* renamed from: i */
    @Nullable
    public C2324p f5998i;

    /* renamed from: j */
    @Nullable
    public HttpURLConnection f5999j;

    /* renamed from: k */
    @Nullable
    public InputStream f6000k;

    /* renamed from: l */
    public boolean f6001l;

    /* renamed from: m */
    public int f6002m;

    /* renamed from: n */
    public long f6003n;

    /* renamed from: o */
    public long f6004o;

    /* renamed from: p */
    public long f6005p;

    /* renamed from: q */
    public long f6006q;

    public C2329u(String str, int i2, int i3, boolean z, @Nullable InterfaceC2333y.e eVar) {
        super(true);
        C4195m.m4769H(str);
        this.f5995f = str;
        this.f5997h = new InterfaceC2333y.e();
        this.f5993d = i2;
        this.f5994e = i3;
        this.f5992c = z;
        this.f5996g = eVar;
    }

    public static URL handleRedirect(URL url, String str) {
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

    public static void maybeTerminateInputStream(HttpURLConnection httpURLConnection, long j2) {
        int i2 = C2344d0.f6035a;
        if (i2 == 19 || i2 == 20) {
            try {
                InputStream inputStream = httpURLConnection.getInputStream();
                if (j2 == -1) {
                    if (inputStream.read() == -1) {
                        return;
                    }
                } else if (j2 <= IjkMediaMeta.AV_CH_TOP_CENTER) {
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

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public void close() {
        try {
            if (this.f6000k != null) {
                HttpURLConnection httpURLConnection = this.f5999j;
                long j2 = this.f6004o;
                if (j2 != -1) {
                    j2 -= this.f6006q;
                }
                maybeTerminateInputStream(httpURLConnection, j2);
                try {
                    this.f6000k.close();
                } catch (IOException e2) {
                    throw new InterfaceC2333y.b(e2, this.f5998i, 3);
                }
            }
        } finally {
            this.f6000k = null;
            closeConnectionQuietly();
            if (this.f6001l) {
                this.f6001l = false;
                transferEnded();
            }
        }
    }

    public final void closeConnectionQuietly() {
        HttpURLConnection httpURLConnection = this.f5999j;
        if (httpURLConnection != null) {
            try {
                httpURLConnection.disconnect();
            } catch (Exception unused) {
            }
            this.f5999j = null;
        }
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.AbstractC2294h, p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public Map<String, List<String>> getResponseHeaders() {
        HttpURLConnection httpURLConnection = this.f5999j;
        return httpURLConnection == null ? Collections.emptyMap() : httpURLConnection.getHeaderFields();
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    @Nullable
    public Uri getUri() {
        HttpURLConnection httpURLConnection = this.f5999j;
        if (httpURLConnection == null) {
            return null;
        }
        return Uri.parse(httpURLConnection.getURL().toString());
    }

    public final HttpURLConnection makeConnection(C2324p c2324p) {
        HttpURLConnection makeConnection;
        C2324p c2324p2 = c2324p;
        URL url = new URL(c2324p2.f5933a.toString());
        int i2 = c2324p2.f5934b;
        byte[] bArr = c2324p2.f5935c;
        long j2 = c2324p2.f5938f;
        long j3 = c2324p2.f5939g;
        boolean m2267b = c2324p2.m2267b(1);
        if (!this.f5992c) {
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
            if ((i2 == 1 || i2 == 3) && (responseCode == 300 || responseCode == 301 || responseCode == 302 || responseCode == 303 || responseCode == 307 || responseCode == 308)) {
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

    /* JADX WARN: Code restructure failed: missing block: B:14:0x0039, code lost:
    
        if (r4 != 0) goto L16;
     */
    /* JADX WARN: Removed duplicated region for block: B:36:0x007a  */
    /* JADX WARN: Removed duplicated region for block: B:50:0x00af  */
    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public long open(p005b.p199l.p200a.p201a.p248o1.C2324p r13) {
        /*
            Method dump skipped, instructions count: 306
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p248o1.C2329u.open(b.l.a.a.o1.p):long");
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public int read(byte[] bArr, int i2, int i3) {
        try {
            skipInternal();
            if (i3 == 0) {
                return 0;
            }
            long j2 = this.f6004o;
            if (j2 != -1) {
                long j3 = j2 - this.f6006q;
                if (j3 != 0) {
                    i3 = (int) Math.min(i3, j3);
                }
                return -1;
            }
            int read = this.f6000k.read(bArr, i2, i3);
            if (read == -1) {
                if (this.f6004o == -1) {
                    return -1;
                }
                throw new EOFException();
            }
            this.f6006q += read;
            bytesTransferred(read);
            return read;
        } catch (IOException e2) {
            throw new InterfaceC2333y.b(e2, this.f5998i, 2);
        }
    }

    public final void skipInternal() {
        if (this.f6005p == this.f6003n) {
            return;
        }
        byte[] andSet = f5991b.getAndSet(null);
        if (andSet == null) {
            andSet = new byte[4096];
        }
        while (true) {
            long j2 = this.f6005p;
            long j3 = this.f6003n;
            if (j2 == j3) {
                f5991b.set(andSet);
                return;
            }
            int read = this.f6000k.read(andSet, 0, (int) Math.min(j3 - j2, andSet.length));
            if (Thread.currentThread().isInterrupted()) {
                throw new InterruptedIOException();
            }
            if (read == -1) {
                throw new EOFException();
            }
            this.f6005p += read;
            bytesTransferred(read);
        }
    }

    public final HttpURLConnection makeConnection(URL url, int i2, byte[] bArr, long j2, long j3, boolean z, boolean z2, Map<String, String> map) {
        HttpURLConnection httpURLConnection = (HttpURLConnection) url.openConnection();
        httpURLConnection.setConnectTimeout(this.f5993d);
        httpURLConnection.setReadTimeout(this.f5994e);
        HashMap hashMap = new HashMap();
        InterfaceC2333y.e eVar = this.f5996g;
        if (eVar != null) {
            hashMap.putAll(eVar.m2283a());
        }
        hashMap.putAll(this.f5997h.m2283a());
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
        httpURLConnection.setRequestProperty("User-Agent", this.f5995f);
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
