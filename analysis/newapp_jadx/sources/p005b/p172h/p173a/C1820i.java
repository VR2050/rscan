package p005b.p172h.p173a;

import android.text.TextUtils;
import android.webkit.MimeTypeMap;
import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Map;
import java.util.Objects;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p172h.p173a.p175s.InterfaceC1837b;
import p005b.p172h.p173a.p176t.InterfaceC1840c;

/* renamed from: b.h.a.i */
/* loaded from: classes.dex */
public class C1820i implements InterfaceC1827p {

    /* renamed from: a */
    public final InterfaceC1840c f2808a;

    /* renamed from: b */
    public final InterfaceC1837b f2809b;

    /* renamed from: c */
    public C1828q f2810c;

    /* renamed from: d */
    public HttpURLConnection f2811d;

    /* renamed from: e */
    public InputStream f2812e;

    public C1820i(String str, InterfaceC1840c interfaceC1840c, InterfaceC1837b interfaceC1837b) {
        Objects.requireNonNull(interfaceC1840c);
        this.f2808a = interfaceC1840c;
        Objects.requireNonNull(interfaceC1837b);
        this.f2809b = interfaceC1837b;
        C1828q c1828q = interfaceC1840c.get(str);
        if (c1828q == null) {
            MimeTypeMap singleton = MimeTypeMap.getSingleton();
            String fileExtensionFromUrl = MimeTypeMap.getFileExtensionFromUrl(str);
            c1828q = new C1828q(str, -2147483648L, TextUtils.isEmpty(fileExtensionFromUrl) ? null : singleton.getMimeTypeFromExtension(fileExtensionFromUrl));
        }
        this.f2810c = c1828q;
    }

    @Override // p005b.p172h.p173a.InterfaceC1827p
    /* renamed from: a */
    public void mo1176a(long j2) {
        try {
            HttpURLConnection m1178c = m1178c(j2, -1);
            this.f2811d = m1178c;
            String contentType = m1178c.getContentType();
            this.f2812e = new BufferedInputStream(this.f2811d.getInputStream(), 8192);
            HttpURLConnection httpURLConnection = this.f2811d;
            int responseCode = httpURLConnection.getResponseCode();
            String headerField = httpURLConnection.getHeaderField("Content-Length");
            long parseLong = headerField == null ? -1L : Long.parseLong(headerField);
            if (responseCode != 200) {
                parseLong = responseCode == 206 ? parseLong + j2 : this.f2810c.f2831b;
            }
            String str = this.f2810c.f2830a;
            C1828q c1828q = new C1828q(str, parseLong, contentType);
            this.f2810c = c1828q;
            this.f2808a.mo1191b(str, c1828q);
        } catch (IOException e2) {
            StringBuilder m586H = C1499a.m586H("Error opening connection for ");
            m586H.append(this.f2810c.f2830a);
            m586H.append(" with offset ");
            m586H.append(j2);
            throw new C1825n(m586H.toString(), e2);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:26:0x006a  */
    /* renamed from: b */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void m1177b() {
        /*
            r8 = this;
            r0 = 0
            r2 = 10000(0x2710, float:1.4013E-41)
            r3 = 0
            java.net.HttpURLConnection r0 = r8.m1178c(r0, r2)     // Catch: java.lang.Throwable -> L3b java.io.IOException -> L3e
            java.lang.String r1 = "Content-Length"
            java.lang.String r1 = r0.getHeaderField(r1)     // Catch: java.lang.Throwable -> L34 java.io.IOException -> L39
            if (r1 != 0) goto L14
            r1 = -1
            goto L18
        L14:
            long r1 = java.lang.Long.parseLong(r1)     // Catch: java.lang.Throwable -> L34 java.io.IOException -> L39
        L18:
            java.lang.String r4 = r0.getContentType()     // Catch: java.lang.Throwable -> L34 java.io.IOException -> L39
            java.io.InputStream r3 = r0.getInputStream()     // Catch: java.lang.Throwable -> L34 java.io.IOException -> L39
            b.h.a.q r5 = new b.h.a.q     // Catch: java.lang.Throwable -> L34 java.io.IOException -> L39
            b.h.a.q r6 = r8.f2810c     // Catch: java.lang.Throwable -> L34 java.io.IOException -> L39
            java.lang.String r6 = r6.f2830a     // Catch: java.lang.Throwable -> L34 java.io.IOException -> L39
            r5.<init>(r6, r1, r4)     // Catch: java.lang.Throwable -> L34 java.io.IOException -> L39
            r8.f2810c = r5     // Catch: java.lang.Throwable -> L34 java.io.IOException -> L39
            b.h.a.t.c r1 = r8.f2808a     // Catch: java.lang.Throwable -> L34 java.io.IOException -> L39
            r1.mo1191b(r6, r5)     // Catch: java.lang.Throwable -> L34 java.io.IOException -> L39
            p005b.p172h.p173a.C1826o.m1186a(r3)
            goto L5d
        L34:
            r1 = move-exception
            r7 = r3
            r3 = r0
            r0 = r7
            goto L61
        L39:
            r1 = move-exception
            goto L40
        L3b:
            r0 = move-exception
            r1 = r3
            goto L65
        L3e:
            r1 = move-exception
            r0 = r3
        L40:
            java.lang.StringBuilder r2 = new java.lang.StringBuilder     // Catch: java.lang.Throwable -> L34
            r2.<init>()     // Catch: java.lang.Throwable -> L34
            java.lang.String r4 = "Error fetching info from "
            r2.append(r4)     // Catch: java.lang.Throwable -> L34
            b.h.a.q r4 = r8.f2810c     // Catch: java.lang.Throwable -> L34
            java.lang.String r4 = r4.f2830a     // Catch: java.lang.Throwable -> L34
            r2.append(r4)     // Catch: java.lang.Throwable -> L34
            java.lang.String r2 = r2.toString()     // Catch: java.lang.Throwable -> L34
            p005b.p172h.p173a.C1817f.m1164a(r2, r1)     // Catch: java.lang.Throwable -> L34
            p005b.p172h.p173a.C1826o.m1186a(r3)
            if (r0 == 0) goto L60
        L5d:
            r0.disconnect()
        L60:
            return
        L61:
            r7 = r3
            r3 = r0
            r0 = r1
            r1 = r7
        L65:
            p005b.p172h.p173a.C1826o.m1186a(r3)
            if (r1 == 0) goto L6d
            r1.disconnect()
        L6d:
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p172h.p173a.C1820i.m1177b():void");
    }

    /* renamed from: c */
    public final HttpURLConnection m1178c(long j2, int i2) {
        HttpURLConnection httpURLConnection;
        boolean z;
        String str = this.f2810c.f2830a;
        int i3 = 0;
        do {
            httpURLConnection = (HttpURLConnection) new URL(str).openConnection();
            Map<String, String> mo1190a = this.f2809b.mo1190a(str);
            if (mo1190a != null) {
                StringBuilder m586H = C1499a.m586H("****** injectCustomHeaders ****** :");
                m586H.append(mo1190a.size());
                TextUtils.isEmpty(m586H.toString());
                for (Map.Entry<String, String> entry : mo1190a.entrySet()) {
                    httpURLConnection.setRequestProperty(entry.getKey(), entry.getValue());
                }
            }
            if (j2 > 0) {
                httpURLConnection.setRequestProperty("Range", C1499a.m631q("bytes=", j2, "-"));
            }
            if (i2 > 0) {
                httpURLConnection.setConnectTimeout(i2);
                httpURLConnection.setReadTimeout(i2);
            }
            int responseCode = httpURLConnection.getResponseCode();
            z = responseCode == 301 || responseCode == 302 || responseCode == 303;
            if (z) {
                str = httpURLConnection.getHeaderField("Location");
                i3++;
                httpURLConnection.disconnect();
            }
            if (i3 > 5) {
                throw new C1825n(C1499a.m626l("Too many redirects: ", i3));
            }
        } while (z);
        return httpURLConnection;
    }

    @Override // p005b.p172h.p173a.InterfaceC1827p
    public void close() {
        HttpURLConnection httpURLConnection = this.f2811d;
        if (httpURLConnection != null) {
            try {
                httpURLConnection.disconnect();
            } catch (ArrayIndexOutOfBoundsException e2) {
                C1817f.m1164a("Error closing connection correctly. Should happen only on Android L. If anybody know how to fix it, please visit https://github.com/danikula/AndroidVideoCache/issues/88. Until good solution is not know, just ignore this issue :(", e2);
            } catch (IllegalArgumentException e3) {
                e = e3;
                throw new RuntimeException("Wait... but why? WTF!? Really shouldn't happen any more after fixing https://github.com/danikula/AndroidVideoCache/issues/43. If you read it on your device log, please, notify me danikula@gmail.com or create issue here https://github.com/danikula/AndroidVideoCache/issues.", e);
            } catch (NullPointerException e4) {
                e = e4;
                throw new RuntimeException("Wait... but why? WTF!? Really shouldn't happen any more after fixing https://github.com/danikula/AndroidVideoCache/issues/43. If you read it on your device log, please, notify me danikula@gmail.com or create issue here https://github.com/danikula/AndroidVideoCache/issues.", e);
            }
        }
    }

    @Override // p005b.p172h.p173a.InterfaceC1827p
    public synchronized long length() {
        if (this.f2810c.f2831b == -2147483648L) {
            m1177b();
        }
        return this.f2810c.f2831b;
    }

    @Override // p005b.p172h.p173a.InterfaceC1827p
    public int read(byte[] bArr) {
        InputStream inputStream = this.f2812e;
        if (inputStream == null) {
            throw new C1825n(C1499a.m582D(C1499a.m586H("Error reading data from "), this.f2810c.f2830a, ": connection is absent!"));
        }
        try {
            return inputStream.read(bArr, 0, bArr.length);
        } catch (InterruptedIOException e2) {
            throw new C1822k(C1499a.m582D(C1499a.m586H("Reading source "), this.f2810c.f2830a, " is interrupted"), e2);
        } catch (IOException e3) {
            StringBuilder m586H = C1499a.m586H("Error reading data from ");
            m586H.append(this.f2810c.f2830a);
            throw new C1825n(m586H.toString(), e3);
        }
    }

    public String toString() {
        StringBuilder m586H = C1499a.m586H("HttpUrlSource{sourceInfo='");
        m586H.append(this.f2810c);
        m586H.append("}");
        return m586H.toString();
    }

    public C1820i(C1820i c1820i) {
        this.f2810c = c1820i.f2810c;
        this.f2808a = c1820i.f2808a;
        this.f2809b = c1820i.f2809b;
    }
}
