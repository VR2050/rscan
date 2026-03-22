package com.alipay.android.phone.mrpc.core;

import android.content.Context;
import android.text.TextUtils;
import android.webkit.CookieManager;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.URL;
import java.util.HashMap;
import java.util.concurrent.Callable;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.client.CookieStore;
import org.apache.http.client.HttpRequestRetryHandler;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.entity.AbstractHttpEntity;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.protocol.HttpContext;

/* renamed from: com.alipay.android.phone.mrpc.core.q */
/* loaded from: classes.dex */
public final class CallableC3157q implements Callable<C3161u> {

    /* renamed from: e */
    private static final HttpRequestRetryHandler f8579e = new C3141ad();

    /* renamed from: a */
    public C3152l f8580a;

    /* renamed from: b */
    public Context f8581b;

    /* renamed from: c */
    public C3155o f8582c;

    /* renamed from: d */
    public String f8583d;

    /* renamed from: f */
    private HttpUriRequest f8584f;

    /* renamed from: i */
    private CookieManager f8587i;

    /* renamed from: j */
    private AbstractHttpEntity f8588j;

    /* renamed from: k */
    private HttpHost f8589k;

    /* renamed from: l */
    private URL f8590l;

    /* renamed from: q */
    private String f8595q;

    /* renamed from: g */
    private HttpContext f8585g = new BasicHttpContext();

    /* renamed from: h */
    private CookieStore f8586h = new BasicCookieStore();

    /* renamed from: m */
    private int f8591m = 0;

    /* renamed from: n */
    private boolean f8592n = false;

    /* renamed from: o */
    private boolean f8593o = false;

    /* renamed from: p */
    private String f8594p = null;

    public CallableC3157q(C3152l c3152l, C3155o c3155o) {
        this.f8580a = c3152l;
        this.f8581b = c3152l.f8557a;
        this.f8582c = c3155o;
    }

    /* renamed from: a */
    private static long m3702a(String[] strArr) {
        for (int i2 = 0; i2 < strArr.length; i2++) {
            if ("max-age".equalsIgnoreCase(strArr[i2])) {
                int i3 = i2 + 1;
                if (strArr[i3] != null) {
                    try {
                        return Long.parseLong(strArr[i3]);
                    } catch (Exception unused) {
                        continue;
                    }
                } else {
                    continue;
                }
            }
        }
        return 0L;
    }

    /* renamed from: a */
    private static HttpUrlHeader m3703a(HttpResponse httpResponse) {
        HttpUrlHeader httpUrlHeader = new HttpUrlHeader();
        for (Header header : httpResponse.getAllHeaders()) {
            httpUrlHeader.setHead(header.getName(), header.getValue());
        }
        return httpUrlHeader;
    }

    /* renamed from: a */
    private C3161u m3704a(HttpResponse httpResponse, int i2, String str) {
        ByteArrayOutputStream byteArrayOutputStream;
        String str2;
        new StringBuilder("开始handle，handleResponse-1,").append(Thread.currentThread().getId());
        HttpEntity entity = httpResponse.getEntity();
        ByteArrayOutputStream byteArrayOutputStream2 = null;
        String str3 = null;
        if (entity == null || httpResponse.getStatusLine().getStatusCode() != 200) {
            if (entity != null) {
                return null;
            }
            httpResponse.getStatusLine().getStatusCode();
            return null;
        }
        new StringBuilder("200，开始处理，handleResponse-2,threadid = ").append(Thread.currentThread().getId());
        try {
            byteArrayOutputStream = new ByteArrayOutputStream();
        } catch (Throwable th) {
            th = th;
        }
        try {
            long currentTimeMillis = System.currentTimeMillis();
            m3706a(entity, byteArrayOutputStream);
            byte[] byteArray = byteArrayOutputStream.toByteArray();
            this.f8593o = false;
            this.f8580a.m3686c(System.currentTimeMillis() - currentTimeMillis);
            this.f8580a.m3684a(byteArray.length);
            new StringBuilder("res:").append(byteArray.length);
            C3156p c3156p = new C3156p(m3703a(httpResponse), i2, str, byteArray);
            long m3707b = m3707b(httpResponse);
            Header contentType = httpResponse.getEntity().getContentType();
            if (contentType != null) {
                HashMap<String, String> m3705a = m3705a(contentType.getValue());
                String str4 = m3705a.get("charset");
                str3 = m3705a.get("Content-Type");
                str2 = str4;
            } else {
                str2 = null;
            }
            c3156p.m3722b(str3);
            c3156p.m3700a(str2);
            c3156p.m3699a(System.currentTimeMillis());
            c3156p.m3701b(m3707b);
            try {
                byteArrayOutputStream.close();
                return c3156p;
            } catch (IOException e2) {
                throw new RuntimeException("ArrayOutputStream close error!", e2.getCause());
            }
        } catch (Throwable th2) {
            th = th2;
            byteArrayOutputStream2 = byteArrayOutputStream;
            if (byteArrayOutputStream2 != null) {
                try {
                    byteArrayOutputStream2.close();
                } catch (IOException e3) {
                    throw new RuntimeException("ArrayOutputStream close error!", e3.getCause());
                }
            }
            throw th;
        }
    }

    /* renamed from: a */
    private static HashMap<String, String> m3705a(String str) {
        HashMap<String, String> hashMap = new HashMap<>();
        for (String str2 : str.split(";")) {
            String[] split = str2.indexOf(61) == -1 ? new String[]{"Content-Type", str2} : str2.split("=");
            hashMap.put(split[0], split[1]);
        }
        return hashMap;
    }

    /* renamed from: a */
    private void m3706a(HttpEntity httpEntity, OutputStream outputStream) {
        InputStream m3658a = C3142b.m3658a(httpEntity);
        long contentLength = httpEntity.getContentLength();
        try {
            try {
                byte[] bArr = new byte[2048];
                while (true) {
                    int read = m3658a.read(bArr);
                    if (read == -1 || this.f8582c.m3721h()) {
                        break;
                    }
                    outputStream.write(bArr, 0, read);
                    if (this.f8582c.m3719f() != null) {
                        int i2 = (contentLength > 0L ? 1 : (contentLength == 0L ? 0 : -1));
                    }
                }
                outputStream.flush();
            } catch (Exception e2) {
                e2.getCause();
                throw new IOException("HttpWorker Request Error!" + e2.getLocalizedMessage());
            }
        } finally {
            C3158r.m3717a(m3658a);
        }
    }

    /* renamed from: b */
    private static long m3707b(HttpResponse httpResponse) {
        Header firstHeader = httpResponse.getFirstHeader("Cache-Control");
        if (firstHeader != null) {
            String[] split = firstHeader.getValue().split("=");
            if (split.length >= 2) {
                try {
                    return m3702a(split);
                } catch (NumberFormatException unused) {
                }
            }
        }
        Header firstHeader2 = httpResponse.getFirstHeader("Expires");
        if (firstHeader2 != null) {
            return C3142b.m3663b(firstHeader2.getValue()) - System.currentTimeMillis();
        }
        return 0L;
    }

    /* renamed from: b */
    private URI m3708b() {
        String m3687a = this.f8582c.m3687a();
        String str = this.f8583d;
        if (str != null) {
            m3687a = str;
        }
        if (m3687a != null) {
            return new URI(m3687a);
        }
        throw new RuntimeException("url should not be null");
    }

    /* renamed from: c */
    private HttpUriRequest m3709c() {
        HttpUriRequest httpUriRequest = this.f8584f;
        if (httpUriRequest != null) {
            return httpUriRequest;
        }
        if (this.f8588j == null) {
            byte[] m3694b = this.f8582c.m3694b();
            String m3693b = this.f8582c.m3693b("gzip");
            if (m3694b != null) {
                if (TextUtils.equals(m3693b, "true")) {
                    this.f8588j = C3142b.m3661a(m3694b);
                } else {
                    this.f8588j = new ByteArrayEntity(m3694b);
                }
                this.f8588j.setContentType(this.f8582c.m3695c());
            }
        }
        AbstractHttpEntity abstractHttpEntity = this.f8588j;
        if (abstractHttpEntity != null) {
            HttpPost httpPost = new HttpPost(m3708b());
            httpPost.setEntity(abstractHttpEntity);
            this.f8584f = httpPost;
        } else {
            this.f8584f = new HttpGet(m3708b());
        }
        return this.f8584f;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Removed duplicated region for block: B:32:0x0106  */
    /* JADX WARN: Removed duplicated region for block: B:35:0x0127 A[Catch: Exception -> 0x0260, NullPointerException -> 0x0282, IOException -> 0x02a6, UnknownHostException -> 0x02d0, HttpHostConnectException -> 0x02fc, NoHttpResponseException -> 0x0320, SocketTimeoutException -> 0x034b, ConnectTimeoutException -> 0x0376, ConnectionPoolTimeoutException -> 0x03a0, SSLException -> 0x03ca, SSLPeerUnverifiedException -> 0x03f4, SSLHandshakeException -> 0x041e, URISyntaxException -> 0x0448, HttpException -> 0x0455, TryCatch #3 {HttpException -> 0x0455, NullPointerException -> 0x0282, SocketTimeoutException -> 0x034b, URISyntaxException -> 0x0448, UnknownHostException -> 0x02d0, SSLHandshakeException -> 0x041e, SSLPeerUnverifiedException -> 0x03f4, SSLException -> 0x03ca, NoHttpResponseException -> 0x0320, ConnectionPoolTimeoutException -> 0x03a0, ConnectTimeoutException -> 0x0376, HttpHostConnectException -> 0x02fc, IOException -> 0x02a6, Exception -> 0x0260, blocks: (B:4:0x0006, B:8:0x0032, B:10:0x003a, B:12:0x0040, B:13:0x0044, B:15:0x004a, B:17:0x0058, B:19:0x00d0, B:21:0x00d6, B:23:0x00e0, B:25:0x00e9, B:27:0x00f5, B:30:0x00ff, B:33:0x011f, B:35:0x0127, B:36:0x0134, B:38:0x015a, B:39:0x0161, B:41:0x0167, B:42:0x016b, B:44:0x0171, B:47:0x017d, B:50:0x01ac, B:56:0x01c8, B:63:0x01e5, B:64:0x01fe, B:67:0x01ff, B:69:0x0207, B:71:0x020d, B:74:0x0219, B:76:0x021d, B:81:0x022d, B:83:0x0235, B:85:0x023f, B:88:0x0107, B:91:0x0254, B:92:0x025f, B:93:0x0017, B:95:0x001b, B:97:0x001f, B:99:0x0025, B:104:0x002d), top: B:3:0x0006 }] */
    /* JADX WARN: Removed duplicated region for block: B:38:0x015a A[Catch: Exception -> 0x0260, NullPointerException -> 0x0282, IOException -> 0x02a6, UnknownHostException -> 0x02d0, HttpHostConnectException -> 0x02fc, NoHttpResponseException -> 0x0320, SocketTimeoutException -> 0x034b, ConnectTimeoutException -> 0x0376, ConnectionPoolTimeoutException -> 0x03a0, SSLException -> 0x03ca, SSLPeerUnverifiedException -> 0x03f4, SSLHandshakeException -> 0x041e, URISyntaxException -> 0x0448, HttpException -> 0x0455, TryCatch #3 {HttpException -> 0x0455, NullPointerException -> 0x0282, SocketTimeoutException -> 0x034b, URISyntaxException -> 0x0448, UnknownHostException -> 0x02d0, SSLHandshakeException -> 0x041e, SSLPeerUnverifiedException -> 0x03f4, SSLException -> 0x03ca, NoHttpResponseException -> 0x0320, ConnectionPoolTimeoutException -> 0x03a0, ConnectTimeoutException -> 0x0376, HttpHostConnectException -> 0x02fc, IOException -> 0x02a6, Exception -> 0x0260, blocks: (B:4:0x0006, B:8:0x0032, B:10:0x003a, B:12:0x0040, B:13:0x0044, B:15:0x004a, B:17:0x0058, B:19:0x00d0, B:21:0x00d6, B:23:0x00e0, B:25:0x00e9, B:27:0x00f5, B:30:0x00ff, B:33:0x011f, B:35:0x0127, B:36:0x0134, B:38:0x015a, B:39:0x0161, B:41:0x0167, B:42:0x016b, B:44:0x0171, B:47:0x017d, B:50:0x01ac, B:56:0x01c8, B:63:0x01e5, B:64:0x01fe, B:67:0x01ff, B:69:0x0207, B:71:0x020d, B:74:0x0219, B:76:0x021d, B:81:0x022d, B:83:0x0235, B:85:0x023f, B:88:0x0107, B:91:0x0254, B:92:0x025f, B:93:0x0017, B:95:0x001b, B:97:0x001f, B:99:0x0025, B:104:0x002d), top: B:3:0x0006 }] */
    /* JADX WARN: Removed duplicated region for block: B:41:0x0167 A[Catch: Exception -> 0x0260, NullPointerException -> 0x0282, IOException -> 0x02a6, UnknownHostException -> 0x02d0, HttpHostConnectException -> 0x02fc, NoHttpResponseException -> 0x0320, SocketTimeoutException -> 0x034b, ConnectTimeoutException -> 0x0376, ConnectionPoolTimeoutException -> 0x03a0, SSLException -> 0x03ca, SSLPeerUnverifiedException -> 0x03f4, SSLHandshakeException -> 0x041e, URISyntaxException -> 0x0448, HttpException -> 0x0455, TryCatch #3 {HttpException -> 0x0455, NullPointerException -> 0x0282, SocketTimeoutException -> 0x034b, URISyntaxException -> 0x0448, UnknownHostException -> 0x02d0, SSLHandshakeException -> 0x041e, SSLPeerUnverifiedException -> 0x03f4, SSLException -> 0x03ca, NoHttpResponseException -> 0x0320, ConnectionPoolTimeoutException -> 0x03a0, ConnectTimeoutException -> 0x0376, HttpHostConnectException -> 0x02fc, IOException -> 0x02a6, Exception -> 0x0260, blocks: (B:4:0x0006, B:8:0x0032, B:10:0x003a, B:12:0x0040, B:13:0x0044, B:15:0x004a, B:17:0x0058, B:19:0x00d0, B:21:0x00d6, B:23:0x00e0, B:25:0x00e9, B:27:0x00f5, B:30:0x00ff, B:33:0x011f, B:35:0x0127, B:36:0x0134, B:38:0x015a, B:39:0x0161, B:41:0x0167, B:42:0x016b, B:44:0x0171, B:47:0x017d, B:50:0x01ac, B:56:0x01c8, B:63:0x01e5, B:64:0x01fe, B:67:0x01ff, B:69:0x0207, B:71:0x020d, B:74:0x0219, B:76:0x021d, B:81:0x022d, B:83:0x0235, B:85:0x023f, B:88:0x0107, B:91:0x0254, B:92:0x025f, B:93:0x0017, B:95:0x001b, B:97:0x001f, B:99:0x0025, B:104:0x002d), top: B:3:0x0006 }] */
    /* JADX WARN: Removed duplicated region for block: B:58:0x01dc  */
    /* JADX WARN: Removed duplicated region for block: B:88:0x0107 A[Catch: Exception -> 0x0260, NullPointerException -> 0x0282, IOException -> 0x02a6, UnknownHostException -> 0x02d0, HttpHostConnectException -> 0x02fc, NoHttpResponseException -> 0x0320, SocketTimeoutException -> 0x034b, ConnectTimeoutException -> 0x0376, ConnectionPoolTimeoutException -> 0x03a0, SSLException -> 0x03ca, SSLPeerUnverifiedException -> 0x03f4, SSLHandshakeException -> 0x041e, URISyntaxException -> 0x0448, HttpException -> 0x0455, TryCatch #3 {HttpException -> 0x0455, NullPointerException -> 0x0282, SocketTimeoutException -> 0x034b, URISyntaxException -> 0x0448, UnknownHostException -> 0x02d0, SSLHandshakeException -> 0x041e, SSLPeerUnverifiedException -> 0x03f4, SSLException -> 0x03ca, NoHttpResponseException -> 0x0320, ConnectionPoolTimeoutException -> 0x03a0, ConnectTimeoutException -> 0x0376, HttpHostConnectException -> 0x02fc, IOException -> 0x02a6, Exception -> 0x0260, blocks: (B:4:0x0006, B:8:0x0032, B:10:0x003a, B:12:0x0040, B:13:0x0044, B:15:0x004a, B:17:0x0058, B:19:0x00d0, B:21:0x00d6, B:23:0x00e0, B:25:0x00e9, B:27:0x00f5, B:30:0x00ff, B:33:0x011f, B:35:0x0127, B:36:0x0134, B:38:0x015a, B:39:0x0161, B:41:0x0167, B:42:0x016b, B:44:0x0171, B:47:0x017d, B:50:0x01ac, B:56:0x01c8, B:63:0x01e5, B:64:0x01fe, B:67:0x01ff, B:69:0x0207, B:71:0x020d, B:74:0x0219, B:76:0x021d, B:81:0x022d, B:83:0x0235, B:85:0x023f, B:88:0x0107, B:91:0x0254, B:92:0x025f, B:93:0x0017, B:95:0x001b, B:97:0x001f, B:99:0x0025, B:104:0x002d), top: B:3:0x0006 }] */
    @Override // java.util.concurrent.Callable
    /* renamed from: d, reason: merged with bridge method [inline-methods] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public com.alipay.android.phone.mrpc.core.C3161u call() {
        /*
            Method dump skipped, instructions count: 1136
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.alipay.android.phone.mrpc.core.CallableC3157q.call():com.alipay.android.phone.mrpc.core.u");
    }

    /* renamed from: e */
    private void m3711e() {
        HttpUriRequest httpUriRequest = this.f8584f;
        if (httpUriRequest != null) {
            httpUriRequest.abort();
        }
    }

    /* renamed from: f */
    private String m3712f() {
        if (!TextUtils.isEmpty(this.f8595q)) {
            return this.f8595q;
        }
        String m3693b = this.f8582c.m3693b("operationType");
        this.f8595q = m3693b;
        return m3693b;
    }

    /* renamed from: g */
    private int m3713g() {
        URL m3714h = m3714h();
        return m3714h.getPort() == -1 ? m3714h.getDefaultPort() : m3714h.getPort();
    }

    /* renamed from: h */
    private URL m3714h() {
        URL url = this.f8590l;
        if (url != null) {
            return url;
        }
        URL url2 = new URL(this.f8582c.m3687a());
        this.f8590l = url2;
        return url2;
    }

    /* renamed from: i */
    private CookieManager m3715i() {
        CookieManager cookieManager = this.f8587i;
        if (cookieManager != null) {
            return cookieManager;
        }
        CookieManager cookieManager2 = CookieManager.getInstance();
        this.f8587i = cookieManager2;
        return cookieManager2;
    }

    /* renamed from: a */
    public final C3155o m3716a() {
        return this.f8582c;
    }
}
