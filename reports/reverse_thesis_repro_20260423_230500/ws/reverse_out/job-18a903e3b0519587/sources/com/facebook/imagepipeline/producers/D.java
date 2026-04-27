package com.facebook.imagepipeline.producers;

import android.net.Uri;
import com.facebook.common.time.RealtimeSinceBootClock;
import com.facebook.imagepipeline.producers.X;
import e0.InterfaceC0512b;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/* JADX INFO: loaded from: classes.dex */
public class D extends AbstractC0359d {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private int f6099a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private String f6100b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final Map f6101c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final ExecutorService f6102d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final InterfaceC0512b f6103e;

    class a implements Runnable {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ c f6104b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ X.a f6105c;

        a(c cVar, X.a aVar) {
            this.f6104b = cVar;
            this.f6105c = aVar;
        }

        @Override // java.lang.Runnable
        public void run() throws Throwable {
            D.this.j(this.f6104b, this.f6105c);
        }
    }

    class b extends AbstractC0361f {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ Future f6107a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ X.a f6108b;

        b(Future future, X.a aVar) {
            this.f6107a = future;
            this.f6108b = aVar;
        }

        @Override // com.facebook.imagepipeline.producers.f0
        public void a() {
            if (this.f6107a.cancel(false)) {
                this.f6108b.b();
            }
        }
    }

    public static class c extends C {

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        private long f6110f;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        private long f6111g;

        /* JADX INFO: renamed from: h, reason: collision with root package name */
        private long f6112h;

        public c(InterfaceC0369n interfaceC0369n, e0 e0Var) {
            super(interfaceC0369n, e0Var);
        }
    }

    public D(int i3) {
        this(null, null, RealtimeSinceBootClock.get());
        this.f6099a = i3;
    }

    private HttpURLConnection g(Uri uri, int i3) throws IOException {
        HttpURLConnection httpURLConnectionO = o(uri);
        String str = this.f6100b;
        if (str != null) {
            httpURLConnectionO.setRequestProperty("User-Agent", str);
        }
        Map map = this.f6101c;
        if (map != null) {
            for (Map.Entry entry : map.entrySet()) {
                httpURLConnectionO.setRequestProperty((String) entry.getKey(), (String) entry.getValue());
            }
        }
        httpURLConnectionO.setConnectTimeout(this.f6099a);
        int responseCode = httpURLConnectionO.getResponseCode();
        if (m(responseCode)) {
            return httpURLConnectionO;
        }
        if (!l(responseCode)) {
            httpURLConnectionO.disconnect();
            throw new IOException(String.format("Image URL %s returned HTTP code %d", uri.toString(), Integer.valueOf(responseCode)));
        }
        String headerField = httpURLConnectionO.getHeaderField("Location");
        httpURLConnectionO.disconnect();
        Uri uri2 = headerField == null ? null : Uri.parse(headerField);
        String scheme = uri.getScheme();
        if (i3 <= 0 || uri2 == null || X.i.a(uri2.getScheme(), scheme)) {
            throw new IOException(i3 == 0 ? h("URL %s follows too many redirects", uri.toString()) : h("URL %s returned %d without a valid redirect", uri.toString(), Integer.valueOf(responseCode)));
        }
        return g(uri2, i3 - 1);
    }

    private static String h(String str, Object... objArr) {
        return String.format(Locale.getDefault(), str, objArr);
    }

    private static boolean l(int i3) {
        if (i3 == 307 || i3 == 308) {
            return true;
        }
        switch (i3) {
            case 300:
            case 301:
            case 302:
            case 303:
                return true;
            default:
                return false;
        }
    }

    private static boolean m(int i3) {
        return i3 >= 200 && i3 < 300;
    }

    static HttpURLConnection o(Uri uri) {
        return (HttpURLConnection) f0.f.p(uri).openConnection();
    }

    @Override // com.facebook.imagepipeline.producers.X
    /* JADX INFO: renamed from: f, reason: merged with bridge method [inline-methods] */
    public c c(InterfaceC0369n interfaceC0369n, e0 e0Var) {
        return new c(interfaceC0369n, e0Var);
    }

    @Override // com.facebook.imagepipeline.producers.X
    /* JADX INFO: renamed from: i, reason: merged with bridge method [inline-methods] */
    public void b(c cVar, X.a aVar) {
        cVar.f6110f = this.f6103e.now();
        cVar.b().Z(new b(this.f6102d.submit(new a(cVar, aVar)), aVar));
    }

    /* JADX WARN: Removed duplicated region for block: B:29:0x0045  */
    /* JADX WARN: Removed duplicated region for block: B:38:0x0040 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:47:? A[SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    void j(com.facebook.imagepipeline.producers.D.c r5, com.facebook.imagepipeline.producers.X.a r6) throws java.lang.Throwable {
        /*
            r4 = this;
            r0 = 0
            android.net.Uri r1 = r5.g()     // Catch: java.lang.Throwable -> L2d java.io.IOException -> L30
            r2 = 5
            java.net.HttpURLConnection r1 = r4.g(r1, r2)     // Catch: java.lang.Throwable -> L2d java.io.IOException -> L30
            e0.b r2 = r4.f6103e     // Catch: java.lang.Throwable -> L1e java.io.IOException -> L20
            long r2 = r2.now()     // Catch: java.lang.Throwable -> L1e java.io.IOException -> L20
            com.facebook.imagepipeline.producers.D.c.o(r5, r2)     // Catch: java.lang.Throwable -> L1e java.io.IOException -> L20
            if (r1 == 0) goto L22
            java.io.InputStream r0 = r1.getInputStream()     // Catch: java.lang.Throwable -> L1e java.io.IOException -> L20
            r5 = -1
            r6.c(r0, r5)     // Catch: java.lang.Throwable -> L1e java.io.IOException -> L20
            goto L22
        L1e:
            r5 = move-exception
            goto L3e
        L20:
            r5 = move-exception
            goto L32
        L22:
            if (r0 == 0) goto L27
            r0.close()     // Catch: java.io.IOException -> L27
        L27:
            if (r1 == 0) goto L3d
        L29:
            r1.disconnect()
            goto L3d
        L2d:
            r5 = move-exception
            r1 = r0
            goto L3e
        L30:
            r5 = move-exception
            r1 = r0
        L32:
            r6.a(r5)     // Catch: java.lang.Throwable -> L1e
            if (r0 == 0) goto L3a
            r0.close()     // Catch: java.io.IOException -> L3a
        L3a:
            if (r1 == 0) goto L3d
            goto L29
        L3d:
            return
        L3e:
            if (r0 == 0) goto L43
            r0.close()     // Catch: java.io.IOException -> L43
        L43:
            if (r1 == 0) goto L48
            r1.disconnect()
        L48:
            throw r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.imagepipeline.producers.D.j(com.facebook.imagepipeline.producers.D$c, com.facebook.imagepipeline.producers.X$a):void");
    }

    @Override // com.facebook.imagepipeline.producers.X
    /* JADX INFO: renamed from: k, reason: merged with bridge method [inline-methods] */
    public Map e(c cVar, int i3) {
        HashMap map = new HashMap(4);
        map.put("queue_time", Long.toString(cVar.f6111g - cVar.f6110f));
        map.put("fetch_time", Long.toString(cVar.f6112h - cVar.f6111g));
        map.put("total_time", Long.toString(cVar.f6112h - cVar.f6110f));
        map.put("image_size", Integer.toString(i3));
        return map;
    }

    @Override // com.facebook.imagepipeline.producers.X
    /* JADX INFO: renamed from: n, reason: merged with bridge method [inline-methods] */
    public void a(c cVar, int i3) {
        cVar.f6112h = this.f6103e.now();
    }

    D(String str, Map map, InterfaceC0512b interfaceC0512b) {
        this.f6102d = Executors.newFixedThreadPool(3);
        this.f6103e = interfaceC0512b;
        this.f6101c = map;
        this.f6100b = str;
    }
}
