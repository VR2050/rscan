package p005b.p085c.p088b.p094e;

import java.net.CookieManager;
import java.util.List;
import java.util.Map;

/* renamed from: b.c.b.e.a */
/* loaded from: classes.dex */
public final class C1362a {

    /* renamed from: a */
    public static final CookieManager f1229a = new CookieManager();

    /* renamed from: b.c.b.e.a$a */
    public static final class a {

        /* renamed from: a */
        public final String f1230a;

        /* renamed from: b */
        public final byte[] f1231b;

        /* renamed from: c */
        public final Map<String, String> f1232c;

        public a(String str, Map<String, String> map, byte[] bArr) {
            this.f1230a = str;
            this.f1231b = bArr;
            this.f1232c = map;
        }

        public String toString() {
            return String.format("<UrlConnectionConfigure url=%s headers=%s>", this.f1230a, this.f1232c);
        }
    }

    /* renamed from: b.c.b.e.a$b */
    public static final class b {

        /* renamed from: a */
        public final Map<String, List<String>> f1233a;

        /* renamed from: b */
        public final byte[] f1234b;

        public b(Map<String, List<String>> map, String str, byte[] bArr) {
            this.f1233a = map;
            this.f1234b = bArr;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:100:0x01c5 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:104:0x01be A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:108:0x01b7 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* renamed from: a */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static p005b.p085c.p088b.p094e.C1362a.b m393a(android.content.Context r11, p005b.p085c.p088b.p094e.C1362a.a r12) {
        /*
            Method dump skipped, instructions count: 478
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p085c.p088b.p094e.C1362a.m393a(android.content.Context, b.c.b.e.a$a):b.c.b.e.a$b");
    }

    /* JADX WARN: Removed duplicated region for block: B:14:0x0049 A[Catch: all -> 0x005a, TRY_LEAVE, TryCatch #2 {all -> 0x005a, blocks: (B:12:0x0037, B:14:0x0049), top: B:11:0x0037 }] */
    /* JADX WARN: Removed duplicated region for block: B:18:? A[RETURN, SYNTHETIC] */
    /* renamed from: b */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.net.Proxy m394b(android.content.Context r5) {
        /*
            r0 = 0
            java.lang.String r1 = "connectivity"
            java.lang.Object r5 = r5.getSystemService(r1)     // Catch: java.lang.Exception -> Le
            android.net.ConnectivityManager r5 = (android.net.ConnectivityManager) r5     // Catch: java.lang.Exception -> Le
            android.net.NetworkInfo r5 = r5.getActiveNetworkInfo()     // Catch: java.lang.Exception -> Le
            goto Lf
        Le:
            r5 = r0
        Lf:
            if (r5 == 0) goto L2a
            boolean r1 = r5.isAvailable()     // Catch: java.lang.Exception -> L2a
            if (r1 == 0) goto L2a
            int r1 = r5.getType()     // Catch: java.lang.Exception -> L2a
            r2 = 1
            if (r1 != r2) goto L21
            java.lang.String r5 = "wifi"
            goto L2c
        L21:
            java.lang.String r5 = r5.getExtraInfo()     // Catch: java.lang.Exception -> L2a
            java.lang.String r5 = r5.toLowerCase()     // Catch: java.lang.Exception -> L2a
            goto L2c
        L2a:
            java.lang.String r5 = "none"
        L2c:
            if (r5 == 0) goto L37
            java.lang.String r1 = "wap"
            boolean r5 = r5.contains(r1)
            if (r5 != 0) goto L37
            return r0
        L37:
            java.lang.String r5 = "https.proxyHost"
            java.lang.String r5 = java.lang.System.getProperty(r5)     // Catch: java.lang.Throwable -> L5a
            java.lang.String r1 = "https.proxyPort"
            java.lang.String r1 = java.lang.System.getProperty(r1)     // Catch: java.lang.Throwable -> L5a
            boolean r2 = android.text.TextUtils.isEmpty(r5)     // Catch: java.lang.Throwable -> L5a
            if (r2 != 0) goto L5a
            java.net.Proxy r2 = new java.net.Proxy     // Catch: java.lang.Throwable -> L5a
            java.net.Proxy$Type r3 = java.net.Proxy.Type.HTTP     // Catch: java.lang.Throwable -> L5a
            java.net.InetSocketAddress r4 = new java.net.InetSocketAddress     // Catch: java.lang.Throwable -> L5a
            int r1 = java.lang.Integer.parseInt(r1)     // Catch: java.lang.Throwable -> L5a
            r4.<init>(r5, r1)     // Catch: java.lang.Throwable -> L5a
            r2.<init>(r3, r4)     // Catch: java.lang.Throwable -> L5a
            r0 = r2
        L5a:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p085c.p088b.p094e.C1362a.m394b(android.content.Context):java.net.Proxy");
    }
}
