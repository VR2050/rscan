package p458k.p459p0.p463g;

import java.util.Objects;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Regex;
import org.jetbrains.annotations.NotNull;
import p458k.C4375d0;
import p458k.C4381g0;
import p458k.C4389k0;
import p458k.C4489z;
import p458k.InterfaceC4369a0;
import p458k.p459p0.C4401c;

/* renamed from: k.p0.g.i */
/* loaded from: classes3.dex */
public final class C4432i implements InterfaceC4369a0 {

    /* renamed from: a */
    public final C4375d0 f11747a;

    public C4432i(@NotNull C4375d0 client) {
        Intrinsics.checkParameterIsNotNull(client, "client");
        this.f11747a = client;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:14:0x00c0  */
    /* JADX WARN: Removed duplicated region for block: B:192:0x035f A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:58:0x02d9  */
    /* JADX WARN: Removed duplicated region for block: B:92:0x02b6 A[SYNTHETIC] */
    /* JADX WARN: Type inference failed for: r18v1, types: [javax.net.ssl.SSLSocketFactory] */
    /* JADX WARN: Type inference failed for: r18v2 */
    /* JADX WARN: Type inference failed for: r18v3 */
    /* JADX WARN: Type inference failed for: r19v0 */
    /* JADX WARN: Type inference failed for: r19v1, types: [javax.net.ssl.HostnameVerifier] */
    /* JADX WARN: Type inference failed for: r19v2 */
    @Override // p458k.InterfaceC4369a0
    @org.jetbrains.annotations.NotNull
    /* renamed from: a */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public p458k.C4389k0 mo280a(@org.jetbrains.annotations.NotNull p458k.InterfaceC4369a0.a r47) {
        /*
            Method dump skipped, instructions count: 884
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p458k.p459p0.p463g.C4432i.mo280a(k.a0$a):k.k0");
    }

    /* renamed from: b */
    public final C4381g0 m5141b(C4389k0 c4389k0, String method) {
        String link;
        if (this.f11747a.f11374n && (link = C4389k0.m4987d(c4389k0, "Location", null, 2)) != null) {
            C4489z c4489z = c4389k0.f11485e.f11440b;
            Objects.requireNonNull(c4489z);
            Intrinsics.checkParameterIsNotNull(link, "link");
            C4489z.a m5296f = c4489z.m5296f(link);
            C4489z m5299a = m5296f != null ? m5296f.m5299a() : null;
            if (m5299a != null) {
                if (!Intrinsics.areEqual(m5299a.f12046d, c4389k0.f11485e.f11440b.f12046d) && !this.f11747a.f11375o) {
                    return null;
                }
                C4381g0.a aVar = new C4381g0.a(c4389k0.f11485e);
                if (C4429f.m5137a(method)) {
                    Intrinsics.checkParameterIsNotNull(method, "method");
                    boolean areEqual = Intrinsics.areEqual(method, "PROPFIND");
                    Intrinsics.checkParameterIsNotNull(method, "method");
                    if (!Intrinsics.areEqual(method, "PROPFIND")) {
                        aVar.m4975e("GET", null);
                    } else {
                        aVar.m4975e(method, areEqual ? c4389k0.f11485e.f11443e : null);
                    }
                    if (!areEqual) {
                        aVar.m4976f("Transfer-Encoding");
                        aVar.m4976f("Content-Length");
                        aVar.m4976f("Content-Type");
                    }
                }
                if (!C4401c.m5016a(c4389k0.f11485e.f11440b, m5299a)) {
                    aVar.m4976f("Authorization");
                }
                aVar.m4979i(m5299a);
                return aVar.m4972b();
            }
        }
        return null;
    }

    /* JADX WARN: Removed duplicated region for block: B:35:0x005a A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:36:0x005b A[RETURN] */
    /* renamed from: c */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean m5142c(java.io.IOException r3, p458k.p459p0.p462f.C4423m r4, boolean r5, p458k.C4381g0 r6) {
        /*
            r2 = this;
            k.d0 r0 = r2.f11747a
            boolean r0 = r0.f11372l
            r1 = 0
            if (r0 != 0) goto L8
            return r1
        L8:
            if (r5 == 0) goto L11
            k.j0 r6 = r6.f11443e
            boolean r6 = r3 instanceof java.io.FileNotFoundException
            if (r6 == 0) goto L11
            return r1
        L11:
            boolean r6 = r3 instanceof java.net.ProtocolException
            r0 = 1
            if (r6 == 0) goto L17
            goto L33
        L17:
            boolean r6 = r3 instanceof java.io.InterruptedIOException
            if (r6 == 0) goto L22
            boolean r3 = r3 instanceof java.net.SocketTimeoutException
            if (r3 == 0) goto L33
            if (r5 != 0) goto L33
            goto L35
        L22:
            boolean r5 = r3 instanceof javax.net.ssl.SSLHandshakeException
            if (r5 == 0) goto L2f
            java.lang.Throwable r5 = r3.getCause()
            boolean r5 = r5 instanceof java.security.cert.CertificateException
            if (r5 == 0) goto L2f
            goto L33
        L2f:
            boolean r3 = r3 instanceof javax.net.ssl.SSLPeerUnverifiedException
            if (r3 == 0) goto L35
        L33:
            r3 = 0
            goto L36
        L35:
            r3 = 1
        L36:
            if (r3 != 0) goto L39
            return r1
        L39:
            k.p0.f.d r3 = r4.f11717f
            if (r3 != 0) goto L40
            kotlin.jvm.internal.Intrinsics.throwNpe()
        L40:
            k.p0.f.i r5 = r3.f11666g
            monitor-enter(r5)
            boolean r3 = r3.f11663d     // Catch: java.lang.Throwable -> L5c
            monitor-exit(r5)
            if (r3 == 0) goto L57
            k.p0.f.d r3 = r4.f11717f
            if (r3 != 0) goto L4f
            kotlin.jvm.internal.Intrinsics.throwNpe()
        L4f:
            boolean r3 = r3.m5094c()
            if (r3 == 0) goto L57
            r3 = 1
            goto L58
        L57:
            r3 = 0
        L58:
            if (r3 != 0) goto L5b
            return r1
        L5b:
            return r0
        L5c:
            r3 = move-exception
            monitor-exit(r5)
            throw r3
        */
        throw new UnsupportedOperationException("Method not decompiled: p458k.p459p0.p463g.C4432i.m5142c(java.io.IOException, k.p0.f.m, boolean, k.g0):boolean");
    }

    /* renamed from: d */
    public final int m5143d(C4389k0 c4389k0, int i2) {
        String m4987d = C4389k0.m4987d(c4389k0, "Retry-After", null, 2);
        if (m4987d == null) {
            return i2;
        }
        if (!new Regex("\\d+").matches(m4987d)) {
            return Integer.MAX_VALUE;
        }
        Integer valueOf = Integer.valueOf(m4987d);
        Intrinsics.checkExpressionValueIsNotNull(valueOf, "Integer.valueOf(header)");
        return valueOf.intValue();
    }
}
