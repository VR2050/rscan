package p005b.p006a.p007a.p008a.p017r.p020m;

import java.io.EOFException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import kotlin.p472io.CloseableKt;
import kotlin.ranges.RangesKt___RangesKt;
import kotlin.text.Charsets;
import kotlin.text.StringsKt__StringsJVMKt;
import org.jetbrains.annotations.NotNull;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p458k.AbstractC4387j0;
import p458k.AbstractC4393m0;
import p458k.C4371b0;
import p458k.C4381g0;
import p458k.C4389k0;
import p458k.C4488y;
import p458k.InterfaceC4369a0;
import p458k.InterfaceC4388k;
import p458k.p459p0.p462f.C4418h;
import p458k.p459p0.p463g.C4428e;
import p458k.p459p0.p463g.C4430g;
import p458k.p459p0.p467k.C4463g;
import p474l.C4744f;
import p474l.C4751m;
import p474l.InterfaceC4746h;

/* renamed from: b.a.a.a.r.m.b */
/* loaded from: classes2.dex */
public final class C0941b implements InterfaceC4369a0 {

    /* renamed from: a */
    @NotNull
    public final Lazy f467a = LazyKt__LazyJVMKt.lazy(a.f468c);

    /* renamed from: b.a.a.a.r.m.b$a */
    public static final class a extends Lambda implements Function0<C4463g> {

        /* renamed from: c */
        public static final a f468c = new a();

        public a() {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        public C4463g invoke() {
            C4463g.a aVar = C4463g.f11988c;
            return C4463g.f11986a;
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // p458k.InterfaceC4369a0
    @NotNull
    /* renamed from: a */
    public C4389k0 mo280a(@NotNull InterfaceC4369a0.a chain) {
        String str;
        String str2;
        char c2;
        Long l2;
        Charset charset;
        byte[] bArr;
        Intrinsics.checkNotNullParameter(chain, "chain");
        C4430g c4430g = (C4430g) chain;
        C4381g0 c4381g0 = c4430g.f11739f;
        AbstractC4387j0 abstractC4387j0 = c4381g0.f11443e;
        InterfaceC4388k m5138c = c4430g.m5138c();
        StringBuilder m586H = C1499a.m586H("--> ");
        m586H.append(c4381g0.f11441c);
        m586H.append(' ');
        m586H.append(c4381g0.f11440b);
        String str3 = "";
        m586H.append(m5138c != null ? Intrinsics.stringPlus(" ", ((C4418h) m5138c).m5105i()) : "");
        String sb = m586H.toString();
        if (abstractC4387j0 != null) {
            StringBuilder m590L = C1499a.m590L(sb, " (");
            m590L.append(abstractC4387j0.mo4920a());
            m590L.append("-byte body)");
            sb = m590L.toString();
        }
        C4463g.m5248l(m282c(), sb, 0, null, 6, null);
        C4488y c4488y = c4381g0.f11442d;
        if (abstractC4387j0 != null) {
            C4371b0 mo4921b = abstractC4387j0.mo4921b();
            if (mo4921b != null && c4488y.m5277a("Content-Type") == null) {
                C4463g.m5248l(m282c(), Intrinsics.stringPlus("Content-Type: ", mo4921b), 0, null, 6, null);
            }
            if (abstractC4387j0.mo4920a() != -1 && c4488y.m5277a("Content-Length") == null) {
                C4463g.m5248l(m282c(), Intrinsics.stringPlus("Content-Length: ", Long.valueOf(abstractC4387j0.mo4920a())), 0, null, 6, null);
            }
        }
        int size = c4488y.size();
        if (size > 0) {
            int i2 = 0;
            while (true) {
                int i3 = i2 + 1;
                m284e(c4488y, i2);
                if (i3 >= size) {
                    break;
                }
                i2 = i3;
            }
        }
        if (abstractC4387j0 == null) {
            C4463g.m5248l(m282c(), Intrinsics.stringPlus("--> END ", c4381g0.f11441c), 0, null, 6, null);
        } else if (m281b(c4381g0.f11442d)) {
            C4463g.m5248l(m282c(), C1499a.m582D(C1499a.m586H("--> END "), c4381g0.f11441c, " (encoded body omitted)"), 0, null, 6, null);
        } else {
            C4744f c4744f = new C4744f();
            abstractC4387j0.mo4922d(c4744f);
            C4371b0 mo4921b2 = abstractC4387j0.mo4921b();
            Charset UTF_8 = mo4921b2 == null ? null : mo4921b2.m4944a(StandardCharsets.UTF_8);
            if (UTF_8 == null) {
                UTF_8 = StandardCharsets.UTF_8;
                Intrinsics.checkNotNullExpressionValue(UTF_8, "UTF_8");
            }
            C4463g.m5248l(m282c(), "", 0, null, 6, null);
            if (m283d(c4744f)) {
                C4463g.m5248l(m282c(), c4744f.mo5395w(UTF_8), 0, null, 6, null);
                C4463g m282c = m282c();
                StringBuilder m586H2 = C1499a.m586H("--> END ");
                m586H2.append(c4381g0.f11441c);
                m586H2.append(" (");
                m586H2.append(abstractC4387j0.mo4920a());
                m586H2.append("-byte body)");
                C4463g.m5248l(m282c, m586H2.toString(), 0, null, 6, null);
            } else {
                C4463g m282c2 = m282c();
                StringBuilder m586H3 = C1499a.m586H("--> END ");
                m586H3.append(c4381g0.f11441c);
                m586H3.append(" (binary ");
                m586H3.append(abstractC4387j0.mo4920a());
                m586H3.append("-byte body omitted)");
                C4463g.m5248l(m282c2, m586H3.toString(), 0, null, 6, null);
            }
        }
        long nanoTime = System.nanoTime();
        try {
            C4389k0 m5139d = c4430g.m5139d(c4381g0);
            long millis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - nanoTime);
            AbstractC4393m0 abstractC4393m0 = m5139d.f11491k;
            if (abstractC4393m0 == null) {
                return m5139d;
            }
            long mo4925d = abstractC4393m0.mo4925d();
            if (mo4925d != -1) {
                str = mo4925d + "-byte";
            } else {
                str = "unknown-length";
            }
            C4463g m282c3 = m282c();
            StringBuilder m586H4 = C1499a.m586H("<-- ");
            m586H4.append(m5139d.f11488h);
            if (m5139d.f11487g.length() == 0) {
                c2 = ' ';
                str2 = "-byte body)";
            } else {
                String str4 = m5139d.f11487g;
                StringBuilder sb2 = new StringBuilder();
                str2 = "-byte body)";
                sb2.append(' ');
                sb2.append(str4);
                str3 = sb2.toString();
                c2 = ' ';
            }
            m586H4.append(str3);
            m586H4.append(c2);
            m586H4.append(m5139d.f11485e.f11440b);
            m586H4.append(" (");
            m586H4.append(millis);
            C4463g.m5248l(m282c3, C1499a.m583E(m586H4, "ms ", str, " body"), 0, null, 6, null);
            C4488y c4488y2 = m5139d.f11490j;
            int size2 = c4488y2.size();
            if (size2 > 0) {
                int i4 = 0;
                while (true) {
                    int i5 = i4 + 1;
                    m284e(c4488y2, i4);
                    if (i5 >= size2) {
                        break;
                    }
                    i4 = i5;
                }
            }
            if (!C4428e.m5135a(m5139d)) {
                C4463g.m5248l(m282c(), "<-- END HTTP", 0, null, 6, null);
            } else if (m281b(m5139d.f11490j)) {
                C4463g.m5248l(m282c(), "<-- END HTTP (encoded body omitted)", 0, null, 6, null);
            } else {
                InterfaceC4746h mo4927k = abstractC4393m0.mo4927k();
                mo4927k.mo5350A(Long.MAX_VALUE);
                C4744f buffer = mo4927k.getBuffer();
                if (StringsKt__StringsJVMKt.equals("gzip", c4488y.m5277a("Content-Encoding"), true)) {
                    l2 = Long.valueOf(buffer.f12133e);
                    C4751m c4751m = new C4751m(buffer.clone());
                    try {
                        buffer = new C4744f();
                        buffer.mo5396y(c4751m);
                        charset = null;
                        CloseableKt.closeFinally(c4751m, null);
                    } finally {
                    }
                } else {
                    l2 = null;
                    charset = null;
                }
                C4371b0 mo4926e = abstractC4393m0.mo4926e();
                Charset UTF_82 = mo4926e == null ? charset : mo4926e.m4944a(StandardCharsets.UTF_8);
                if (UTF_82 == null) {
                    UTF_82 = StandardCharsets.UTF_8;
                    Intrinsics.checkNotNullExpressionValue(UTF_82, "UTF_8");
                }
                if (!m283d(buffer)) {
                    C4463g.m5248l(m282c(), "", 0, null, 6, null);
                    byte[] mo5386l = buffer.clone().mo5386l();
                    try {
                        try {
                            SecretKeySpec secretKeySpec = new SecretKeySpec("67f69826eac1a4f1".getBytes(), "AES-128-ECB");
                            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                            cipher.init(2, secretKeySpec);
                            bArr = cipher.doFinal(mo5386l);
                        } catch (Exception e2) {
                            System.out.println(e2.toString());
                            bArr = charset;
                        }
                        Intrinsics.checkNotNullExpressionValue(bArr, "AesSecurity().decryptOrigin(responseBuffer, NetConfig.AES_KEY)");
                        C2354n.m2454a1(new String(bArr, Charsets.UTF_8));
                    } catch (Exception unused) {
                        C4463g.m5248l(m282c(), new String(mo5386l, Charsets.UTF_8), 0, null, 6, null);
                    }
                    C4463g m282c4 = m282c();
                    StringBuilder m586H5 = C1499a.m586H("<-- END HTTP (binary ");
                    m586H5.append(buffer.f12133e);
                    m586H5.append("-byte body omitted)");
                    C4463g.m5248l(m282c4, m586H5.toString(), 0, null, 6, null);
                    return m5139d;
                }
                if (mo4925d != 0) {
                    C4463g.m5248l(m282c(), "", 0, null, 6, null);
                    C4463g.m5248l(m282c(), buffer.clone().mo5395w(UTF_82), 0, null, 6, null);
                }
                if (l2 != null) {
                    C4463g m282c5 = m282c();
                    StringBuilder m586H6 = C1499a.m586H("<-- END HTTP (");
                    m586H6.append(buffer.f12133e);
                    m586H6.append("-byte, ");
                    m586H6.append(l2);
                    m586H6.append("-gzipped-byte body)");
                    C4463g.m5248l(m282c5, m586H6.toString(), 0, null, 6, null);
                } else {
                    C4463g m282c6 = m282c();
                    StringBuilder m586H7 = C1499a.m586H("<-- END HTTP (");
                    m586H7.append(buffer.f12133e);
                    m586H7.append(str2);
                    C4463g.m5248l(m282c6, m586H7.toString(), 0, null, 6, null);
                }
            }
            return m5139d;
        } catch (Exception e3) {
            C4463g.m5248l(m282c(), Intrinsics.stringPlus("<-- HTTP FAILED: ", e3), 0, null, 6, null);
            throw e3;
        }
    }

    /* renamed from: b */
    public final boolean m281b(C4488y c4488y) {
        String m5277a = c4488y.m5277a("Content-Encoding");
        return (m5277a == null || StringsKt__StringsJVMKt.equals(m5277a, "identity", true) || StringsKt__StringsJVMKt.equals(m5277a, "gzip", true)) ? false : true;
    }

    /* renamed from: c */
    public final C4463g m282c() {
        return (C4463g) this.f467a.getValue();
    }

    /* renamed from: d */
    public final boolean m283d(C4744f c4744f) {
        try {
            C4744f c4744f2 = new C4744f();
            c4744f.m5392t(c4744f2, 0L, RangesKt___RangesKt.coerceAtMost(c4744f.f12133e, 64L));
            int i2 = 0;
            do {
                i2++;
                if (c4744f2.mo5387m()) {
                    break;
                }
                int m5367U = c4744f2.m5367U();
                if (Character.isISOControl(m5367U) && !Character.isWhitespace(m5367U)) {
                    return false;
                }
            } while (i2 < 16);
            return true;
        } catch (EOFException unused) {
            return false;
        }
    }

    /* renamed from: e */
    public final void m284e(C4488y c4488y, int i2) {
        C4463g m282c = m282c();
        StringBuilder sb = new StringBuilder();
        int i3 = i2 * 2;
        sb.append(c4488y.f12041e[i3]);
        sb.append(": ");
        sb.append(c4488y.f12041e[i3 + 1]);
        C4463g.m5248l(m282c, sb.toString(), 0, null, 6, null);
    }
}
