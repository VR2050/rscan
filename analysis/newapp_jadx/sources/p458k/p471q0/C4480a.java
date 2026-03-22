package p458k.p471q0;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import kotlin.collections.SetsKt__SetsKt;
import kotlin.jvm.JvmField;
import kotlin.jvm.JvmOverloads;
import kotlin.jvm.internal.Intrinsics;
import kotlin.p472io.CloseableKt;
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

/* renamed from: k.q0.a */
/* loaded from: classes3.dex */
public final class C4480a implements InterfaceC4369a0 {

    /* renamed from: a */
    public volatile Set<String> f12011a;

    /* renamed from: b */
    @NotNull
    public volatile a f12012b;

    /* renamed from: c */
    public final b f12013c;

    /* renamed from: k.q0.a$a */
    public enum a {
        NONE,
        /* JADX INFO: Fake field, exist only in values array */
        BASIC,
        HEADERS,
        BODY
    }

    /* renamed from: k.q0.a$b */
    public interface b {

        /* renamed from: a */
        @JvmField
        @NotNull
        public static final b f12018a = new b() { // from class: k.q0.b$a
            @Override // p458k.p471q0.C4480a.b
            /* renamed from: a */
            public void mo268a(@NotNull String message) {
                Intrinsics.checkParameterIsNotNull(message, "message");
                C4463g.a aVar = C4463g.f11988c;
                C4463g.m5248l(C4463g.f11986a, message, 0, null, 6, null);
            }
        };

        /* renamed from: a */
        void mo268a(@NotNull String str);
    }

    @JvmOverloads
    public C4480a(@NotNull b logger) {
        Intrinsics.checkParameterIsNotNull(logger, "logger");
        this.f12013c = logger;
        this.f12011a = SetsKt__SetsKt.emptySet();
        this.f12012b = a.NONE;
    }

    @Override // p458k.InterfaceC4369a0
    @NotNull
    /* renamed from: a */
    public C4389k0 mo280a(@NotNull InterfaceC4369a0.a chain) {
        String str;
        String str2;
        String sb;
        Charset UTF_8;
        Charset UTF_82;
        Intrinsics.checkParameterIsNotNull(chain, "chain");
        a aVar = this.f12012b;
        C4430g c4430g = (C4430g) chain;
        C4381g0 c4381g0 = c4430g.f11739f;
        if (aVar == a.NONE) {
            return c4430g.m5139d(c4381g0);
        }
        boolean z = aVar == a.BODY;
        boolean z2 = z || aVar == a.HEADERS;
        AbstractC4387j0 abstractC4387j0 = c4381g0.f11443e;
        InterfaceC4388k m5138c = c4430g.m5138c();
        StringBuilder m586H = C1499a.m586H("--> ");
        m586H.append(c4381g0.f11441c);
        m586H.append(' ');
        m586H.append(c4381g0.f11440b);
        if (m5138c != null) {
            StringBuilder m586H2 = C1499a.m586H(" ");
            m586H2.append(((C4418h) m5138c).m5105i());
            str = m586H2.toString();
        } else {
            str = "";
        }
        m586H.append(str);
        String sb2 = m586H.toString();
        if (!z2 && abstractC4387j0 != null) {
            StringBuilder m590L = C1499a.m590L(sb2, " (");
            m590L.append(abstractC4387j0.mo4920a());
            m590L.append("-byte body)");
            sb2 = m590L.toString();
        }
        this.f12013c.mo268a(sb2);
        if (z2) {
            C4488y c4488y = c4381g0.f11442d;
            if (abstractC4387j0 != null) {
                C4371b0 mo4921b = abstractC4387j0.mo4921b();
                if (mo4921b != null && c4488y.m5277a("Content-Type") == null) {
                    this.f12013c.mo268a("Content-Type: " + mo4921b);
                }
                if (abstractC4387j0.mo4920a() != -1 && c4488y.m5277a("Content-Length") == null) {
                    b bVar = this.f12013c;
                    StringBuilder m586H3 = C1499a.m586H("Content-Length: ");
                    m586H3.append(abstractC4387j0.mo4920a());
                    bVar.mo268a(m586H3.toString());
                }
            }
            int size = c4488y.size();
            for (int i2 = 0; i2 < size; i2++) {
                m5263c(c4488y, i2);
            }
            if (!z || abstractC4387j0 == null) {
                b bVar2 = this.f12013c;
                StringBuilder m586H4 = C1499a.m586H("--> END ");
                m586H4.append(c4381g0.f11441c);
                bVar2.mo268a(m586H4.toString());
            } else if (m5262b(c4381g0.f11442d)) {
                b bVar3 = this.f12013c;
                StringBuilder m586H5 = C1499a.m586H("--> END ");
                m586H5.append(c4381g0.f11441c);
                m586H5.append(" (encoded body omitted)");
                bVar3.mo268a(m586H5.toString());
            } else {
                C4744f c4744f = new C4744f();
                abstractC4387j0.mo4922d(c4744f);
                C4371b0 mo4921b2 = abstractC4387j0.mo4921b();
                if (mo4921b2 == null || (UTF_82 = mo4921b2.m4944a(StandardCharsets.UTF_8)) == null) {
                    UTF_82 = StandardCharsets.UTF_8;
                    Intrinsics.checkExpressionValueIsNotNull(UTF_82, "UTF_8");
                }
                this.f12013c.mo268a("");
                if (C2354n.m2417O0(c4744f)) {
                    this.f12013c.mo268a(c4744f.mo5395w(UTF_82));
                    b bVar4 = this.f12013c;
                    StringBuilder m586H6 = C1499a.m586H("--> END ");
                    m586H6.append(c4381g0.f11441c);
                    m586H6.append(" (");
                    m586H6.append(abstractC4387j0.mo4920a());
                    m586H6.append("-byte body)");
                    bVar4.mo268a(m586H6.toString());
                } else {
                    b bVar5 = this.f12013c;
                    StringBuilder m586H7 = C1499a.m586H("--> END ");
                    m586H7.append(c4381g0.f11441c);
                    m586H7.append(" (binary ");
                    m586H7.append(abstractC4387j0.mo4920a());
                    m586H7.append("-byte body omitted)");
                    bVar5.mo268a(m586H7.toString());
                }
            }
        }
        long nanoTime = System.nanoTime();
        try {
            C4389k0 m5139d = c4430g.m5139d(c4381g0);
            long millis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - nanoTime);
            AbstractC4393m0 abstractC4393m0 = m5139d.f11491k;
            if (abstractC4393m0 == null) {
                Intrinsics.throwNpe();
            }
            long mo4925d = abstractC4393m0.mo4925d();
            String str3 = mo4925d != -1 ? mo4925d + "-byte" : "unknown-length";
            b bVar6 = this.f12013c;
            StringBuilder m586H8 = C1499a.m586H("<-- ");
            m586H8.append(m5139d.f11488h);
            if (m5139d.f11487g.length() == 0) {
                str2 = "-byte body omitted)";
                sb = "";
            } else {
                String str4 = m5139d.f11487g;
                StringBuilder sb3 = new StringBuilder();
                str2 = "-byte body omitted)";
                sb3.append(String.valueOf(' '));
                sb3.append(str4);
                sb = sb3.toString();
            }
            m586H8.append(sb);
            m586H8.append(' ');
            m586H8.append(m5139d.f11485e.f11440b);
            m586H8.append(" (");
            m586H8.append(millis);
            m586H8.append("ms");
            m586H8.append(!z2 ? C1499a.m639y(", ", str3, " body") : "");
            m586H8.append(')');
            bVar6.mo268a(m586H8.toString());
            if (z2) {
                C4488y c4488y2 = m5139d.f11490j;
                int size2 = c4488y2.size();
                for (int i3 = 0; i3 < size2; i3++) {
                    m5263c(c4488y2, i3);
                }
                if (!z || !C4428e.m5135a(m5139d)) {
                    this.f12013c.mo268a("<-- END HTTP");
                } else if (m5262b(m5139d.f11490j)) {
                    this.f12013c.mo268a("<-- END HTTP (encoded body omitted)");
                } else {
                    InterfaceC4746h mo4927k = abstractC4393m0.mo4927k();
                    mo4927k.mo5350A(Long.MAX_VALUE);
                    C4744f buffer = mo4927k.getBuffer();
                    Long l2 = null;
                    if (StringsKt__StringsJVMKt.equals("gzip", c4488y2.m5277a("Content-Encoding"), true)) {
                        Long valueOf = Long.valueOf(buffer.f12133e);
                        C4751m c4751m = new C4751m(buffer.clone());
                        try {
                            buffer = new C4744f();
                            buffer.mo5396y(c4751m);
                            CloseableKt.closeFinally(c4751m, null);
                            l2 = valueOf;
                        } finally {
                        }
                    }
                    C4371b0 mo4926e = abstractC4393m0.mo4926e();
                    if (mo4926e == null || (UTF_8 = mo4926e.m4944a(StandardCharsets.UTF_8)) == null) {
                        UTF_8 = StandardCharsets.UTF_8;
                        Intrinsics.checkExpressionValueIsNotNull(UTF_8, "UTF_8");
                    }
                    if (!C2354n.m2417O0(buffer)) {
                        this.f12013c.mo268a("");
                        b bVar7 = this.f12013c;
                        StringBuilder m586H9 = C1499a.m586H("<-- END HTTP (binary ");
                        m586H9.append(buffer.f12133e);
                        m586H9.append(str2);
                        bVar7.mo268a(m586H9.toString());
                        return m5139d;
                    }
                    if (mo4925d != 0) {
                        this.f12013c.mo268a("");
                        this.f12013c.mo268a(buffer.clone().mo5395w(UTF_8));
                    }
                    if (l2 != null) {
                        b bVar8 = this.f12013c;
                        StringBuilder m586H10 = C1499a.m586H("<-- END HTTP (");
                        m586H10.append(buffer.f12133e);
                        m586H10.append("-byte, ");
                        m586H10.append(l2);
                        m586H10.append("-gzipped-byte body)");
                        bVar8.mo268a(m586H10.toString());
                    } else {
                        b bVar9 = this.f12013c;
                        StringBuilder m586H11 = C1499a.m586H("<-- END HTTP (");
                        m586H11.append(buffer.f12133e);
                        m586H11.append("-byte body)");
                        bVar9.mo268a(m586H11.toString());
                    }
                }
            }
            return m5139d;
        } catch (Exception e2) {
            this.f12013c.mo268a("<-- HTTP FAILED: " + e2);
            throw e2;
        }
    }

    /* renamed from: b */
    public final boolean m5262b(C4488y c4488y) {
        String m5277a = c4488y.m5277a("Content-Encoding");
        return (m5277a == null || StringsKt__StringsJVMKt.equals(m5277a, "identity", true) || StringsKt__StringsJVMKt.equals(m5277a, "gzip", true)) ? false : true;
    }

    /* renamed from: c */
    public final void m5263c(C4488y c4488y, int i2) {
        int i3 = i2 * 2;
        String str = this.f12011a.contains(c4488y.f12041e[i3]) ? "██" : c4488y.f12041e[i3 + 1];
        this.f12013c.mo268a(c4488y.f12041e[i3] + ": " + str);
    }

    @NotNull
    /* renamed from: d */
    public final C4480a m5264d(@NotNull a level) {
        Intrinsics.checkParameterIsNotNull(level, "level");
        this.f12012b = level;
        return this;
    }
}
