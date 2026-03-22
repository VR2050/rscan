package p458k.p459p0.p463g;

import java.util.List;
import kotlin.collections.CollectionsKt__CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt__StringsJVMKt;
import org.jetbrains.annotations.NotNull;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p458k.AbstractC4387j0;
import p458k.AbstractC4393m0;
import p458k.C4371b0;
import p458k.C4381g0;
import p458k.C4389k0;
import p458k.C4398p;
import p458k.C4488y;
import p458k.InterfaceC4369a0;
import p458k.InterfaceC4481r;
import p458k.p459p0.C4401c;
import p474l.C4751m;

/* renamed from: k.p0.g.a */
/* loaded from: classes3.dex */
public final class C4424a implements InterfaceC4369a0 {

    /* renamed from: a */
    public final InterfaceC4481r f11729a;

    public C4424a(@NotNull InterfaceC4481r cookieJar) {
        Intrinsics.checkParameterIsNotNull(cookieJar, "cookieJar");
        this.f11729a = cookieJar;
    }

    @Override // p458k.InterfaceC4369a0
    @NotNull
    /* renamed from: a */
    public C4389k0 mo280a(@NotNull InterfaceC4369a0.a chain) {
        boolean z;
        AbstractC4393m0 abstractC4393m0;
        Intrinsics.checkParameterIsNotNull(chain, "chain");
        C4430g c4430g = (C4430g) chain;
        C4381g0 c4381g0 = c4430g.f11739f;
        C4381g0.a aVar = new C4381g0.a(c4381g0);
        AbstractC4387j0 abstractC4387j0 = c4381g0.f11443e;
        if (abstractC4387j0 != null) {
            C4371b0 mo4921b = abstractC4387j0.mo4921b();
            if (mo4921b != null) {
                aVar.m4973c("Content-Type", mo4921b.f11310d);
            }
            long mo4920a = abstractC4387j0.mo4920a();
            if (mo4920a != -1) {
                aVar.m4973c("Content-Length", String.valueOf(mo4920a));
                aVar.m4976f("Transfer-Encoding");
            } else {
                aVar.m4973c("Transfer-Encoding", "chunked");
                aVar.m4976f("Content-Length");
            }
        }
        int i2 = 0;
        if (c4381g0.m4970b("Host") == null) {
            aVar.m4973c("Host", C4401c.m5037v(c4381g0.f11440b, false));
        }
        if (c4381g0.m4970b("Connection") == null) {
            aVar.m4973c("Connection", "Keep-Alive");
        }
        if (c4381g0.m4970b("Accept-Encoding") == null && c4381g0.m4970b("Range") == null) {
            aVar.m4973c("Accept-Encoding", "gzip");
            z = true;
        } else {
            z = false;
        }
        List<C4398p> mo5261b = this.f11729a.mo5261b(c4381g0.f11440b);
        if (!mo5261b.isEmpty()) {
            StringBuilder sb = new StringBuilder();
            for (Object obj : mo5261b) {
                int i3 = i2 + 1;
                if (i2 < 0) {
                    CollectionsKt__CollectionsKt.throwIndexOverflow();
                }
                C4398p c4398p = (C4398p) obj;
                if (i2 > 0) {
                    sb.append("; ");
                }
                sb.append(c4398p.f11544f);
                sb.append('=');
                sb.append(c4398p.f11545g);
                i2 = i3;
            }
            String sb2 = sb.toString();
            Intrinsics.checkExpressionValueIsNotNull(sb2, "StringBuilder().apply(builderAction).toString()");
            aVar.m4973c("Cookie", sb2);
        }
        if (c4381g0.m4970b("User-Agent") == null) {
            aVar.m4973c("User-Agent", "okhttp/4.3.1");
        }
        C4389k0 m5139d = c4430g.m5139d(aVar.m4972b());
        C4428e.m5136b(this.f11729a, c4381g0.f11440b, m5139d.f11490j);
        C4389k0.a aVar2 = new C4389k0.a(m5139d);
        aVar2.m4997h(c4381g0);
        if (z && StringsKt__StringsJVMKt.equals("gzip", C4389k0.m4987d(m5139d, "Content-Encoding", null, 2), true) && C4428e.m5135a(m5139d) && (abstractC4393m0 = m5139d.f11491k) != null) {
            C4751m c4751m = new C4751m(abstractC4393m0.mo4927k());
            C4488y.a m5279c = m5139d.f11490j.m5279c();
            m5279c.m5287f("Content-Encoding");
            m5279c.m5287f("Content-Length");
            aVar2.m4994e(m5279c.m5285d());
            aVar2.f11504g = new C4431h(C4389k0.m4987d(m5139d, "Content-Type", null, 2), -1L, C2354n.m2500o(c4751m));
        }
        return aVar2.m4990a();
    }
}
