package p476m.p477a.p485b.p488j0;

import java.util.Locale;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p476m.p477a.p485b.C4795c0;
import p476m.p477a.p485b.InterfaceC4797d0;
import p476m.p477a.p485b.InterfaceC4898r;
import p476m.p477a.p485b.InterfaceC4899s;
import p476m.p477a.p485b.p493l0.C4859g;
import p476m.p477a.p485b.p493l0.C4865m;
import p476m.p477a.p485b.p494m0.InterfaceC4877d;

/* renamed from: m.a.b.j0.e */
/* loaded from: classes3.dex */
public class C4817e implements InterfaceC4899s {

    /* renamed from: a */
    public static final C4817e f12316a = new C4817e();

    /* renamed from: b */
    public final InterfaceC4797d0 f12317b;

    public C4817e() {
        C4818f c4818f = C4818f.f12318a;
        C2354n.m2470e1(c4818f, "Reason phrase catalog");
        this.f12317b = c4818f;
    }

    /* renamed from: a */
    public InterfaceC4898r m5486a(C4795c0 c4795c0, int i2, InterfaceC4877d interfaceC4877d) {
        C2354n.m2470e1(c4795c0, "HTTP version");
        Locale locale = Locale.getDefault();
        return new C4859g(new C4865m(c4795c0, i2, this.f12317b.mo5472a(i2, locale)), this.f12317b, locale);
    }
}
