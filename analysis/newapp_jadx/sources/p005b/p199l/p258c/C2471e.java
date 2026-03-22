package p005b.p199l.p258c;

import p005b.p199l.p258c.p265e0.C2472a;
import p005b.p199l.p258c.p265e0.C2474c;
import p005b.p199l.p258c.p265e0.EnumC2473b;

/* renamed from: b.l.c.e */
/* loaded from: classes2.dex */
public class C2471e extends AbstractC2496z<Number> {
    public C2471e(C2480j c2480j) {
    }

    @Override // p005b.p199l.p258c.AbstractC2496z
    /* renamed from: b */
    public Number mo2766b(C2472a c2472a) {
        if (c2472a.mo2777Z() != EnumC2473b.NULL) {
            return Double.valueOf(c2472a.mo2771E());
        }
        c2472a.mo2775V();
        return null;
    }

    @Override // p005b.p199l.p258c.AbstractC2496z
    /* renamed from: c */
    public void mo2767c(C2474c c2474c, Number number) {
        Number number2 = number;
        if (number2 == null) {
            c2474c.mo2800v();
        } else {
            C2480j.m2847a(number2.doubleValue());
            c2474c.mo2790U(number2);
        }
    }
}
