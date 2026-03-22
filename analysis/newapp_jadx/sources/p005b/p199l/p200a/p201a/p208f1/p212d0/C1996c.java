package p005b.p199l.p200a.p201a.p208f1.p212d0;

import java.util.Arrays;
import p005b.p199l.p200a.p201a.C2205l0;
import p005b.p199l.p200a.p201a.p208f1.C2003e;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2042i;
import p005b.p199l.p200a.p201a.p250p1.C2360t;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.f1.d0.c */
/* loaded from: classes.dex */
public class C1996c implements InterfaceC2041h {

    /* renamed from: a */
    public InterfaceC2042i f3744a;

    /* renamed from: b */
    public AbstractC2001h f3745b;

    /* renamed from: c */
    public boolean f3746c;

    /* renamed from: a */
    public final boolean m1553a(C2003e c2003e) {
        boolean z;
        boolean equals;
        C1998e c1998e = new C1998e();
        if (c1998e.m1556a(c2003e, true) && (c1998e.f3753b & 2) == 2) {
            int min = Math.min(c1998e.f3757f, 8);
            C2360t c2360t = new C2360t(min);
            c2003e.m1565e(c2360t.f6133a, 0, min, false);
            c2360t.m2567C(0);
            if (c2360t.m2569a() >= 5 && c2360t.m2585q() == 127 && c2360t.m2586r() == 1179402563) {
                this.f3745b = new C1995b();
            } else {
                c2360t.m2567C(0);
                try {
                    z = C4195m.m4780M0(1, c2360t, true);
                } catch (C2205l0 unused) {
                    z = false;
                }
                if (z) {
                    this.f3745b = new C2002i();
                } else {
                    c2360t.m2567C(0);
                    int m2569a = c2360t.m2569a();
                    byte[] bArr = C2000g.f3760n;
                    if (m2569a < bArr.length) {
                        equals = false;
                    } else {
                        byte[] bArr2 = new byte[bArr.length];
                        int length = bArr.length;
                        System.arraycopy(c2360t.f6133a, c2360t.f6134b, bArr2, 0, length);
                        c2360t.f6134b += length;
                        equals = Arrays.equals(bArr2, bArr);
                    }
                    if (equals) {
                        this.f3745b = new C2000g();
                    }
                }
            }
            return true;
        }
        return false;
    }

    /* JADX WARN: Removed duplicated region for block: B:66:0x0166  */
    /* JADX WARN: Removed duplicated region for block: B:68:? A[RETURN, SYNTHETIC] */
    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: d */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public int mo1479d(p005b.p199l.p200a.p201a.p208f1.C2003e r21, p005b.p199l.p200a.p201a.p208f1.C2049p r22) {
        /*
            Method dump skipped, instructions count: 371
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p208f1.p212d0.C1996c.mo1479d(b.l.a.a.f1.e, b.l.a.a.f1.p):int");
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: e */
    public void mo1480e(InterfaceC2042i interfaceC2042i) {
        this.f3744a = interfaceC2042i;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: f */
    public void mo1481f(long j2, long j3) {
        AbstractC2001h abstractC2001h = this.f3745b;
        if (abstractC2001h != null) {
            C1997d c1997d = abstractC2001h.f3762a;
            c1997d.f3747a.m1557b();
            c1997d.f3748b.m2592x();
            c1997d.f3749c = -1;
            c1997d.f3751e = false;
            if (j2 == 0) {
                abstractC2001h.mo1552e(!abstractC2001h.f3773l);
            } else if (abstractC2001h.f3769h != 0) {
                long j4 = (abstractC2001h.f3770i * j3) / 1000000;
                abstractC2001h.f3766e = j4;
                abstractC2001h.f3765d.mo1548c(j4);
                abstractC2001h.f3769h = 2;
            }
        }
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: h */
    public boolean mo1483h(C2003e c2003e) {
        try {
            return m1553a(c2003e);
        } catch (C2205l0 unused) {
            return false;
        }
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    public void release() {
    }
}
