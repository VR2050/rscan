package p005b.p199l.p200a.p201a.p208f1.p218z;

import p005b.p199l.p200a.p201a.p208f1.C2003e;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2042i;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2050q;
import p005b.p199l.p200a.p201a.p250p1.C2360t;

/* renamed from: b.l.a.a.f1.z.b */
/* loaded from: classes.dex */
public final class C2062b implements InterfaceC2041h {

    /* renamed from: f */
    public InterfaceC2042i f4256f;

    /* renamed from: h */
    public boolean f4258h;

    /* renamed from: i */
    public long f4259i;

    /* renamed from: j */
    public int f4260j;

    /* renamed from: k */
    public int f4261k;

    /* renamed from: l */
    public int f4262l;

    /* renamed from: m */
    public long f4263m;

    /* renamed from: n */
    public boolean f4264n;

    /* renamed from: o */
    public C2061a f4265o;

    /* renamed from: p */
    public C2065e f4266p;

    /* renamed from: a */
    public final C2360t f4251a = new C2360t(4);

    /* renamed from: b */
    public final C2360t f4252b = new C2360t(9);

    /* renamed from: c */
    public final C2360t f4253c = new C2360t(11);

    /* renamed from: d */
    public final C2360t f4254d = new C2360t();

    /* renamed from: e */
    public final C2063c f4255e = new C2063c();

    /* renamed from: g */
    public int f4257g = 1;

    /* renamed from: a */
    public final void m1646a() {
        if (this.f4264n) {
            return;
        }
        this.f4256f.mo1623a(new InterfaceC2050q.b(-9223372036854775807L, 0L));
        this.f4264n = true;
    }

    /* renamed from: b */
    public final C2360t m1647b(C2003e c2003e) {
        int i2 = this.f4262l;
        C2360t c2360t = this.f4254d;
        byte[] bArr = c2360t.f6133a;
        if (i2 > bArr.length) {
            c2360t.f6133a = new byte[Math.max(bArr.length * 2, i2)];
            c2360t.f6135c = 0;
            c2360t.f6134b = 0;
        } else {
            c2360t.m2567C(0);
        }
        this.f4254d.m2566B(this.f4262l);
        c2003e.m1568h(this.f4254d.f6133a, 0, this.f4262l, false);
        return this.f4254d;
    }

    /* JADX WARN: Removed duplicated region for block: B:61:0x009e  */
    /* JADX WARN: Removed duplicated region for block: B:65:0x00a9 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:67:0x0004 A[SYNTHETIC] */
    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: d */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public int mo1479d(p005b.p199l.p200a.p201a.p208f1.C2003e r17, p005b.p199l.p200a.p201a.p208f1.C2049p r18) {
        /*
            Method dump skipped, instructions count: 357
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p208f1.p218z.C2062b.mo1479d(b.l.a.a.f1.e, b.l.a.a.f1.p):int");
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: e */
    public void mo1480e(InterfaceC2042i interfaceC2042i) {
        this.f4256f = interfaceC2042i;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: f */
    public void mo1481f(long j2, long j3) {
        this.f4257g = 1;
        this.f4258h = false;
        this.f4260j = 0;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: h */
    public boolean mo1483h(C2003e c2003e) {
        c2003e.m1565e(this.f4251a.f6133a, 0, 3, false);
        this.f4251a.m2567C(0);
        if (this.f4251a.m2587s() != 4607062) {
            return false;
        }
        c2003e.m1565e(this.f4251a.f6133a, 0, 2, false);
        this.f4251a.m2567C(0);
        if ((this.f4251a.m2590v() & 250) != 0) {
            return false;
        }
        c2003e.m1565e(this.f4251a.f6133a, 0, 4, false);
        this.f4251a.m2567C(0);
        int m2573e = this.f4251a.m2573e();
        c2003e.f3791f = 0;
        c2003e.m1561a(m2573e, false);
        c2003e.m1565e(this.f4251a.f6133a, 0, 4, false);
        this.f4251a.m2567C(0);
        return this.f4251a.m2573e() == 0;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    public void release() {
    }
}
