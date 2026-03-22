package p005b.p199l.p200a.p201a.p208f1.p214f0;

import androidx.annotation.Nullable;
import java.util.Objects;
import p005b.p199l.p200a.p201a.p208f1.C2003e;
import p005b.p199l.p200a.p201a.p208f1.C2049p;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2042i;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2050q;
import p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2011c0;
import p005b.p199l.p200a.p201a.p250p1.C2359s;
import p005b.p199l.p200a.p201a.p250p1.C2360t;

/* renamed from: b.l.a.a.f1.f0.e */
/* loaded from: classes.dex */
public final class C2014e implements InterfaceC2041h {

    /* renamed from: c */
    public final C2360t f3881c;

    /* renamed from: d */
    public final C2359s f3882d;

    /* renamed from: e */
    @Nullable
    public InterfaceC2042i f3883e;

    /* renamed from: f */
    public long f3884f;

    /* renamed from: i */
    public boolean f3887i;

    /* renamed from: j */
    public boolean f3888j;

    /* renamed from: a */
    public final C2015f f3879a = new C2015f(true, null);

    /* renamed from: b */
    public final C2360t f3880b = new C2360t(2048);

    /* renamed from: h */
    public int f3886h = -1;

    /* renamed from: g */
    public long f3885g = -1;

    public C2014e(int i2) {
        C2360t c2360t = new C2360t(10);
        this.f3881c = c2360t;
        this.f3882d = new C2359s(c2360t.f6133a);
    }

    /* renamed from: a */
    public final int m1587a(C2003e c2003e) {
        int i2 = 0;
        while (true) {
            c2003e.m1565e(this.f3881c.f6133a, 0, 10, false);
            this.f3881c.m2567C(0);
            if (this.f3881c.m2587s() != 4801587) {
                break;
            }
            this.f3881c.m2568D(3);
            int m2584p = this.f3881c.m2584p();
            i2 += m2584p + 10;
            c2003e.m1561a(m2584p, false);
        }
        c2003e.f3791f = 0;
        c2003e.m1561a(i2, false);
        if (this.f3885g == -1) {
            this.f3885g = i2;
        }
        return i2;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: d */
    public int mo1479d(C2003e c2003e, C2049p c2049p) {
        long j2 = c2003e.f3788c;
        int m1566f = c2003e.m1566f(this.f3880b.f6133a, 0, 2048);
        boolean z = m1566f == -1;
        if (!this.f3888j) {
            InterfaceC2042i interfaceC2042i = this.f3883e;
            Objects.requireNonNull(interfaceC2042i);
            interfaceC2042i.mo1623a(new InterfaceC2050q.b(-9223372036854775807L, 0L));
            this.f3888j = true;
        }
        if (z) {
            return -1;
        }
        this.f3880b.m2567C(0);
        this.f3880b.m2566B(m1566f);
        if (!this.f3887i) {
            this.f3879a.f3908t = this.f3884f;
            this.f3887i = true;
        }
        this.f3879a.mo1573b(this.f3880b);
        return 0;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: e */
    public void mo1480e(InterfaceC2042i interfaceC2042i) {
        this.f3883e = interfaceC2042i;
        this.f3879a.mo1576e(interfaceC2042i, new InterfaceC2011c0.d(Integer.MIN_VALUE, 0, 1));
        interfaceC2042i.mo1624o();
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: f */
    public void mo1481f(long j2, long j3) {
        this.f3887i = false;
        this.f3879a.mo1574c();
        this.f3884f = j3;
    }

    /* JADX WARN: Code restructure failed: missing block: B:18:0x0021, code lost:
    
        r9.f3791f = 0;
        r3 = r3 + 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:19:0x0029, code lost:
    
        if ((r3 - r0) < 8192) goto L9;
     */
    /* JADX WARN: Code restructure failed: missing block: B:22:0x002b, code lost:
    
        return false;
     */
    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: h */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean mo1483h(p005b.p199l.p200a.p201a.p208f1.C2003e r9) {
        /*
            r8 = this;
            int r0 = r8.m1587a(r9)
            r1 = 0
            r3 = r0
        L6:
            r2 = 0
            r4 = 0
        L8:
            b.l.a.a.p1.t r5 = r8.f3881c
            byte[] r5 = r5.f6133a
            r6 = 2
            r9.m1565e(r5, r1, r6, r1)
            b.l.a.a.p1.t r5 = r8.f3881c
            r5.m2567C(r1)
            b.l.a.a.p1.t r5 = r8.f3881c
            int r5 = r5.m2590v()
            boolean r5 = p005b.p199l.p200a.p201a.p208f1.p214f0.C2015f.m1588g(r5)
            if (r5 != 0) goto L30
            r9.f3791f = r1
            int r3 = r3 + 1
            int r2 = r3 - r0
            r4 = 8192(0x2000, float:1.148E-41)
            if (r2 < r4) goto L2c
            return r1
        L2c:
            r9.m1561a(r3, r1)
            goto L6
        L30:
            r5 = 1
            int r2 = r2 + r5
            r6 = 4
            if (r2 < r6) goto L3a
            r7 = 188(0xbc, float:2.63E-43)
            if (r4 <= r7) goto L3a
            return r5
        L3a:
            b.l.a.a.p1.t r5 = r8.f3881c
            byte[] r5 = r5.f6133a
            r9.m1565e(r5, r1, r6, r1)
            b.l.a.a.p1.s r5 = r8.f3882d
            r6 = 14
            r5.m2562j(r6)
            b.l.a.a.p1.s r5 = r8.f3882d
            r6 = 13
            int r5 = r5.m2558f(r6)
            r6 = 6
            if (r5 > r6) goto L54
            return r1
        L54:
            int r6 = r5 + (-6)
            r9.m1561a(r6, r1)
            int r4 = r4 + r5
            goto L8
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p208f1.p214f0.C2014e.mo1483h(b.l.a.a.f1.e):boolean");
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    public void release() {
    }
}
