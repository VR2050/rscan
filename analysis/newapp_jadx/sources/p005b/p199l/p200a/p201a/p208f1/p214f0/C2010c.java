package p005b.p199l.p200a.p201a.p208f1.p214f0;

import p005b.p199l.p200a.p201a.p208f1.C2003e;
import p005b.p199l.p200a.p201a.p208f1.C2049p;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2042i;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2050q;
import p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2011c0;
import p005b.p199l.p200a.p201a.p250p1.C2360t;

/* renamed from: b.l.a.a.f1.f0.c */
/* loaded from: classes.dex */
public final class C2010c implements InterfaceC2041h {

    /* renamed from: a */
    public final C2012d f3850a = new C2012d(null);

    /* renamed from: b */
    public final C2360t f3851b = new C2360t(16384);

    /* renamed from: c */
    public boolean f3852c;

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: d */
    public int mo1479d(C2003e c2003e, C2049p c2049p) {
        int m1566f = c2003e.m1566f(this.f3851b.f6133a, 0, 16384);
        if (m1566f == -1) {
            return -1;
        }
        this.f3851b.m2567C(0);
        this.f3851b.m2566B(m1566f);
        if (!this.f3852c) {
            this.f3850a.f3876m = 0L;
            this.f3852c = true;
        }
        this.f3850a.mo1573b(this.f3851b);
        return 0;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: e */
    public void mo1480e(InterfaceC2042i interfaceC2042i) {
        this.f3850a.mo1576e(interfaceC2042i, new InterfaceC2011c0.d(Integer.MIN_VALUE, 0, 1));
        interfaceC2042i.mo1624o();
        interfaceC2042i.mo1623a(new InterfaceC2050q.b(-9223372036854775807L, 0L));
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: f */
    public void mo1481f(long j2, long j3) {
        this.f3852c = false;
        this.f3850a.mo1574c();
    }

    /* JADX WARN: Code restructure failed: missing block: B:12:0x0039, code lost:
    
        r15.f3791f = 0;
        r4 = r4 + 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:13:0x0041, code lost:
    
        if ((r4 - r3) < 8192) goto L13;
     */
    /* JADX WARN: Code restructure failed: missing block: B:16:0x0043, code lost:
    
        return false;
     */
    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: h */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean mo1483h(p005b.p199l.p200a.p201a.p208f1.C2003e r15) {
        /*
            r14 = this;
            b.l.a.a.p1.t r0 = new b.l.a.a.p1.t
            r1 = 10
            r0.<init>(r1)
            r2 = 0
            r3 = 0
        L9:
            byte[] r4 = r0.f6133a
            r15.m1565e(r4, r2, r1, r2)
            r0.m2567C(r2)
            int r4 = r0.m2587s()
            r5 = 4801587(0x494433, float:6.728456E-39)
            r6 = 3
            if (r4 == r5) goto L8c
            r15.f3791f = r2
            r15.m1561a(r3, r2)
            r4 = r3
        L21:
            r1 = 0
        L22:
            byte[] r5 = r0.f6133a
            r7 = 7
            r15.m1565e(r5, r2, r7, r2)
            r0.m2567C(r2)
            int r5 = r0.m2590v()
            r8 = 44096(0xac40, float:6.1792E-41)
            r9 = 44097(0xac41, float:6.1793E-41)
            if (r5 == r8) goto L48
            if (r5 == r9) goto L48
            r15.f3791f = r2
            int r4 = r4 + 1
            int r1 = r4 - r3
            r5 = 8192(0x2000, float:1.148E-41)
            if (r1 < r5) goto L44
            return r2
        L44:
            r15.m1561a(r4, r2)
            goto L21
        L48:
            r8 = 1
            int r1 = r1 + r8
            r10 = 4
            if (r1 < r10) goto L4e
            return r8
        L4e:
            byte[] r8 = r0.f6133a
            int r11 = r8.length
            r12 = -1
            if (r11 >= r7) goto L56
            r11 = -1
            goto L83
        L56:
            r11 = 2
            r11 = r8[r11]
            r11 = r11 & 255(0xff, float:3.57E-43)
            int r11 = r11 << 8
            r13 = r8[r6]
            r13 = r13 & 255(0xff, float:3.57E-43)
            r11 = r11 | r13
            r13 = 65535(0xffff, float:9.1834E-41)
            if (r11 != r13) goto L7d
            r10 = r8[r10]
            r10 = r10 & 255(0xff, float:3.57E-43)
            int r10 = r10 << 16
            r11 = 5
            r11 = r8[r11]
            r11 = r11 & 255(0xff, float:3.57E-43)
            int r11 = r11 << 8
            r10 = r10 | r11
            r11 = 6
            r8 = r8[r11]
            r8 = r8 & 255(0xff, float:3.57E-43)
            r11 = r10 | r8
            goto L7e
        L7d:
            r7 = 4
        L7e:
            if (r5 != r9) goto L82
            int r7 = r7 + 2
        L82:
            int r11 = r11 + r7
        L83:
            if (r11 != r12) goto L86
            return r2
        L86:
            int r11 = r11 + (-7)
            r15.m1561a(r11, r2)
            goto L22
        L8c:
            r0.m2568D(r6)
            int r4 = r0.m2584p()
            int r5 = r4 + 10
            int r3 = r3 + r5
            r15.m1561a(r4, r2)
            goto L9
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p208f1.p214f0.C2010c.mo1483h(b.l.a.a.f1.e):boolean");
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    public void release() {
    }
}
