package p005b.p199l.p200a.p201a.p208f1.p214f0;

import p005b.p199l.p200a.p201a.p208f1.C2003e;
import p005b.p199l.p200a.p201a.p208f1.C2049p;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2042i;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2050q;
import p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2011c0;
import p005b.p199l.p200a.p201a.p250p1.C2360t;

/* renamed from: b.l.a.a.f1.f0.a */
/* loaded from: classes.dex */
public final class C2006a implements InterfaceC2041h {

    /* renamed from: a */
    public final C2008b f3802a = new C2008b(null);

    /* renamed from: b */
    public final C2360t f3803b = new C2360t(2786);

    /* renamed from: c */
    public boolean f3804c;

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: d */
    public int mo1479d(C2003e c2003e, C2049p c2049p) {
        int m1566f = c2003e.m1566f(this.f3803b.f6133a, 0, 2786);
        if (m1566f == -1) {
            return -1;
        }
        this.f3803b.m2567C(0);
        this.f3803b.m2566B(m1566f);
        if (!this.f3804c) {
            this.f3802a.f3824l = 0L;
            this.f3804c = true;
        }
        this.f3802a.mo1573b(this.f3803b);
        return 0;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: e */
    public void mo1480e(InterfaceC2042i interfaceC2042i) {
        this.f3802a.mo1576e(interfaceC2042i, new InterfaceC2011c0.d(Integer.MIN_VALUE, 0, 1));
        interfaceC2042i.mo1624o();
        interfaceC2042i.mo1623a(new InterfaceC2050q.b(-9223372036854775807L, 0L));
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: f */
    public void mo1481f(long j2, long j3) {
        this.f3804c = false;
        this.f3802a.mo1574c();
    }

    /* JADX WARN: Code restructure failed: missing block: B:30:0x0033, code lost:
    
        r14.f3791f = 0;
        r5 = r5 + 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:31:0x003b, code lost:
    
        if ((r5 - r3) < 8192) goto L12;
     */
    /* JADX WARN: Code restructure failed: missing block: B:34:0x003d, code lost:
    
        return false;
     */
    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: h */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean mo1483h(p005b.p199l.p200a.p201a.p208f1.C2003e r14) {
        /*
            r13 = this;
            b.l.a.a.p1.t r0 = new b.l.a.a.p1.t
            r1 = 10
            r0.<init>(r1)
            r2 = 0
            r3 = 0
        L9:
            byte[] r4 = r0.f6133a
            r14.m1565e(r4, r2, r1, r2)
            r0.m2567C(r2)
            int r4 = r0.m2587s()
            r5 = 4801587(0x494433, float:6.728456E-39)
            r6 = 3
            if (r4 == r5) goto L83
            r14.f3791f = r2
            r14.m1561a(r3, r2)
            r5 = r3
        L21:
            r4 = 0
        L22:
            byte[] r7 = r0.f6133a
            r8 = 6
            r14.m1565e(r7, r2, r8, r2)
            r0.m2567C(r2)
            int r7 = r0.m2590v()
            r9 = 2935(0xb77, float:4.113E-42)
            if (r7 == r9) goto L42
            r14.f3791f = r2
            int r5 = r5 + 1
            int r4 = r5 - r3
            r7 = 8192(0x2000, float:1.148E-41)
            if (r4 < r7) goto L3e
            return r2
        L3e:
            r14.m1561a(r5, r2)
            goto L21
        L42:
            r7 = 1
            int r4 = r4 + r7
            r9 = 4
            if (r4 < r9) goto L48
            return r7
        L48:
            byte[] r10 = r0.f6133a
            int r11 = r10.length
            r12 = -1
            if (r11 >= r8) goto L50
            r9 = -1
            goto L7a
        L50:
            r11 = 5
            r11 = r10[r11]
            r11 = r11 & 248(0xf8, float:3.48E-43)
            int r11 = r11 >> r6
            if (r11 <= r1) goto L5a
            r11 = 1
            goto L5b
        L5a:
            r11 = 0
        L5b:
            if (r11 == 0) goto L6d
            r8 = 2
            r9 = r10[r8]
            r9 = r9 & 7
            int r9 = r9 << 8
            r10 = r10[r6]
            r10 = r10 & 255(0xff, float:3.57E-43)
            r9 = r9 | r10
            int r9 = r9 + r7
            int r9 = r9 * 2
            goto L7a
        L6d:
            r7 = r10[r9]
            r7 = r7 & 192(0xc0, float:2.69E-43)
            int r7 = r7 >> r8
            r8 = r10[r9]
            r8 = r8 & 63
            int r9 = p005b.p199l.p200a.p201a.p202a1.C1915g.m1263a(r7, r8)
        L7a:
            if (r9 != r12) goto L7d
            return r2
        L7d:
            int r9 = r9 + (-6)
            r14.m1561a(r9, r2)
            goto L22
        L83:
            r0.m2568D(r6)
            int r4 = r0.m2584p()
            int r5 = r4 + 10
            int r3 = r3 + r5
            r14.m1561a(r4, r2)
            goto L9
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p208f1.p214f0.C2006a.mo1483h(b.l.a.a.f1.e):boolean");
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    public void release() {
    }
}
