package p005b.p199l.p200a.p201a.p208f1.p211c0;

import java.util.ArrayDeque;
import p005b.p199l.p200a.p201a.p208f1.C2003e;
import p005b.p199l.p200a.p201a.p208f1.C2051r;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2042i;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2050q;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2052s;
import p005b.p199l.p200a.p201a.p208f1.p211c0.AbstractC1981a;
import p005b.p199l.p200a.p201a.p250p1.C2358r;
import p005b.p199l.p200a.p201a.p250p1.C2360t;

/* renamed from: b.l.a.a.f1.c0.f */
/* loaded from: classes.dex */
public final class C1986f implements InterfaceC2041h, InterfaceC2050q {

    /* renamed from: f */
    public int f3657f;

    /* renamed from: g */
    public int f3658g;

    /* renamed from: h */
    public long f3659h;

    /* renamed from: i */
    public int f3660i;

    /* renamed from: j */
    public C2360t f3661j;

    /* renamed from: l */
    public int f3663l;

    /* renamed from: m */
    public int f3664m;

    /* renamed from: n */
    public int f3665n;

    /* renamed from: o */
    public InterfaceC2042i f3666o;

    /* renamed from: p */
    public a[] f3667p;

    /* renamed from: q */
    public long[][] f3668q;

    /* renamed from: r */
    public int f3669r;

    /* renamed from: s */
    public long f3670s;

    /* renamed from: t */
    public boolean f3671t;

    /* renamed from: d */
    public final C2360t f3655d = new C2360t(16);

    /* renamed from: e */
    public final ArrayDeque<AbstractC1981a.a> f3656e = new ArrayDeque<>();

    /* renamed from: a */
    public final C2360t f3652a = new C2360t(C2358r.f6109a);

    /* renamed from: b */
    public final C2360t f3653b = new C2360t(4);

    /* renamed from: c */
    public final C2360t f3654c = new C2360t();

    /* renamed from: k */
    public int f3662k = -1;

    /* renamed from: b.l.a.a.f1.c0.f$a */
    public static final class a {

        /* renamed from: a */
        public final C1989i f3672a;

        /* renamed from: b */
        public final C1992l f3673b;

        /* renamed from: c */
        public final InterfaceC2052s f3674c;

        /* renamed from: d */
        public int f3675d;

        public a(C1989i c1989i, C1992l c1992l, InterfaceC2052s interfaceC2052s) {
            this.f3672a = c1989i;
            this.f3673b = c1992l;
            this.f3674c = interfaceC2052s;
        }
    }

    public C1986f(int i2) {
    }

    /* renamed from: k */
    public static long m1535k(C1992l c1992l, long j2, long j3) {
        int m1542a = c1992l.m1542a(j2);
        if (m1542a == -1) {
            m1542a = c1992l.m1543b(j2);
        }
        return m1542a == -1 ? j3 : Math.min(c1992l.f3714c[m1542a], j3);
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2050q
    /* renamed from: c */
    public boolean mo1462c() {
        return true;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:11:0x03a2 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:137:0x021c A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:139:0x0006 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:14:0x0006 A[SYNTHETIC] */
    /* JADX WARN: Type inference failed for: r4v1 */
    /* JADX WARN: Type inference failed for: r4v2, types: [boolean, int] */
    /* JADX WARN: Type inference failed for: r4v9 */
    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: d */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public int mo1479d(p005b.p199l.p200a.p201a.p208f1.C2003e r31, p005b.p199l.p200a.p201a.p208f1.C2049p r32) {
        /*
            Method dump skipped, instructions count: 940
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p208f1.p211c0.C1986f.mo1479d(b.l.a.a.f1.e, b.l.a.a.f1.p):int");
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: e */
    public void mo1480e(InterfaceC2042i interfaceC2042i) {
        this.f3666o = interfaceC2042i;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: f */
    public void mo1481f(long j2, long j3) {
        this.f3656e.clear();
        this.f3660i = 0;
        this.f3662k = -1;
        this.f3663l = 0;
        this.f3664m = 0;
        this.f3665n = 0;
        if (j2 == 0) {
            m1536j();
            return;
        }
        a[] aVarArr = this.f3667p;
        if (aVarArr != null) {
            for (a aVar : aVarArr) {
                C1992l c1992l = aVar.f3673b;
                int m1542a = c1992l.m1542a(j3);
                if (m1542a == -1) {
                    m1542a = c1992l.m1543b(j3);
                }
                aVar.f3675d = m1542a;
            }
        }
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2050q
    /* renamed from: g */
    public InterfaceC2050q.a mo1463g(long j2) {
        long j3;
        long j4;
        long j5;
        long j6;
        int m1543b;
        long j7 = j2;
        a[] aVarArr = this.f3667p;
        if (aVarArr.length == 0) {
            return new InterfaceC2050q.a(C2051r.f4192a);
        }
        long j8 = -1;
        int i2 = this.f3669r;
        if (i2 != -1) {
            C1992l c1992l = aVarArr[i2].f3673b;
            int m1542a = c1992l.m1542a(j7);
            if (m1542a == -1) {
                m1542a = c1992l.m1543b(j7);
            }
            if (m1542a == -1) {
                return new InterfaceC2050q.a(C2051r.f4192a);
            }
            long j9 = c1992l.f3717f[m1542a];
            j3 = c1992l.f3714c[m1542a];
            if (j9 >= j7 || m1542a >= c1992l.f3713b - 1 || (m1543b = c1992l.m1543b(j7)) == -1 || m1543b == m1542a) {
                j6 = -9223372036854775807L;
            } else {
                long j10 = c1992l.f3717f[m1543b];
                long j11 = c1992l.f3714c[m1543b];
                j6 = j10;
                j8 = j11;
            }
            j4 = j8;
            j5 = j6;
            j7 = j9;
        } else {
            j3 = Long.MAX_VALUE;
            j4 = -1;
            j5 = -9223372036854775807L;
        }
        int i3 = 0;
        while (true) {
            a[] aVarArr2 = this.f3667p;
            if (i3 >= aVarArr2.length) {
                break;
            }
            if (i3 != this.f3669r) {
                C1992l c1992l2 = aVarArr2[i3].f3673b;
                long m1535k = m1535k(c1992l2, j7, j3);
                if (j5 != -9223372036854775807L) {
                    j4 = m1535k(c1992l2, j5, j4);
                }
                j3 = m1535k;
            }
            i3++;
        }
        C2051r c2051r = new C2051r(j7, j3);
        return j5 == -9223372036854775807L ? new InterfaceC2050q.a(c2051r) : new InterfaceC2050q.a(c2051r, new C2051r(j5, j4));
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: h */
    public boolean mo1483h(C2003e c2003e) {
        return C1988h.m1539a(c2003e, false);
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2050q
    /* renamed from: i */
    public long mo1464i() {
        return this.f3670s;
    }

    /* renamed from: j */
    public final void m1536j() {
        this.f3657f = 0;
        this.f3660i = 0;
    }

    /* renamed from: l */
    public final void m1537l(long j2) {
        while (!this.f3656e.isEmpty() && this.f3656e.peek().f3585b == j2) {
            AbstractC1981a.a pop = this.f3656e.pop();
            if (pop.f3584a == 1836019574) {
                m1538m(pop);
                this.f3656e.clear();
                this.f3657f = 2;
            } else if (!this.f3656e.isEmpty()) {
                this.f3656e.peek().f3587d.add(pop);
            }
        }
        if (this.f3657f != 2) {
            m1536j();
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:146:0x076a  */
    /* JADX WARN: Removed duplicated region for block: B:148:0x0788  */
    /* JADX WARN: Removed duplicated region for block: B:266:0x06a0  */
    /* JADX WARN: Removed duplicated region for block: B:296:0x0573  */
    /* JADX WARN: Removed duplicated region for block: B:317:0x0a11  */
    /* JADX WARN: Removed duplicated region for block: B:342:0x0b32 A[LOOP:18: B:340:0x0b2f->B:342:0x0b32, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:347:0x0b50  */
    /* JADX WARN: Removed duplicated region for block: B:402:0x02b7  */
    /* JADX WARN: Removed duplicated region for block: B:405:0x02ba A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:495:0x00a3 A[Catch: all -> 0x0231, TryCatch #0 {all -> 0x0231, blocks: (B:489:0x0090, B:491:0x0096, B:493:0x009b, B:495:0x00a3, B:399:0x00af, B:408:0x00bc, B:411:0x00c9, B:414:0x00d6, B:417:0x00e3, B:419:0x00ed, B:424:0x0106, B:432:0x0128, B:435:0x0135, B:438:0x0142, B:441:0x014f, B:444:0x015c, B:447:0x0169, B:450:0x0176, B:453:0x0183, B:456:0x0190, B:459:0x019d, B:463:0x01ae, B:465:0x01b2, B:467:0x01c3, B:472:0x01cf, B:477:0x01de, B:485:0x01ee, B:486:0x029d, B:502:0x0203, B:504:0x020a, B:506:0x0217, B:507:0x022b, B:520:0x0250, B:523:0x025c, B:526:0x0268, B:529:0x0274, B:532:0x0280, B:535:0x028c, B:538:0x0296, B:539:0x02a5, B:540:0x02ac), top: B:488:0x0090 }] */
    /* JADX WARN: Removed duplicated region for block: B:50:0x0418  */
    /* JADX WARN: Removed duplicated region for block: B:88:0x055d  */
    /* JADX WARN: Removed duplicated region for block: B:95:0x0578  */
    /* renamed from: m */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void m1538m(p005b.p199l.p200a.p201a.p208f1.p211c0.AbstractC1981a.a r77) {
        /*
            Method dump skipped, instructions count: 2976
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p208f1.p211c0.C1986f.m1538m(b.l.a.a.f1.c0.a$a):void");
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    public void release() {
    }
}
