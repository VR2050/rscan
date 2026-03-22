package p005b.p199l.p200a.p201a.p208f1.p214f0;

import android.util.SparseArray;
import android.util.SparseBooleanArray;
import android.util.SparseIntArray;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import p005b.p199l.p200a.p201a.C2205l0;
import p005b.p199l.p200a.p201a.p208f1.C2003e;
import p005b.p199l.p200a.p201a.p208f1.C2049p;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2042i;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2050q;
import p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2011c0;
import p005b.p199l.p200a.p201a.p250p1.C2342c0;
import p005b.p199l.p200a.p201a.p250p1.C2359s;
import p005b.p199l.p200a.p201a.p250p1.C2360t;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.f1.f0.b0 */
/* loaded from: classes.dex */
public final class C2009b0 implements InterfaceC2041h {

    /* renamed from: a */
    public final int f3825a;

    /* renamed from: b */
    public final List<C2342c0> f3826b;

    /* renamed from: c */
    public final C2360t f3827c;

    /* renamed from: d */
    public final SparseIntArray f3828d;

    /* renamed from: e */
    public final InterfaceC2011c0.c f3829e;

    /* renamed from: f */
    public final SparseArray<InterfaceC2011c0> f3830f;

    /* renamed from: g */
    public final SparseBooleanArray f3831g;

    /* renamed from: h */
    public final SparseBooleanArray f3832h;

    /* renamed from: i */
    public final C2007a0 f3833i;

    /* renamed from: j */
    public C2035z f3834j;

    /* renamed from: k */
    public InterfaceC2042i f3835k;

    /* renamed from: l */
    public int f3836l;

    /* renamed from: m */
    public boolean f3837m;

    /* renamed from: n */
    public boolean f3838n;

    /* renamed from: o */
    public boolean f3839o;

    /* renamed from: p */
    public InterfaceC2011c0 f3840p;

    /* renamed from: q */
    public int f3841q;

    /* renamed from: r */
    public int f3842r;

    /* renamed from: b.l.a.a.f1.f0.b0$a */
    public class a implements InterfaceC2031v {

        /* renamed from: a */
        public final C2359s f3843a = new C2359s(new byte[4]);

        public a() {
        }

        @Override // p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2031v
        /* renamed from: a */
        public void mo1578a(C2342c0 c2342c0, InterfaceC2042i interfaceC2042i, InterfaceC2011c0.d dVar) {
        }

        @Override // p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2031v
        /* renamed from: b */
        public void mo1579b(C2360t c2360t) {
            if (c2360t.m2585q() != 0) {
                return;
            }
            c2360t.m2568D(7);
            int m2569a = c2360t.m2569a() / 4;
            for (int i2 = 0; i2 < m2569a; i2++) {
                c2360t.m2571c(this.f3843a, 4);
                int m2558f = this.f3843a.m2558f(16);
                this.f3843a.m2564l(3);
                if (m2558f == 0) {
                    this.f3843a.m2564l(13);
                } else {
                    int m2558f2 = this.f3843a.m2558f(13);
                    C2009b0 c2009b0 = C2009b0.this;
                    c2009b0.f3830f.put(m2558f2, new C2032w(c2009b0.new b(m2558f2)));
                    C2009b0.this.f3836l++;
                }
            }
            C2009b0 c2009b02 = C2009b0.this;
            if (c2009b02.f3825a != 2) {
                c2009b02.f3830f.remove(0);
            }
        }
    }

    /* renamed from: b.l.a.a.f1.f0.b0$b */
    public class b implements InterfaceC2031v {

        /* renamed from: a */
        public final C2359s f3845a = new C2359s(new byte[5]);

        /* renamed from: b */
        public final SparseArray<InterfaceC2011c0> f3846b = new SparseArray<>();

        /* renamed from: c */
        public final SparseIntArray f3847c = new SparseIntArray();

        /* renamed from: d */
        public final int f3848d;

        public b(int i2) {
            this.f3848d = i2;
        }

        @Override // p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2031v
        /* renamed from: a */
        public void mo1578a(C2342c0 c2342c0, InterfaceC2042i interfaceC2042i, InterfaceC2011c0.d dVar) {
        }

        /* JADX WARN: Code restructure failed: missing block: B:45:0x012d, code lost:
        
            if (r24.m2585q() == r13) goto L47;
         */
        /* JADX WARN: Removed duplicated region for block: B:80:0x01ff  */
        /* JADX WARN: Removed duplicated region for block: B:85:0x020c  */
        @Override // p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2031v
        /* renamed from: b */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public void mo1579b(p005b.p199l.p200a.p201a.p250p1.C2360t r24) {
            /*
                Method dump skipped, instructions count: 716
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p208f1.p214f0.C2009b0.b.mo1579b(b.l.a.a.p1.t):void");
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public C2009b0(int i2, C2342c0 c2342c0, InterfaceC2011c0.c cVar) {
        this.f3829e = cVar;
        this.f3825a = i2;
        if (i2 == 1 || i2 == 2) {
            this.f3826b = Collections.singletonList(c2342c0);
        } else {
            ArrayList arrayList = new ArrayList();
            this.f3826b = arrayList;
            arrayList.add(c2342c0);
        }
        this.f3827c = new C2360t(new byte[9400], 0);
        SparseBooleanArray sparseBooleanArray = new SparseBooleanArray();
        this.f3831g = sparseBooleanArray;
        this.f3832h = new SparseBooleanArray();
        SparseArray<InterfaceC2011c0> sparseArray = new SparseArray<>();
        this.f3830f = sparseArray;
        this.f3828d = new SparseIntArray();
        this.f3833i = new C2007a0();
        this.f3842r = -1;
        sparseBooleanArray.clear();
        sparseArray.clear();
        SparseArray sparseArray2 = new SparseArray();
        int size = sparseArray2.size();
        for (int i3 = 0; i3 < size; i3++) {
            this.f3830f.put(sparseArray2.keyAt(i3), sparseArray2.valueAt(i3));
        }
        this.f3830f.put(0, new C2032w(new a()));
        this.f3840p = null;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r15v1 */
    /* JADX WARN: Type inference failed for: r15v2, types: [boolean, int] */
    /* JADX WARN: Type inference failed for: r15v8 */
    /* JADX WARN: Type inference failed for: r15v9 */
    /* JADX WARN: Type inference failed for: r3v1 */
    /* JADX WARN: Type inference failed for: r3v19 */
    /* JADX WARN: Type inference failed for: r3v2, types: [boolean, int] */
    /* JADX WARN: Type inference failed for: r3v8 */
    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: d */
    public int mo1479d(C2003e c2003e, C2049p c2049p) {
        ?? r3;
        ?? r15;
        int i2;
        boolean z;
        int i3;
        boolean z2;
        long j2 = c2003e.f3788c;
        if (this.f3837m) {
            long j3 = -9223372036854775807L;
            if ((j2 == -1 || this.f3825a == 2) ? false : true) {
                C2007a0 c2007a0 = this.f3833i;
                if (!c2007a0.f3807c) {
                    int i4 = this.f3842r;
                    if (i4 <= 0) {
                        c2007a0.m1572a(c2003e);
                        return 0;
                    }
                    if (!c2007a0.f3809e) {
                        int min = (int) Math.min(112800L, j2);
                        long j4 = j2 - min;
                        if (c2003e.f3789d == j4) {
                            c2007a0.f3806b.m2593y(min);
                            c2003e.f3791f = 0;
                            c2003e.m1565e(c2007a0.f3806b.f6133a, 0, min, false);
                            C2360t c2360t = c2007a0.f3806b;
                            int i5 = c2360t.f6134b;
                            int i6 = c2360t.f6135c;
                            while (true) {
                                i6--;
                                if (i6 < i5) {
                                    break;
                                }
                                if (c2360t.f6133a[i6] == 71) {
                                    long m4764E0 = C4195m.m4764E0(c2360t, i6, i4);
                                    if (m4764E0 != -9223372036854775807L) {
                                        j3 = m4764E0;
                                        break;
                                    }
                                }
                            }
                            c2007a0.f3811g = j3;
                            c2007a0.f3809e = true;
                            return 0;
                        }
                        c2049p.f4187a = j4;
                    } else {
                        if (c2007a0.f3811g == -9223372036854775807L) {
                            c2007a0.m1572a(c2003e);
                            return 0;
                        }
                        if (c2007a0.f3808d) {
                            long j5 = c2007a0.f3810f;
                            if (j5 == -9223372036854775807L) {
                                c2007a0.m1572a(c2003e);
                                return 0;
                            }
                            c2007a0.f3812h = c2007a0.f3805a.m2306b(c2007a0.f3811g) - c2007a0.f3805a.m2306b(j5);
                            c2007a0.m1572a(c2003e);
                            return 0;
                        }
                        int min2 = (int) Math.min(112800L, j2);
                        long j6 = 0;
                        if (c2003e.f3789d == j6) {
                            c2007a0.f3806b.m2593y(min2);
                            c2003e.f3791f = 0;
                            c2003e.m1565e(c2007a0.f3806b.f6133a, 0, min2, false);
                            C2360t c2360t2 = c2007a0.f3806b;
                            int i7 = c2360t2.f6134b;
                            int i8 = c2360t2.f6135c;
                            while (true) {
                                if (i7 >= i8) {
                                    break;
                                }
                                if (c2360t2.f6133a[i7] == 71) {
                                    long m4764E02 = C4195m.m4764E0(c2360t2, i7, i4);
                                    if (m4764E02 != -9223372036854775807L) {
                                        j3 = m4764E02;
                                        break;
                                    }
                                }
                                i7++;
                            }
                            c2007a0.f3810f = j3;
                            c2007a0.f3808d = true;
                            return 0;
                        }
                        c2049p.f4187a = j6;
                    }
                    return 1;
                }
            }
            if (this.f3838n) {
                z2 = false;
            } else {
                this.f3838n = true;
                C2007a0 c2007a02 = this.f3833i;
                long j7 = c2007a02.f3812h;
                if (j7 != -9223372036854775807L) {
                    z2 = false;
                    C2035z c2035z = new C2035z(c2007a02.f3805a, j7, j2, this.f3842r);
                    this.f3834j = c2035z;
                    this.f3835k.mo1623a(c2035z.f3395a);
                } else {
                    z2 = false;
                    this.f3835k.mo1623a(new InterfaceC2050q.b(j7, 0L));
                }
            }
            if (this.f3839o) {
                this.f3839o = z2;
                mo1481f(0L, 0L);
                if (c2003e.f3789d != 0) {
                    c2049p.f4187a = 0L;
                    return 1;
                }
            }
            r3 = 1;
            r3 = 1;
            C2035z c2035z2 = this.f3834j;
            r15 = z2;
            if (c2035z2 != null) {
                r15 = z2;
                if (c2035z2.m1457b()) {
                    return this.f3834j.m1456a(c2003e, c2049p);
                }
            }
        } else {
            r3 = 1;
            r15 = 0;
        }
        C2360t c2360t3 = this.f3827c;
        byte[] bArr = c2360t3.f6133a;
        if (9400 - c2360t3.f6134b < 188) {
            int m2569a = c2360t3.m2569a();
            if (m2569a > 0) {
                System.arraycopy(bArr, this.f3827c.f6134b, bArr, r15, m2569a);
            }
            this.f3827c.m2565A(bArr, m2569a);
        }
        while (true) {
            if (this.f3827c.m2569a() >= 188) {
                i2 = -1;
                z = true;
                break;
            }
            int i9 = this.f3827c.f6135c;
            int m1566f = c2003e.m1566f(bArr, i9, 9400 - i9);
            i2 = -1;
            if (m1566f == -1) {
                z = false;
                break;
            }
            this.f3827c.m2566B(i9 + m1566f);
        }
        if (!z) {
            return i2;
        }
        C2360t c2360t4 = this.f3827c;
        int i10 = c2360t4.f6134b;
        int i11 = c2360t4.f6135c;
        byte[] bArr2 = c2360t4.f6133a;
        int i12 = i10;
        while (i12 < i11 && bArr2[i12] != 71) {
            i12++;
        }
        this.f3827c.m2567C(i12);
        int i13 = i12 + 188;
        if (i13 > i11) {
            int i14 = (i12 - i10) + this.f3841q;
            this.f3841q = i14;
            i3 = 2;
            if (this.f3825a == 2 && i14 > 376) {
                throw new C2205l0("Cannot find sync byte. Most likely not a Transport Stream.");
            }
        } else {
            i3 = 2;
            this.f3841q = r15;
        }
        C2360t c2360t5 = this.f3827c;
        int i15 = c2360t5.f6135c;
        if (i13 > i15) {
            return r15;
        }
        int m2573e = c2360t5.m2573e();
        if ((8388608 & m2573e) != 0) {
            this.f3827c.m2567C(i13);
            return r15;
        }
        int i16 = ((4194304 & m2573e) != 0 ? 1 : 0) | 0;
        int i17 = (2096896 & m2573e) >> 8;
        boolean z3 = (m2573e & 32) != 0;
        InterfaceC2011c0 interfaceC2011c0 = (m2573e & 16) != 0 ? this.f3830f.get(i17) : null;
        if (interfaceC2011c0 == null) {
            this.f3827c.m2567C(i13);
            return r15;
        }
        if (this.f3825a != i3) {
            int i18 = m2573e & 15;
            int i19 = this.f3828d.get(i17, i18 - 1);
            this.f3828d.put(i17, i18);
            if (i19 == i18) {
                this.f3827c.m2567C(i13);
                return r15;
            }
            if (i18 != ((i19 + r3) & 15)) {
                interfaceC2011c0.mo1582c();
            }
        }
        if (z3) {
            int m2585q = this.f3827c.m2585q();
            i16 |= (this.f3827c.m2585q() & 64) != 0 ? 2 : 0;
            this.f3827c.m2568D(m2585q - r3);
        }
        boolean z4 = this.f3837m;
        if (this.f3825a == i3 || z4 || !this.f3832h.get(i17, r15)) {
            this.f3827c.m2566B(i13);
            interfaceC2011c0.mo1581b(this.f3827c, i16);
            this.f3827c.m2566B(i15);
        }
        if (this.f3825a != i3 && !z4 && this.f3837m && j2 != -1) {
            this.f3839o = r3;
        }
        this.f3827c.m2567C(i13);
        return r15;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: e */
    public void mo1480e(InterfaceC2042i interfaceC2042i) {
        this.f3835k = interfaceC2042i;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: f */
    public void mo1481f(long j2, long j3) {
        C2035z c2035z;
        C4195m.m4771I(this.f3825a != 2);
        int size = this.f3826b.size();
        for (int i2 = 0; i2 < size; i2++) {
            C2342c0 c2342c0 = this.f3826b.get(i2);
            if ((c2342c0.m2307c() == -9223372036854775807L) || (c2342c0.m2307c() != 0 && c2342c0.f6031a != j3)) {
                c2342c0.f6033c = -9223372036854775807L;
                c2342c0.m2308d(j3);
            }
        }
        if (j3 != 0 && (c2035z = this.f3834j) != null) {
            c2035z.m1460e(j3);
        }
        this.f3827c.m2592x();
        this.f3828d.clear();
        for (int i3 = 0; i3 < this.f3830f.size(); i3++) {
            this.f3830f.valueAt(i3).mo1582c();
        }
        this.f3841q = 0;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: h */
    public boolean mo1483h(C2003e c2003e) {
        boolean z;
        byte[] bArr = this.f3827c.f6133a;
        c2003e.m1565e(bArr, 0, 940, false);
        for (int i2 = 0; i2 < 188; i2++) {
            int i3 = 0;
            while (true) {
                if (i3 >= 5) {
                    z = true;
                    break;
                }
                if (bArr[(i3 * 188) + i2] != 71) {
                    z = false;
                    break;
                }
                i3++;
            }
            if (z) {
                c2003e.m1569i(i2);
                return true;
            }
        }
        return false;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    public void release() {
    }
}
