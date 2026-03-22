package p005b.p199l.p200a.p201a.p227k1;

import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.source.TrackGroupArray;
import java.util.Objects;
import p005b.p199l.p200a.p201a.C1964f0;
import p005b.p199l.p200a.p201a.C2400v0;
import p005b.p199l.p200a.p201a.p204c1.C1945e;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.k1.p */
/* loaded from: classes.dex */
public final class C2193p implements InterfaceC2201x, InterfaceC2201x.a {

    /* renamed from: c */
    public final InterfaceC2201x f5214c;

    /* renamed from: e */
    @Nullable
    public InterfaceC2201x.a f5215e;

    /* renamed from: f */
    public a[] f5216f = new a[0];

    /* renamed from: g */
    public long f5217g;

    /* renamed from: h */
    public long f5218h;

    /* renamed from: i */
    public long f5219i;

    /* renamed from: b.l.a.a.k1.p$a */
    public final class a implements InterfaceC2107e0 {

        /* renamed from: c */
        public final InterfaceC2107e0 f5220c;

        /* renamed from: e */
        public boolean f5221e;

        public a(InterfaceC2107e0 interfaceC2107e0) {
            this.f5220c = interfaceC2107e0;
        }

        @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2107e0
        /* renamed from: a */
        public void mo1786a() {
            this.f5220c.mo1786a();
        }

        @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2107e0
        /* renamed from: i */
        public int mo1787i(C1964f0 c1964f0, C1945e c1945e, boolean z) {
            if (C2193p.this.m2021a()) {
                return -3;
            }
            if (this.f5221e) {
                c1945e.setFlags(4);
                return -4;
            }
            int mo1787i = this.f5220c.mo1787i(c1964f0, c1945e, z);
            if (mo1787i == -5) {
                Format format = c1964f0.f3394c;
                Objects.requireNonNull(format);
                int i2 = format.f9231B;
                if (i2 != 0 || format.f9232C != 0) {
                    C2193p c2193p = C2193p.this;
                    if (c2193p.f5218h != 0) {
                        i2 = 0;
                    }
                    c1964f0.f3394c = format.m4045o(i2, c2193p.f5219i == Long.MIN_VALUE ? format.f9232C : 0);
                }
                return -5;
            }
            C2193p c2193p2 = C2193p.this;
            long j2 = c2193p2.f5219i;
            if (j2 == Long.MIN_VALUE || ((mo1787i != -4 || c1945e.f3307f < j2) && !(mo1787i == -3 && c2193p2.mo1763f() == Long.MIN_VALUE))) {
                return mo1787i;
            }
            c1945e.clear();
            c1945e.setFlags(4);
            this.f5221e = true;
            return -4;
        }

        @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2107e0
        public boolean isReady() {
            return !C2193p.this.m2021a() && this.f5220c.isReady();
        }

        @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2107e0
        /* renamed from: o */
        public int mo1788o(long j2) {
            if (C2193p.this.m2021a()) {
                return -3;
            }
            return this.f5220c.mo1788o(j2);
        }
    }

    public C2193p(InterfaceC2201x interfaceC2201x, boolean z, long j2, long j3) {
        this.f5214c = interfaceC2201x;
        this.f5217g = z ? j2 : -9223372036854775807L;
        this.f5218h = j2;
        this.f5219i = j3;
    }

    /* renamed from: a */
    public boolean m2021a() {
        return this.f5217g != -9223372036854775807L;
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x, p005b.p199l.p200a.p201a.p227k1.InterfaceC2109f0
    /* renamed from: b */
    public long mo1759b() {
        long mo1759b = this.f5214c.mo1759b();
        if (mo1759b != Long.MIN_VALUE) {
            long j2 = this.f5219i;
            if (j2 == Long.MIN_VALUE || mo1759b < j2) {
                return mo1759b;
            }
        }
        return Long.MIN_VALUE;
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x, p005b.p199l.p200a.p201a.p227k1.InterfaceC2109f0
    /* renamed from: c */
    public boolean mo1760c(long j2) {
        return this.f5214c.mo1760c(j2);
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x, p005b.p199l.p200a.p201a.p227k1.InterfaceC2109f0
    /* renamed from: d */
    public boolean mo1761d() {
        return this.f5214c.mo1761d();
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x
    /* renamed from: e */
    public long mo1762e(long j2, C2400v0 c2400v0) {
        long j3 = this.f5218h;
        if (j2 == j3) {
            return j3;
        }
        long m2330h = C2344d0.m2330h(c2400v0.f6334c, 0L, j2 - j3);
        long j4 = c2400v0.f6335d;
        long j5 = this.f5219i;
        long m2330h2 = C2344d0.m2330h(j4, 0L, j5 == Long.MIN_VALUE ? Long.MAX_VALUE : j5 - j2);
        if (m2330h != c2400v0.f6334c || m2330h2 != c2400v0.f6335d) {
            c2400v0 = new C2400v0(m2330h, m2330h2);
        }
        return this.f5214c.mo1762e(j2, c2400v0);
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x, p005b.p199l.p200a.p201a.p227k1.InterfaceC2109f0
    /* renamed from: f */
    public long mo1763f() {
        long mo1763f = this.f5214c.mo1763f();
        if (mo1763f != Long.MIN_VALUE) {
            long j2 = this.f5219i;
            if (j2 == Long.MIN_VALUE || mo1763f < j2) {
                return mo1763f;
            }
        }
        return Long.MIN_VALUE;
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x, p005b.p199l.p200a.p201a.p227k1.InterfaceC2109f0
    /* renamed from: g */
    public void mo1764g(long j2) {
        this.f5214c.mo1764g(j2);
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2109f0.a
    /* renamed from: i */
    public void mo1421i(InterfaceC2201x interfaceC2201x) {
        InterfaceC2201x.a aVar = this.f5215e;
        Objects.requireNonNull(aVar);
        aVar.mo1421i(this);
    }

    /* JADX WARN: Code restructure failed: missing block: B:34:0x0083, code lost:
    
        if (r1 > r5) goto L36;
     */
    /* JADX WARN: Removed duplicated region for block: B:29:0x0073  */
    /* JADX WARN: Removed duplicated region for block: B:39:0x008d  */
    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x
    /* renamed from: j */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public long mo1767j(p005b.p199l.p200a.p201a.p245m1.InterfaceC2257f[] r16, boolean[] r17, p005b.p199l.p200a.p201a.p227k1.InterfaceC2107e0[] r18, boolean[] r19, long r20) {
        /*
            r15 = this;
            r0 = r15
            r8 = r16
            r9 = r18
            int r1 = r9.length
            b.l.a.a.k1.p$a[] r1 = new p005b.p199l.p200a.p201a.p227k1.C2193p.a[r1]
            r0.f5216f = r1
            int r1 = r9.length
            b.l.a.a.k1.e0[] r10 = new p005b.p199l.p200a.p201a.p227k1.InterfaceC2107e0[r1]
            r11 = 0
            r1 = 0
        Lf:
            int r2 = r9.length
            r12 = 0
            if (r1 >= r2) goto L28
            b.l.a.a.k1.p$a[] r2 = r0.f5216f
            r3 = r9[r1]
            b.l.a.a.k1.p$a r3 = (p005b.p199l.p200a.p201a.p227k1.C2193p.a) r3
            r2[r1] = r3
            r3 = r2[r1]
            if (r3 == 0) goto L23
            r2 = r2[r1]
            b.l.a.a.k1.e0 r12 = r2.f5220c
        L23:
            r10[r1] = r12
            int r1 = r1 + 1
            goto Lf
        L28:
            b.l.a.a.k1.x r1 = r0.f5214c
            r2 = r16
            r3 = r17
            r4 = r10
            r5 = r19
            r6 = r20
            long r1 = r1.mo1767j(r2, r3, r4, r5, r6)
            boolean r3 = r15.m2021a()
            r4 = 1
            if (r3 == 0) goto L68
            long r5 = r0.f5218h
            int r3 = (r20 > r5 ? 1 : (r20 == r5 ? 0 : -1))
            if (r3 != 0) goto L68
            r13 = 0
            int r3 = (r5 > r13 ? 1 : (r5 == r13 ? 0 : -1))
            if (r3 == 0) goto L63
            int r3 = r8.length
            r5 = 0
        L4c:
            if (r5 >= r3) goto L63
            r6 = r8[r5]
            if (r6 == 0) goto L60
            com.google.android.exoplayer2.Format r6 = r6.mo2156l()
            java.lang.String r6 = r6.f9245l
            boolean r6 = p005b.p199l.p200a.p201a.p250p1.C2357q.m2545h(r6)
            if (r6 != 0) goto L60
            r3 = 1
            goto L64
        L60:
            int r5 = r5 + 1
            goto L4c
        L63:
            r3 = 0
        L64:
            if (r3 == 0) goto L68
            r5 = r1
            goto L6d
        L68:
            r5 = -9223372036854775807(0x8000000000000001, double:-4.9E-324)
        L6d:
            r0.f5217g = r5
            int r3 = (r1 > r20 ? 1 : (r1 == r20 ? 0 : -1))
            if (r3 == 0) goto L87
            long r5 = r0.f5218h
            int r3 = (r1 > r5 ? 1 : (r1 == r5 ? 0 : -1))
            if (r3 < 0) goto L86
            long r5 = r0.f5219i
            r7 = -9223372036854775808
            int r3 = (r5 > r7 ? 1 : (r5 == r7 ? 0 : -1))
            if (r3 == 0) goto L87
            int r3 = (r1 > r5 ? 1 : (r1 == r5 ? 0 : -1))
            if (r3 > 0) goto L86
            goto L87
        L86:
            r4 = 0
        L87:
            p403d.p404a.p405a.p407b.p408a.C4195m.m4771I(r4)
        L8a:
            int r3 = r9.length
            if (r11 >= r3) goto Lb6
            r3 = r10[r11]
            if (r3 != 0) goto L96
            b.l.a.a.k1.p$a[] r3 = r0.f5216f
            r3[r11] = r12
            goto Lad
        L96:
            b.l.a.a.k1.p$a[] r3 = r0.f5216f
            r4 = r3[r11]
            if (r4 == 0) goto La4
            r4 = r3[r11]
            b.l.a.a.k1.e0 r4 = r4.f5220c
            r5 = r10[r11]
            if (r4 == r5) goto Lad
        La4:
            b.l.a.a.k1.p$a r4 = new b.l.a.a.k1.p$a
            r5 = r10[r11]
            r4.<init>(r5)
            r3[r11] = r4
        Lad:
            b.l.a.a.k1.p$a[] r3 = r0.f5216f
            r3 = r3[r11]
            r9[r11] = r3
            int r11 = r11 + 1
            goto L8a
        Lb6:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p227k1.C2193p.mo1767j(b.l.a.a.m1.f[], boolean[], b.l.a.a.k1.e0[], boolean[], long):long");
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x.a
    /* renamed from: k */
    public void mo1423k(InterfaceC2201x interfaceC2201x) {
        InterfaceC2201x.a aVar = this.f5215e;
        Objects.requireNonNull(aVar);
        aVar.mo1423k(this);
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x
    /* renamed from: m */
    public void mo1770m() {
        this.f5214c.mo1770m();
    }

    /* JADX WARN: Code restructure failed: missing block: B:17:0x0031, code lost:
    
        if (r0 > r7) goto L17;
     */
    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x
    /* renamed from: n */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public long mo1771n(long r7) {
        /*
            r6 = this;
            r0 = -9223372036854775807(0x8000000000000001, double:-4.9E-324)
            r6.f5217g = r0
            b.l.a.a.k1.p$a[] r0 = r6.f5216f
            int r1 = r0.length
            r2 = 0
            r3 = 0
        Lc:
            if (r3 >= r1) goto L17
            r4 = r0[r3]
            if (r4 == 0) goto L14
            r4.f5221e = r2
        L14:
            int r3 = r3 + 1
            goto Lc
        L17:
            b.l.a.a.k1.x r0 = r6.f5214c
            long r0 = r0.mo1771n(r7)
            int r3 = (r0 > r7 ? 1 : (r0 == r7 ? 0 : -1))
            if (r3 == 0) goto L33
            long r7 = r6.f5218h
            int r3 = (r0 > r7 ? 1 : (r0 == r7 ? 0 : -1))
            if (r3 < 0) goto L34
            long r7 = r6.f5219i
            r3 = -9223372036854775808
            int r5 = (r7 > r3 ? 1 : (r7 == r3 ? 0 : -1))
            if (r5 == 0) goto L33
            int r3 = (r0 > r7 ? 1 : (r0 == r7 ? 0 : -1))
            if (r3 > 0) goto L34
        L33:
            r2 = 1
        L34:
            p403d.p404a.p405a.p407b.p408a.C4195m.m4771I(r2)
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p227k1.C2193p.mo1771n(long):long");
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x
    /* renamed from: p */
    public long mo1772p() {
        if (m2021a()) {
            long j2 = this.f5217g;
            this.f5217g = -9223372036854775807L;
            long mo1772p = mo1772p();
            return mo1772p != -9223372036854775807L ? mo1772p : j2;
        }
        long mo1772p2 = this.f5214c.mo1772p();
        if (mo1772p2 == -9223372036854775807L) {
            return -9223372036854775807L;
        }
        boolean z = true;
        C4195m.m4771I(mo1772p2 >= this.f5218h);
        long j3 = this.f5219i;
        if (j3 != Long.MIN_VALUE && mo1772p2 > j3) {
            z = false;
        }
        C4195m.m4771I(z);
        return mo1772p2;
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x
    /* renamed from: q */
    public void mo1773q(InterfaceC2201x.a aVar, long j2) {
        this.f5215e = aVar;
        this.f5214c.mo1773q(this, j2);
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x
    /* renamed from: r */
    public TrackGroupArray mo1774r() {
        return this.f5214c.mo1774r();
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x
    /* renamed from: u */
    public void mo1776u(long j2, boolean z) {
        this.f5214c.mo1776u(j2, z);
    }
}
