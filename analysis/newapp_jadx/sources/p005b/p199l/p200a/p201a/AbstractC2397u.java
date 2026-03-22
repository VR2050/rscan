package p005b.p199l.p200a.p201a;

import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.drm.DrmInitData;
import p005b.p199l.p200a.p201a.p204c1.C1945e;
import p005b.p199l.p200a.p201a.p205d1.InterfaceC1954e;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2107e0;
import p005b.p199l.p200a.p201a.p250p1.InterfaceC2356p;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.u */
/* loaded from: classes.dex */
public abstract class AbstractC2397u implements InterfaceC2396t0 {

    /* renamed from: c */
    public final int f6314c;

    /* renamed from: f */
    public C2398u0 f6316f;

    /* renamed from: g */
    public int f6317g;

    /* renamed from: h */
    public int f6318h;

    /* renamed from: i */
    public InterfaceC2107e0 f6319i;

    /* renamed from: j */
    public Format[] f6320j;

    /* renamed from: k */
    public long f6321k;

    /* renamed from: m */
    public boolean f6323m;

    /* renamed from: n */
    public boolean f6324n;

    /* renamed from: e */
    public final C1964f0 f6315e = new C1964f0();

    /* renamed from: l */
    public long f6322l = Long.MIN_VALUE;

    public AbstractC2397u(int i2) {
        this.f6314c = i2;
    }

    /* renamed from: F */
    public static boolean m2664F(@Nullable InterfaceC1954e<?> interfaceC1954e, @Nullable DrmInitData drmInitData) {
        if (drmInitData == null) {
            return true;
        }
        if (interfaceC1954e == null) {
            return false;
        }
        return interfaceC1954e.mo1446e(drmInitData);
    }

    /* renamed from: A */
    public void mo1301A() {
    }

    /* renamed from: B */
    public void mo1302B() {
    }

    /* renamed from: C */
    public abstract void mo1303C(Format[] formatArr, long j2);

    /* renamed from: D */
    public final int m2665D(C1964f0 c1964f0, C1945e c1945e, boolean z) {
        int mo1787i = this.f6319i.mo1787i(c1964f0, c1945e, z);
        if (mo1787i == -4) {
            if (c1945e.isEndOfStream()) {
                this.f6322l = Long.MIN_VALUE;
                return this.f6323m ? -4 : -3;
            }
            long j2 = c1945e.f3307f + this.f6321k;
            c1945e.f3307f = j2;
            this.f6322l = Math.max(this.f6322l, j2);
        } else if (mo1787i == -5) {
            Format format = c1964f0.f3394c;
            long j3 = format.f9249p;
            if (j3 != Long.MAX_VALUE) {
                c1964f0.f3394c = format.m4047w(j3 + this.f6321k);
            }
        }
        return mo1787i;
    }

    /* renamed from: E */
    public abstract int mo1661E(Format format);

    /* renamed from: G */
    public int mo1662G() {
        return 0;
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2396t0
    /* renamed from: a */
    public final void mo2652a(int i2) {
        this.f6317g = i2;
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2396t0
    /* renamed from: d */
    public final void mo2653d() {
        C4195m.m4771I(this.f6318h == 1);
        this.f6315e.m1455a();
        this.f6318h = 0;
        this.f6319i = null;
        this.f6320j = null;
        this.f6323m = false;
        mo1325w();
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2396t0
    /* renamed from: e */
    public final boolean mo2654e() {
        return this.f6322l == Long.MIN_VALUE;
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2396t0
    /* renamed from: f */
    public final void mo2655f(C2398u0 c2398u0, Format[] formatArr, InterfaceC2107e0 interfaceC2107e0, long j2, boolean z, long j3) {
        C4195m.m4771I(this.f6318h == 0);
        this.f6316f = c2398u0;
        this.f6318h = 1;
        mo1326x(z);
        C4195m.m4771I(!this.f6323m);
        this.f6319i = interfaceC2107e0;
        this.f6322l = j3;
        this.f6320j = formatArr;
        this.f6321k = j3;
        mo1303C(formatArr, j3);
        mo1327y(j2, z);
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2396t0
    /* renamed from: g */
    public final void mo2656g() {
        this.f6323m = true;
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2396t0
    public final int getState() {
        return this.f6318h;
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2396t0
    public final int getTrackType() {
        return this.f6314c;
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2396t0
    /* renamed from: h */
    public final AbstractC2397u mo2657h() {
        return this;
    }

    @Override // p005b.p199l.p200a.p201a.C2392r0.b
    /* renamed from: k */
    public void mo1318k(int i2, @Nullable Object obj) {
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2396t0
    @Nullable
    /* renamed from: l */
    public final InterfaceC2107e0 mo2658l() {
        return this.f6319i;
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2396t0
    /* renamed from: m */
    public /* synthetic */ void mo1684m(float f2) {
        C2394s0.m2650a(this, f2);
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2396t0
    /* renamed from: n */
    public final void mo2659n() {
        this.f6319i.mo1786a();
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2396t0
    /* renamed from: o */
    public final long mo2660o() {
        return this.f6322l;
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2396t0
    /* renamed from: p */
    public final void mo2661p(long j2) {
        this.f6323m = false;
        this.f6322l = j2;
        mo1327y(j2, false);
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2396t0
    /* renamed from: q */
    public final boolean mo2662q() {
        return this.f6323m;
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2396t0
    @Nullable
    /* renamed from: r */
    public InterfaceC2356p mo1322r() {
        return null;
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2396t0
    public final void reset() {
        C4195m.m4771I(this.f6318h == 0);
        this.f6315e.m1455a();
        mo1328z();
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2396t0
    public final void start() {
        C4195m.m4771I(this.f6318h == 1);
        this.f6318h = 2;
        mo1301A();
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2396t0
    public final void stop() {
        C4195m.m4771I(this.f6318h == 2);
        this.f6318h = 1;
        mo1302B();
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2396t0
    /* renamed from: t */
    public final void mo2663t(Format[] formatArr, InterfaceC2107e0 interfaceC2107e0, long j2) {
        C4195m.m4771I(!this.f6323m);
        this.f6319i = interfaceC2107e0;
        this.f6322l = j2;
        this.f6320j = formatArr;
        this.f6321k = j2;
        mo1303C(formatArr, j2);
    }

    /* JADX WARN: Removed duplicated region for block: B:11:0x0021  */
    /* JADX WARN: Removed duplicated region for block: B:15:0x0023  */
    /* renamed from: u */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final p005b.p199l.p200a.p201a.C1936b0 m2666u(java.lang.Exception r10, @androidx.annotation.Nullable com.google.android.exoplayer2.Format r11) {
        /*
            r9 = this;
            r0 = 4
            if (r11 == 0) goto L1a
            boolean r1 = r9.f6324n
            if (r1 != 0) goto L1a
            r1 = 1
            r9.f6324n = r1
            r1 = 0
            int r2 = r9.mo1661E(r11)     // Catch: java.lang.Throwable -> L14 p005b.p199l.p200a.p201a.C1936b0 -> L18
            r2 = r2 & 7
            r9.f6324n = r1
            goto L1b
        L14:
            r10 = move-exception
            r9.f6324n = r1
            throw r10
        L18:
            r9.f6324n = r1
        L1a:
            r2 = 4
        L1b:
            int r6 = r9.f6317g
            b.l.a.a.b0 r1 = new b.l.a.a.b0
            if (r11 != 0) goto L23
            r8 = 4
            goto L24
        L23:
            r8 = r2
        L24:
            r4 = 1
            r3 = r1
            r5 = r10
            r7 = r11
            r3.<init>(r4, r5, r6, r7, r8)
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.AbstractC2397u.m2666u(java.lang.Exception, com.google.android.exoplayer2.Format):b.l.a.a.b0");
    }

    /* renamed from: v */
    public final C1964f0 m2667v() {
        this.f6315e.m1455a();
        return this.f6315e;
    }

    /* renamed from: w */
    public abstract void mo1325w();

    /* renamed from: x */
    public void mo1326x(boolean z) {
    }

    /* renamed from: y */
    public abstract void mo1327y(long j2, boolean z);

    /* renamed from: z */
    public void mo1328z() {
    }
}
