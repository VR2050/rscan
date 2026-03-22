package p005b.p199l.p200a.p201a;

import android.annotation.SuppressLint;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.util.Pair;
import androidx.annotation.Nullable;
import com.google.android.exoplayer2.source.TrackGroupArray;
import java.util.ArrayDeque;
import java.util.Iterator;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;
import p005b.p199l.p200a.p201a.AbstractC2395t;
import p005b.p199l.p200a.p201a.AbstractC2404x0;
import p005b.p199l.p200a.p201a.C1940c0;
import p005b.p199l.p200a.p201a.C1949d0;
import p005b.p199l.p200a.p201a.C2392r0;
import p005b.p199l.p200a.p201a.InterfaceC2368q0;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2202y;
import p005b.p199l.p200a.p201a.p245m1.AbstractC2259h;
import p005b.p199l.p200a.p201a.p245m1.C2258g;
import p005b.p199l.p200a.p201a.p245m1.C2260i;
import p005b.p199l.p200a.p201a.p245m1.InterfaceC2257f;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2292g;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p005b.p199l.p200a.p201a.p250p1.InterfaceC2346f;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.c0 */
/* loaded from: classes.dex */
public final class C1940c0 extends AbstractC2395t implements InterfaceC2368q0 {

    /* renamed from: b */
    public final C2260i f3250b;

    /* renamed from: c */
    public final InterfaceC2396t0[] f3251c;

    /* renamed from: d */
    public final AbstractC2259h f3252d;

    /* renamed from: e */
    public final Handler f3253e;

    /* renamed from: f */
    public final C1949d0 f3254f;

    /* renamed from: g */
    public final Handler f3255g;

    /* renamed from: h */
    public final CopyOnWriteArrayList<AbstractC2395t.a> f3256h;

    /* renamed from: i */
    public final AbstractC2404x0.b f3257i;

    /* renamed from: j */
    public final ArrayDeque<Runnable> f3258j;

    /* renamed from: k */
    public InterfaceC2202y f3259k;

    /* renamed from: l */
    public boolean f3260l;

    /* renamed from: m */
    public int f3261m;

    /* renamed from: n */
    public int f3262n;

    /* renamed from: o */
    public boolean f3263o;

    /* renamed from: p */
    public int f3264p;

    /* renamed from: q */
    public boolean f3265q;

    /* renamed from: r */
    public boolean f3266r;

    /* renamed from: s */
    public int f3267s;

    /* renamed from: t */
    public C2262n0 f3268t;

    /* renamed from: u */
    public C2400v0 f3269u;

    /* renamed from: v */
    public C2251m0 f3270v;

    /* renamed from: w */
    public int f3271w;

    /* renamed from: x */
    public int f3272x;

    /* renamed from: y */
    public long f3273y;

    /* renamed from: b.l.a.a.c0$a */
    public class a extends Handler {
        public a(Looper looper) {
            super(looper);
        }

        @Override // android.os.Handler
        public void handleMessage(Message message) {
            C1940c0 c1940c0 = C1940c0.this;
            Objects.requireNonNull(c1940c0);
            int i2 = message.what;
            if (i2 != 0) {
                if (i2 != 1) {
                    throw new IllegalStateException();
                }
                final C2262n0 c2262n0 = (C2262n0) message.obj;
                if (message.arg1 != 0) {
                    c1940c0.f3267s--;
                }
                if (c1940c0.f3267s != 0 || c1940c0.f3268t.equals(c2262n0)) {
                    return;
                }
                c1940c0.f3268t = c2262n0;
                c1940c0.m1347J(new AbstractC2395t.b() { // from class: b.l.a.a.b
                    @Override // p005b.p199l.p200a.p201a.AbstractC2395t.b
                    /* renamed from: a */
                    public final void mo1338a(InterfaceC2368q0.a aVar) {
                        aVar.onPlaybackParametersChanged(C2262n0.this);
                    }
                });
                return;
            }
            C2251m0 c2251m0 = (C2251m0) message.obj;
            int i3 = message.arg1;
            int i4 = message.arg2;
            boolean z = i4 != -1;
            int i5 = c1940c0.f3264p - i3;
            c1940c0.f3264p = i5;
            if (i5 == 0) {
                C2251m0 m2140a = c2251m0.f5612d == -9223372036854775807L ? c2251m0.m2140a(c2251m0.f5611c, 0L, c2251m0.f5613e, c2251m0.f5621m) : c2251m0;
                if (!c1940c0.f3270v.f5610b.m2691q() && m2140a.f5610b.m2691q()) {
                    c1940c0.f3272x = 0;
                    c1940c0.f3271w = 0;
                    c1940c0.f3273y = 0L;
                }
                int i6 = c1940c0.f3265q ? 0 : 2;
                boolean z2 = c1940c0.f3266r;
                c1940c0.f3265q = false;
                c1940c0.f3266r = false;
                c1940c0.m1353P(m2140a, z, i4, i6, z2);
            }
        }
    }

    /* renamed from: b.l.a.a.c0$b */
    public static final class b implements Runnable {

        /* renamed from: c */
        public final C2251m0 f3275c;

        /* renamed from: e */
        public final CopyOnWriteArrayList<AbstractC2395t.a> f3276e;

        /* renamed from: f */
        public final AbstractC2259h f3277f;

        /* renamed from: g */
        public final boolean f3278g;

        /* renamed from: h */
        public final int f3279h;

        /* renamed from: i */
        public final int f3280i;

        /* renamed from: j */
        public final boolean f3281j;

        /* renamed from: k */
        public final boolean f3282k;

        /* renamed from: l */
        public final boolean f3283l;

        /* renamed from: m */
        public final boolean f3284m;

        /* renamed from: n */
        public final boolean f3285n;

        /* renamed from: o */
        public final boolean f3286o;

        /* renamed from: p */
        public final boolean f3287p;

        /* renamed from: q */
        public final boolean f3288q;

        public b(C2251m0 c2251m0, C2251m0 c2251m02, CopyOnWriteArrayList<AbstractC2395t.a> copyOnWriteArrayList, AbstractC2259h abstractC2259h, boolean z, int i2, int i3, boolean z2, boolean z3, boolean z4) {
            this.f3275c = c2251m0;
            this.f3276e = new CopyOnWriteArrayList<>(copyOnWriteArrayList);
            this.f3277f = abstractC2259h;
            this.f3278g = z;
            this.f3279h = i2;
            this.f3280i = i3;
            this.f3281j = z2;
            this.f3287p = z3;
            this.f3288q = z4;
            this.f3282k = c2251m02.f5614f != c2251m0.f5614f;
            C1936b0 c1936b0 = c2251m02.f5615g;
            C1936b0 c1936b02 = c2251m0.f5615g;
            this.f3283l = (c1936b0 == c1936b02 || c1936b02 == null) ? false : true;
            this.f3284m = c2251m02.f5610b != c2251m0.f5610b;
            this.f3285n = c2251m02.f5616h != c2251m0.f5616h;
            this.f3286o = c2251m02.f5618j != c2251m0.f5618j;
        }

        @Override // java.lang.Runnable
        public void run() {
            if (this.f3284m || this.f3280i == 0) {
                C1940c0.m1339I(this.f3276e, new AbstractC2395t.b() { // from class: b.l.a.a.f
                    @Override // p005b.p199l.p200a.p201a.AbstractC2395t.b
                    /* renamed from: a */
                    public final void mo1338a(InterfaceC2368q0.a aVar) {
                        C1940c0.b bVar = C1940c0.b.this;
                        aVar.onTimelineChanged(bVar.f3275c.f5610b, bVar.f3280i);
                    }
                });
            }
            if (this.f3278g) {
                C1940c0.m1339I(this.f3276e, new AbstractC2395t.b() { // from class: b.l.a.a.h
                    @Override // p005b.p199l.p200a.p201a.AbstractC2395t.b
                    /* renamed from: a */
                    public final void mo1338a(InterfaceC2368q0.a aVar) {
                        aVar.onPositionDiscontinuity(C1940c0.b.this.f3279h);
                    }
                });
            }
            if (this.f3283l) {
                C1940c0.m1339I(this.f3276e, new AbstractC2395t.b() { // from class: b.l.a.a.e
                    @Override // p005b.p199l.p200a.p201a.AbstractC2395t.b
                    /* renamed from: a */
                    public final void mo1338a(InterfaceC2368q0.a aVar) {
                        aVar.onPlayerError(C1940c0.b.this.f3275c.f5615g);
                    }
                });
            }
            if (this.f3286o) {
                this.f3277f.mo2160a(this.f3275c.f5618j.f5666d);
                C1940c0.m1339I(this.f3276e, new AbstractC2395t.b() { // from class: b.l.a.a.i
                    @Override // p005b.p199l.p200a.p201a.AbstractC2395t.b
                    /* renamed from: a */
                    public final void mo1338a(InterfaceC2368q0.a aVar) {
                        C2251m0 c2251m0 = C1940c0.b.this.f3275c;
                        aVar.onTracksChanged(c2251m0.f5617i, c2251m0.f5618j.f5665c);
                    }
                });
            }
            if (this.f3285n) {
                C1940c0.m1339I(this.f3276e, new AbstractC2395t.b() { // from class: b.l.a.a.g
                    @Override // p005b.p199l.p200a.p201a.AbstractC2395t.b
                    /* renamed from: a */
                    public final void mo1338a(InterfaceC2368q0.a aVar) {
                        aVar.onLoadingChanged(C1940c0.b.this.f3275c.f5616h);
                    }
                });
            }
            if (this.f3282k) {
                C1940c0.m1339I(this.f3276e, new AbstractC2395t.b() { // from class: b.l.a.a.k
                    @Override // p005b.p199l.p200a.p201a.AbstractC2395t.b
                    /* renamed from: a */
                    public final void mo1338a(InterfaceC2368q0.a aVar) {
                        C1940c0.b bVar = C1940c0.b.this;
                        aVar.onPlayerStateChanged(bVar.f3287p, bVar.f3275c.f5614f);
                    }
                });
            }
            if (this.f3288q) {
                C1940c0.m1339I(this.f3276e, new AbstractC2395t.b() { // from class: b.l.a.a.j
                    @Override // p005b.p199l.p200a.p201a.AbstractC2395t.b
                    /* renamed from: a */
                    public final void mo1338a(InterfaceC2368q0.a aVar) {
                        aVar.onIsPlayingChanged(C1940c0.b.this.f3275c.f5614f == 3);
                    }
                });
            }
            if (this.f3281j) {
                C1940c0.m1339I(this.f3276e, new AbstractC2395t.b() { // from class: b.l.a.a.q
                    @Override // p005b.p199l.p200a.p201a.AbstractC2395t.b
                    /* renamed from: a */
                    public final void mo1338a(InterfaceC2368q0.a aVar) {
                        aVar.onSeekProcessed();
                    }
                });
            }
        }
    }

    @SuppressLint({"HandlerLeak"})
    public C1940c0(InterfaceC2396t0[] interfaceC2396t0Arr, AbstractC2259h abstractC2259h, InterfaceC2077h0 interfaceC2077h0, InterfaceC2292g interfaceC2292g, InterfaceC2346f interfaceC2346f, Looper looper) {
        Integer.toHexString(System.identityHashCode(this));
        String str = C2344d0.f6039e;
        C4195m.m4771I(interfaceC2396t0Arr.length > 0);
        this.f3251c = interfaceC2396t0Arr;
        Objects.requireNonNull(abstractC2259h);
        this.f3252d = abstractC2259h;
        this.f3260l = false;
        this.f3262n = 0;
        this.f3263o = false;
        this.f3256h = new CopyOnWriteArrayList<>();
        C2260i c2260i = new C2260i(new C2398u0[interfaceC2396t0Arr.length], new InterfaceC2257f[interfaceC2396t0Arr.length], null);
        this.f3250b = c2260i;
        this.f3257i = new AbstractC2404x0.b();
        this.f3268t = C2262n0.f5668a;
        this.f3269u = C2400v0.f6333b;
        this.f3261m = 0;
        a aVar = new a(looper);
        this.f3253e = aVar;
        this.f3270v = C2251m0.m2139d(0L, c2260i);
        this.f3258j = new ArrayDeque<>();
        C1949d0 c1949d0 = new C1949d0(interfaceC2396t0Arr, abstractC2259h, c2260i, interfaceC2077h0, interfaceC2292g, this.f3260l, this.f3262n, this.f3263o, aVar, interfaceC2346f);
        this.f3254f = c1949d0;
        this.f3255g = new Handler(c1949d0.f3349k.getLooper());
    }

    /* renamed from: I */
    public static void m1339I(CopyOnWriteArrayList<AbstractC2395t.a> copyOnWriteArrayList, AbstractC2395t.b bVar) {
        Iterator<AbstractC2395t.a> it = copyOnWriteArrayList.iterator();
        while (it.hasNext()) {
            AbstractC2395t.a next = it.next();
            if (!next.f6313b) {
                bVar.mo1338a(next.f6312a);
            }
        }
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    /* renamed from: A */
    public boolean mo1340A() {
        return this.f3263o;
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    /* renamed from: B */
    public long mo1341B() {
        if (m1351N()) {
            return this.f3273y;
        }
        C2251m0 c2251m0 = this.f3270v;
        if (c2251m0.f5619k.f5250d != c2251m0.f5611c.f5250d) {
            return c2251m0.f5610b.m2690n(mo1367o(), this.f6311a).m2698a();
        }
        long j2 = c2251m0.f5620l;
        if (this.f3270v.f5619k.m2024a()) {
            C2251m0 c2251m02 = this.f3270v;
            AbstractC2404x0.b mo1929h = c2251m02.f5610b.mo1929h(c2251m02.f5619k.f5247a, this.f3257i);
            long m2695d = mo1929h.m2695d(this.f3270v.f5619k.f5248b);
            j2 = m2695d == Long.MIN_VALUE ? mo1929h.f6369c : m2695d;
        }
        return m1349L(this.f3270v.f5619k, j2);
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    /* renamed from: C */
    public C2258g mo1342C() {
        return this.f3270v.f5618j.f5665c;
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    /* renamed from: D */
    public int mo1343D(int i2) {
        return this.f3251c[i2].getTrackType();
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    @Nullable
    /* renamed from: E */
    public InterfaceC2368q0.b mo1344E() {
        return null;
    }

    /* renamed from: G */
    public C2392r0 m1345G(C2392r0.b bVar) {
        return new C2392r0(this.f3254f, bVar, this.f3270v.f5610b, mo1367o(), this.f3255g);
    }

    /* renamed from: H */
    public final C2251m0 m1346H(boolean z, boolean z2, boolean z3, int i2) {
        int mo1831b;
        if (z) {
            this.f3271w = 0;
            this.f3272x = 0;
            this.f3273y = 0L;
        } else {
            this.f3271w = mo1367o();
            if (m1351N()) {
                mo1831b = this.f3272x;
            } else {
                C2251m0 c2251m0 = this.f3270v;
                mo1831b = c2251m0.f5610b.mo1831b(c2251m0.f5611c.f5247a);
            }
            this.f3272x = mo1831b;
            this.f3273y = getCurrentPosition();
        }
        boolean z4 = z || z2;
        InterfaceC2202y.a m2143e = z4 ? this.f3270v.m2143e(this.f3263o, this.f6311a, this.f3257i) : this.f3270v.f5611c;
        long j2 = z4 ? 0L : this.f3270v.f5622n;
        return new C2251m0(z2 ? AbstractC2404x0.f6366a : this.f3270v.f5610b, m2143e, j2, z4 ? -9223372036854775807L : this.f3270v.f5613e, i2, z3 ? null : this.f3270v.f5615g, false, z2 ? TrackGroupArray.f9396c : this.f3270v.f5617i, z2 ? this.f3250b : this.f3270v.f5618j, m2143e, j2, 0L, j2);
    }

    /* renamed from: J */
    public final void m1347J(final AbstractC2395t.b bVar) {
        final CopyOnWriteArrayList copyOnWriteArrayList = new CopyOnWriteArrayList(this.f3256h);
        m1348K(new Runnable() { // from class: b.l.a.a.m
            @Override // java.lang.Runnable
            public final void run() {
                C1940c0.m1339I(copyOnWriteArrayList, bVar);
            }
        });
    }

    /* renamed from: K */
    public final void m1348K(Runnable runnable) {
        boolean z = !this.f3258j.isEmpty();
        this.f3258j.addLast(runnable);
        if (z) {
            return;
        }
        while (!this.f3258j.isEmpty()) {
            this.f3258j.peekFirst().run();
            this.f3258j.removeFirst();
        }
    }

    /* renamed from: L */
    public final long m1349L(InterfaceC2202y.a aVar, long j2) {
        long m2669b = C2399v.m2669b(j2);
        this.f3270v.f5610b.mo1929h(aVar.f5247a, this.f3257i);
        return m2669b + C2399v.m2669b(this.f3257i.f6370d);
    }

    /* renamed from: M */
    public void m1350M(final boolean z, final int i2) {
        boolean isPlaying = isPlaying();
        int i3 = (this.f3260l && this.f3261m == 0) ? 1 : 0;
        int i4 = (z && i2 == 0) ? 1 : 0;
        if (i3 != i4) {
            this.f3254f.f3348j.m2297a(1, i4, 0).sendToTarget();
        }
        final boolean z2 = this.f3260l != z;
        final boolean z3 = this.f3261m != i2;
        this.f3260l = z;
        this.f3261m = i2;
        final boolean isPlaying2 = isPlaying();
        final boolean z4 = isPlaying != isPlaying2;
        if (z2 || z3 || z4) {
            final int i5 = this.f3270v.f5614f;
            m1347J(new AbstractC2395t.b() { // from class: b.l.a.a.d
                @Override // p005b.p199l.p200a.p201a.AbstractC2395t.b
                /* renamed from: a */
                public final void mo1338a(InterfaceC2368q0.a aVar) {
                    boolean z5 = z2;
                    boolean z6 = z;
                    int i6 = i5;
                    boolean z7 = z3;
                    int i7 = i2;
                    boolean z8 = z4;
                    boolean z9 = isPlaying2;
                    if (z5) {
                        aVar.onPlayerStateChanged(z6, i6);
                    }
                    if (z7) {
                        aVar.onPlaybackSuppressionReasonChanged(i7);
                    }
                    if (z8) {
                        aVar.onIsPlayingChanged(z9);
                    }
                }
            });
        }
    }

    /* renamed from: N */
    public final boolean m1351N() {
        return this.f3270v.f5610b.m2691q() || this.f3264p > 0;
    }

    /* renamed from: O */
    public void m1352O(boolean z) {
        C2251m0 m1346H = m1346H(z, z, z, 1);
        this.f3264p++;
        this.f3254f.f3348j.m2297a(6, z ? 1 : 0, 0).sendToTarget();
        m1353P(m1346H, false, 4, 1, false);
    }

    /* renamed from: P */
    public final void m1353P(C2251m0 c2251m0, boolean z, int i2, int i3, boolean z2) {
        boolean isPlaying = isPlaying();
        C2251m0 c2251m02 = this.f3270v;
        this.f3270v = c2251m0;
        m1348K(new b(c2251m0, c2251m02, this.f3256h, this.f3252d, z, i2, i3, z2, this.f3260l, isPlaying != isPlaying()));
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    /* renamed from: a */
    public int mo1354a() {
        return this.f3270v.f5614f;
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    /* renamed from: b */
    public C2262n0 mo1355b() {
        return this.f3268t;
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    /* renamed from: c */
    public boolean mo1356c() {
        return !m1351N() && this.f3270v.f5611c.m2024a();
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    /* renamed from: d */
    public void mo1357d(final int i2) {
        if (this.f3262n != i2) {
            this.f3262n = i2;
            this.f3254f.f3348j.m2297a(12, i2, 0).sendToTarget();
            m1347J(new AbstractC2395t.b() { // from class: b.l.a.a.o
                @Override // p005b.p199l.p200a.p201a.AbstractC2395t.b
                /* renamed from: a */
                public final void mo1338a(InterfaceC2368q0.a aVar) {
                    aVar.onRepeatModeChanged(i2);
                }
            });
        }
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    /* renamed from: e */
    public int mo1358e() {
        return this.f3262n;
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    /* renamed from: f */
    public long mo1359f() {
        return C2399v.m2669b(this.f3270v.f5621m);
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    /* renamed from: g */
    public void mo1360g(int i2, long j2) {
        AbstractC2404x0 abstractC2404x0 = this.f3270v.f5610b;
        if (i2 < 0 || (!abstractC2404x0.m2691q() && i2 >= abstractC2404x0.mo1836p())) {
            throw new C2067g0(abstractC2404x0, i2, j2);
        }
        this.f3266r = true;
        this.f3264p++;
        if (mo1356c()) {
            this.f3253e.obtainMessage(0, 1, -1, this.f3270v).sendToTarget();
            return;
        }
        this.f3271w = i2;
        if (abstractC2404x0.m2691q()) {
            this.f3273y = j2 != -9223372036854775807L ? j2 : 0L;
            this.f3272x = 0;
        } else {
            long m2668a = j2 == -9223372036854775807L ? abstractC2404x0.mo1835o(i2, this.f6311a, 0L).f6380i : C2399v.m2668a(j2);
            Pair<Object, Long> m2688j = abstractC2404x0.m2688j(this.f6311a, this.f3257i, i2, m2668a);
            this.f3273y = C2399v.m2669b(m2668a);
            this.f3272x = abstractC2404x0.mo1831b(m2688j.first);
        }
        this.f3254f.f3348j.m2298b(3, new C1949d0.e(abstractC2404x0, i2, C2399v.m2668a(j2))).sendToTarget();
        m1347J(new AbstractC2395t.b() { // from class: b.l.a.a.c
            @Override // p005b.p199l.p200a.p201a.AbstractC2395t.b
            /* renamed from: a */
            public final void mo1338a(InterfaceC2368q0.a aVar) {
                aVar.onPositionDiscontinuity(1);
            }
        });
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    public long getCurrentPosition() {
        if (m1351N()) {
            return this.f3273y;
        }
        if (this.f3270v.f5611c.m2024a()) {
            return C2399v.m2669b(this.f3270v.f5622n);
        }
        C2251m0 c2251m0 = this.f3270v;
        return m1349L(c2251m0.f5611c, c2251m0.f5622n);
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    public long getDuration() {
        if (mo1356c()) {
            C2251m0 c2251m0 = this.f3270v;
            InterfaceC2202y.a aVar = c2251m0.f5611c;
            c2251m0.f5610b.mo1929h(aVar.f5247a, this.f3257i);
            return C2399v.m2669b(this.f3257i.m2692a(aVar.f5248b, aVar.f5249c));
        }
        AbstractC2404x0 mo1375y = mo1375y();
        if (mo1375y.m2691q()) {
            return -9223372036854775807L;
        }
        return mo1375y.m2690n(mo1367o(), this.f6311a).m2698a();
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    /* renamed from: h */
    public boolean mo1361h() {
        return this.f3260l;
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    /* renamed from: i */
    public void mo1362i(final boolean z) {
        if (this.f3263o != z) {
            this.f3263o = z;
            this.f3254f.f3348j.m2297a(13, z ? 1 : 0, 0).sendToTarget();
            m1347J(new AbstractC2395t.b() { // from class: b.l.a.a.l
                @Override // p005b.p199l.p200a.p201a.AbstractC2395t.b
                /* renamed from: a */
                public final void mo1338a(InterfaceC2368q0.a aVar) {
                    aVar.onShuffleModeEnabledChanged(z);
                }
            });
        }
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    @Nullable
    /* renamed from: j */
    public C1936b0 mo1363j() {
        return this.f3270v.f5615g;
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    /* renamed from: l */
    public void mo1364l(InterfaceC2368q0.a aVar) {
        this.f3256h.addIfAbsent(new AbstractC2395t.a(aVar));
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    /* renamed from: m */
    public int mo1365m() {
        if (mo1356c()) {
            return this.f3270v.f5611c.f5249c;
        }
        return -1;
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    /* renamed from: n */
    public void mo1366n(InterfaceC2368q0.a aVar) {
        Iterator<AbstractC2395t.a> it = this.f3256h.iterator();
        while (it.hasNext()) {
            AbstractC2395t.a next = it.next();
            if (next.f6312a.equals(aVar)) {
                next.f6313b = true;
                this.f3256h.remove(next);
            }
        }
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    /* renamed from: o */
    public int mo1367o() {
        if (m1351N()) {
            return this.f3271w;
        }
        C2251m0 c2251m0 = this.f3270v;
        return c2251m0.f5610b.mo1929h(c2251m0.f5611c.f5247a, this.f3257i).f6368b;
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    /* renamed from: p */
    public void mo1368p(boolean z) {
        m1350M(z, 0);
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    @Nullable
    /* renamed from: q */
    public InterfaceC2368q0.c mo1369q() {
        return null;
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    /* renamed from: r */
    public long mo1370r() {
        if (!mo1356c()) {
            return getCurrentPosition();
        }
        C2251m0 c2251m0 = this.f3270v;
        c2251m0.f5610b.mo1929h(c2251m0.f5611c.f5247a, this.f3257i);
        C2251m0 c2251m02 = this.f3270v;
        return c2251m02.f5613e == -9223372036854775807L ? C2399v.m2669b(c2251m02.f5610b.m2690n(mo1367o(), this.f6311a).f6380i) : C2399v.m2669b(this.f3257i.f6370d) + C2399v.m2669b(this.f3270v.f5613e);
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    /* renamed from: t */
    public long mo1371t() {
        if (!mo1356c()) {
            return mo1341B();
        }
        C2251m0 c2251m0 = this.f3270v;
        return c2251m0.f5619k.equals(c2251m0.f5611c) ? C2399v.m2669b(this.f3270v.f5620l) : getDuration();
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    /* renamed from: u */
    public int mo1372u() {
        if (mo1356c()) {
            return this.f3270v.f5611c.f5248b;
        }
        return -1;
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    /* renamed from: w */
    public int mo1373w() {
        return this.f3261m;
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    /* renamed from: x */
    public TrackGroupArray mo1374x() {
        return this.f3270v.f5617i;
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    /* renamed from: y */
    public AbstractC2404x0 mo1375y() {
        return this.f3270v.f5610b;
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    /* renamed from: z */
    public Looper mo1376z() {
        return this.f3253e.getLooper();
    }
}
