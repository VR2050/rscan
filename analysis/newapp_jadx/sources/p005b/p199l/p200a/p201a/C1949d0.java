package p005b.p199l.p200a.p201a;

import android.os.Handler;
import android.os.HandlerThread;
import android.util.Pair;
import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.source.TrackGroupArray;
import java.util.ArrayList;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import p005b.p199l.p200a.p201a.AbstractC2404x0;
import p005b.p199l.p200a.p201a.C2392r0;
import p005b.p199l.p200a.p201a.C2407z;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2202y;
import p005b.p199l.p200a.p201a.p245m1.AbstractC2259h;
import p005b.p199l.p200a.p201a.p245m1.C2258g;
import p005b.p199l.p200a.p201a.p245m1.C2260i;
import p005b.p199l.p200a.p201a.p245m1.InterfaceC2257f;
import p005b.p199l.p200a.p201a.p248o1.C2325q;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2292g;
import p005b.p199l.p200a.p201a.p250p1.C2338a0;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p005b.p199l.p200a.p201a.p250p1.C2365y;
import p005b.p199l.p200a.p201a.p250p1.InterfaceC2346f;
import p005b.p199l.p200a.p201a.p250p1.InterfaceC2356p;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.d0 */
/* loaded from: classes.dex */
public final class C1949d0 implements Handler.Callback, InterfaceC2201x.a, InterfaceC2202y.b, C2407z.a, C2392r0.a {

    /* renamed from: A */
    public boolean f3331A;

    /* renamed from: B */
    public boolean f3332B;

    /* renamed from: C */
    public boolean f3333C;

    /* renamed from: D */
    public int f3334D;

    /* renamed from: E */
    public boolean f3335E;

    /* renamed from: F */
    public boolean f3336F;

    /* renamed from: G */
    public int f3337G;

    /* renamed from: H */
    public e f3338H;

    /* renamed from: I */
    public long f3339I;

    /* renamed from: J */
    public int f3340J;

    /* renamed from: K */
    public boolean f3341K;

    /* renamed from: c */
    public final InterfaceC2396t0[] f3342c;

    /* renamed from: e */
    public final AbstractC2397u[] f3343e;

    /* renamed from: f */
    public final AbstractC2259h f3344f;

    /* renamed from: g */
    public final C2260i f3345g;

    /* renamed from: h */
    public final InterfaceC2077h0 f3346h;

    /* renamed from: i */
    public final InterfaceC2292g f3347i;

    /* renamed from: j */
    public final C2338a0 f3348j;

    /* renamed from: k */
    public final HandlerThread f3349k;

    /* renamed from: l */
    public final Handler f3350l;

    /* renamed from: m */
    public final AbstractC2404x0.c f3351m;

    /* renamed from: n */
    public final AbstractC2404x0.b f3352n;

    /* renamed from: o */
    public final long f3353o;

    /* renamed from: p */
    public final boolean f3354p;

    /* renamed from: q */
    public final C2407z f3355q;

    /* renamed from: r */
    public final d f3356r;

    /* renamed from: s */
    public final ArrayList<c> f3357s;

    /* renamed from: t */
    public final InterfaceC2346f f3358t;

    /* renamed from: u */
    public final C2097k0 f3359u = new C2097k0();

    /* renamed from: v */
    public C2400v0 f3360v;

    /* renamed from: w */
    public C2251m0 f3361w;

    /* renamed from: x */
    public InterfaceC2202y f3362x;

    /* renamed from: y */
    public InterfaceC2396t0[] f3363y;

    /* renamed from: z */
    public boolean f3364z;

    /* renamed from: b.l.a.a.d0$b */
    public static final class b {

        /* renamed from: a */
        public final InterfaceC2202y f3365a;

        /* renamed from: b */
        public final AbstractC2404x0 f3366b;

        public b(InterfaceC2202y interfaceC2202y, AbstractC2404x0 abstractC2404x0) {
            this.f3365a = interfaceC2202y;
            this.f3366b = abstractC2404x0;
        }
    }

    /* renamed from: b.l.a.a.d0$c */
    public static final class c implements Comparable<c> {

        /* renamed from: c */
        public final C2392r0 f3367c;

        /* renamed from: e */
        public int f3368e;

        /* renamed from: f */
        public long f3369f;

        /* renamed from: g */
        @Nullable
        public Object f3370g;

        /* JADX WARN: Code restructure failed: missing block: B:9:0x0015, code lost:
        
            if (r0 != null) goto L13;
         */
        @Override // java.lang.Comparable
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public int compareTo(p005b.p199l.p200a.p201a.C1949d0.c r9) {
            /*
                r8 = this;
                b.l.a.a.d0$c r9 = (p005b.p199l.p200a.p201a.C1949d0.c) r9
                java.lang.Object r0 = r8.f3370g
                r1 = 1
                r2 = 0
                if (r0 != 0) goto La
                r3 = 1
                goto Lb
            La:
                r3 = 0
            Lb:
                java.lang.Object r4 = r9.f3370g
                if (r4 != 0) goto L11
                r4 = 1
                goto L12
            L11:
                r4 = 0
            L12:
                r5 = -1
                if (r3 == r4) goto L1a
                if (r0 == 0) goto L18
            L17:
                r1 = -1
            L18:
                r2 = r1
                goto L35
            L1a:
                if (r0 != 0) goto L1d
                goto L35
            L1d:
                int r0 = r8.f3368e
                int r3 = r9.f3368e
                int r0 = r0 - r3
                if (r0 == 0) goto L26
                r2 = r0
                goto L35
            L26:
                long r3 = r8.f3369f
                long r6 = r9.f3369f
                int r9 = p005b.p199l.p200a.p201a.p250p1.C2344d0.f6035a
                int r9 = (r3 > r6 ? 1 : (r3 == r6 ? 0 : -1))
                if (r9 >= 0) goto L31
                goto L17
            L31:
                if (r9 != 0) goto L18
                r1 = 0
                goto L18
            L35:
                return r2
            */
            throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.C1949d0.c.compareTo(java.lang.Object):int");
        }
    }

    /* renamed from: b.l.a.a.d0$d */
    public static final class d {

        /* renamed from: a */
        public C2251m0 f3371a;

        /* renamed from: b */
        public int f3372b;

        /* renamed from: c */
        public boolean f3373c;

        /* renamed from: d */
        public int f3374d;

        public d(a aVar) {
        }

        /* renamed from: a */
        public void m1439a(int i2) {
            this.f3372b += i2;
        }

        /* renamed from: b */
        public void m1440b(int i2) {
            if (this.f3373c && this.f3374d != 4) {
                C4195m.m4765F(i2 == 4);
            } else {
                this.f3373c = true;
                this.f3374d = i2;
            }
        }
    }

    /* renamed from: b.l.a.a.d0$e */
    public static final class e {

        /* renamed from: a */
        public final AbstractC2404x0 f3375a;

        /* renamed from: b */
        public final int f3376b;

        /* renamed from: c */
        public final long f3377c;

        public e(AbstractC2404x0 abstractC2404x0, int i2, long j2) {
            this.f3375a = abstractC2404x0;
            this.f3376b = i2;
            this.f3377c = j2;
        }
    }

    public C1949d0(InterfaceC2396t0[] interfaceC2396t0Arr, AbstractC2259h abstractC2259h, C2260i c2260i, InterfaceC2077h0 interfaceC2077h0, InterfaceC2292g interfaceC2292g, boolean z, int i2, boolean z2, Handler handler, InterfaceC2346f interfaceC2346f) {
        this.f3342c = interfaceC2396t0Arr;
        this.f3344f = abstractC2259h;
        this.f3345g = c2260i;
        this.f3346h = interfaceC2077h0;
        this.f3347i = interfaceC2292g;
        this.f3331A = z;
        this.f3334D = i2;
        this.f3335E = z2;
        this.f3350l = handler;
        this.f3358t = interfaceC2346f;
        C2405y c2405y = (C2405y) interfaceC2077h0;
        this.f3353o = c2405y.f6391i;
        Objects.requireNonNull(c2405y);
        this.f3354p = false;
        this.f3360v = C2400v0.f6333b;
        this.f3361w = C2251m0.m2139d(-9223372036854775807L, c2260i);
        this.f3356r = new d(null);
        this.f3343e = new AbstractC2397u[interfaceC2396t0Arr.length];
        for (int i3 = 0; i3 < interfaceC2396t0Arr.length; i3++) {
            interfaceC2396t0Arr[i3].mo2652a(i3);
            this.f3343e[i3] = interfaceC2396t0Arr[i3].mo2657h();
        }
        this.f3355q = new C2407z(this, interfaceC2346f);
        this.f3357s = new ArrayList<>();
        this.f3363y = new InterfaceC2396t0[0];
        this.f3351m = new AbstractC2404x0.c();
        this.f3352n = new AbstractC2404x0.b();
        abstractC2259h.f5662a = interfaceC2292g;
        HandlerThread handlerThread = new HandlerThread("ExoPlayerImplInternal:Handler", -16);
        this.f3349k = handlerThread;
        handlerThread.start();
        this.f3348j = interfaceC2346f.mo2353b(handlerThread.getLooper(), this);
        this.f3341K = true;
    }

    /* renamed from: g */
    public static Format[] m1388g(InterfaceC2257f interfaceC2257f) {
        int length = interfaceC2257f != null ? interfaceC2257f.length() : 0;
        Format[] formatArr = new Format[length];
        for (int i2 = 0; i2 < length; i2++) {
            formatArr[i2] = interfaceC2257f.mo2152e(i2);
        }
        return formatArr;
    }

    /* JADX WARN: Removed duplicated region for block: B:31:0x008c  */
    /* JADX WARN: Removed duplicated region for block: B:38:0x00b3  */
    /* JADX WARN: Removed duplicated region for block: B:41:0x00cd  */
    /* JADX WARN: Removed duplicated region for block: B:43:0x00d8  */
    /* JADX WARN: Removed duplicated region for block: B:46:0x00e3  */
    /* JADX WARN: Removed duplicated region for block: B:49:0x00f1  */
    /* JADX WARN: Removed duplicated region for block: B:52:0x00f9  */
    /* JADX WARN: Removed duplicated region for block: B:55:0x0101  */
    /* JADX WARN: Removed duplicated region for block: B:65:0x0104  */
    /* JADX WARN: Removed duplicated region for block: B:66:0x00fc  */
    /* JADX WARN: Removed duplicated region for block: B:67:0x00f3  */
    /* JADX WARN: Removed duplicated region for block: B:68:0x00e6  */
    /* JADX WARN: Removed duplicated region for block: B:69:0x00da  */
    /* JADX WARN: Removed duplicated region for block: B:70:0x00d0  */
    /* JADX WARN: Removed duplicated region for block: B:71:0x00c0  */
    /* renamed from: A */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void m1389A(boolean r24, boolean r25, boolean r26, boolean r27, boolean r28) {
        /*
            Method dump skipped, instructions count: 289
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.C1949d0.m1389A(boolean, boolean, boolean, boolean, boolean):void");
    }

    /* renamed from: B */
    public final void m1390B(long j2) {
        C2091i0 c2091i0 = this.f3359u.f4429g;
        if (c2091i0 != null) {
            j2 += c2091i0.f4411n;
        }
        this.f3339I = j2;
        this.f3355q.f6396c.m2608a(j2);
        for (InterfaceC2396t0 interfaceC2396t0 : this.f3363y) {
            interfaceC2396t0.mo2661p(this.f3339I);
        }
        for (C2091i0 c2091i02 = this.f3359u.f4429g; c2091i02 != null; c2091i02 = c2091i02.f4408k) {
            for (InterfaceC2257f interfaceC2257f : c2091i02.f4410m.f5665c.m2164a()) {
                if (interfaceC2257f != null) {
                    interfaceC2257f.mo2157p();
                }
            }
        }
    }

    /* renamed from: C */
    public final boolean m1391C(c cVar) {
        Object obj = cVar.f3370g;
        if (obj != null) {
            int mo1831b = this.f3361w.f5610b.mo1831b(obj);
            if (mo1831b == -1) {
                return false;
            }
            cVar.f3368e = mo1831b;
            return true;
        }
        C2392r0 c2392r0 = cVar.f3367c;
        AbstractC2404x0 abstractC2404x0 = c2392r0.f6296c;
        int i2 = c2392r0.f6300g;
        Objects.requireNonNull(c2392r0);
        long m2668a = C2399v.m2668a(-9223372036854775807L);
        AbstractC2404x0 abstractC2404x02 = this.f3361w.f5610b;
        Pair<Object, Long> pair = null;
        if (!abstractC2404x02.m2691q()) {
            if (abstractC2404x0.m2691q()) {
                abstractC2404x0 = abstractC2404x02;
            }
            try {
                Pair<Object, Long> m2688j = abstractC2404x0.m2688j(this.f3351m, this.f3352n, i2, m2668a);
                if (abstractC2404x02 == abstractC2404x0 || abstractC2404x02.mo1831b(m2688j.first) != -1) {
                    pair = m2688j;
                }
            } catch (IndexOutOfBoundsException unused) {
            }
        }
        if (pair == null) {
            return false;
        }
        int mo1831b2 = this.f3361w.f5610b.mo1831b(pair.first);
        long longValue = ((Long) pair.second).longValue();
        Object obj2 = pair.first;
        cVar.f3368e = mo1831b2;
        cVar.f3369f = longValue;
        cVar.f3370g = obj2;
        return true;
    }

    @Nullable
    /* renamed from: D */
    public final Pair<Object, Long> m1392D(e eVar, boolean z) {
        Pair<Object, Long> m2688j;
        Object m1393E;
        AbstractC2404x0 abstractC2404x0 = this.f3361w.f5610b;
        AbstractC2404x0 abstractC2404x02 = eVar.f3375a;
        if (abstractC2404x0.m2691q()) {
            return null;
        }
        if (abstractC2404x02.m2691q()) {
            abstractC2404x02 = abstractC2404x0;
        }
        try {
            m2688j = abstractC2404x02.m2688j(this.f3351m, this.f3352n, eVar.f3376b, eVar.f3377c);
        } catch (IndexOutOfBoundsException unused) {
        }
        if (abstractC2404x0 == abstractC2404x02 || abstractC2404x0.mo1831b(m2688j.first) != -1) {
            return m2688j;
        }
        if (z && (m1393E = m1393E(m2688j.first, abstractC2404x02, abstractC2404x0)) != null) {
            return m1420h(abstractC2404x0, abstractC2404x0.mo1929h(m1393E, this.f3352n).f6368b, -9223372036854775807L);
        }
        return null;
    }

    @Nullable
    /* renamed from: E */
    public final Object m1393E(Object obj, AbstractC2404x0 abstractC2404x0, AbstractC2404x0 abstractC2404x02) {
        int mo1831b = abstractC2404x0.mo1831b(obj);
        int mo1833i = abstractC2404x0.mo1833i();
        int i2 = mo1831b;
        int i3 = -1;
        for (int i4 = 0; i4 < mo1833i && i3 == -1; i4++) {
            i2 = abstractC2404x0.m2686d(i2, this.f3352n, this.f3351m, this.f3334D, this.f3335E);
            if (i2 == -1) {
                break;
            }
            i3 = abstractC2404x02.mo1831b(abstractC2404x0.mo1834m(i2));
        }
        if (i3 == -1) {
            return null;
        }
        return abstractC2404x02.mo1834m(i3);
    }

    /* renamed from: F */
    public final void m1394F(long j2, long j3) {
        this.f3348j.f6024a.removeMessages(2);
        this.f3348j.f6024a.sendEmptyMessageAtTime(2, j2 + j3);
    }

    /* renamed from: G */
    public final void m1395G(boolean z) {
        InterfaceC2202y.a aVar = this.f3359u.f4429g.f4403f.f4415a;
        long m1397I = m1397I(aVar, this.f3361w.f5622n, true);
        if (m1397I != this.f3361w.f5622n) {
            this.f3361w = m1415b(aVar, m1397I, this.f3361w.f5613e);
            if (z) {
                this.f3356r.m1440b(4);
            }
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:20:0x00e8  */
    /* JADX WARN: Removed duplicated region for block: B:23:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Type inference failed for: r8v0 */
    /* JADX WARN: Type inference failed for: r8v1 */
    /* renamed from: H */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void m1396H(p005b.p199l.p200a.p201a.C1949d0.e r17) {
        /*
            Method dump skipped, instructions count: 261
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.C1949d0.m1396H(b.l.a.a.d0$e):void");
    }

    /* renamed from: I */
    public final long m1397I(InterfaceC2202y.a aVar, long j2, boolean z) {
        m1409U();
        this.f3332B = false;
        C2251m0 c2251m0 = this.f3361w;
        if (c2251m0.f5614f != 1 && !c2251m0.f5610b.m2691q()) {
            m1406R(2);
        }
        C2091i0 c2091i0 = this.f3359u.f4429g;
        C2091i0 c2091i02 = c2091i0;
        while (true) {
            if (c2091i02 == null) {
                break;
            }
            if (aVar.equals(c2091i02.f4403f.f4415a) && c2091i02.f4401d) {
                this.f3359u.m1752j(c2091i02);
                break;
            }
            c2091i02 = this.f3359u.m1743a();
        }
        if (z || c2091i0 != c2091i02 || (c2091i02 != null && c2091i02.f4411n + j2 < 0)) {
            for (InterfaceC2396t0 interfaceC2396t0 : this.f3363y) {
                m1417d(interfaceC2396t0);
            }
            this.f3363y = new InterfaceC2396t0[0];
            c2091i0 = null;
            if (c2091i02 != null) {
                c2091i02.f4411n = 0L;
            }
        }
        if (c2091i02 != null) {
            m1413Y(c2091i0);
            if (c2091i02.f4402e) {
                long mo1771n = c2091i02.f4398a.mo1771n(j2);
                c2091i02.f4398a.mo1776u(mo1771n - this.f3353o, this.f3354p);
                j2 = mo1771n;
            }
            m1390B(j2);
            m1434v();
        } else {
            this.f3359u.m1744b(true);
            this.f3361w = this.f3361w.m2142c(TrackGroupArray.f9396c, this.f3345g);
            m1390B(j2);
        }
        m1426n(false);
        this.f3348j.m2299c(2);
        return j2;
    }

    /* renamed from: J */
    public final void m1398J(C2392r0 c2392r0) {
        if (c2392r0.f6299f.getLooper() != this.f3348j.f6024a.getLooper()) {
            this.f3348j.m2298b(16, c2392r0).sendToTarget();
            return;
        }
        m1416c(c2392r0);
        int i2 = this.f3361w.f5614f;
        if (i2 == 3 || i2 == 2) {
            this.f3348j.m2299c(2);
        }
    }

    /* renamed from: K */
    public final void m1399K(final C2392r0 c2392r0) {
        Handler handler = c2392r0.f6299f;
        if (handler.getLooper().getThread().isAlive()) {
            handler.post(new Runnable() { // from class: b.l.a.a.p
                @Override // java.lang.Runnable
                public final void run() {
                    C1949d0 c1949d0 = C1949d0.this;
                    C2392r0 c2392r02 = c2392r0;
                    Objects.requireNonNull(c1949d0);
                    try {
                        c1949d0.m1416c(c2392r02);
                    } catch (C1936b0 e2) {
                        throw new RuntimeException(e2);
                    }
                }
            });
        } else {
            c2392r0.m2645b(false);
        }
    }

    /* renamed from: L */
    public final void m1400L() {
        for (InterfaceC2396t0 interfaceC2396t0 : this.f3342c) {
            if (interfaceC2396t0.mo2658l() != null) {
                interfaceC2396t0.mo2656g();
            }
        }
    }

    /* renamed from: M */
    public final void m1401M(boolean z, @Nullable AtomicBoolean atomicBoolean) {
        if (this.f3336F != z) {
            this.f3336F = z;
            if (!z) {
                for (InterfaceC2396t0 interfaceC2396t0 : this.f3342c) {
                    if (interfaceC2396t0.getState() == 0) {
                        interfaceC2396t0.reset();
                    }
                }
            }
        }
        if (atomicBoolean != null) {
            synchronized (this) {
                atomicBoolean.set(true);
                notifyAll();
            }
        }
    }

    /* renamed from: N */
    public final void m1402N(boolean z) {
        this.f3332B = false;
        this.f3331A = z;
        if (!z) {
            m1409U();
            m1412X();
            return;
        }
        int i2 = this.f3361w.f5614f;
        if (i2 == 3) {
            m1407S();
            this.f3348j.m2299c(2);
        } else if (i2 == 2) {
            this.f3348j.m2299c(2);
        }
    }

    /* renamed from: O */
    public final void m1403O(C2262n0 c2262n0) {
        this.f3355q.mo1324s(c2262n0);
        this.f3348j.f6024a.obtainMessage(17, 1, 0, this.f3355q.mo1312b()).sendToTarget();
    }

    /* renamed from: P */
    public final void m1404P(int i2) {
        this.f3334D = i2;
        C2097k0 c2097k0 = this.f3359u;
        c2097k0.f4427e = i2;
        if (!c2097k0.m1755m()) {
            m1395G(true);
        }
        m1426n(false);
    }

    /* renamed from: Q */
    public final void m1405Q(boolean z) {
        this.f3335E = z;
        C2097k0 c2097k0 = this.f3359u;
        c2097k0.f4428f = z;
        if (!c2097k0.m1755m()) {
            m1395G(true);
        }
        m1426n(false);
    }

    /* renamed from: R */
    public final void m1406R(int i2) {
        C2251m0 c2251m0 = this.f3361w;
        if (c2251m0.f5614f != i2) {
            this.f3361w = new C2251m0(c2251m0.f5610b, c2251m0.f5611c, c2251m0.f5612d, c2251m0.f5613e, i2, c2251m0.f5615g, c2251m0.f5616h, c2251m0.f5617i, c2251m0.f5618j, c2251m0.f5619k, c2251m0.f5620l, c2251m0.f5621m, c2251m0.f5622n);
        }
    }

    /* renamed from: S */
    public final void m1407S() {
        this.f3332B = false;
        C2407z c2407z = this.f3355q;
        c2407z.f6401i = true;
        c2407z.f6396c.m2609c();
        for (InterfaceC2396t0 interfaceC2396t0 : this.f3363y) {
            interfaceC2396t0.start();
        }
    }

    /* renamed from: T */
    public final void m1408T(boolean z, boolean z2, boolean z3) {
        m1389A(z || !this.f3336F, true, z2, z2, z2);
        this.f3356r.m1439a(this.f3337G + (z3 ? 1 : 0));
        this.f3337G = 0;
        ((C2405y) this.f3346h).m2701b(true);
        m1406R(1);
    }

    /* renamed from: U */
    public final void m1409U() {
        C2407z c2407z = this.f3355q;
        c2407z.f6401i = false;
        C2365y c2365y = c2407z.f6396c;
        if (c2365y.f6153e) {
            c2365y.m2608a(c2365y.mo1317i());
            c2365y.f6153e = false;
        }
        for (InterfaceC2396t0 interfaceC2396t0 : this.f3363y) {
            if (interfaceC2396t0.getState() == 2) {
                interfaceC2396t0.stop();
            }
        }
    }

    /* renamed from: V */
    public final void m1410V() {
        C2091i0 c2091i0 = this.f3359u.f4431i;
        boolean z = this.f3333C || (c2091i0 != null && c2091i0.f4398a.mo1761d());
        C2251m0 c2251m0 = this.f3361w;
        if (z != c2251m0.f5616h) {
            this.f3361w = new C2251m0(c2251m0.f5610b, c2251m0.f5611c, c2251m0.f5612d, c2251m0.f5613e, c2251m0.f5614f, c2251m0.f5615g, z, c2251m0.f5617i, c2251m0.f5618j, c2251m0.f5619k, c2251m0.f5620l, c2251m0.f5621m, c2251m0.f5622n);
        }
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* renamed from: W */
    public final void m1411W(TrackGroupArray trackGroupArray, C2260i c2260i) {
        boolean z;
        InterfaceC2077h0 interfaceC2077h0 = this.f3346h;
        InterfaceC2396t0[] interfaceC2396t0Arr = this.f3342c;
        C2258g c2258g = c2260i.f5665c;
        C2405y c2405y = (C2405y) interfaceC2077h0;
        Objects.requireNonNull(c2405y);
        int i2 = 0;
        while (true) {
            if (i2 >= interfaceC2396t0Arr.length) {
                z = false;
                break;
            } else {
                if (interfaceC2396t0Arr[i2].getTrackType() == 2 && c2258g.f5660b[i2] != null) {
                    z = true;
                    break;
                }
                i2++;
            }
        }
        c2405y.f6394l = z;
        int i3 = c2405y.f6389g;
        if (i3 == -1) {
            i3 = 0;
            for (int i4 = 0; i4 < interfaceC2396t0Arr.length; i4++) {
                if (c2258g.f5660b[i4] != null) {
                    int i5 = 131072;
                    switch (interfaceC2396t0Arr[i4].getTrackType()) {
                        case 0:
                            i5 = 36438016;
                            i3 += i5;
                            break;
                        case 1:
                            i5 = 3538944;
                            i3 += i5;
                            break;
                        case 2:
                            i5 = 32768000;
                            i3 += i5;
                            break;
                        case 3:
                        case 4:
                        case 5:
                            i3 += i5;
                            break;
                        case 6:
                            i5 = 0;
                            i3 += i5;
                            break;
                        default:
                            throw new IllegalArgumentException();
                    }
                }
            }
        }
        c2405y.f6392j = i3;
        c2405y.f6383a.m2271b(i3);
    }

    /* JADX WARN: Code restructure failed: missing block: B:107:0x016c, code lost:
    
        r4 = null;
     */
    /* renamed from: X */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void m1412X() {
        /*
            Method dump skipped, instructions count: 506
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.C1949d0.m1412X():void");
    }

    /* renamed from: Y */
    public final void m1413Y(@Nullable C2091i0 c2091i0) {
        C2091i0 c2091i02 = this.f3359u.f4429g;
        if (c2091i02 == null || c2091i0 == c2091i02) {
            return;
        }
        boolean[] zArr = new boolean[this.f3342c.length];
        int i2 = 0;
        int i3 = 0;
        while (true) {
            InterfaceC2396t0[] interfaceC2396t0Arr = this.f3342c;
            if (i2 >= interfaceC2396t0Arr.length) {
                this.f3361w = this.f3361w.m2142c(c2091i02.f4409l, c2091i02.f4410m);
                m1419f(zArr, i3);
                return;
            }
            InterfaceC2396t0 interfaceC2396t0 = interfaceC2396t0Arr[i2];
            zArr[i2] = interfaceC2396t0.getState() != 0;
            if (c2091i02.f4410m.m2166b(i2)) {
                i3++;
            }
            if (zArr[i2] && (!c2091i02.f4410m.m2166b(i2) || (interfaceC2396t0.mo2662q() && interfaceC2396t0.mo2658l() == c2091i0.f4400c[i2]))) {
                m1417d(interfaceC2396t0);
            }
            i2++;
        }
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2202y.b
    /* renamed from: a */
    public void mo1414a(InterfaceC2202y interfaceC2202y, AbstractC2404x0 abstractC2404x0) {
        this.f3348j.m2298b(8, new b(interfaceC2202y, abstractC2404x0)).sendToTarget();
    }

    /* renamed from: b */
    public final C2251m0 m1415b(InterfaceC2202y.a aVar, long j2, long j3) {
        this.f3341K = true;
        return this.f3361w.m2140a(aVar, j2, j3, m1422j());
    }

    /* renamed from: c */
    public final void m1416c(C2392r0 c2392r0) {
        c2392r0.m2644a();
        try {
            c2392r0.f6294a.mo1318k(c2392r0.f6297d, c2392r0.f6298e);
        } finally {
            c2392r0.m2645b(true);
        }
    }

    /* renamed from: d */
    public final void m1417d(InterfaceC2396t0 interfaceC2396t0) {
        C2407z c2407z = this.f3355q;
        if (interfaceC2396t0 == c2407z.f6398f) {
            c2407z.f6399g = null;
            c2407z.f6398f = null;
            c2407z.f6400h = true;
        }
        if (interfaceC2396t0.getState() == 2) {
            interfaceC2396t0.stop();
        }
        interfaceC2396t0.mo2653d();
    }

    /* JADX WARN: Code restructure failed: missing block: B:122:0x0382, code lost:
    
        if (r6 >= r1.f6392j) goto L246;
     */
    /* JADX WARN: Code restructure failed: missing block: B:127:0x038b, code lost:
    
        if (r5 == false) goto L249;
     */
    /* JADX WARN: Code restructure failed: missing block: B:178:0x00b0, code lost:
    
        if (r14 != (-9223372036854775807L)) goto L46;
     */
    /* JADX WARN: Removed duplicated region for block: B:182:0x00d9  */
    /* JADX WARN: Removed duplicated region for block: B:187:0x0102  */
    /* JADX WARN: Removed duplicated region for block: B:191:0x0116  */
    /* JADX WARN: Removed duplicated region for block: B:194:0x012b  */
    /* JADX WARN: Removed duplicated region for block: B:254:0x01e8  */
    /* JADX WARN: Removed duplicated region for block: B:266:0x0211  */
    /* JADX WARN: Removed duplicated region for block: B:278:0x0013 A[EDGE_INSN: B:278:0x0013->B:4:0x0013 BREAK  A[LOOP:5: B:252:0x01e3->B:275:0x0245], SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:280:0x0120  */
    /* JADX WARN: Removed duplicated region for block: B:281:0x00e7  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0257  */
    /* renamed from: e */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void m1418e() {
        /*
            Method dump skipped, instructions count: 1033
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.C1949d0.m1418e():void");
    }

    /* renamed from: f */
    public final void m1419f(boolean[] zArr, int i2) {
        int i3;
        InterfaceC2356p interfaceC2356p;
        this.f3363y = new InterfaceC2396t0[i2];
        C2260i c2260i = this.f3359u.f4429g.f4410m;
        for (int i4 = 0; i4 < this.f3342c.length; i4++) {
            if (!c2260i.m2166b(i4)) {
                this.f3342c[i4].reset();
            }
        }
        int i5 = 0;
        int i6 = 0;
        while (i5 < this.f3342c.length) {
            if (c2260i.m2166b(i5)) {
                boolean z = zArr[i5];
                int i7 = i6 + 1;
                C2091i0 c2091i0 = this.f3359u.f4429g;
                InterfaceC2396t0 interfaceC2396t0 = this.f3342c[i5];
                this.f3363y[i6] = interfaceC2396t0;
                if (interfaceC2396t0.getState() == 0) {
                    C2260i c2260i2 = c2091i0.f4410m;
                    C2398u0 c2398u0 = c2260i2.f5664b[i5];
                    Format[] m1388g = m1388g(c2260i2.f5665c.f5660b[i5]);
                    boolean z2 = this.f3331A && this.f3361w.f5614f == 3;
                    boolean z3 = !z && z2;
                    i3 = i5;
                    interfaceC2396t0.mo2655f(c2398u0, m1388g, c2091i0.f4400c[i5], this.f3339I, z3, c2091i0.f4411n);
                    C2407z c2407z = this.f3355q;
                    Objects.requireNonNull(c2407z);
                    InterfaceC2356p mo1322r = interfaceC2396t0.mo1322r();
                    if (mo1322r != null && mo1322r != (interfaceC2356p = c2407z.f6399g)) {
                        if (interfaceC2356p != null) {
                            throw new C1936b0(2, new IllegalStateException("Multiple renderer media clocks enabled."));
                        }
                        c2407z.f6399g = mo1322r;
                        c2407z.f6398f = interfaceC2396t0;
                        mo1322r.mo1324s(c2407z.f6396c.f6156h);
                    }
                    if (z2) {
                        interfaceC2396t0.start();
                    }
                } else {
                    i3 = i5;
                }
                i6 = i7;
            } else {
                i3 = i5;
            }
            i5 = i3 + 1;
        }
    }

    /* renamed from: h */
    public final Pair<Object, Long> m1420h(AbstractC2404x0 abstractC2404x0, int i2, long j2) {
        return abstractC2404x0.m2688j(this.f3351m, this.f3352n, i2, j2);
    }

    /* JADX WARN: Removed duplicated region for block: B:93:0x00c5  */
    /* JADX WARN: Removed duplicated region for block: B:95:0x00cd  */
    @Override // android.os.Handler.Callback
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean handleMessage(android.os.Message r9) {
        /*
            Method dump skipped, instructions count: 456
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.C1949d0.handleMessage(android.os.Message):boolean");
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2109f0.a
    /* renamed from: i */
    public void mo1421i(InterfaceC2201x interfaceC2201x) {
        this.f3348j.m2298b(10, interfaceC2201x).sendToTarget();
    }

    /* renamed from: j */
    public final long m1422j() {
        return m1424l(this.f3361w.f5620l);
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x.a
    /* renamed from: k */
    public void mo1423k(InterfaceC2201x interfaceC2201x) {
        this.f3348j.m2298b(9, interfaceC2201x).sendToTarget();
    }

    /* renamed from: l */
    public final long m1424l(long j2) {
        C2091i0 c2091i0 = this.f3359u.f4431i;
        if (c2091i0 == null) {
            return 0L;
        }
        return Math.max(0L, j2 - (this.f3339I - c2091i0.f4411n));
    }

    /* renamed from: m */
    public final void m1425m(InterfaceC2201x interfaceC2201x) {
        C2097k0 c2097k0 = this.f3359u;
        C2091i0 c2091i0 = c2097k0.f4431i;
        if (c2091i0 != null && c2091i0.f4398a == interfaceC2201x) {
            c2097k0.m1751i(this.f3339I);
            m1434v();
        }
    }

    /* renamed from: n */
    public final void m1426n(boolean z) {
        C2091i0 c2091i0;
        boolean z2;
        C1949d0 c1949d0 = this;
        C2091i0 c2091i02 = c1949d0.f3359u.f4431i;
        InterfaceC2202y.a aVar = c2091i02 == null ? c1949d0.f3361w.f5611c : c2091i02.f4403f.f4415a;
        boolean z3 = !c1949d0.f3361w.f5619k.equals(aVar);
        if (z3) {
            C2251m0 c2251m0 = c1949d0.f3361w;
            z2 = z3;
            c2091i0 = c2091i02;
            c1949d0 = this;
            c1949d0.f3361w = new C2251m0(c2251m0.f5610b, c2251m0.f5611c, c2251m0.f5612d, c2251m0.f5613e, c2251m0.f5614f, c2251m0.f5615g, c2251m0.f5616h, c2251m0.f5617i, c2251m0.f5618j, aVar, c2251m0.f5620l, c2251m0.f5621m, c2251m0.f5622n);
        } else {
            c2091i0 = c2091i02;
            z2 = z3;
        }
        C2251m0 c2251m02 = c1949d0.f3361w;
        c2251m02.f5620l = c2091i0 == null ? c2251m02.f5622n : c2091i0.m1738d();
        c1949d0.f3361w.f5621m = m1422j();
        if ((z2 || z) && c2091i0 != null) {
            C2091i0 c2091i03 = c2091i0;
            if (c2091i03.f4401d) {
                c1949d0.m1411W(c2091i03.f4409l, c2091i03.f4410m);
            }
        }
    }

    /* renamed from: o */
    public final void m1427o(InterfaceC2201x interfaceC2201x) {
        C2091i0 c2091i0 = this.f3359u.f4431i;
        if (c2091i0 != null && c2091i0.f4398a == interfaceC2201x) {
            float f2 = this.f3355q.mo1312b().f5669b;
            AbstractC2404x0 abstractC2404x0 = this.f3361w.f5610b;
            c2091i0.f4401d = true;
            c2091i0.f4409l = c2091i0.f4398a.mo1774r();
            long m1735a = c2091i0.m1735a(c2091i0.m1742h(f2, abstractC2404x0), c2091i0.f4403f.f4416b, false, new boolean[c2091i0.f4405h.length]);
            long j2 = c2091i0.f4411n;
            C2094j0 c2094j0 = c2091i0.f4403f;
            long j3 = c2094j0.f4416b;
            c2091i0.f4411n = (j3 - m1735a) + j2;
            if (m1735a != j3) {
                c2094j0 = new C2094j0(c2094j0.f4415a, m1735a, c2094j0.f4417c, c2094j0.f4418d, c2094j0.f4419e, c2094j0.f4420f, c2094j0.f4421g);
            }
            c2091i0.f4403f = c2094j0;
            m1411W(c2091i0.f4409l, c2091i0.f4410m);
            if (c2091i0 == this.f3359u.f4429g) {
                m1390B(c2091i0.f4403f.f4416b);
                m1413Y(null);
            }
            m1434v();
        }
    }

    /* renamed from: p */
    public final void m1428p(C2262n0 c2262n0, boolean z) {
        this.f3350l.obtainMessage(1, z ? 1 : 0, 0, c2262n0).sendToTarget();
        float f2 = c2262n0.f5669b;
        for (C2091i0 c2091i0 = this.f3359u.f4429g; c2091i0 != null; c2091i0 = c2091i0.f4408k) {
            for (InterfaceC2257f interfaceC2257f : c2091i0.f4410m.f5665c.m2164a()) {
                if (interfaceC2257f != null) {
                    interfaceC2257f.mo2147n(f2);
                }
            }
        }
        for (InterfaceC2396t0 interfaceC2396t0 : this.f3342c) {
            if (interfaceC2396t0 != null) {
                interfaceC2396t0.mo1684m(c2262n0.f5669b);
            }
        }
    }

    /* renamed from: q */
    public final void m1429q() {
        if (this.f3361w.f5614f != 1) {
            m1406R(4);
        }
        m1389A(false, false, true, false, true);
    }

    /* JADX WARN: Code restructure failed: missing block: B:79:0x0269, code lost:
    
        r12 = true;
     */
    /* JADX WARN: Removed duplicated region for block: B:109:0x027c A[LOOP:3: B:109:0x027c->B:116:0x027c, LOOP_START, PHI: r0
      0x027c: PHI (r0v23 b.l.a.a.i0) = (r0v17 b.l.a.a.i0), (r0v24 b.l.a.a.i0) binds: [B:108:0x027a, B:116:0x027c] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:121:0x029c  */
    /* JADX WARN: Removed duplicated region for block: B:124:0x02a5  */
    /* JADX WARN: Removed duplicated region for block: B:126:0x02a7  */
    /* renamed from: r */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void m1430r(p005b.p199l.p200a.p201a.C1949d0.b r36) {
        /*
            Method dump skipped, instructions count: 698
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.C1949d0.m1430r(b.l.a.a.d0$b):void");
    }

    /* JADX WARN: Code restructure failed: missing block: B:14:0x0028, code lost:
    
        return false;
     */
    /* renamed from: s */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean m1431s() {
        /*
            r6 = this;
            b.l.a.a.k0 r0 = r6.f3359u
            b.l.a.a.i0 r0 = r0.f4430h
            boolean r1 = r0.f4401d
            r2 = 0
            if (r1 != 0) goto La
            return r2
        La:
            r1 = 0
        Lb:
            b.l.a.a.t0[] r3 = r6.f3342c
            int r4 = r3.length
            if (r1 >= r4) goto L29
            r3 = r3[r1]
            b.l.a.a.k1.e0[] r4 = r0.f4400c
            r4 = r4[r1]
            b.l.a.a.k1.e0 r5 = r3.mo2658l()
            if (r5 != r4) goto L28
            if (r4 == 0) goto L25
            boolean r3 = r3.mo2654e()
            if (r3 != 0) goto L25
            goto L28
        L25:
            int r1 = r1 + 1
            goto Lb
        L28:
            return r2
        L29:
            r0 = 1
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.C1949d0.m1431s():boolean");
    }

    /* renamed from: t */
    public final boolean m1432t() {
        C2091i0 c2091i0 = this.f3359u.f4431i;
        if (c2091i0 == null) {
            return false;
        }
        return (!c2091i0.f4401d ? 0L : c2091i0.f4398a.mo1759b()) != Long.MIN_VALUE;
    }

    /* renamed from: u */
    public final boolean m1433u() {
        C2091i0 c2091i0 = this.f3359u.f4429g;
        long j2 = c2091i0.f4403f.f4419e;
        return c2091i0.f4401d && (j2 == -9223372036854775807L || this.f3361w.f5622n < j2);
    }

    /* renamed from: v */
    public final void m1434v() {
        int i2;
        if (m1432t()) {
            C2091i0 c2091i0 = this.f3359u.f4431i;
            long m1424l = m1424l(!c2091i0.f4401d ? 0L : c2091i0.f4398a.mo1759b());
            float f2 = this.f3355q.mo1312b().f5669b;
            C2405y c2405y = (C2405y) this.f3346h;
            C2325q c2325q = c2405y.f6383a;
            synchronized (c2325q) {
                i2 = c2325q.f5946e * c2325q.f5943b;
            }
            boolean z = i2 >= c2405y.f6392j;
            long j2 = c2405y.f6394l ? c2405y.f6385c : c2405y.f6384b;
            if (f2 > 1.0f) {
                int i3 = C2344d0.f6035a;
                if (f2 != 1.0f) {
                    j2 = Math.round(j2 * f2);
                }
                j2 = Math.min(j2, c2405y.f6386d);
            }
            if (m1424l < j2) {
                c2405y.f6393k = c2405y.f6390h || !z;
            } else if (m1424l >= c2405y.f6386d || z) {
                c2405y.f6393k = false;
            }
            r1 = c2405y.f6393k;
        }
        this.f3333C = r1;
        if (r1) {
            C2091i0 c2091i02 = this.f3359u.f4431i;
            long j3 = this.f3339I;
            C4195m.m4771I(c2091i02.m1740f());
            c2091i02.f4398a.mo1760c(j3 - c2091i02.f4411n);
        }
        m1410V();
    }

    /* renamed from: w */
    public final void m1435w() {
        d dVar = this.f3356r;
        C2251m0 c2251m0 = this.f3361w;
        if (c2251m0 != dVar.f3371a || dVar.f3372b > 0 || dVar.f3373c) {
            this.f3350l.obtainMessage(0, dVar.f3372b, dVar.f3373c ? dVar.f3374d : -1, c2251m0).sendToTarget();
            d dVar2 = this.f3356r;
            dVar2.f3371a = this.f3361w;
            dVar2.f3372b = 0;
            dVar2.f3373c = false;
        }
    }

    /* renamed from: x */
    public final void m1436x(InterfaceC2202y interfaceC2202y, boolean z, boolean z2) {
        this.f3337G++;
        m1389A(false, true, z, z2, true);
        ((C2405y) this.f3346h).m2701b(false);
        this.f3362x = interfaceC2202y;
        m1406R(2);
        interfaceC2202y.mo1996h(this, this.f3347i.mo2196c());
        this.f3348j.m2299c(2);
    }

    /* renamed from: y */
    public final void m1437y() {
        m1389A(true, true, true, true, false);
        ((C2405y) this.f3346h).m2701b(true);
        m1406R(1);
        this.f3349k.quit();
        synchronized (this) {
            this.f3364z = true;
            notifyAll();
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:19:0x010f  */
    /* JADX WARN: Removed duplicated region for block: B:24:0x0049 A[SYNTHETIC] */
    /* renamed from: z */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void m1438z() {
        /*
            Method dump skipped, instructions count: 279
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.C1949d0.m1438z():void");
    }
}
