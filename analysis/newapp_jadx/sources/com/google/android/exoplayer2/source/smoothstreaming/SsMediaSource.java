package com.google.android.exoplayer2.source.smoothstreaming;

import android.net.Uri;
import android.os.Handler;
import android.os.SystemClock;
import androidx.annotation.Nullable;
import androidx.work.WorkRequest;
import com.google.android.exoplayer2.source.smoothstreaming.SsMediaSource;
import java.io.IOException;
import java.util.ArrayList;
import p005b.p199l.p200a.p201a.C1960e0;
import p005b.p199l.p200a.p201a.C2399v;
import p005b.p199l.p200a.p201a.p205d1.InterfaceC1954e;
import p005b.p199l.p200a.p201a.p227k1.AbstractC2185n;
import p005b.p199l.p200a.p201a.p227k1.C2113h0;
import p005b.p199l.p200a.p201a.p227k1.C2196s;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2202y;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2203z;
import p005b.p199l.p200a.p201a.p227k1.p229k0.C2125g;
import p005b.p199l.p200a.p201a.p227k1.p234n0.C2187b;
import p005b.p199l.p200a.p201a.p227k1.p234n0.C2189d;
import p005b.p199l.p200a.p201a.p227k1.p234n0.InterfaceC2188c;
import p005b.p199l.p200a.p201a.p227k1.p234n0.p235e.C2190a;
import p005b.p199l.p200a.p201a.p248o1.C2281a0;
import p005b.p199l.p200a.p201a.p248o1.C2285c0;
import p005b.p199l.p200a.p201a.p248o1.C2287d0;
import p005b.p199l.p200a.p201a.p248o1.C2324p;
import p005b.p199l.p200a.p201a.p248o1.C2331w;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2283b0;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2288e;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2291f0;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2334z;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* loaded from: classes.dex */
public final class SsMediaSource extends AbstractC2185n implements C2281a0.b<C2285c0<C2190a>> {

    /* renamed from: A */
    public Handler f9484A;

    /* renamed from: i */
    public final boolean f9485i;

    /* renamed from: j */
    public final Uri f9486j;

    /* renamed from: k */
    public final InterfaceC2321m.a f9487k;

    /* renamed from: l */
    public final InterfaceC2188c.a f9488l;

    /* renamed from: m */
    public final C2196s f9489m;

    /* renamed from: n */
    public final InterfaceC1954e<?> f9490n;

    /* renamed from: o */
    public final InterfaceC2334z f9491o;

    /* renamed from: p */
    public final long f9492p;

    /* renamed from: q */
    public final InterfaceC2203z.a f9493q;

    /* renamed from: r */
    public final C2285c0.a<? extends C2190a> f9494r;

    /* renamed from: s */
    public final ArrayList<C2189d> f9495s;

    /* renamed from: t */
    @Nullable
    public final Object f9496t;

    /* renamed from: u */
    public InterfaceC2321m f9497u;

    /* renamed from: v */
    public C2281a0 f9498v;

    /* renamed from: w */
    public InterfaceC2283b0 f9499w;

    /* renamed from: x */
    @Nullable
    public InterfaceC2291f0 f9500x;

    /* renamed from: y */
    public long f9501y;

    /* renamed from: z */
    public C2190a f9502z;

    public static final class Factory {

        /* renamed from: a */
        public final InterfaceC2188c.a f9503a;

        /* renamed from: b */
        @Nullable
        public final InterfaceC2321m.a f9504b;

        /* renamed from: c */
        @Nullable
        public C2285c0.a<? extends C2190a> f9505c;

        /* renamed from: d */
        public C2196s f9506d;

        /* renamed from: e */
        public InterfaceC1954e<?> f9507e;

        /* renamed from: f */
        public InterfaceC2334z f9508f;

        /* renamed from: g */
        public long f9509g;

        public Factory(InterfaceC2321m.a aVar) {
            this(new C2187b.a(aVar), aVar);
        }

        public Factory(InterfaceC2188c.a aVar, @Nullable InterfaceC2321m.a aVar2) {
            this.f9503a = aVar;
            this.f9504b = aVar2;
            this.f9507e = InterfaceC1954e.f3383a;
            this.f9508f = new C2331w();
            this.f9509g = WorkRequest.DEFAULT_BACKOFF_DELAY_MILLIS;
            this.f9506d = new C2196s();
        }
    }

    static {
        C1960e0.m1454a("goog.exo.smoothstreaming");
    }

    public SsMediaSource(C2190a c2190a, Uri uri, InterfaceC2321m.a aVar, C2285c0.a aVar2, InterfaceC2188c.a aVar3, C2196s c2196s, InterfaceC1954e interfaceC1954e, InterfaceC2334z interfaceC2334z, long j2, Object obj, C3306a c3306a) {
        C4195m.m4771I(true);
        this.f9502z = null;
        String lastPathSegment = uri.getLastPathSegment();
        this.f9486j = (lastPathSegment == null || !C2344d0.m2320L(lastPathSegment).matches("manifest(\\(.+\\))?")) ? Uri.withAppendedPath(uri, "Manifest") : uri;
        this.f9487k = aVar;
        this.f9494r = aVar2;
        this.f9488l = aVar3;
        this.f9489m = c2196s;
        this.f9490n = interfaceC1954e;
        this.f9491o = interfaceC2334z;
        this.f9492p = j2;
        this.f9493q = m1998j(null);
        this.f9496t = null;
        this.f9485i = false;
        this.f9495s = new ArrayList<>();
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2202y
    /* renamed from: a */
    public InterfaceC2201x mo1789a(InterfaceC2202y.a aVar, InterfaceC2288e interfaceC2288e, long j2) {
        C2189d c2189d = new C2189d(this.f9502z, this.f9488l, this.f9500x, this.f9489m, this.f9490n, this.f9491o, this.f5128f.m2045u(0, aVar, 0L), this.f9499w, interfaceC2288e);
        this.f9495s.add(c2189d);
        return c2189d;
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2202y
    /* renamed from: f */
    public void mo1790f() {
        this.f9499w.mo2180a();
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2202y
    /* renamed from: g */
    public void mo1791g(InterfaceC2201x interfaceC2201x) {
        C2189d c2189d = (C2189d) interfaceC2201x;
        for (C2125g<InterfaceC2188c> c2125g : c2189d.f5152o) {
            c2125g.m1843A(null);
        }
        c2189d.f5150m = null;
        c2189d.f5146i.m2041q();
        this.f9495s.remove(interfaceC2201x);
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.C2281a0.b
    /* renamed from: k */
    public void mo1768k(C2285c0<C2190a> c2285c0, long j2, long j3, boolean z) {
        C2285c0<C2190a> c2285c02 = c2285c0;
        InterfaceC2203z.a aVar = this.f9493q;
        C2324p c2324p = c2285c02.f5789a;
        C2287d0 c2287d0 = c2285c02.f5791c;
        aVar.m2030f(c2324p, c2287d0.f5798c, c2287d0.f5799d, c2285c02.f5790b, j2, j3, c2287d0.f5797b);
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.C2281a0.b
    /* renamed from: l */
    public void mo1769l(C2285c0<C2190a> c2285c0, long j2, long j3) {
        C2285c0<C2190a> c2285c02 = c2285c0;
        InterfaceC2203z.a aVar = this.f9493q;
        C2324p c2324p = c2285c02.f5789a;
        C2287d0 c2287d0 = c2285c02.f5791c;
        aVar.m2033i(c2324p, c2287d0.f5798c, c2287d0.f5799d, c2285c02.f5790b, j2, j3, c2287d0.f5797b);
        this.f9502z = c2285c02.f5793e;
        this.f9501y = j2 - j3;
        m4067r();
        if (this.f9502z.f5158d) {
            this.f9484A.postDelayed(new Runnable() { // from class: b.l.a.a.k1.n0.a
                @Override // java.lang.Runnable
                public final void run() {
                    SsMediaSource.this.m4068t();
                }
            }, Math.max(0L, (this.f9501y + 5000) - SystemClock.elapsedRealtime()));
        }
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.AbstractC2185n
    /* renamed from: o */
    public void mo1792o(@Nullable InterfaceC2291f0 interfaceC2291f0) {
        this.f9500x = interfaceC2291f0;
        this.f9490n.mo1443b();
        if (this.f9485i) {
            this.f9499w = new InterfaceC2283b0.a();
            m4067r();
            return;
        }
        this.f9497u = this.f9487k.createDataSource();
        C2281a0 c2281a0 = new C2281a0("Loader:Manifest");
        this.f9498v = c2281a0;
        this.f9499w = c2281a0;
        this.f9484A = new Handler();
        m4068t();
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.AbstractC2185n
    /* renamed from: q */
    public void mo1793q() {
        this.f9502z = this.f9485i ? this.f9502z : null;
        this.f9497u = null;
        this.f9501y = 0L;
        C2281a0 c2281a0 = this.f9498v;
        if (c2281a0 != null) {
            c2281a0.m2185g(null);
            this.f9498v = null;
        }
        Handler handler = this.f9484A;
        if (handler != null) {
            handler.removeCallbacksAndMessages(null);
            this.f9484A = null;
        }
        this.f9490n.release();
    }

    /* renamed from: r */
    public final void m4067r() {
        C2113h0 c2113h0;
        for (int i2 = 0; i2 < this.f9495s.size(); i2++) {
            C2189d c2189d = this.f9495s.get(i2);
            C2190a c2190a = this.f9502z;
            c2189d.f5151n = c2190a;
            for (C2125g<InterfaceC2188c> c2125g : c2189d.f5152o) {
                c2125g.f4653h.mo2003c(c2190a);
            }
            c2189d.f5150m.mo1421i(c2189d);
        }
        long j2 = Long.MIN_VALUE;
        long j3 = Long.MAX_VALUE;
        for (C2190a.b bVar : this.f9502z.f5160f) {
            if (bVar.f5176k > 0) {
                j3 = Math.min(j3, bVar.f5180o[0]);
                int i3 = bVar.f5176k;
                j2 = Math.max(j2, bVar.m2005a(i3 - 1) + bVar.f5180o[i3 - 1]);
            }
        }
        if (j3 == Long.MAX_VALUE) {
            long j4 = this.f9502z.f5158d ? -9223372036854775807L : 0L;
            C2190a c2190a2 = this.f9502z;
            boolean z = c2190a2.f5158d;
            c2113h0 = new C2113h0(j4, 0L, 0L, 0L, true, z, z, c2190a2, this.f9496t);
        } else {
            C2190a c2190a3 = this.f9502z;
            if (c2190a3.f5158d) {
                long j5 = c2190a3.f5162h;
                if (j5 != -9223372036854775807L && j5 > 0) {
                    j3 = Math.max(j3, j2 - j5);
                }
                long j6 = j3;
                long j7 = j2 - j6;
                long m2668a = j7 - C2399v.m2668a(this.f9492p);
                if (m2668a < 5000000) {
                    m2668a = Math.min(5000000L, j7 / 2);
                }
                c2113h0 = new C2113h0(-9223372036854775807L, j7, j6, m2668a, true, true, true, this.f9502z, this.f9496t);
            } else {
                long j8 = c2190a3.f5161g;
                long j9 = j8 != -9223372036854775807L ? j8 : j2 - j3;
                c2113h0 = new C2113h0(j3 + j9, j9, j3, 0L, true, false, false, this.f9502z, this.f9496t);
            }
        }
        m2001p(c2113h0);
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.C2281a0.b
    /* renamed from: s */
    public C2281a0.c mo1775s(C2285c0<C2190a> c2285c0, long j2, long j3, IOException iOException, int i2) {
        C2285c0<C2190a> c2285c02 = c2285c0;
        long m2281c = ((C2331w) this.f9491o).m2281c(4, j3, iOException, i2);
        C2281a0.c m2179c = m2281c == -9223372036854775807L ? C2281a0.f5768b : C2281a0.m2179c(false, m2281c);
        InterfaceC2203z.a aVar = this.f9493q;
        C2324p c2324p = c2285c02.f5789a;
        C2287d0 c2287d0 = c2285c02.f5791c;
        aVar.m2036l(c2324p, c2287d0.f5798c, c2287d0.f5799d, c2285c02.f5790b, j2, j3, c2287d0.f5797b, iOException, !m2179c.m2187a());
        return m2179c;
    }

    /* renamed from: t */
    public final void m4068t() {
        if (this.f9498v.m2182d()) {
            return;
        }
        C2285c0 c2285c0 = new C2285c0(this.f9497u, this.f9486j, 4, this.f9494r);
        this.f9493q.m2039o(c2285c0.f5789a, c2285c0.f5790b, this.f9498v.m2186h(c2285c0, this, ((C2331w) this.f9491o).m2280b(c2285c0.f5790b)));
    }
}
