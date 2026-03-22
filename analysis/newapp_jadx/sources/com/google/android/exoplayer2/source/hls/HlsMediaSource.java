package com.google.android.exoplayer2.source.hls;

import android.net.Uri;
import android.os.Handler;
import androidx.annotation.Nullable;
import java.util.Iterator;
import java.util.Objects;
import p005b.p199l.p200a.p201a.C1960e0;
import p005b.p199l.p200a.p201a.p205d1.InterfaceC1954e;
import p005b.p199l.p200a.p201a.p227k1.AbstractC2185n;
import p005b.p199l.p200a.p201a.p227k1.C2196s;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2202y;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2203z;
import p005b.p199l.p200a.p201a.p227k1.p232m0.C2162e;
import p005b.p199l.p200a.p201a.p227k1.p232m0.C2170m;
import p005b.p199l.p200a.p201a.p227k1.p232m0.C2172o;
import p005b.p199l.p200a.p201a.p227k1.p232m0.InterfaceC2166i;
import p005b.p199l.p200a.p201a.p227k1.p232m0.InterfaceC2167j;
import p005b.p199l.p200a.p201a.p227k1.p232m0.p233s.C2176a;
import p005b.p199l.p200a.p201a.p227k1.p232m0.p233s.C2177b;
import p005b.p199l.p200a.p201a.p227k1.p232m0.p233s.C2178c;
import p005b.p199l.p200a.p201a.p227k1.p232m0.p233s.C2182g;
import p005b.p199l.p200a.p201a.p227k1.p232m0.p233s.InterfaceC2183h;
import p005b.p199l.p200a.p201a.p227k1.p232m0.p233s.InterfaceC2184i;
import p005b.p199l.p200a.p201a.p248o1.C2281a0;
import p005b.p199l.p200a.p201a.p248o1.C2285c0;
import p005b.p199l.p200a.p201a.p248o1.C2331w;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2288e;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2291f0;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2334z;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* loaded from: classes.dex */
public final class HlsMediaSource extends AbstractC2185n implements InterfaceC2184i.e {

    /* renamed from: i */
    public final InterfaceC2167j f9456i;

    /* renamed from: j */
    public final Uri f9457j;

    /* renamed from: k */
    public final InterfaceC2166i f9458k;

    /* renamed from: l */
    public final C2196s f9459l;

    /* renamed from: m */
    public final InterfaceC1954e<?> f9460m;

    /* renamed from: n */
    public final InterfaceC2334z f9461n;

    /* renamed from: o */
    public final boolean f9462o;

    /* renamed from: p */
    public final int f9463p;

    /* renamed from: q */
    public final boolean f9464q;

    /* renamed from: r */
    public final InterfaceC2184i f9465r;

    /* renamed from: s */
    @Nullable
    public final Object f9466s = null;

    /* renamed from: t */
    @Nullable
    public InterfaceC2291f0 f9467t;

    public static final class Factory {

        /* renamed from: a */
        public final InterfaceC2166i f9468a;

        /* renamed from: b */
        public InterfaceC2167j f9469b;

        /* renamed from: c */
        public InterfaceC2183h f9470c = new C2177b();

        /* renamed from: d */
        public InterfaceC2184i.a f9471d;

        /* renamed from: e */
        public C2196s f9472e;

        /* renamed from: f */
        public InterfaceC1954e<?> f9473f;

        /* renamed from: g */
        public InterfaceC2334z f9474g;

        /* renamed from: h */
        public int f9475h;

        public Factory(InterfaceC2321m.a aVar) {
            this.f9468a = new C2162e(aVar);
            int i2 = C2178c.f5011c;
            this.f9471d = C2176a.f5010a;
            this.f9469b = InterfaceC2167j.f4889a;
            this.f9473f = InterfaceC1954e.f3383a;
            this.f9474g = new C2331w();
            this.f9472e = new C2196s();
            this.f9475h = 1;
        }
    }

    static {
        C1960e0.m1454a("goog.exo.hls");
    }

    public HlsMediaSource(Uri uri, InterfaceC2166i interfaceC2166i, InterfaceC2167j interfaceC2167j, C2196s c2196s, InterfaceC1954e interfaceC1954e, InterfaceC2334z interfaceC2334z, InterfaceC2184i interfaceC2184i, boolean z, int i2, boolean z2, Object obj, C3303a c3303a) {
        this.f9457j = uri;
        this.f9458k = interfaceC2166i;
        this.f9456i = interfaceC2167j;
        this.f9459l = c2196s;
        this.f9460m = interfaceC1954e;
        this.f9461n = interfaceC2334z;
        this.f9465r = interfaceC2184i;
        this.f9462o = z;
        this.f9463p = i2;
        this.f9464q = z2;
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2202y
    /* renamed from: a */
    public InterfaceC2201x mo1789a(InterfaceC2202y.a aVar, InterfaceC2288e interfaceC2288e, long j2) {
        return new C2170m(this.f9456i, this.f9465r, this.f9458k, this.f9467t, this.f9460m, this.f9461n, this.f5128f.m2045u(0, aVar, 0L), interfaceC2288e, this.f9459l, this.f9462o, this.f9463p, this.f9464q);
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2202y
    /* renamed from: f */
    public void mo1790f() {
        C2178c c2178c = (C2178c) this.f9465r;
        C2281a0 c2281a0 = c2178c.f5020m;
        if (c2281a0 != null) {
            c2281a0.m2184f(Integer.MIN_VALUE);
        }
        Uri uri = c2178c.f5024q;
        if (uri != null) {
            c2178c.m1972e(uri);
        }
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2202y
    /* renamed from: g */
    public void mo1791g(InterfaceC2201x interfaceC2201x) {
        C2170m c2170m = (C2170m) interfaceC2201x;
        ((C2178c) c2170m.f4920e).f5016i.remove(c2170m);
        for (C2172o c2172o : c2170m.f4936u) {
            if (c2172o.f4948E) {
                for (C2172o.c cVar : c2172o.f4987w) {
                    cVar.m1830z();
                }
            }
            c2172o.f4976l.m2185g(c2172o);
            c2172o.f4984t.removeCallbacksAndMessages(null);
            c2172o.f4952I = true;
            c2172o.f4985u.clear();
        }
        c2170m.f4933r = null;
        c2170m.f4925j.m2041q();
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.AbstractC2185n
    /* renamed from: o */
    public void mo1792o(@Nullable InterfaceC2291f0 interfaceC2291f0) {
        this.f9467t = interfaceC2291f0;
        this.f9460m.mo1443b();
        InterfaceC2203z.a m1998j = m1998j(null);
        InterfaceC2184i interfaceC2184i = this.f9465r;
        Uri uri = this.f9457j;
        C2178c c2178c = (C2178c) interfaceC2184i;
        Objects.requireNonNull(c2178c);
        c2178c.f5021n = new Handler();
        c2178c.f5019l = m1998j;
        c2178c.f5022o = this;
        InterfaceC2321m mo1933a = c2178c.f5012e.mo1933a(4);
        Objects.requireNonNull((C2177b) c2178c.f5013f);
        C2285c0 c2285c0 = new C2285c0(mo1933a, uri, 4, new C2182g());
        C4195m.m4771I(c2178c.f5020m == null);
        C2281a0 c2281a0 = new C2281a0("DefaultHlsPlaylistTracker:MasterPlaylist");
        c2178c.f5020m = c2281a0;
        m1998j.m2039o(c2285c0.f5789a, c2285c0.f5790b, c2281a0.m2186h(c2285c0, c2178c, ((C2331w) c2178c.f5014g).m2280b(c2285c0.f5790b)));
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.AbstractC2185n
    /* renamed from: q */
    public void mo1793q() {
        C2178c c2178c = (C2178c) this.f9465r;
        c2178c.f5024q = null;
        c2178c.f5025r = null;
        c2178c.f5023p = null;
        c2178c.f5027t = -9223372036854775807L;
        c2178c.f5020m.m2185g(null);
        c2178c.f5020m = null;
        Iterator<C2178c.a> it = c2178c.f5015h.values().iterator();
        while (it.hasNext()) {
            it.next().f5029e.m2185g(null);
        }
        c2178c.f5021n.removeCallbacksAndMessages(null);
        c2178c.f5021n = null;
        c2178c.f5015h.clear();
        this.f9460m.release();
    }
}
