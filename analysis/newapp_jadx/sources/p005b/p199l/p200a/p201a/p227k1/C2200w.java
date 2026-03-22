package p005b.p199l.p200a.p201a.p227k1;

import android.os.Handler;
import android.util.Pair;
import androidx.annotation.Nullable;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import p005b.p199l.p200a.p201a.AbstractC2404x0;
import p005b.p199l.p200a.p201a.p227k1.AbstractC2194q;
import p005b.p199l.p200a.p201a.p227k1.C2200w;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2111g0;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2202y;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2288e;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2291f0;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.k1.w */
/* loaded from: classes.dex */
public final class C2200w extends AbstractC2194q<Void> {

    /* renamed from: l */
    public final InterfaceC2202y f5239l;

    /* renamed from: m */
    public final int f5240m;

    /* renamed from: n */
    public final Map<InterfaceC2202y.a, InterfaceC2202y.a> f5241n;

    /* renamed from: o */
    public final Map<InterfaceC2201x, InterfaceC2202y.a> f5242o;

    /* renamed from: b.l.a.a.k1.w$a */
    public static final class a extends AbstractC2198u {
        public a(AbstractC2404x0 abstractC2404x0) {
            super(abstractC2404x0);
        }

        @Override // p005b.p199l.p200a.p201a.AbstractC2404x0
        /* renamed from: e */
        public int mo1928e(int i2, int i3, boolean z) {
            int mo1928e = this.f5233b.mo1928e(i2, i3, z);
            return mo1928e == -1 ? this.f5233b.mo1926a(z) : mo1928e;
        }

        @Override // p005b.p199l.p200a.p201a.AbstractC2404x0
        /* renamed from: l */
        public int mo1930l(int i2, int i3, boolean z) {
            int mo1930l = this.f5233b.mo1930l(i2, i3, z);
            return mo1930l == -1 ? this.f5233b.mo1927c(z) : mo1930l;
        }
    }

    /* renamed from: b.l.a.a.k1.w$b */
    public static final class b extends AbstractC2157m {

        /* renamed from: e */
        public final AbstractC2404x0 f5243e;

        /* renamed from: f */
        public final int f5244f;

        /* renamed from: g */
        public final int f5245g;

        /* renamed from: h */
        public final int f5246h;

        public b(AbstractC2404x0 abstractC2404x0, int i2) {
            super(false, new InterfaceC2111g0.a(i2));
            this.f5243e = abstractC2404x0;
            int mo1833i = abstractC2404x0.mo1833i();
            this.f5244f = mo1833i;
            this.f5245g = abstractC2404x0.mo1836p();
            this.f5246h = i2;
            if (mo1833i > 0) {
                C4195m.m4773J(i2 <= Integer.MAX_VALUE / mo1833i, "LoopingMediaSource contains too many periods");
            }
        }

        @Override // p005b.p199l.p200a.p201a.AbstractC2404x0
        /* renamed from: i */
        public int mo1833i() {
            return this.f5244f * this.f5246h;
        }

        @Override // p005b.p199l.p200a.p201a.AbstractC2404x0
        /* renamed from: p */
        public int mo1836p() {
            return this.f5245g * this.f5246h;
        }
    }

    public C2200w(InterfaceC2202y interfaceC2202y) {
        C4195m.m4765F(true);
        this.f5239l = interfaceC2202y;
        this.f5240m = Integer.MAX_VALUE;
        this.f5241n = new HashMap();
        this.f5242o = new HashMap();
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2202y
    /* renamed from: a */
    public InterfaceC2201x mo1789a(InterfaceC2202y.a aVar, InterfaceC2288e interfaceC2288e, long j2) {
        if (this.f5240m == Integer.MAX_VALUE) {
            return this.f5239l.mo1789a(aVar, interfaceC2288e, j2);
        }
        Object obj = aVar.f5247a;
        Object obj2 = ((Pair) obj).second;
        InterfaceC2202y.a aVar2 = obj.equals(obj2) ? aVar : new InterfaceC2202y.a(obj2, aVar.f5248b, aVar.f5249c, aVar.f5250d, aVar.f5251e);
        this.f5241n.put(aVar2, aVar);
        InterfaceC2201x mo1789a = this.f5239l.mo1789a(aVar2, interfaceC2288e, j2);
        this.f5242o.put(mo1789a, aVar2);
        return mo1789a;
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2202y
    /* renamed from: g */
    public void mo1791g(InterfaceC2201x interfaceC2201x) {
        this.f5239l.mo1791g(interfaceC2201x);
        InterfaceC2202y.a remove = this.f5242o.remove(interfaceC2201x);
        if (remove != null) {
            this.f5241n.remove(remove);
        }
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.AbstractC2185n
    /* renamed from: o */
    public void mo1792o(@Nullable InterfaceC2291f0 interfaceC2291f0) {
        this.f5225k = interfaceC2291f0;
        this.f5224j = new Handler();
        final Object obj = null;
        InterfaceC2202y interfaceC2202y = this.f5239l;
        C4195m.m4765F(!this.f5223i.containsKey(null));
        InterfaceC2202y.b bVar = new InterfaceC2202y.b() { // from class: b.l.a.a.k1.a
            @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2202y.b
            /* renamed from: a */
            public final void mo1414a(InterfaceC2202y interfaceC2202y2, AbstractC2404x0 abstractC2404x0) {
                AbstractC2194q abstractC2194q = AbstractC2194q.this;
                Object obj2 = obj;
                Objects.requireNonNull(abstractC2194q);
                C2200w c2200w = (C2200w) abstractC2194q;
                int i2 = c2200w.f5240m;
                c2200w.m2001p(i2 != Integer.MAX_VALUE ? new C2200w.b(abstractC2404x0, i2) : new C2200w.a(abstractC2404x0));
            }
        };
        AbstractC2194q.a aVar = new AbstractC2194q.a(null);
        this.f5223i.put(null, new AbstractC2194q.b(interfaceC2202y, bVar, aVar));
        Handler handler = this.f5224j;
        Objects.requireNonNull(handler);
        interfaceC2202y.mo1993c(handler, aVar);
        interfaceC2202y.mo1996h(bVar, this.f5225k);
        if (!this.f5127e.isEmpty()) {
            return;
        }
        interfaceC2202y.mo1995e(bVar);
    }
}
