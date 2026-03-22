package p005b.p199l.p200a.p201a.p227k1;

import android.os.Handler;
import androidx.annotation.CallSuper;
import androidx.annotation.Nullable;
import java.io.IOException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Objects;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2202y;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2203z;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2291f0;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* renamed from: b.l.a.a.k1.q */
/* loaded from: classes.dex */
public abstract class AbstractC2194q<T> extends AbstractC2185n {

    /* renamed from: i */
    public final HashMap<T, b> f5223i = new HashMap<>();

    /* renamed from: j */
    @Nullable
    public Handler f5224j;

    /* renamed from: k */
    @Nullable
    public InterfaceC2291f0 f5225k;

    /* renamed from: b.l.a.a.k1.q$a */
    public final class a implements InterfaceC2203z {

        /* renamed from: c */
        public final T f5226c;

        /* renamed from: e */
        public InterfaceC2203z.a f5227e;

        public a(T t) {
            this.f5227e = AbstractC2194q.this.m1998j(null);
            this.f5226c = t;
        }

        /* renamed from: a */
        public final boolean m2022a(int i2, @Nullable InterfaceC2202y.a aVar) {
            if (aVar != null) {
                AbstractC2194q abstractC2194q = AbstractC2194q.this;
                T t = this.f5226c;
                C2200w c2200w = (C2200w) abstractC2194q;
                Objects.requireNonNull(c2200w);
                if (c2200w.f5240m != Integer.MAX_VALUE) {
                    aVar = c2200w.f5241n.get(aVar);
                }
                if (aVar == null) {
                    return false;
                }
            } else {
                aVar = null;
            }
            Objects.requireNonNull(AbstractC2194q.this);
            InterfaceC2203z.a aVar2 = this.f5227e;
            if (aVar2.f5252a == i2 && C2344d0.m2323a(aVar2.f5253b, aVar)) {
                return true;
            }
            this.f5227e = AbstractC2194q.this.f5128f.m2045u(i2, aVar, 0L);
            return true;
        }

        /* renamed from: b */
        public final InterfaceC2203z.c m2023b(InterfaceC2203z.c cVar) {
            AbstractC2194q abstractC2194q = AbstractC2194q.this;
            long j2 = cVar.f5264f;
            Objects.requireNonNull(abstractC2194q);
            AbstractC2194q abstractC2194q2 = AbstractC2194q.this;
            long j3 = cVar.f5265g;
            Objects.requireNonNull(abstractC2194q2);
            return (j2 == cVar.f5264f && j3 == cVar.f5265g) ? cVar : new InterfaceC2203z.c(cVar.f5259a, cVar.f5260b, cVar.f5261c, cVar.f5262d, cVar.f5263e, j2, j3);
        }

        @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2203z
        public void onDownstreamFormatChanged(int i2, @Nullable InterfaceC2202y.a aVar, InterfaceC2203z.c cVar) {
            if (m2022a(i2, aVar)) {
                this.f5227e.m2027c(m2023b(cVar));
            }
        }

        @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2203z
        public void onLoadCanceled(int i2, @Nullable InterfaceC2202y.a aVar, InterfaceC2203z.b bVar, InterfaceC2203z.c cVar) {
            if (m2022a(i2, aVar)) {
                this.f5227e.m2028d(bVar, m2023b(cVar));
            }
        }

        @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2203z
        public void onLoadCompleted(int i2, @Nullable InterfaceC2202y.a aVar, InterfaceC2203z.b bVar, InterfaceC2203z.c cVar) {
            if (m2022a(i2, aVar)) {
                this.f5227e.m2031g(bVar, m2023b(cVar));
            }
        }

        @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2203z
        public void onLoadError(int i2, @Nullable InterfaceC2202y.a aVar, InterfaceC2203z.b bVar, InterfaceC2203z.c cVar, IOException iOException, boolean z) {
            if (m2022a(i2, aVar)) {
                this.f5227e.m2034j(bVar, m2023b(cVar), iOException, z);
            }
        }

        @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2203z
        public void onLoadStarted(int i2, @Nullable InterfaceC2202y.a aVar, InterfaceC2203z.b bVar, InterfaceC2203z.c cVar) {
            if (m2022a(i2, aVar)) {
                this.f5227e.m2037m(bVar, m2023b(cVar));
            }
        }

        @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2203z
        public void onMediaPeriodCreated(int i2, InterfaceC2202y.a aVar) {
            if (m2022a(i2, aVar)) {
                AbstractC2194q abstractC2194q = AbstractC2194q.this;
                Objects.requireNonNull(this.f5227e.f5253b);
                Objects.requireNonNull(abstractC2194q);
                this.f5227e.m2040p();
            }
        }

        @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2203z
        public void onMediaPeriodReleased(int i2, InterfaceC2202y.a aVar) {
            if (m2022a(i2, aVar)) {
                AbstractC2194q abstractC2194q = AbstractC2194q.this;
                Objects.requireNonNull(this.f5227e.f5253b);
                Objects.requireNonNull(abstractC2194q);
                this.f5227e.m2041q();
            }
        }

        @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2203z
        public void onReadingStarted(int i2, InterfaceC2202y.a aVar) {
            if (m2022a(i2, aVar)) {
                this.f5227e.m2043s();
            }
        }

        @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2203z
        public void onUpstreamDiscarded(int i2, @Nullable InterfaceC2202y.a aVar, InterfaceC2203z.c cVar) {
            if (m2022a(i2, aVar)) {
                this.f5227e.m2044t(m2023b(cVar));
            }
        }
    }

    /* renamed from: b.l.a.a.k1.q$b */
    public static final class b {

        /* renamed from: a */
        public final InterfaceC2202y f5229a;

        /* renamed from: b */
        public final InterfaceC2202y.b f5230b;

        /* renamed from: c */
        public final InterfaceC2203z f5231c;

        public b(InterfaceC2202y interfaceC2202y, InterfaceC2202y.b bVar, InterfaceC2203z interfaceC2203z) {
            this.f5229a = interfaceC2202y;
            this.f5230b = bVar;
            this.f5231c = interfaceC2203z;
        }
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2202y
    @CallSuper
    /* renamed from: f */
    public void mo1790f() {
        Iterator<b> it = this.f5223i.values().iterator();
        while (it.hasNext()) {
            it.next().f5229a.mo1790f();
        }
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.AbstractC2185n
    @CallSuper
    /* renamed from: m */
    public void mo1999m() {
        for (b bVar : this.f5223i.values()) {
            bVar.f5229a.mo1995e(bVar.f5230b);
        }
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.AbstractC2185n
    @CallSuper
    /* renamed from: n */
    public void mo2000n() {
        for (b bVar : this.f5223i.values()) {
            bVar.f5229a.mo1997i(bVar.f5230b);
        }
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.AbstractC2185n
    @CallSuper
    /* renamed from: q */
    public void mo1793q() {
        for (b bVar : this.f5223i.values()) {
            bVar.f5229a.mo1992b(bVar.f5230b);
            bVar.f5229a.mo1994d(bVar.f5231c);
        }
        this.f5223i.clear();
    }
}
