package l0;

import G0.x;
import X.i;
import X.k;
import X.n;
import android.content.res.Resources;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import b0.AbstractC0311a;
import com.facebook.common.time.AwakeTimeSinceBootClock;
import h0.InterfaceC0547c;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executor;
import m0.C0626a;
import o0.AbstractC0637a;
import p0.AbstractC0642a;
import p0.AbstractC0643b;
import q0.C0653a;
import r0.C0674a;
import s0.AbstractC0681a;
import s0.InterfaceC0683c;
import s0.o;
import s0.q;
import v0.InterfaceC0706b;
import y0.InterfaceC0728g;
import y0.l;

/* JADX INFO: renamed from: l0.e, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0617e extends AbstractC0642a {

    /* JADX INFO: renamed from: M, reason: collision with root package name */
    private static final Class f9492M = C0617e.class;

    /* JADX INFO: renamed from: A, reason: collision with root package name */
    private final M0.a f9493A;

    /* JADX INFO: renamed from: B, reason: collision with root package name */
    private final X.f f9494B;

    /* JADX INFO: renamed from: C, reason: collision with root package name */
    private final x f9495C;

    /* JADX INFO: renamed from: D, reason: collision with root package name */
    private R.d f9496D;

    /* JADX INFO: renamed from: E, reason: collision with root package name */
    private n f9497E;

    /* JADX INFO: renamed from: F, reason: collision with root package name */
    private boolean f9498F;

    /* JADX INFO: renamed from: G, reason: collision with root package name */
    private X.f f9499G;

    /* JADX INFO: renamed from: H, reason: collision with root package name */
    private C0626a f9500H;

    /* JADX INFO: renamed from: I, reason: collision with root package name */
    private Set f9501I;

    /* JADX INFO: renamed from: J, reason: collision with root package name */
    private T0.b f9502J;

    /* JADX INFO: renamed from: K, reason: collision with root package name */
    private T0.b[] f9503K;

    /* JADX INFO: renamed from: L, reason: collision with root package name */
    private T0.b f9504L;

    /* JADX INFO: renamed from: z, reason: collision with root package name */
    private final Resources f9505z;

    public C0617e(Resources resources, AbstractC0637a abstractC0637a, M0.a aVar, M0.a aVar2, Executor executor, x xVar, X.f fVar) {
        super(abstractC0637a, executor, null, null);
        this.f9505z = resources;
        this.f9493A = new C0613a(resources, aVar, aVar2);
        this.f9494B = fVar;
        this.f9495C = xVar;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static o l0(Drawable drawable) {
        if (drawable == 0) {
            return null;
        }
        if (drawable instanceof o) {
            return (o) drawable;
        }
        if (drawable instanceof InterfaceC0683c) {
            return l0(((InterfaceC0683c) drawable).p());
        }
        if (drawable instanceof AbstractC0681a) {
            AbstractC0681a abstractC0681a = (AbstractC0681a) drawable;
            int iD = abstractC0681a.d();
            for (int i3 = 0; i3 < iD; i3++) {
                o oVarL0 = l0(abstractC0681a.b(i3));
                if (oVarL0 != null) {
                    return oVarL0;
                }
            }
        }
        return null;
    }

    private void r0(n nVar) {
        this.f9497E = nVar;
        v0(null);
    }

    private Drawable u0(X.f fVar, N0.d dVar) {
        Drawable drawableB;
        if (fVar == null) {
            return null;
        }
        Iterator<E> it = fVar.iterator();
        while (it.hasNext()) {
            M0.a aVar = (M0.a) it.next();
            if (aVar.a(dVar) && (drawableB = aVar.b(dVar)) != null) {
                return drawableB;
            }
        }
        return null;
    }

    private void v0(N0.d dVar) {
        if (this.f9498F) {
            if (s() == null) {
                C0653a c0653a = new C0653a();
                k(new C0674a(c0653a));
                b0(c0653a);
            }
            if (s() instanceof C0653a) {
                C0(dVar, (C0653a) s());
            }
        }
    }

    @Override // p0.AbstractC0642a
    protected Uri A() {
        return l.a(this.f9502J, this.f9504L, this.f9503K, T0.b.f2742A);
    }

    public void A0(X.f fVar) {
        this.f9499G = fVar;
    }

    public void B0(boolean z3) {
        this.f9498F = z3;
    }

    protected void C0(N0.d dVar, C0653a c0653a) {
        o oVarL0;
        c0653a.j(w());
        InterfaceC0706b interfaceC0706bC = c();
        q qVarA = null;
        if (interfaceC0706bC != null && (oVarL0 = l0(interfaceC0706bC.d())) != null) {
            qVarA = oVarL0.A();
        }
        c0653a.m(qVarA);
        String strN0 = n0();
        if (strN0 != null) {
            c0653a.b("cc", strN0);
        }
        if (dVar == null) {
            c0653a.i();
        } else {
            c0653a.k(dVar.h(), dVar.d());
            c0653a.l(dVar.b0());
        }
    }

    @Override // p0.AbstractC0642a, v0.InterfaceC0705a
    public void e(InterfaceC0706b interfaceC0706b) {
        super.e(interfaceC0706b);
        v0(null);
    }

    public synchronized void j0(P0.e eVar) {
        try {
            if (this.f9501I == null) {
                this.f9501I = new HashSet();
            }
            this.f9501I.add(eVar);
        } catch (Throwable th) {
            throw th;
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // p0.AbstractC0642a
    /* JADX INFO: renamed from: k0, reason: merged with bridge method [inline-methods] */
    public Drawable m(AbstractC0311a abstractC0311a) {
        try {
            if (U0.b.d()) {
                U0.b.a("PipelineDraweeController#createDrawable");
            }
            k.i(AbstractC0311a.d0(abstractC0311a));
            N0.d dVar = (N0.d) abstractC0311a.P();
            v0(dVar);
            Drawable drawableU0 = u0(this.f9499G, dVar);
            if (drawableU0 != null) {
                if (U0.b.d()) {
                    U0.b.b();
                }
                return drawableU0;
            }
            Drawable drawableU02 = u0(this.f9494B, dVar);
            if (drawableU02 != null) {
                if (U0.b.d()) {
                    U0.b.b();
                }
                return drawableU02;
            }
            Drawable drawableB = this.f9493A.b(dVar);
            if (drawableB != null) {
                if (U0.b.d()) {
                    U0.b.b();
                }
                return drawableB;
            }
            throw new UnsupportedOperationException("Unrecognized image class: " + dVar);
        } catch (Throwable th) {
            if (U0.b.d()) {
                U0.b.b();
            }
            throw th;
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // p0.AbstractC0642a
    /* JADX INFO: renamed from: m0, reason: merged with bridge method [inline-methods] */
    public AbstractC0311a o() {
        R.d dVar;
        if (U0.b.d()) {
            U0.b.a("PipelineDraweeController#getCachedImage");
        }
        try {
            x xVar = this.f9495C;
            if (xVar != null && (dVar = this.f9496D) != null) {
                AbstractC0311a abstractC0311a = xVar.get(dVar);
                if (abstractC0311a != null && !((N0.d) abstractC0311a.P()).k().a()) {
                    abstractC0311a.close();
                    return null;
                }
                if (U0.b.d()) {
                    U0.b.b();
                }
                return abstractC0311a;
            }
            if (U0.b.d()) {
                U0.b.b();
            }
            return null;
        } finally {
            if (U0.b.d()) {
                U0.b.b();
            }
        }
    }

    protected String n0() {
        Object objP = p();
        if (objP == null) {
            return null;
        }
        return objP.toString();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // p0.AbstractC0642a
    /* JADX INFO: renamed from: o0, reason: merged with bridge method [inline-methods] */
    public int y(AbstractC0311a abstractC0311a) {
        if (abstractC0311a != null) {
            return abstractC0311a.W();
        }
        return 0;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // p0.AbstractC0642a
    /* JADX INFO: renamed from: p0, reason: merged with bridge method [inline-methods] */
    public N0.l z(AbstractC0311a abstractC0311a) {
        k.i(AbstractC0311a.d0(abstractC0311a));
        return ((N0.d) abstractC0311a.P()).s();
    }

    public synchronized P0.e q0() {
        Set set = this.f9501I;
        if (set == null) {
            return null;
        }
        return new P0.c(set);
    }

    public void s0(n nVar, String str, R.d dVar, Object obj, X.f fVar) {
        if (U0.b.d()) {
            U0.b.a("PipelineDraweeController#initialize");
        }
        super.E(str, obj);
        r0(nVar);
        this.f9496D = dVar;
        A0(fVar);
        v0(null);
        if (U0.b.d()) {
            U0.b.b();
        }
    }

    @Override // p0.AbstractC0642a
    protected InterfaceC0547c t() {
        if (U0.b.d()) {
            U0.b.a("PipelineDraweeController#getDataSource");
        }
        if (Y.a.w(2)) {
            Y.a.y(f9492M, "controller %x: getDataSource", Integer.valueOf(System.identityHashCode(this)));
        }
        InterfaceC0547c interfaceC0547c = (InterfaceC0547c) this.f9497E.get();
        if (U0.b.d()) {
            U0.b.b();
        }
        return interfaceC0547c;
    }

    protected synchronized void t0(InterfaceC0728g interfaceC0728g, AbstractC0643b abstractC0643b) {
        try {
            C0626a c0626a = this.f9500H;
            if (c0626a != null) {
                c0626a.f();
            }
            if (interfaceC0728g != null) {
                if (this.f9500H == null) {
                    this.f9500H = new C0626a(AwakeTimeSinceBootClock.get(), this);
                }
                this.f9500H.c(interfaceC0728g);
                this.f9500H.g(true);
            }
            this.f9502J = (T0.b) abstractC0643b.l();
            this.f9503K = (T0.b[]) abstractC0643b.k();
            this.f9504L = (T0.b) abstractC0643b.m();
        } catch (Throwable th) {
            throw th;
        }
    }

    @Override // p0.AbstractC0642a
    public String toString() {
        return i.b(this).b("super", super.toString()).b("dataSourceSupplier", this.f9497E).toString();
    }

    @Override // p0.AbstractC0642a
    /* JADX INFO: renamed from: w0, reason: merged with bridge method [inline-methods] */
    public Map L(N0.l lVar) {
        if (lVar == null) {
            return null;
        }
        return lVar.b();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // p0.AbstractC0642a
    /* JADX INFO: renamed from: x0, reason: merged with bridge method [inline-methods] */
    public void N(String str, AbstractC0311a abstractC0311a) {
        super.N(str, abstractC0311a);
        synchronized (this) {
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // p0.AbstractC0642a
    /* JADX INFO: renamed from: y0, reason: merged with bridge method [inline-methods] */
    public void S(AbstractC0311a abstractC0311a) {
        AbstractC0311a.D(abstractC0311a);
    }

    public synchronized void z0(P0.e eVar) {
        Set set = this.f9501I;
        if (set == null) {
            return;
        }
        set.remove(eVar);
    }

    @Override // p0.AbstractC0642a
    protected void Q(Drawable drawable) {
    }
}
