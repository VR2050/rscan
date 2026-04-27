package p0;

import X.g;
import X.i;
import X.k;
import android.graphics.PointF;
import android.graphics.Rect;
import android.graphics.drawable.Animatable;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.view.MotionEvent;
import h0.AbstractC0546b;
import h0.InterfaceC0547c;
import java.util.Map;
import java.util.concurrent.Executor;
import o0.AbstractC0637a;
import o0.c;
import t0.C0690a;
import u0.C0702a;
import v0.InterfaceC0705a;
import v0.InterfaceC0706b;
import v0.InterfaceC0707c;
import x0.C0717b;
import y0.C0725d;
import y0.InterfaceC0723b;

/* JADX INFO: renamed from: p0.a, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public abstract class AbstractC0642a implements InterfaceC0705a, AbstractC0637a.InterfaceC0141a, C0702a.InterfaceC0149a {

    /* JADX INFO: renamed from: w, reason: collision with root package name */
    private static final Map f9783w = g.of("component_tag", "drawee");

    /* JADX INFO: renamed from: x, reason: collision with root package name */
    private static final Map f9784x = g.of("origin", "memory_bitmap", "origin_sub", "shortcut");

    /* JADX INFO: renamed from: y, reason: collision with root package name */
    private static final Class f9785y = AbstractC0642a.class;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final AbstractC0637a f9787b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final Executor f9788c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private o0.d f9789d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private C0702a f9790e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    protected InterfaceC0645d f9791f;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private InterfaceC0707c f9793h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private Drawable f9794i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private String f9795j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private Object f9796k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private boolean f9797l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private boolean f9798m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private boolean f9799n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private boolean f9800o;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private boolean f9801p;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private String f9802q;

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    private InterfaceC0547c f9803r;

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    private Object f9804s;

    /* JADX INFO: renamed from: v, reason: collision with root package name */
    protected Drawable f9807v;

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final o0.c f9786a = o0.c.a();

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    protected C0725d f9792g = new C0725d();

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    private boolean f9805t = true;

    /* JADX INFO: renamed from: u, reason: collision with root package name */
    private boolean f9806u = false;

    /* JADX INFO: renamed from: p0.a$a, reason: collision with other inner class name */
    class C0145a extends AbstractC0546b {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ String f9808a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ boolean f9809b;

        C0145a(String str, boolean z3) {
            this.f9808a = str;
            this.f9809b = z3;
        }

        @Override // h0.AbstractC0546b, h0.InterfaceC0549e
        public void b(InterfaceC0547c interfaceC0547c) {
            boolean zE = interfaceC0547c.e();
            AbstractC0642a.this.P(this.f9808a, interfaceC0547c, interfaceC0547c.g(), zE);
        }

        @Override // h0.AbstractC0546b
        public void e(InterfaceC0547c interfaceC0547c) {
            AbstractC0642a.this.M(this.f9808a, interfaceC0547c, interfaceC0547c.f(), true);
        }

        @Override // h0.AbstractC0546b
        public void f(InterfaceC0547c interfaceC0547c) {
            boolean zE = interfaceC0547c.e();
            boolean zC = interfaceC0547c.c();
            float fG = interfaceC0547c.g();
            Object objA = interfaceC0547c.a();
            if (objA != null) {
                AbstractC0642a.this.O(this.f9808a, interfaceC0547c, objA, fG, zE, this.f9809b, zC);
            } else if (zE) {
                AbstractC0642a.this.M(this.f9808a, interfaceC0547c, new NullPointerException(), true);
            }
        }
    }

    /* JADX INFO: renamed from: p0.a$b */
    private static class b extends f {
        private b() {
        }

        public static b f(InterfaceC0645d interfaceC0645d, InterfaceC0645d interfaceC0645d2) {
            if (U0.b.d()) {
                U0.b.a("AbstractDraweeController#createInternal");
            }
            b bVar = new b();
            bVar.a(interfaceC0645d);
            bVar.a(interfaceC0645d2);
            if (U0.b.d()) {
                U0.b.b();
            }
            return bVar;
        }
    }

    public AbstractC0642a(AbstractC0637a abstractC0637a, Executor executor, String str, Object obj) {
        this.f9787b = abstractC0637a;
        this.f9788c = executor;
        D(str, obj);
    }

    private InterfaceC0707c C() {
        InterfaceC0707c interfaceC0707c = this.f9793h;
        if (interfaceC0707c != null) {
            return interfaceC0707c;
        }
        throw new IllegalStateException("mSettableDraweeHierarchy is null; Caller context: " + this.f9796k);
    }

    private synchronized void D(String str, Object obj) {
        AbstractC0637a abstractC0637a;
        try {
            if (U0.b.d()) {
                U0.b.a("AbstractDraweeController#init");
            }
            this.f9786a.b(c.a.ON_INIT_CONTROLLER);
            if (!this.f9805t && (abstractC0637a = this.f9787b) != null) {
                abstractC0637a.a(this);
            }
            this.f9797l = false;
            this.f9799n = false;
            R();
            this.f9801p = false;
            o0.d dVar = this.f9789d;
            if (dVar != null) {
                dVar.a();
            }
            C0702a c0702a = this.f9790e;
            if (c0702a != null) {
                c0702a.a();
                this.f9790e.f(this);
            }
            InterfaceC0645d interfaceC0645d = this.f9791f;
            if (interfaceC0645d instanceof b) {
                ((b) interfaceC0645d).d();
            } else {
                this.f9791f = null;
            }
            InterfaceC0707c interfaceC0707c = this.f9793h;
            if (interfaceC0707c != null) {
                interfaceC0707c.h();
                this.f9793h.c(null);
                this.f9793h = null;
            }
            this.f9794i = null;
            if (Y.a.w(2)) {
                Y.a.A(f9785y, "controller %x %s -> %s: initialize", Integer.valueOf(System.identityHashCode(this)), this.f9795j, str);
            }
            this.f9795j = str;
            this.f9796k = obj;
            if (U0.b.d()) {
                U0.b.b();
            }
        } catch (Throwable th) {
            throw th;
        }
    }

    private boolean F(String str, InterfaceC0547c interfaceC0547c) {
        if (interfaceC0547c == null && this.f9803r == null) {
            return true;
        }
        return str.equals(this.f9795j) && interfaceC0547c == this.f9803r && this.f9798m;
    }

    private void H(String str, Throwable th) {
        if (Y.a.w(2)) {
            Y.a.B(f9785y, "controller %x %s: %s: failure: %s", Integer.valueOf(System.identityHashCode(this)), this.f9795j, str, th);
        }
    }

    private void I(String str, Object obj) {
        if (Y.a.w(2)) {
            Y.a.C(f9785y, "controller %x %s: %s: image: %s %x", Integer.valueOf(System.identityHashCode(this)), this.f9795j, str, x(obj), Integer.valueOf(y(obj)));
        }
    }

    private InterfaceC0723b.a J(InterfaceC0547c interfaceC0547c, Object obj, Uri uri) {
        return K(interfaceC0547c == null ? null : interfaceC0547c.b(), L(obj), uri);
    }

    private InterfaceC0723b.a K(Map map, Map map2, Uri uri) {
        String str;
        PointF pointFN;
        InterfaceC0707c interfaceC0707c = this.f9793h;
        if (interfaceC0707c instanceof C0690a) {
            C0690a c0690a = (C0690a) interfaceC0707c;
            String strValueOf = String.valueOf(c0690a.o());
            pointFN = c0690a.n();
            str = strValueOf;
        } else {
            str = null;
            pointFN = null;
        }
        return C0717b.a(f9783w, f9784x, map, null, u(), str, pointFN, map2, p(), G(), uri);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void M(String str, InterfaceC0547c interfaceC0547c, Throwable th, boolean z3) {
        Drawable drawable;
        if (U0.b.d()) {
            U0.b.a("AbstractDraweeController#onFailureInternal");
        }
        if (!F(str, interfaceC0547c)) {
            H("ignore_old_datasource @ onFailure", th);
            interfaceC0547c.close();
            if (U0.b.d()) {
                U0.b.b();
                return;
            }
            return;
        }
        this.f9786a.b(z3 ? c.a.ON_DATASOURCE_FAILURE : c.a.ON_DATASOURCE_FAILURE_INT);
        if (z3) {
            H("final_failed @ onFailure", th);
            this.f9803r = null;
            this.f9800o = true;
            InterfaceC0707c interfaceC0707c = this.f9793h;
            if (interfaceC0707c != null) {
                if (this.f9801p && (drawable = this.f9807v) != null) {
                    interfaceC0707c.e(drawable, 1.0f, true);
                } else if (h0()) {
                    interfaceC0707c.f(th);
                } else {
                    interfaceC0707c.g(th);
                }
            }
            U(th, interfaceC0547c);
        } else {
            H("intermediate_failed @ onFailure", th);
            V(th);
        }
        if (U0.b.d()) {
            U0.b.b();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void O(String str, InterfaceC0547c interfaceC0547c, Object obj, float f3, boolean z3, boolean z4, boolean z5) {
        try {
            if (U0.b.d()) {
                U0.b.a("AbstractDraweeController#onNewResultInternal");
            }
            if (!F(str, interfaceC0547c)) {
                I("ignore_old_datasource @ onNewResult", obj);
                S(obj);
                interfaceC0547c.close();
                if (U0.b.d()) {
                    U0.b.b();
                    return;
                }
                return;
            }
            this.f9786a.b(z3 ? c.a.ON_DATASOURCE_RESULT : c.a.ON_DATASOURCE_RESULT_INT);
            try {
                Drawable drawableM = m(obj);
                Object obj2 = this.f9804s;
                Drawable drawable = this.f9807v;
                this.f9804s = obj;
                this.f9807v = drawableM;
                try {
                    if (z3) {
                        I("set_final_result @ onNewResult", obj);
                        this.f9803r = null;
                        C().e(drawableM, 1.0f, z4);
                        Z(str, obj, interfaceC0547c);
                    } else if (z5) {
                        I("set_temporary_result @ onNewResult", obj);
                        C().e(drawableM, 1.0f, z4);
                        Z(str, obj, interfaceC0547c);
                    } else {
                        I("set_intermediate_result @ onNewResult", obj);
                        C().e(drawableM, f3, z4);
                        W(str, obj);
                    }
                    if (drawable != null && drawable != drawableM) {
                        Q(drawable);
                    }
                    if (obj2 != null && obj2 != obj) {
                        I("release_previous_result @ onNewResult", obj2);
                        S(obj2);
                    }
                    if (U0.b.d()) {
                        U0.b.b();
                    }
                } catch (Throwable th) {
                    if (drawable != null && drawable != drawableM) {
                        Q(drawable);
                    }
                    if (obj2 != null && obj2 != obj) {
                        I("release_previous_result @ onNewResult", obj2);
                        S(obj2);
                    }
                    throw th;
                }
            } catch (Exception e3) {
                I("drawable_failed @ onNewResult", obj);
                S(obj);
                M(str, interfaceC0547c, e3, z3);
                if (U0.b.d()) {
                    U0.b.b();
                }
            }
        } catch (Throwable th2) {
            if (U0.b.d()) {
                U0.b.b();
            }
            throw th2;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void P(String str, InterfaceC0547c interfaceC0547c, float f3, boolean z3) {
        if (!F(str, interfaceC0547c)) {
            H("ignore_old_datasource @ onProgress", null);
            interfaceC0547c.close();
        } else {
            if (z3) {
                return;
            }
            this.f9793h.a(f3, false);
        }
    }

    private void R() {
        Map mapB;
        boolean z3 = this.f9798m;
        this.f9798m = false;
        this.f9800o = false;
        InterfaceC0547c interfaceC0547c = this.f9803r;
        Map map = null;
        if (interfaceC0547c != null) {
            mapB = interfaceC0547c.b();
            this.f9803r.close();
            this.f9803r = null;
        } else {
            mapB = null;
        }
        Drawable drawable = this.f9807v;
        if (drawable != null) {
            Q(drawable);
        }
        if (this.f9802q != null) {
            this.f9802q = null;
        }
        this.f9807v = null;
        Object obj = this.f9804s;
        if (obj != null) {
            Map mapL = L(z(obj));
            I("release", this.f9804s);
            S(this.f9804s);
            this.f9804s = null;
            map = mapL;
        }
        if (z3) {
            X(mapB, map);
        }
    }

    private void U(Throwable th, InterfaceC0547c interfaceC0547c) {
        InterfaceC0723b.a aVarJ = J(interfaceC0547c, null, null);
        q().q(this.f9795j, th);
        r().y(this.f9795j, th, aVarJ);
    }

    private void V(Throwable th) {
        q().l(this.f9795j, th);
        r().r(this.f9795j);
    }

    private void W(String str, Object obj) {
        Object objZ = z(obj);
        q().b(str, objZ);
        r().b(str, objZ);
    }

    private void X(Map map, Map map2) {
        q().c(this.f9795j);
        r().x(this.f9795j, K(map, map2, null));
    }

    private void Z(String str, Object obj, InterfaceC0547c interfaceC0547c) {
        Object objZ = z(obj);
        q().k(str, objZ, n());
        r().v(str, objZ, J(interfaceC0547c, objZ, null));
    }

    private boolean h0() {
        o0.d dVar;
        return this.f9800o && (dVar = this.f9789d) != null && dVar.e();
    }

    private Rect u() {
        InterfaceC0707c interfaceC0707c = this.f9793h;
        if (interfaceC0707c == null) {
            return null;
        }
        return interfaceC0707c.b();
    }

    protected abstract Uri A();

    protected o0.d B() {
        if (this.f9789d == null) {
            this.f9789d = new o0.d();
        }
        return this.f9789d;
    }

    protected void E(String str, Object obj) {
        D(str, obj);
        this.f9805t = false;
        this.f9806u = false;
    }

    protected boolean G() {
        return this.f9806u;
    }

    public abstract Map L(Object obj);

    protected abstract void Q(Drawable drawable);

    protected abstract void S(Object obj);

    public void T(InterfaceC0723b interfaceC0723b) {
        this.f9792g.D(interfaceC0723b);
    }

    protected void Y(InterfaceC0547c interfaceC0547c, Object obj) {
        q().j(this.f9795j, this.f9796k);
        r().p(this.f9795j, this.f9796k, J(interfaceC0547c, obj, A()));
    }

    @Override // o0.AbstractC0637a.InterfaceC0141a
    public void a() {
        this.f9786a.b(c.a.ON_RELEASE_CONTROLLER);
        o0.d dVar = this.f9789d;
        if (dVar != null) {
            dVar.c();
        }
        C0702a c0702a = this.f9790e;
        if (c0702a != null) {
            c0702a.e();
        }
        InterfaceC0707c interfaceC0707c = this.f9793h;
        if (interfaceC0707c != null) {
            interfaceC0707c.h();
        }
        R();
    }

    public void a0(String str) {
        this.f9802q = str;
    }

    @Override // v0.InterfaceC0705a
    public void b() {
        if (U0.b.d()) {
            U0.b.a("AbstractDraweeController#onDetach");
        }
        if (Y.a.w(2)) {
            Y.a.z(f9785y, "controller %x %s: onDetach", Integer.valueOf(System.identityHashCode(this)), this.f9795j);
        }
        this.f9786a.b(c.a.ON_DETACH_CONTROLLER);
        this.f9797l = false;
        this.f9787b.d(this);
        if (U0.b.d()) {
            U0.b.b();
        }
    }

    protected void b0(Drawable drawable) {
        this.f9794i = drawable;
        InterfaceC0707c interfaceC0707c = this.f9793h;
        if (interfaceC0707c != null) {
            interfaceC0707c.c(drawable);
        }
    }

    @Override // v0.InterfaceC0705a
    public InterfaceC0706b c() {
        return this.f9793h;
    }

    @Override // v0.InterfaceC0705a
    public boolean d(MotionEvent motionEvent) {
        if (Y.a.w(2)) {
            Y.a.A(f9785y, "controller %x %s: onTouchEvent %s", Integer.valueOf(System.identityHashCode(this)), this.f9795j, motionEvent);
        }
        C0702a c0702a = this.f9790e;
        if (c0702a == null) {
            return false;
        }
        if (!c0702a.b() && !g0()) {
            return false;
        }
        this.f9790e.d(motionEvent);
        return true;
    }

    protected void d0(C0702a c0702a) {
        this.f9790e = c0702a;
        if (c0702a != null) {
            c0702a.f(this);
        }
    }

    @Override // v0.InterfaceC0705a
    public void e(InterfaceC0706b interfaceC0706b) {
        if (Y.a.w(2)) {
            Y.a.A(f9785y, "controller %x %s: setHierarchy: %s", Integer.valueOf(System.identityHashCode(this)), this.f9795j, interfaceC0706b);
        }
        this.f9786a.b(interfaceC0706b != null ? c.a.ON_SET_HIERARCHY : c.a.ON_CLEAR_HIERARCHY);
        if (this.f9798m) {
            this.f9787b.a(this);
            a();
        }
        InterfaceC0707c interfaceC0707c = this.f9793h;
        if (interfaceC0707c != null) {
            interfaceC0707c.c(null);
            this.f9793h = null;
        }
        if (interfaceC0706b != null) {
            k.b(Boolean.valueOf(interfaceC0706b instanceof InterfaceC0707c));
            InterfaceC0707c interfaceC0707c2 = (InterfaceC0707c) interfaceC0706b;
            this.f9793h = interfaceC0707c2;
            interfaceC0707c2.c(this.f9794i);
        }
    }

    protected void e0(boolean z3) {
        this.f9806u = z3;
    }

    @Override // v0.InterfaceC0705a
    public void f() {
        if (U0.b.d()) {
            U0.b.a("AbstractDraweeController#onAttach");
        }
        if (Y.a.w(2)) {
            Y.a.A(f9785y, "controller %x %s: onAttach: %s", Integer.valueOf(System.identityHashCode(this)), this.f9795j, this.f9798m ? "request already submitted" : "request needs submit");
        }
        this.f9786a.b(c.a.ON_ATTACH_CONTROLLER);
        k.g(this.f9793h);
        this.f9787b.a(this);
        this.f9797l = true;
        if (!this.f9798m) {
            i0();
        }
        if (U0.b.d()) {
            U0.b.b();
        }
    }

    protected void f0(boolean z3) {
        this.f9801p = z3;
    }

    @Override // u0.C0702a.InterfaceC0149a
    public boolean g() {
        if (Y.a.w(2)) {
            Y.a.z(f9785y, "controller %x %s: onClick", Integer.valueOf(System.identityHashCode(this)), this.f9795j);
        }
        if (!h0()) {
            return false;
        }
        this.f9789d.b();
        this.f9793h.h();
        i0();
        return true;
    }

    protected boolean g0() {
        return h0();
    }

    protected void i0() {
        if (U0.b.d()) {
            U0.b.a("AbstractDraweeController#submitRequest");
        }
        Object objO = o();
        if (objO != null) {
            if (U0.b.d()) {
                U0.b.a("AbstractDraweeController#submitRequest->cache");
            }
            this.f9803r = null;
            this.f9798m = true;
            this.f9800o = false;
            this.f9786a.b(c.a.ON_SUBMIT_CACHE_HIT);
            Y(this.f9803r, z(objO));
            N(this.f9795j, objO);
            O(this.f9795j, this.f9803r, objO, 1.0f, true, true, true);
            if (U0.b.d()) {
                U0.b.b();
            }
            if (U0.b.d()) {
                U0.b.b();
                return;
            }
            return;
        }
        this.f9786a.b(c.a.ON_DATASOURCE_SUBMIT);
        this.f9793h.a(0.0f, true);
        this.f9798m = true;
        this.f9800o = false;
        InterfaceC0547c interfaceC0547cT = t();
        this.f9803r = interfaceC0547cT;
        Y(interfaceC0547cT, null);
        if (Y.a.w(2)) {
            Y.a.A(f9785y, "controller %x %s: submitRequest: dataSource: %x", Integer.valueOf(System.identityHashCode(this)), this.f9795j, Integer.valueOf(System.identityHashCode(this.f9803r)));
        }
        this.f9803r.h(new C0145a(this.f9795j, this.f9803r.d()), this.f9788c);
        if (U0.b.d()) {
            U0.b.b();
        }
    }

    public void k(InterfaceC0645d interfaceC0645d) {
        k.g(interfaceC0645d);
        InterfaceC0645d interfaceC0645d2 = this.f9791f;
        if (interfaceC0645d2 instanceof b) {
            ((b) interfaceC0645d2).a(interfaceC0645d);
        } else if (interfaceC0645d2 != null) {
            this.f9791f = b.f(interfaceC0645d2, interfaceC0645d);
        } else {
            this.f9791f = interfaceC0645d;
        }
    }

    public void l(InterfaceC0723b interfaceC0723b) {
        this.f9792g.A(interfaceC0723b);
    }

    protected abstract Drawable m(Object obj);

    public Animatable n() {
        Object obj = this.f9807v;
        if (obj instanceof Animatable) {
            return (Animatable) obj;
        }
        return null;
    }

    protected abstract Object o();

    public Object p() {
        return this.f9796k;
    }

    protected InterfaceC0645d q() {
        InterfaceC0645d interfaceC0645d = this.f9791f;
        return interfaceC0645d == null ? C0644c.a() : interfaceC0645d;
    }

    protected InterfaceC0723b r() {
        return this.f9792g;
    }

    protected Drawable s() {
        return this.f9794i;
    }

    protected abstract InterfaceC0547c t();

    public String toString() {
        return i.b(this).c("isAttached", this.f9797l).c("isRequestSubmitted", this.f9798m).c("hasFetchFailed", this.f9800o).a("fetchedImage", y(this.f9804s)).b("events", this.f9786a.toString()).toString();
    }

    protected C0702a v() {
        return this.f9790e;
    }

    public String w() {
        return this.f9795j;
    }

    protected String x(Object obj) {
        return obj != null ? obj.getClass().getSimpleName() : "<null>";
    }

    protected abstract int y(Object obj);

    protected abstract Object z(Object obj);

    public void c0(InterfaceC0646e interfaceC0646e) {
    }

    protected void N(String str, Object obj) {
    }
}
