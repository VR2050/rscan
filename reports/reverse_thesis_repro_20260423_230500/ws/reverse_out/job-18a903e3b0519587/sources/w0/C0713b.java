package w0;

import X.i;
import X.k;
import android.content.Context;
import android.graphics.drawable.Drawable;
import android.view.MotionEvent;
import o0.c;
import s0.E;
import s0.F;
import v0.InterfaceC0705a;
import v0.InterfaceC0706b;

/* JADX INFO: renamed from: w0.b, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0713b implements F {

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private InterfaceC0706b f10286e;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private boolean f10283b = false;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private boolean f10284c = false;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private boolean f10285d = true;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private InterfaceC0705a f10287f = null;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private final o0.c f10288g = o0.c.a();

    public C0713b(InterfaceC0706b interfaceC0706b) {
        if (interfaceC0706b != null) {
            p(interfaceC0706b);
        }
    }

    private void a() {
        if (this.f10283b) {
            return;
        }
        this.f10288g.b(c.a.ON_ATTACH_CONTROLLER);
        this.f10283b = true;
        InterfaceC0705a interfaceC0705a = this.f10287f;
        if (interfaceC0705a == null || interfaceC0705a.c() == null) {
            return;
        }
        this.f10287f.f();
    }

    private void b() {
        if (this.f10284c && this.f10285d) {
            a();
        } else {
            d();
        }
    }

    public static C0713b c(InterfaceC0706b interfaceC0706b, Context context) {
        C0713b c0713b = new C0713b(interfaceC0706b);
        c0713b.m(context);
        return c0713b;
    }

    private void d() {
        if (this.f10283b) {
            this.f10288g.b(c.a.ON_DETACH_CONTROLLER);
            this.f10283b = false;
            if (h()) {
                this.f10287f.b();
            }
        }
    }

    private void q(F f3) {
        Object objG = g();
        if (objG instanceof E) {
            ((E) objG).s(f3);
        }
    }

    public InterfaceC0705a e() {
        return this.f10287f;
    }

    public InterfaceC0706b f() {
        return (InterfaceC0706b) k.g(this.f10286e);
    }

    public Drawable g() {
        InterfaceC0706b interfaceC0706b = this.f10286e;
        if (interfaceC0706b == null) {
            return null;
        }
        return interfaceC0706b.d();
    }

    public boolean h() {
        InterfaceC0705a interfaceC0705a = this.f10287f;
        return interfaceC0705a != null && interfaceC0705a.c() == this.f10286e;
    }

    @Override // s0.F
    public void i(boolean z3) {
        if (this.f10285d == z3) {
            return;
        }
        this.f10288g.b(z3 ? c.a.ON_DRAWABLE_SHOW : c.a.ON_DRAWABLE_HIDE);
        this.f10285d = z3;
        b();
    }

    public void j() {
        this.f10288g.b(c.a.ON_HOLDER_ATTACH);
        this.f10284c = true;
        b();
    }

    public void k() {
        this.f10288g.b(c.a.ON_HOLDER_DETACH);
        this.f10284c = false;
        b();
    }

    public boolean l(MotionEvent motionEvent) {
        if (h()) {
            return this.f10287f.d(motionEvent);
        }
        return false;
    }

    public void n() {
        o(null);
    }

    public void o(InterfaceC0705a interfaceC0705a) {
        boolean z3 = this.f10283b;
        if (z3) {
            d();
        }
        if (h()) {
            this.f10288g.b(c.a.ON_CLEAR_OLD_CONTROLLER);
            this.f10287f.e(null);
        }
        this.f10287f = interfaceC0705a;
        if (interfaceC0705a != null) {
            this.f10288g.b(c.a.ON_SET_CONTROLLER);
            this.f10287f.e(this.f10286e);
        } else {
            this.f10288g.b(c.a.ON_CLEAR_CONTROLLER);
        }
        if (z3) {
            a();
        }
    }

    @Override // s0.F
    public void onDraw() {
        if (this.f10283b) {
            return;
        }
        Y.a.G(o0.c.class, "%x: Draw requested for a non-attached controller %x. %s", Integer.valueOf(System.identityHashCode(this)), Integer.valueOf(System.identityHashCode(this.f10287f)), toString());
        this.f10284c = true;
        this.f10285d = true;
        b();
    }

    public void p(InterfaceC0706b interfaceC0706b) {
        this.f10288g.b(c.a.ON_SET_HIERARCHY);
        boolean zH = h();
        q(null);
        InterfaceC0706b interfaceC0706b2 = (InterfaceC0706b) k.g(interfaceC0706b);
        this.f10286e = interfaceC0706b2;
        Drawable drawableD = interfaceC0706b2.d();
        i(drawableD == null || drawableD.isVisible());
        q(this);
        if (zH) {
            this.f10287f.e(interfaceC0706b);
        }
    }

    public String toString() {
        return i.b(this).c("controllerAttached", this.f10283b).c("holderAttached", this.f10284c).c("drawableVisible", this.f10285d).b("events", this.f10288g.toString()).toString();
    }

    public void m(Context context) {
    }
}
