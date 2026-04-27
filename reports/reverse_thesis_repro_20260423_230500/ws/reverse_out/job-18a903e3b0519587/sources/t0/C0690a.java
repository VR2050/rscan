package t0;

import X.k;
import android.content.res.Resources;
import android.graphics.ColorFilter;
import android.graphics.PointF;
import android.graphics.Rect;
import android.graphics.drawable.Animatable;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import java.util.Iterator;
import s0.C0686f;
import s0.InterfaceC0683c;
import s0.g;
import s0.o;
import s0.q;
import v0.InterfaceC0707c;

/* JADX INFO: renamed from: t0.a, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0690a implements InterfaceC0707c {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Drawable f10136a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final Resources f10137b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private C0693d f10138c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final C0692c f10139d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final C0686f f10140e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final g f10141f;

    C0690a(C0691b c0691b) {
        ColorDrawable colorDrawable = new ColorDrawable(0);
        this.f10136a = colorDrawable;
        if (U0.b.d()) {
            U0.b.a("GenericDraweeHierarchy()");
        }
        this.f10137b = c0691b.o();
        this.f10138c = c0691b.r();
        g gVar = new g(colorDrawable);
        this.f10141f = gVar;
        int i3 = 1;
        int size = c0691b.i() != null ? c0691b.i().size() : 1;
        int i4 = (size == 0 ? 1 : size) + (c0691b.l() != null ? 1 : 0);
        Drawable[] drawableArr = new Drawable[i4 + 6];
        drawableArr[0] = j(c0691b.e(), null);
        drawableArr[1] = j(c0691b.j(), c0691b.k());
        drawableArr[2] = i(gVar, c0691b.d(), c0691b.c(), c0691b.b());
        drawableArr[3] = j(c0691b.m(), c0691b.n());
        drawableArr[4] = j(c0691b.p(), c0691b.q());
        drawableArr[5] = j(c0691b.g(), c0691b.h());
        if (i4 > 0) {
            if (c0691b.i() != null) {
                Iterator it = c0691b.i().iterator();
                i3 = 0;
                while (it.hasNext()) {
                    drawableArr[i3 + 6] = j((Drawable) it.next(), null);
                    i3++;
                }
            }
            if (c0691b.l() != null) {
                drawableArr[i3 + 6] = j(c0691b.l(), null);
            }
        }
        C0686f c0686f = new C0686f(drawableArr, false, 2);
        this.f10140e = c0686f;
        c0686f.u(c0691b.f());
        C0692c c0692c = new C0692c(e.e(c0686f, this.f10138c));
        this.f10139d = c0692c;
        c0692c.mutate();
        u();
        if (U0.b.d()) {
            U0.b.b();
        }
    }

    private Drawable i(Drawable drawable, q qVar, PointF pointF, ColorFilter colorFilter) {
        drawable.setColorFilter(colorFilter);
        return e.g(drawable, qVar, pointF);
    }

    private Drawable j(Drawable drawable, q qVar) {
        return e.f(e.d(drawable, this.f10138c, this.f10137b), qVar);
    }

    private void k(int i3) {
        if (i3 >= 0) {
            this.f10140e.l(i3);
        }
    }

    private void l() {
        m(1);
        m(2);
        m(3);
        m(4);
        m(5);
    }

    private void m(int i3) {
        if (i3 >= 0) {
            this.f10140e.m(i3);
        }
    }

    private InterfaceC0683c p(int i3) {
        InterfaceC0683c interfaceC0683cC = this.f10140e.c(i3);
        interfaceC0683cC.p();
        return interfaceC0683cC.p() instanceof o ? (o) interfaceC0683cC.p() : interfaceC0683cC;
    }

    private o r(int i3) {
        InterfaceC0683c interfaceC0683cP = p(i3);
        return interfaceC0683cP instanceof o ? (o) interfaceC0683cP : e.k(interfaceC0683cP, q.f10114a);
    }

    private boolean s(int i3) {
        return p(i3) instanceof o;
    }

    private void t() {
        this.f10141f.d(this.f10136a);
    }

    private void u() {
        C0686f c0686f = this.f10140e;
        if (c0686f != null) {
            c0686f.g();
            this.f10140e.k();
            l();
            k(1);
            this.f10140e.o();
            this.f10140e.j();
        }
    }

    private void w(int i3, Drawable drawable) {
        if (drawable == null) {
            this.f10140e.e(i3, null);
        } else {
            p(i3).d(e.d(drawable, this.f10138c, this.f10137b));
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    private void z(float f3) {
        Drawable drawableB = this.f10140e.b(3);
        if (drawableB == 0) {
            return;
        }
        if (f3 >= 0.999f) {
            if (drawableB instanceof Animatable) {
                ((Animatable) drawableB).stop();
            }
            m(3);
        } else {
            if (drawableB instanceof Animatable) {
                ((Animatable) drawableB).start();
            }
            k(3);
        }
        drawableB.setLevel(Math.round(f3 * 10000.0f));
    }

    public void A(Drawable drawable) {
        w(3, drawable);
    }

    public void B(C0693d c0693d) {
        this.f10138c = c0693d;
        e.j(this.f10139d, c0693d);
        for (int i3 = 0; i3 < this.f10140e.d(); i3++) {
            e.i(p(i3), this.f10138c, this.f10137b);
        }
    }

    @Override // v0.InterfaceC0707c
    public void a(float f3, boolean z3) {
        if (this.f10140e.b(3) == null) {
            return;
        }
        this.f10140e.g();
        z(f3);
        if (z3) {
            this.f10140e.o();
        }
        this.f10140e.j();
    }

    @Override // v0.InterfaceC0706b
    public Rect b() {
        return this.f10139d.getBounds();
    }

    @Override // v0.InterfaceC0707c
    public void c(Drawable drawable) {
        this.f10139d.x(drawable);
    }

    @Override // v0.InterfaceC0706b
    public Drawable d() {
        return this.f10139d;
    }

    @Override // v0.InterfaceC0707c
    public void e(Drawable drawable, float f3, boolean z3) {
        Drawable drawableD = e.d(drawable, this.f10138c, this.f10137b);
        drawableD.mutate();
        this.f10141f.d(drawableD);
        this.f10140e.g();
        l();
        k(2);
        z(f3);
        if (z3) {
            this.f10140e.o();
        }
        this.f10140e.j();
    }

    @Override // v0.InterfaceC0707c
    public void f(Throwable th) {
        this.f10140e.g();
        l();
        if (this.f10140e.b(4) != null) {
            k(4);
        } else {
            k(1);
        }
        this.f10140e.j();
    }

    @Override // v0.InterfaceC0707c
    public void g(Throwable th) {
        this.f10140e.g();
        l();
        if (this.f10140e.b(5) != null) {
            k(5);
        } else {
            k(1);
        }
        this.f10140e.j();
    }

    @Override // v0.InterfaceC0707c
    public void h() {
        t();
        u();
    }

    public PointF n() {
        if (s(2)) {
            return r(2).z();
        }
        return null;
    }

    public q o() {
        if (s(2)) {
            return r(2).A();
        }
        return null;
    }

    public C0693d q() {
        return this.f10138c;
    }

    public void v(q qVar) {
        k.g(qVar);
        r(2).C(qVar);
    }

    public void x(int i3) {
        this.f10140e.u(i3);
    }

    public void y(Drawable drawable, q qVar) {
        w(1, drawable);
        r(1).C(qVar);
    }
}
