package m0;

import P0.c;
import android.graphics.Rect;
import androidx.activity.result.d;
import e0.InterfaceC0512b;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import l0.C0617e;
import n0.C0632a;
import n0.C0633b;
import v0.InterfaceC0706b;
import y0.C0731j;
import y0.EnumC0726e;
import y0.EnumC0732k;
import y0.InterfaceC0728g;
import y0.InterfaceC0730i;
import y0.n;

/* JADX INFO: renamed from: m0.a, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0626a implements InterfaceC0730i {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final C0617e f9599a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final InterfaceC0512b f9600b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final C0731j f9601c = new C0731j(EnumC0732k.f10483d);

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private C0632a f9602d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private C0633b f9603e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private c f9604f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private List f9605g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private boolean f9606h;

    public C0626a(InterfaceC0512b interfaceC0512b, C0617e c0617e) {
        this.f9600b = interfaceC0512b;
        this.f9599a = c0617e;
    }

    private void h() {
        if (this.f9603e == null) {
            this.f9603e = new C0633b(this.f9600b, this.f9601c, this);
        }
        if (this.f9602d == null) {
            this.f9602d = new C0632a(this.f9600b, this.f9601c);
        }
        if (this.f9604f == null) {
            this.f9604f = new c(this.f9602d);
        }
    }

    @Override // y0.InterfaceC0730i
    public void a(C0731j c0731j, EnumC0726e enumC0726e) {
        List list;
        c0731j.H(enumC0726e);
        if (!this.f9606h || (list = this.f9605g) == null || list.isEmpty()) {
            return;
        }
        if (enumC0726e == EnumC0726e.f10396h) {
            d();
        }
        c0731j.S();
        Iterator it = this.f9605g.iterator();
        if (it.hasNext()) {
            d.a(it.next());
            throw null;
        }
    }

    @Override // y0.InterfaceC0730i
    public void b(C0731j c0731j, n nVar) {
        List list;
        if (!this.f9606h || (list = this.f9605g) == null || list.isEmpty()) {
            return;
        }
        c0731j.S();
        Iterator it = this.f9605g.iterator();
        if (it.hasNext()) {
            d.a(it.next());
            throw null;
        }
    }

    public void c(InterfaceC0728g interfaceC0728g) {
        if (interfaceC0728g == null) {
            return;
        }
        if (this.f9605g == null) {
            this.f9605g = new CopyOnWriteArrayList();
        }
        this.f9605g.add(interfaceC0728g);
    }

    public void d() {
        InterfaceC0706b interfaceC0706bC = this.f9599a.c();
        if (interfaceC0706bC == null || interfaceC0706bC.d() == null) {
            return;
        }
        Rect bounds = interfaceC0706bC.d().getBounds();
        this.f9601c.N(bounds.width());
        this.f9601c.M(bounds.height());
    }

    public void e() {
        List list = this.f9605g;
        if (list != null) {
            list.clear();
        }
    }

    public void f() {
        e();
        g(false);
        this.f9601c.w();
    }

    public void g(boolean z3) {
        this.f9606h = z3;
        if (!z3) {
            C0633b c0633b = this.f9603e;
            if (c0633b != null) {
                this.f9599a.T(c0633b);
            }
            c cVar = this.f9604f;
            if (cVar != null) {
                this.f9599a.z0(cVar);
                return;
            }
            return;
        }
        h();
        C0633b c0633b2 = this.f9603e;
        if (c0633b2 != null) {
            this.f9599a.l(c0633b2);
        }
        c cVar2 = this.f9604f;
        if (cVar2 != null) {
            this.f9599a.j0(cVar2);
        }
    }
}
