package androidx.fragment.app;

import android.app.Application;
import android.content.Context;
import android.content.ContextWrapper;
import android.os.Bundle;
import androidx.lifecycle.InterfaceC0307e;
import androidx.lifecycle.f;
import androidx.lifecycle.z;

/* JADX INFO: loaded from: classes.dex */
class J implements InterfaceC0307e, F.d, androidx.lifecycle.C {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final Fragment f4862b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final androidx.lifecycle.B f4863c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private androidx.lifecycle.l f4864d = null;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private F.c f4865e = null;

    J(Fragment fragment, androidx.lifecycle.B b3) {
        this.f4862b = fragment;
        this.f4863c = b3;
    }

    @Override // F.d
    public androidx.savedstate.a b() {
        d();
        return this.f4865e.b();
    }

    void c(f.a aVar) {
        this.f4864d.h(aVar);
    }

    void d() {
        if (this.f4864d == null) {
            this.f4864d = new androidx.lifecycle.l(this);
            F.c cVarA = F.c.a(this);
            this.f4865e = cVarA;
            cVarA.c();
            androidx.lifecycle.v.a(this);
        }
    }

    boolean e() {
        return this.f4864d != null;
    }

    void f(Bundle bundle) {
        this.f4865e.d(bundle);
    }

    void g(Bundle bundle) {
        this.f4865e.e(bundle);
    }

    void h(f.b bVar) {
        this.f4864d.m(bVar);
    }

    @Override // androidx.lifecycle.InterfaceC0307e
    public E.a k() {
        Application application;
        Context applicationContext = this.f4862b.l1().getApplicationContext();
        while (true) {
            if (!(applicationContext instanceof ContextWrapper)) {
                application = null;
                break;
            }
            if (applicationContext instanceof Application) {
                application = (Application) applicationContext;
                break;
            }
            applicationContext = ((ContextWrapper) applicationContext).getBaseContext();
        }
        E.d dVar = new E.d();
        if (application != null) {
            dVar.b(z.a.f5190e, application);
        }
        dVar.b(androidx.lifecycle.v.f5173a, this);
        dVar.b(androidx.lifecycle.v.f5174b, this);
        if (this.f4862b.m() != null) {
            dVar.b(androidx.lifecycle.v.f5175c, this.f4862b.m());
        }
        return dVar;
    }

    @Override // androidx.lifecycle.C
    public androidx.lifecycle.B r() {
        d();
        return this.f4863c;
    }

    @Override // androidx.lifecycle.k
    public androidx.lifecycle.f s() {
        d();
        return this.f4864d;
    }
}
