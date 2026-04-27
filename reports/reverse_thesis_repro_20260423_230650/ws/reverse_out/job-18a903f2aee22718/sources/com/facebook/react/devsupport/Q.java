package com.facebook.react.devsupport;

import android.app.Activity;
import android.view.View;
import android.view.ViewGroup;

/* JADX INFO: loaded from: classes.dex */
public final class Q implements d1.j {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final j1.e f6780a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private View f6781b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private P f6782c;

    public Q(j1.e eVar) {
        t2.j.f(eVar, "devSupportManager");
        this.f6780a = eVar;
    }

    @Override // d1.j
    public boolean a() {
        P p3 = this.f6782c;
        if (p3 != null) {
            return p3.isShowing();
        }
        return false;
    }

    @Override // d1.j
    public void b() {
        if (a() || !e()) {
            return;
        }
        Activity activityI = this.f6780a.i();
        if (activityI == null || activityI.isFinishing()) {
            S1.c.a("Unable to launch logbox because react activity is not available, here is the error that logbox would've displayed: ");
            return;
        }
        P p3 = new P(activityI, this.f6781b);
        this.f6782c = p3;
        p3.setCancelable(false);
        p3.show();
    }

    @Override // d1.j
    public void c() {
        P p3;
        if (a() && (p3 = this.f6782c) != null) {
            p3.dismiss();
        }
        View view = this.f6781b;
        ViewGroup viewGroup = (ViewGroup) (view != null ? view.getParent() : null);
        if (viewGroup != null) {
            viewGroup.removeView(this.f6781b);
        }
        this.f6782c = null;
    }

    @Override // d1.j
    public void d() {
        View view = this.f6781b;
        if (view != null) {
            this.f6780a.b(view);
            this.f6781b = null;
        }
    }

    @Override // d1.j
    public boolean e() {
        return this.f6781b != null;
    }

    @Override // d1.j
    public void f(String str) {
        t2.j.f(str, "appKey");
        Z0.a.b(t2.j.b(str, "LogBox"), "This surface manager can only create LogBox React application");
        View viewA = this.f6780a.a("LogBox");
        this.f6781b = viewA;
        if (viewA == null) {
            S1.c.a("Unable to launch logbox because react was unable to create the root view");
        }
    }
}
