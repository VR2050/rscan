package androidx.fragment.app;

import android.content.Context;
import android.util.AttributeSet;
import android.view.MenuItem;
import android.view.View;

/* JADX INFO: renamed from: androidx.fragment.app.n, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0302n {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final p f5007a;

    private C0302n(p pVar) {
        this.f5007a = pVar;
    }

    public static C0302n b(p pVar) {
        return new C0302n((p) q.g.g(pVar, "callbacks == null"));
    }

    public void a(Fragment fragment) {
        p pVar = this.f5007a;
        pVar.f5013f.m(pVar, pVar, fragment);
    }

    public void c() {
        this.f5007a.f5013f.x();
    }

    public boolean d(MenuItem menuItem) {
        return this.f5007a.f5013f.A(menuItem);
    }

    public void e() {
        this.f5007a.f5013f.B();
    }

    public void f() {
        this.f5007a.f5013f.D();
    }

    public void g() {
        this.f5007a.f5013f.M();
    }

    public void h() {
        this.f5007a.f5013f.Q();
    }

    public void i() {
        this.f5007a.f5013f.R();
    }

    public void j() {
        this.f5007a.f5013f.T();
    }

    public boolean k() {
        return this.f5007a.f5013f.a0(true);
    }

    public x l() {
        return this.f5007a.f5013f;
    }

    public void m() {
        this.f5007a.f5013f.U0();
    }

    public View n(View view, String str, Context context, AttributeSet attributeSet) {
        return this.f5007a.f5013f.u0().onCreateView(view, str, context, attributeSet);
    }
}
