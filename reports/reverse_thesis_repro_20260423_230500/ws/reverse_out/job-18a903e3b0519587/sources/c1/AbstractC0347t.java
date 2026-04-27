package c1;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.res.Configuration;
import android.os.Build;
import android.os.Bundle;
import android.view.KeyEvent;
import c2.C0353a;
import com.facebook.react.bridge.Callback;
import q1.C0655b;

/* JADX INFO: renamed from: c1.t, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public abstract class AbstractC0347t {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Activity f5661a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final String f5662b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private A1.g f5663c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private Callback f5664d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private C0350w f5665e;

    /* JADX INFO: renamed from: c1.t$a */
    class a extends C0350w {
        a(Activity activity, K k3, String str, Bundle bundle, boolean z3) {
            super(activity, k3, str, bundle, z3);
        }

        @Override // c1.C0350w
        protected W a() {
            W wD = AbstractC0347t.this.d();
            return wD == null ? super.a() : wD;
        }
    }

    public AbstractC0347t(AbstractActivityC0344p abstractActivityC0344p, String str) {
        this.f5661a = abstractActivityC0344p;
        this.f5662b = str;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void m() {
        String strG = g();
        Bundle bundleC = c();
        if (Build.VERSION.SDK_INT >= 26 && l()) {
            this.f5661a.getWindow().setColorMode(1);
        }
        if (C0655b.c()) {
            this.f5665e = new C0350w(h(), i(), strG, bundleC);
        } else {
            this.f5665e = new a(h(), j(), strG, bundleC, k());
        }
        if (strG != null) {
            o(strG);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void n(int i3, String[] strArr, int[] iArr, Object[] objArr) {
        A1.g gVar = this.f5663c;
        if (gVar == null || !gVar.onRequestPermissionsResult(i3, strArr, iArr)) {
            return;
        }
        this.f5663c = null;
    }

    public void A() {
        this.f5665e.m();
        Callback callback = this.f5664d;
        if (callback != null) {
            callback.invoke(new Object[0]);
            this.f5664d = null;
        }
    }

    public void B() {
        C0350w c0350w = this.f5665e;
        if (c0350w != null) {
            c0350w.q();
        }
    }

    public void C(boolean z3) {
        this.f5665e.r(z3);
    }

    public void D(String[] strArr, int i3, A1.g gVar) {
        this.f5663c = gVar;
        h().requestPermissions(strArr, i3);
    }

    protected Bundle c() {
        return f();
    }

    protected W d() {
        return null;
    }

    protected Context e() {
        return (Context) Z0.a.c(this.f5661a);
    }

    protected Bundle f() {
        return null;
    }

    public String g() {
        return this.f5662b;
    }

    protected Activity h() {
        return (Activity) e();
    }

    public InterfaceC0351x i() {
        return ((InterfaceC0349v) h().getApplication()).b();
    }

    protected K j() {
        return ((InterfaceC0349v) h().getApplication()).a();
    }

    protected abstract boolean k();

    protected boolean l() {
        return false;
    }

    protected void o(String str) {
        this.f5665e.g(str);
        h().setContentView(this.f5665e.e());
    }

    public void p(int i3, int i4, Intent intent) {
        this.f5665e.h(i3, i4, intent, true);
    }

    public boolean q() {
        return this.f5665e.i();
    }

    public void r(Configuration configuration) {
        this.f5665e.j(configuration);
    }

    public void s(Bundle bundle) {
        C0353a.o(0L, "ReactActivityDelegate.onCreate::init", new Runnable() { // from class: c1.r
            @Override // java.lang.Runnable
            public final void run() {
                this.f5656b.m();
            }
        });
    }

    public void t() {
        this.f5665e.k();
    }

    public boolean u(int i3, KeyEvent keyEvent) {
        return this.f5665e.n(i3, keyEvent);
    }

    public boolean v(int i3, KeyEvent keyEvent) {
        return this.f5665e.o(i3);
    }

    public boolean w(int i3, KeyEvent keyEvent) {
        return this.f5665e.s(i3, keyEvent);
    }

    public boolean x(Intent intent) {
        return this.f5665e.p(intent);
    }

    public void y() {
        this.f5665e.l();
    }

    public void z(final int i3, final String[] strArr, final int[] iArr) {
        this.f5664d = new Callback() { // from class: c1.s
            @Override // com.facebook.react.bridge.Callback
            public final void invoke(Object[] objArr) {
                this.f5657b.n(i3, strArr, iArr, objArr);
            }
        };
    }
}
