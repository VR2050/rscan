package androidx.fragment.app;

import a.InterfaceC0214b;
import android.content.Context;
import android.content.Intent;
import android.content.res.Configuration;
import android.os.Bundle;
import android.util.AttributeSet;
import android.view.LayoutInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.Window;
import androidx.activity.ComponentActivity;
import androidx.activity.OnBackPressedDispatcher;
import androidx.core.view.InterfaceC0284v;
import androidx.core.view.InterfaceC0287y;
import androidx.lifecycle.f;
import androidx.savedstate.a;
import java.io.FileDescriptor;
import java.io.PrintWriter;
import q.InterfaceC0651a;

/* JADX INFO: renamed from: androidx.fragment.app.j, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public abstract class AbstractActivityC0298j extends ComponentActivity {

    /* JADX INFO: renamed from: x, reason: collision with root package name */
    boolean f4991x;

    /* JADX INFO: renamed from: y, reason: collision with root package name */
    boolean f4992y;

    /* JADX INFO: renamed from: v, reason: collision with root package name */
    final C0302n f4989v = C0302n.b(new a());

    /* JADX INFO: renamed from: w, reason: collision with root package name */
    final androidx.lifecycle.l f4990w = new androidx.lifecycle.l(this);

    /* JADX INFO: renamed from: z, reason: collision with root package name */
    boolean f4993z = true;

    /* JADX INFO: renamed from: androidx.fragment.app.j$a */
    class a extends p implements androidx.core.content.c, androidx.core.content.d, androidx.core.app.j, androidx.core.app.k, androidx.lifecycle.C, androidx.activity.o, androidx.activity.result.f, F.d, B, InterfaceC0284v {
        public a() {
            super(AbstractActivityC0298j.this);
        }

        public void A() {
            AbstractActivityC0298j.this.invalidateOptionsMenu();
        }

        @Override // androidx.fragment.app.p
        /* JADX INFO: renamed from: B, reason: merged with bridge method [inline-methods] */
        public AbstractActivityC0298j x() {
            return AbstractActivityC0298j.this;
        }

        @Override // androidx.activity.o
        public OnBackPressedDispatcher a() {
            return AbstractActivityC0298j.this.a();
        }

        @Override // F.d
        public androidx.savedstate.a b() {
            return AbstractActivityC0298j.this.b();
        }

        @Override // androidx.fragment.app.B
        public void c(x xVar, Fragment fragment) {
            AbstractActivityC0298j.this.a0(fragment);
        }

        @Override // androidx.core.view.InterfaceC0284v
        public void d(InterfaceC0287y interfaceC0287y) {
            AbstractActivityC0298j.this.d(interfaceC0287y);
        }

        @Override // androidx.fragment.app.AbstractC0300l
        public View f(int i3) {
            return AbstractActivityC0298j.this.findViewById(i3);
        }

        @Override // androidx.core.app.j
        public void g(InterfaceC0651a interfaceC0651a) {
            AbstractActivityC0298j.this.g(interfaceC0651a);
        }

        @Override // androidx.fragment.app.AbstractC0300l
        public boolean h() {
            Window window = AbstractActivityC0298j.this.getWindow();
            return (window == null || window.peekDecorView() == null) ? false : true;
        }

        @Override // androidx.core.content.c
        public void j(InterfaceC0651a interfaceC0651a) {
            AbstractActivityC0298j.this.j(interfaceC0651a);
        }

        @Override // androidx.core.app.k
        public void l(InterfaceC0651a interfaceC0651a) {
            AbstractActivityC0298j.this.l(interfaceC0651a);
        }

        @Override // androidx.core.view.InterfaceC0284v
        public void m(InterfaceC0287y interfaceC0287y) {
            AbstractActivityC0298j.this.m(interfaceC0287y);
        }

        @Override // androidx.activity.result.f
        public androidx.activity.result.e n() {
            return AbstractActivityC0298j.this.n();
        }

        @Override // androidx.core.app.j
        public void p(InterfaceC0651a interfaceC0651a) {
            AbstractActivityC0298j.this.p(interfaceC0651a);
        }

        @Override // androidx.core.content.c
        public void q(InterfaceC0651a interfaceC0651a) {
            AbstractActivityC0298j.this.q(interfaceC0651a);
        }

        @Override // androidx.lifecycle.C
        public androidx.lifecycle.B r() {
            return AbstractActivityC0298j.this.r();
        }

        @Override // androidx.lifecycle.k
        public androidx.lifecycle.f s() {
            return AbstractActivityC0298j.this.f4990w;
        }

        @Override // androidx.core.app.k
        public void t(InterfaceC0651a interfaceC0651a) {
            AbstractActivityC0298j.this.t(interfaceC0651a);
        }

        @Override // androidx.core.content.d
        public void u(InterfaceC0651a interfaceC0651a) {
            AbstractActivityC0298j.this.u(interfaceC0651a);
        }

        @Override // androidx.fragment.app.p
        public void v(String str, FileDescriptor fileDescriptor, PrintWriter printWriter, String[] strArr) {
            AbstractActivityC0298j.this.dump(str, fileDescriptor, printWriter, strArr);
        }

        @Override // androidx.core.content.d
        public void w(InterfaceC0651a interfaceC0651a) {
            AbstractActivityC0298j.this.w(interfaceC0651a);
        }

        @Override // androidx.fragment.app.p
        public LayoutInflater y() {
            return AbstractActivityC0298j.this.getLayoutInflater().cloneInContext(AbstractActivityC0298j.this);
        }

        @Override // androidx.fragment.app.p
        public void z() {
            A();
        }
    }

    public AbstractActivityC0298j() {
        T();
    }

    private void T() {
        b().h("android:support:lifecycle", new a.c() { // from class: androidx.fragment.app.f
            @Override // androidx.savedstate.a.c
            public final Bundle a() {
                return this.f4985a.U();
            }
        });
        q(new InterfaceC0651a() { // from class: androidx.fragment.app.g
            @Override // q.InterfaceC0651a
            public final void a(Object obj) {
                this.f4986a.V((Configuration) obj);
            }
        });
        E(new InterfaceC0651a() { // from class: androidx.fragment.app.h
            @Override // q.InterfaceC0651a
            public final void a(Object obj) {
                this.f4987a.W((Intent) obj);
            }
        });
        D(new InterfaceC0214b() { // from class: androidx.fragment.app.i
            @Override // a.InterfaceC0214b
            public final void a(Context context) {
                this.f4988a.X(context);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ Bundle U() {
        Y();
        this.f4990w.h(f.a.ON_STOP);
        return new Bundle();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void V(Configuration configuration) {
        this.f4989v.m();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void W(Intent intent) {
        this.f4989v.m();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void X(Context context) {
        this.f4989v.a(null);
    }

    private static boolean Z(x xVar, f.b bVar) {
        boolean Z2 = false;
        for (Fragment fragment : xVar.s0()) {
            if (fragment != null) {
                if (fragment.y() != null) {
                    Z2 |= Z(fragment.n(), bVar);
                }
                J j3 = fragment.f4775U;
                if (j3 != null && j3.s().b().b(f.b.STARTED)) {
                    fragment.f4775U.h(bVar);
                    Z2 = true;
                }
                if (fragment.f4774T.b().b(f.b.STARTED)) {
                    fragment.f4774T.m(bVar);
                    Z2 = true;
                }
            }
        }
        return Z2;
    }

    final View R(View view, String str, Context context, AttributeSet attributeSet) {
        return this.f4989v.n(view, str, context, attributeSet);
    }

    public x S() {
        return this.f4989v.l();
    }

    void Y() {
        while (Z(S(), f.b.CREATED)) {
        }
    }

    public void a0(Fragment fragment) {
    }

    protected void b0() {
        this.f4990w.h(f.a.ON_RESUME);
        this.f4989v.h();
    }

    @Override // android.app.Activity
    public void dump(String str, FileDescriptor fileDescriptor, PrintWriter printWriter, String[] strArr) {
        super.dump(str, fileDescriptor, printWriter, strArr);
        if (x(strArr)) {
            printWriter.print(str);
            printWriter.print("Local FragmentActivity ");
            printWriter.print(Integer.toHexString(System.identityHashCode(this)));
            printWriter.println(" State:");
            String str2 = str + "  ";
            printWriter.print(str2);
            printWriter.print("mCreated=");
            printWriter.print(this.f4991x);
            printWriter.print(" mResumed=");
            printWriter.print(this.f4992y);
            printWriter.print(" mStopped=");
            printWriter.print(this.f4993z);
            if (getApplication() != null) {
                androidx.loader.app.a.b(this).a(str2, fileDescriptor, printWriter, strArr);
            }
            this.f4989v.l().W(str, fileDescriptor, printWriter, strArr);
        }
    }

    @Override // androidx.activity.ComponentActivity, android.app.Activity
    protected void onActivityResult(int i3, int i4, Intent intent) {
        this.f4989v.m();
        super.onActivityResult(i3, i4, intent);
    }

    @Override // androidx.activity.ComponentActivity, androidx.core.app.f, android.app.Activity
    protected void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        this.f4990w.h(f.a.ON_CREATE);
        this.f4989v.e();
    }

    @Override // android.app.Activity, android.view.LayoutInflater.Factory2
    public View onCreateView(View view, String str, Context context, AttributeSet attributeSet) {
        View viewR = R(view, str, context, attributeSet);
        return viewR == null ? super.onCreateView(view, str, context, attributeSet) : viewR;
    }

    @Override // android.app.Activity
    protected void onDestroy() {
        super.onDestroy();
        this.f4989v.f();
        this.f4990w.h(f.a.ON_DESTROY);
    }

    @Override // androidx.activity.ComponentActivity, android.app.Activity, android.view.Window.Callback
    public boolean onMenuItemSelected(int i3, MenuItem menuItem) {
        if (super.onMenuItemSelected(i3, menuItem)) {
            return true;
        }
        if (i3 == 6) {
            return this.f4989v.d(menuItem);
        }
        return false;
    }

    @Override // android.app.Activity
    protected void onPause() {
        super.onPause();
        this.f4992y = false;
        this.f4989v.g();
        this.f4990w.h(f.a.ON_PAUSE);
    }

    @Override // android.app.Activity
    protected void onPostResume() {
        super.onPostResume();
        b0();
    }

    @Override // androidx.activity.ComponentActivity, android.app.Activity
    public void onRequestPermissionsResult(int i3, String[] strArr, int[] iArr) {
        this.f4989v.m();
        super.onRequestPermissionsResult(i3, strArr, iArr);
    }

    @Override // android.app.Activity
    protected void onResume() {
        this.f4989v.m();
        super.onResume();
        this.f4992y = true;
        this.f4989v.k();
    }

    @Override // android.app.Activity
    protected void onStart() {
        this.f4989v.m();
        super.onStart();
        this.f4993z = false;
        if (!this.f4991x) {
            this.f4991x = true;
            this.f4989v.c();
        }
        this.f4989v.k();
        this.f4990w.h(f.a.ON_START);
        this.f4989v.i();
    }

    @Override // android.app.Activity
    public void onStateNotSaved() {
        this.f4989v.m();
    }

    @Override // android.app.Activity
    protected void onStop() {
        super.onStop();
        this.f4993z = true;
        Y();
        this.f4989v.j();
        this.f4990w.h(f.a.ON_STOP);
    }

    @Override // android.app.Activity, android.view.LayoutInflater.Factory
    public View onCreateView(String str, Context context, AttributeSet attributeSet) {
        View viewR = R(null, str, context, attributeSet);
        return viewR == null ? super.onCreateView(str, context, attributeSet) : viewR;
    }
}
