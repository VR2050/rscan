package androidx.activity;

import a.C0213a;
import a.InterfaceC0214b;
import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.IntentSender;
import android.content.res.Configuration;
import android.os.Bundle;
import android.os.Looper;
import android.os.SystemClock;
import android.text.TextUtils;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewTreeObserver;
import android.view.Window;
import android.window.OnBackInvokedDispatcher;
import androidx.core.view.C0285w;
import androidx.core.view.InterfaceC0284v;
import androidx.core.view.InterfaceC0287y;
import androidx.lifecycle.B;
import androidx.lifecycle.C;
import androidx.lifecycle.D;
import androidx.lifecycle.E;
import androidx.lifecycle.InterfaceC0307e;
import androidx.lifecycle.f;
import androidx.lifecycle.t;
import androidx.lifecycle.v;
import androidx.lifecycle.z;
import androidx.savedstate.a;
import java.util.Iterator;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicInteger;
import q.InterfaceC0651a;
import s2.InterfaceC0688a;

/* JADX INFO: loaded from: classes.dex */
public abstract class ComponentActivity extends androidx.core.app.f implements androidx.lifecycle.k, C, InterfaceC0307e, F.d, o, androidx.activity.result.f, androidx.core.content.c, androidx.core.content.d, androidx.core.app.j, androidx.core.app.k, InterfaceC0284v, l {

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    final C0213a f2930d = new C0213a();

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final C0285w f2931e = new C0285w(new Runnable() { // from class: androidx.activity.b
        @Override // java.lang.Runnable
        public final void run() {
            this.f2979b.I();
        }
    });

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final androidx.lifecycle.l f2932f = new androidx.lifecycle.l(this);

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    final F.c f2933g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private B f2934h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private final OnBackPressedDispatcher f2935i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private final f f2936j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    final k f2937k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private int f2938l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private final AtomicInteger f2939m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private final androidx.activity.result.e f2940n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private final CopyOnWriteArrayList f2941o;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private final CopyOnWriteArrayList f2942p;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private final CopyOnWriteArrayList f2943q;

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    private final CopyOnWriteArrayList f2944r;

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    private final CopyOnWriteArrayList f2945s;

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    private boolean f2946t;

    /* JADX INFO: renamed from: u, reason: collision with root package name */
    private boolean f2947u;

    class a implements Runnable {
        a() {
        }

        @Override // java.lang.Runnable
        public void run() {
            try {
                ComponentActivity.super.onBackPressed();
            } catch (IllegalStateException e3) {
                if (!TextUtils.equals(e3.getMessage(), "Can not perform this action after onSaveInstanceState")) {
                    throw e3;
                }
            }
        }
    }

    class b extends androidx.activity.result.e {
        b() {
        }
    }

    static class c {
        static void a(View view) {
            view.cancelPendingInputEvents();
        }
    }

    static class d {
        static OnBackInvokedDispatcher a(Activity activity) {
            return activity.getOnBackInvokedDispatcher();
        }
    }

    static final class e {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        Object f2953a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        B f2954b;

        e() {
        }
    }

    private interface f extends Executor {
        void a(View view);
    }

    class g implements f, ViewTreeObserver.OnDrawListener, Runnable {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        Runnable f2956c;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final long f2955b = SystemClock.uptimeMillis() + 10000;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        boolean f2957d = false;

        g() {
        }

        /* JADX INFO: Access modifiers changed from: private */
        public /* synthetic */ void c() {
            Runnable runnable = this.f2956c;
            if (runnable != null) {
                runnable.run();
                this.f2956c = null;
            }
        }

        @Override // androidx.activity.ComponentActivity.f
        public void a(View view) {
            if (this.f2957d) {
                return;
            }
            this.f2957d = true;
            view.getViewTreeObserver().addOnDrawListener(this);
        }

        @Override // java.util.concurrent.Executor
        public void execute(Runnable runnable) {
            this.f2956c = runnable;
            View decorView = ComponentActivity.this.getWindow().getDecorView();
            if (!this.f2957d) {
                decorView.postOnAnimation(new Runnable() { // from class: androidx.activity.f
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f2983b.c();
                    }
                });
            } else if (Looper.myLooper() == Looper.getMainLooper()) {
                decorView.invalidate();
            } else {
                decorView.postInvalidate();
            }
        }

        @Override // android.view.ViewTreeObserver.OnDrawListener
        public void onDraw() {
            Runnable runnable = this.f2956c;
            if (runnable == null) {
                if (SystemClock.uptimeMillis() > this.f2955b) {
                    this.f2957d = false;
                    ComponentActivity.this.getWindow().getDecorView().post(this);
                    return;
                }
                return;
            }
            runnable.run();
            this.f2956c = null;
            if (ComponentActivity.this.f2937k.c()) {
                this.f2957d = false;
                ComponentActivity.this.getWindow().getDecorView().post(this);
            }
        }

        @Override // java.lang.Runnable
        public void run() {
            ComponentActivity.this.getWindow().getDecorView().getViewTreeObserver().removeOnDrawListener(this);
        }
    }

    public ComponentActivity() {
        F.c cVarA = F.c.a(this);
        this.f2933g = cVarA;
        this.f2935i = new OnBackPressedDispatcher(new a());
        f fVarF = F();
        this.f2936j = fVarF;
        this.f2937k = new k(fVarF, new InterfaceC0688a() { // from class: androidx.activity.c
            @Override // s2.InterfaceC0688a
            public final Object a() {
                return this.f2980b.J();
            }
        });
        this.f2939m = new AtomicInteger();
        this.f2940n = new b();
        this.f2941o = new CopyOnWriteArrayList();
        this.f2942p = new CopyOnWriteArrayList();
        this.f2943q = new CopyOnWriteArrayList();
        this.f2944r = new CopyOnWriteArrayList();
        this.f2945s = new CopyOnWriteArrayList();
        this.f2946t = false;
        this.f2947u = false;
        if (s() == null) {
            throw new IllegalStateException("getLifecycle() returned null in ComponentActivity's constructor. Please make sure you are lazily constructing your Lifecycle in the first call to getLifecycle() rather than relying on field initialization.");
        }
        s().a(new androidx.lifecycle.i() { // from class: androidx.activity.ComponentActivity.3
            @Override // androidx.lifecycle.i
            public void d(androidx.lifecycle.k kVar, f.a aVar) {
                if (aVar == f.a.ON_STOP) {
                    Window window = ComponentActivity.this.getWindow();
                    View viewPeekDecorView = window != null ? window.peekDecorView() : null;
                    if (viewPeekDecorView != null) {
                        c.a(viewPeekDecorView);
                    }
                }
            }
        });
        s().a(new androidx.lifecycle.i() { // from class: androidx.activity.ComponentActivity.4
            @Override // androidx.lifecycle.i
            public void d(androidx.lifecycle.k kVar, f.a aVar) {
                if (aVar == f.a.ON_DESTROY) {
                    ComponentActivity.this.f2930d.b();
                    if (ComponentActivity.this.isChangingConfigurations()) {
                        return;
                    }
                    ComponentActivity.this.r().a();
                }
            }
        });
        s().a(new androidx.lifecycle.i() { // from class: androidx.activity.ComponentActivity.5
            @Override // androidx.lifecycle.i
            public void d(androidx.lifecycle.k kVar, f.a aVar) {
                ComponentActivity.this.G();
                ComponentActivity.this.s().c(this);
            }
        });
        cVarA.c();
        v.a(this);
        b().h("android:support:activity-result", new a.c() { // from class: androidx.activity.d
            @Override // androidx.savedstate.a.c
            public final Bundle a() {
                return this.f2981a.K();
            }
        });
        D(new InterfaceC0214b() { // from class: androidx.activity.e
            @Override // a.InterfaceC0214b
            public final void a(Context context) {
                this.f2982a.L(context);
            }
        });
    }

    private f F() {
        return new g();
    }

    private void H() {
        D.a(getWindow().getDecorView(), this);
        E.a(getWindow().getDecorView(), this);
        F.e.a(getWindow().getDecorView(), this);
        r.a(getWindow().getDecorView(), this);
        q.a(getWindow().getDecorView(), this);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ h2.r J() {
        reportFullyDrawn();
        return null;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ Bundle K() {
        Bundle bundle = new Bundle();
        this.f2940n.f(bundle);
        return bundle;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void L(Context context) {
        Bundle bundleB = b().b("android:support:activity-result");
        if (bundleB != null) {
            this.f2940n.e(bundleB);
        }
    }

    public final void D(InterfaceC0214b interfaceC0214b) {
        this.f2930d.a(interfaceC0214b);
    }

    public final void E(InterfaceC0651a interfaceC0651a) {
        this.f2943q.add(interfaceC0651a);
    }

    void G() {
        if (this.f2934h == null) {
            e eVar = (e) getLastNonConfigurationInstance();
            if (eVar != null) {
                this.f2934h = eVar.f2954b;
            }
            if (this.f2934h == null) {
                this.f2934h = new B();
            }
        }
    }

    public void I() {
        invalidateOptionsMenu();
    }

    public Object M() {
        return null;
    }

    @Override // androidx.activity.o
    public final OnBackPressedDispatcher a() {
        return this.f2935i;
    }

    @Override // F.d
    public final androidx.savedstate.a b() {
        return this.f2933g.b();
    }

    @Override // androidx.core.view.InterfaceC0284v
    public void d(InterfaceC0287y interfaceC0287y) {
        this.f2931e.f(interfaceC0287y);
    }

    @Override // androidx.core.app.j
    public final void g(InterfaceC0651a interfaceC0651a) {
        this.f2944r.remove(interfaceC0651a);
    }

    @Override // androidx.core.content.c
    public final void j(InterfaceC0651a interfaceC0651a) {
        this.f2941o.remove(interfaceC0651a);
    }

    @Override // androidx.lifecycle.InterfaceC0307e
    public E.a k() {
        E.d dVar = new E.d();
        if (getApplication() != null) {
            dVar.b(z.a.f5190e, getApplication());
        }
        dVar.b(v.f5173a, this);
        dVar.b(v.f5174b, this);
        if (getIntent() != null && getIntent().getExtras() != null) {
            dVar.b(v.f5175c, getIntent().getExtras());
        }
        return dVar;
    }

    @Override // androidx.core.app.k
    public final void l(InterfaceC0651a interfaceC0651a) {
        this.f2945s.add(interfaceC0651a);
    }

    @Override // androidx.core.view.InterfaceC0284v
    public void m(InterfaceC0287y interfaceC0287y) {
        this.f2931e.a(interfaceC0287y);
    }

    @Override // androidx.activity.result.f
    public final androidx.activity.result.e n() {
        return this.f2940n;
    }

    @Override // android.app.Activity
    protected void onActivityResult(int i3, int i4, Intent intent) {
        if (this.f2940n.b(i3, i4, intent)) {
            return;
        }
        super.onActivityResult(i3, i4, intent);
    }

    @Override // android.app.Activity
    public void onBackPressed() {
        this.f2935i.e();
    }

    @Override // android.app.Activity, android.content.ComponentCallbacks
    public void onConfigurationChanged(Configuration configuration) {
        super.onConfigurationChanged(configuration);
        Iterator it = this.f2941o.iterator();
        while (it.hasNext()) {
            ((InterfaceC0651a) it.next()).a(configuration);
        }
    }

    @Override // androidx.core.app.f, android.app.Activity
    protected void onCreate(Bundle bundle) {
        this.f2933g.d(bundle);
        this.f2930d.c(this);
        super.onCreate(bundle);
        t.e(this);
        if (androidx.core.os.a.b()) {
            this.f2935i.f(d.a(this));
        }
        int i3 = this.f2938l;
        if (i3 != 0) {
            setContentView(i3);
        }
    }

    @Override // android.app.Activity, android.view.Window.Callback
    public boolean onCreatePanelMenu(int i3, Menu menu) {
        if (i3 != 0) {
            return true;
        }
        super.onCreatePanelMenu(i3, menu);
        this.f2931e.b(menu, getMenuInflater());
        return true;
    }

    @Override // android.app.Activity, android.view.Window.Callback
    public boolean onMenuItemSelected(int i3, MenuItem menuItem) {
        if (super.onMenuItemSelected(i3, menuItem)) {
            return true;
        }
        if (i3 == 0) {
            return this.f2931e.d(menuItem);
        }
        return false;
    }

    @Override // android.app.Activity
    public void onMultiWindowModeChanged(boolean z3) {
        if (this.f2946t) {
            return;
        }
        Iterator it = this.f2944r.iterator();
        while (it.hasNext()) {
            ((InterfaceC0651a) it.next()).a(new androidx.core.app.g(z3));
        }
    }

    @Override // android.app.Activity
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        Iterator it = this.f2943q.iterator();
        while (it.hasNext()) {
            ((InterfaceC0651a) it.next()).a(intent);
        }
    }

    @Override // android.app.Activity, android.view.Window.Callback
    public void onPanelClosed(int i3, Menu menu) {
        this.f2931e.c(menu);
        super.onPanelClosed(i3, menu);
    }

    @Override // android.app.Activity
    public void onPictureInPictureModeChanged(boolean z3) {
        if (this.f2947u) {
            return;
        }
        Iterator it = this.f2945s.iterator();
        while (it.hasNext()) {
            ((InterfaceC0651a) it.next()).a(new androidx.core.app.l(z3));
        }
    }

    @Override // android.app.Activity, android.view.Window.Callback
    public boolean onPreparePanel(int i3, View view, Menu menu) {
        if (i3 != 0) {
            return true;
        }
        super.onPreparePanel(i3, view, menu);
        this.f2931e.e(menu);
        return true;
    }

    @Override // android.app.Activity
    public void onRequestPermissionsResult(int i3, String[] strArr, int[] iArr) {
        if (this.f2940n.b(i3, -1, new Intent().putExtra("androidx.activity.result.contract.extra.PERMISSIONS", strArr).putExtra("androidx.activity.result.contract.extra.PERMISSION_GRANT_RESULTS", iArr))) {
            return;
        }
        super.onRequestPermissionsResult(i3, strArr, iArr);
    }

    @Override // android.app.Activity
    public final Object onRetainNonConfigurationInstance() {
        e eVar;
        Object objM = M();
        B b3 = this.f2934h;
        if (b3 == null && (eVar = (e) getLastNonConfigurationInstance()) != null) {
            b3 = eVar.f2954b;
        }
        if (b3 == null && objM == null) {
            return null;
        }
        e eVar2 = new e();
        eVar2.f2953a = objM;
        eVar2.f2954b = b3;
        return eVar2;
    }

    @Override // androidx.core.app.f, android.app.Activity
    protected void onSaveInstanceState(Bundle bundle) {
        androidx.lifecycle.f fVarS = s();
        if (fVarS instanceof androidx.lifecycle.l) {
            ((androidx.lifecycle.l) fVarS).m(f.b.CREATED);
        }
        super.onSaveInstanceState(bundle);
        this.f2933g.e(bundle);
    }

    @Override // android.app.Activity, android.content.ComponentCallbacks2
    public void onTrimMemory(int i3) {
        super.onTrimMemory(i3);
        Iterator it = this.f2942p.iterator();
        while (it.hasNext()) {
            ((InterfaceC0651a) it.next()).a(Integer.valueOf(i3));
        }
    }

    @Override // androidx.core.app.j
    public final void p(InterfaceC0651a interfaceC0651a) {
        this.f2944r.add(interfaceC0651a);
    }

    @Override // androidx.core.content.c
    public final void q(InterfaceC0651a interfaceC0651a) {
        this.f2941o.add(interfaceC0651a);
    }

    @Override // androidx.lifecycle.C
    public B r() {
        if (getApplication() == null) {
            throw new IllegalStateException("Your activity is not yet attached to the Application instance. You can't request ViewModel before onCreate call.");
        }
        G();
        return this.f2934h;
    }

    @Override // android.app.Activity
    public void reportFullyDrawn() {
        try {
            if (I.a.h()) {
                I.a.c("reportFullyDrawn() for ComponentActivity");
            }
            super.reportFullyDrawn();
            this.f2937k.b();
            I.a.f();
        } catch (Throwable th) {
            I.a.f();
            throw th;
        }
    }

    @Override // androidx.lifecycle.k
    public androidx.lifecycle.f s() {
        return this.f2932f;
    }

    @Override // android.app.Activity
    public abstract void setContentView(int i3);

    @Override // android.app.Activity
    public void setContentView(View view) {
        H();
        this.f2936j.a(getWindow().getDecorView());
        super.setContentView(view);
    }

    @Override // android.app.Activity
    public void startActivityForResult(Intent intent, int i3) {
        super.startActivityForResult(intent, i3);
    }

    @Override // android.app.Activity
    public void startIntentSenderForResult(IntentSender intentSender, int i3, Intent intent, int i4, int i5, int i6) throws IntentSender.SendIntentException {
        super.startIntentSenderForResult(intentSender, i3, intent, i4, i5, i6);
    }

    @Override // androidx.core.app.k
    public final void t(InterfaceC0651a interfaceC0651a) {
        this.f2945s.remove(interfaceC0651a);
    }

    @Override // androidx.core.content.d
    public final void u(InterfaceC0651a interfaceC0651a) {
        this.f2942p.remove(interfaceC0651a);
    }

    @Override // androidx.core.content.d
    public final void w(InterfaceC0651a interfaceC0651a) {
        this.f2942p.add(interfaceC0651a);
    }

    @Override // android.app.Activity
    public void startActivityForResult(Intent intent, int i3, Bundle bundle) {
        super.startActivityForResult(intent, i3, bundle);
    }

    @Override // android.app.Activity
    public void startIntentSenderForResult(IntentSender intentSender, int i3, Intent intent, int i4, int i5, int i6, Bundle bundle) throws IntentSender.SendIntentException {
        super.startIntentSenderForResult(intentSender, i3, intent, i4, i5, i6, bundle);
    }

    @Override // android.app.Activity
    public void onMultiWindowModeChanged(boolean z3, Configuration configuration) {
        this.f2946t = true;
        try {
            super.onMultiWindowModeChanged(z3, configuration);
            this.f2946t = false;
            Iterator it = this.f2944r.iterator();
            while (it.hasNext()) {
                ((InterfaceC0651a) it.next()).a(new androidx.core.app.g(z3, configuration));
            }
        } catch (Throwable th) {
            this.f2946t = false;
            throw th;
        }
    }

    @Override // android.app.Activity
    public void onPictureInPictureModeChanged(boolean z3, Configuration configuration) {
        this.f2947u = true;
        try {
            super.onPictureInPictureModeChanged(z3, configuration);
            this.f2947u = false;
            Iterator it = this.f2945s.iterator();
            while (it.hasNext()) {
                ((InterfaceC0651a) it.next()).a(new androidx.core.app.l(z3, configuration));
            }
        } catch (Throwable th) {
            this.f2947u = false;
            throw th;
        }
    }
}
