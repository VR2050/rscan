package com.facebook.react.devsupport;

import android.app.Activity;
import android.app.Dialog;
import android.graphics.drawable.ColorDrawable;
import android.os.Bundle;
import android.view.KeyEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.widget.FrameLayout;
import androidx.core.view.C0271j0;
import c1.AbstractC0343o;
import com.facebook.fbreact.specs.NativeRedBoxSpec;
import com.facebook.react.bridge.LifecycleEventListener;
import com.facebook.react.bridge.ReactContext;
import com.facebook.react.devsupport.i0;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public final class i0 implements d1.j {

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    public static final a f6850e = new a(null);

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final j1.e f6851a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final K f6852b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private Dialog f6853c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private g0 f6854d;

    public static final class a {

        /* JADX INFO: renamed from: com.facebook.react.devsupport.i0$a$a, reason: collision with other inner class name */
        public static final class C0107a implements LifecycleEventListener {

            /* JADX INFO: renamed from: b, reason: collision with root package name */
            final /* synthetic */ Runnable f6855b;

            /* JADX INFO: renamed from: c, reason: collision with root package name */
            final /* synthetic */ ReactContext f6856c;

            C0107a(Runnable runnable, ReactContext reactContext) {
                this.f6855b = runnable;
                this.f6856c = reactContext;
            }

            @Override // com.facebook.react.bridge.LifecycleEventListener
            public void onHostDestroy() {
            }

            @Override // com.facebook.react.bridge.LifecycleEventListener
            public void onHostPause() {
            }

            @Override // com.facebook.react.bridge.LifecycleEventListener
            public void onHostResume() {
                this.f6855b.run();
                this.f6856c.removeLifecycleEventListener(this);
            }
        }

        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public final void b(ReactContext reactContext, Runnable runnable) {
            reactContext.addLifecycleEventListener(new C0107a(runnable, reactContext));
        }

        private a() {
        }
    }

    public static final class b extends Dialog {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ i0 f6857b;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        b(Activity activity, i0 i0Var, int i3) {
            super(activity, i3);
            this.f6857b = i0Var;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final C0271j0 b(int i3, View view, C0271j0 c0271j0) {
            t2.j.f(view, "view");
            t2.j.f(c0271j0, "windowInsetsCompat");
            androidx.core.graphics.b bVarF = c0271j0.f(i3);
            t2.j.e(bVarF, "getInsets(...)");
            ViewGroup.LayoutParams layoutParams = view.getLayoutParams();
            t2.j.d(layoutParams, "null cannot be cast to non-null type android.widget.FrameLayout.LayoutParams");
            ((FrameLayout.LayoutParams) layoutParams).setMargins(bVarF.f4321a, bVarF.f4322b, bVarF.f4323c, bVarF.f4324d);
            return C0271j0.f4470b;
        }

        @Override // android.app.Dialog
        protected void onCreate(Bundle bundle) {
            Window window = getWindow();
            if (window == null) {
                throw new IllegalStateException("Required value was null.");
            }
            window.setBackgroundDrawable(new ColorDrawable(-16777216));
            final int iE = C0271j0.m.e() | C0271j0.m.a();
            g0 g0Var = this.f6857b.f6854d;
            if (g0Var == null) {
                throw new IllegalStateException("Required value was null.");
            }
            androidx.core.view.V.i0(g0Var, new androidx.core.view.E() { // from class: com.facebook.react.devsupport.j0
                @Override // androidx.core.view.E
                public final C0271j0 a(View view, C0271j0 c0271j0) {
                    return i0.b.b(iE, view, c0271j0);
                }
            });
        }

        @Override // android.app.Dialog, android.view.KeyEvent.Callback
        public boolean onKeyUp(int i3, KeyEvent keyEvent) {
            t2.j.f(keyEvent, "event");
            if (i3 == 82) {
                this.f6857b.f6851a.w();
                return true;
            }
            if (this.f6857b.f6852b.b(i3, getCurrentFocus())) {
                this.f6857b.f6851a.r();
            }
            return super.onKeyUp(i3, keyEvent);
        }
    }

    public i0(j1.e eVar) {
        t2.j.f(eVar, "devSupportManager");
        this.f6851a = eVar;
        this.f6852b = new K();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void k(i0 i0Var) {
        i0Var.b();
    }

    @Override // d1.j
    public boolean a() {
        Dialog dialog = this.f6853c;
        return dialog != null && dialog.isShowing();
    }

    @Override // d1.j
    public void b() {
        String strK = this.f6851a.k();
        Activity activityI = this.f6851a.i();
        if (activityI == null || activityI.isFinishing()) {
            ReactContext reactContextC = this.f6851a.C();
            if (reactContextC != null) {
                f6850e.b(reactContextC, new Runnable() { // from class: com.facebook.react.devsupport.h0
                    @Override // java.lang.Runnable
                    public final void run() {
                        i0.k(this.f6848b);
                    }
                });
                return;
            }
            if (strK == null) {
                strK = "N/A";
            }
            Y.a.m("ReactNative", "Unable to launch redbox because react activity and react context is not available, here is the error that redbox would've displayed: " + strK);
            return;
        }
        g0 g0Var = this.f6854d;
        if ((g0Var != null ? g0Var.getContext() : null) != activityI) {
            f(NativeRedBoxSpec.NAME);
        }
        g0 g0Var2 = this.f6854d;
        if (g0Var2 != null) {
            g0Var2.g();
        }
        if (this.f6853c == null) {
            b bVar = new b(activityI, this, AbstractC0343o.f5650c);
            bVar.requestWindowFeature(1);
            g0 g0Var3 = this.f6854d;
            if (g0Var3 == null) {
                throw new IllegalStateException("Required value was null.");
            }
            bVar.setContentView(g0Var3);
            this.f6853c = bVar;
        }
        Dialog dialog = this.f6853c;
        if (dialog != null) {
            dialog.show();
        }
    }

    @Override // d1.j
    public void c() {
        try {
            Dialog dialog = this.f6853c;
            if (dialog != null) {
                dialog.dismiss();
            }
        } catch (IllegalArgumentException e3) {
            Y.a.n("ReactNative", "RedBoxDialogSurfaceDelegate: error while dismissing dialog: ", e3);
        }
        d();
        this.f6853c = null;
    }

    @Override // d1.j
    public void d() {
        this.f6854d = null;
    }

    @Override // d1.j
    public boolean e() {
        return this.f6854d != null;
    }

    @Override // d1.j
    public void f(String str) {
        t2.j.f(str, "appKey");
        this.f6851a.s();
        Activity activityI = this.f6851a.i();
        if (activityI != null && !activityI.isFinishing()) {
            g0 g0Var = new g0(activityI, this.f6851a, null);
            g0Var.d();
            this.f6854d = g0Var;
            return;
        }
        String strK = this.f6851a.k();
        if (strK == null) {
            strK = "N/A";
        }
        Y.a.m("ReactNative", "Unable to launch redbox because react activity is not available, here is the error that redbox would've displayed: " + strK);
    }
}
