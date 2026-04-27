package androidx.activity;

import android.app.Dialog;
import android.content.Context;
import android.os.Build;
import android.os.Bundle;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.window.OnBackInvokedDispatcher;
import androidx.lifecycle.D;
import androidx.lifecycle.f;

/* JADX INFO: loaded from: classes.dex */
public class i extends Dialog implements androidx.lifecycle.k, o, F.d {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private androidx.lifecycle.l f2985b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final F.c f2986c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final OnBackPressedDispatcher f2987d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public i(Context context, int i3) {
        super(context, i3);
        t2.j.f(context, "context");
        this.f2986c = F.c.f730d.a(this);
        this.f2987d = new OnBackPressedDispatcher(new Runnable() { // from class: androidx.activity.h
            @Override // java.lang.Runnable
            public final void run() {
                i.g(this.f2984b);
            }
        });
    }

    private final androidx.lifecycle.l d() {
        androidx.lifecycle.l lVar = this.f2985b;
        if (lVar != null) {
            return lVar;
        }
        androidx.lifecycle.l lVar2 = new androidx.lifecycle.l(this);
        this.f2985b = lVar2;
        return lVar2;
    }

    private final void e() {
        Window window = getWindow();
        t2.j.c(window);
        View decorView = window.getDecorView();
        t2.j.e(decorView, "window!!.decorView");
        D.a(decorView, this);
        Window window2 = getWindow();
        t2.j.c(window2);
        View decorView2 = window2.getDecorView();
        t2.j.e(decorView2, "window!!.decorView");
        r.a(decorView2, this);
        Window window3 = getWindow();
        t2.j.c(window3);
        View decorView3 = window3.getDecorView();
        t2.j.e(decorView3, "window!!.decorView");
        F.e.a(decorView3, this);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void g(i iVar) {
        t2.j.f(iVar, "this$0");
        super.onBackPressed();
    }

    @Override // androidx.activity.o
    public final OnBackPressedDispatcher a() {
        return this.f2987d;
    }

    @Override // android.app.Dialog
    public void addContentView(View view, ViewGroup.LayoutParams layoutParams) {
        t2.j.f(view, "view");
        e();
        super.addContentView(view, layoutParams);
    }

    @Override // F.d
    public androidx.savedstate.a b() {
        return this.f2986c.b();
    }

    @Override // android.app.Dialog
    public void onBackPressed() {
        this.f2987d.e();
    }

    @Override // android.app.Dialog
    protected void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        if (Build.VERSION.SDK_INT >= 33) {
            OnBackPressedDispatcher onBackPressedDispatcher = this.f2987d;
            OnBackInvokedDispatcher onBackInvokedDispatcher = getOnBackInvokedDispatcher();
            t2.j.e(onBackInvokedDispatcher, "onBackInvokedDispatcher");
            onBackPressedDispatcher.f(onBackInvokedDispatcher);
        }
        this.f2986c.d(bundle);
        d().h(f.a.ON_CREATE);
    }

    @Override // android.app.Dialog
    public Bundle onSaveInstanceState() {
        Bundle bundleOnSaveInstanceState = super.onSaveInstanceState();
        t2.j.e(bundleOnSaveInstanceState, "super.onSaveInstanceState()");
        this.f2986c.e(bundleOnSaveInstanceState);
        return bundleOnSaveInstanceState;
    }

    @Override // android.app.Dialog
    protected void onStart() {
        super.onStart();
        d().h(f.a.ON_RESUME);
    }

    @Override // android.app.Dialog
    protected void onStop() {
        d().h(f.a.ON_DESTROY);
        this.f2985b = null;
        super.onStop();
    }

    @Override // androidx.lifecycle.k
    public androidx.lifecycle.f s() {
        return d();
    }

    @Override // android.app.Dialog
    public void setContentView(int i3) {
        e();
        super.setContentView(i3);
    }

    @Override // android.app.Dialog
    public void setContentView(View view) {
        t2.j.f(view, "view");
        e();
        super.setContentView(view);
    }

    @Override // android.app.Dialog
    public void setContentView(View view, ViewGroup.LayoutParams layoutParams) {
        t2.j.f(view, "view");
        e();
        super.setContentView(view, layoutParams);
    }
}
