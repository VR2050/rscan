package com.facebook.react.views.drawer;

import O1.m;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.accessibility.AccessibilityEvent;
import androidx.core.view.C0252a;
import androidx.core.view.V;
import c1.AbstractC0339k;
import com.facebook.react.bridge.ReactContext;
import com.facebook.react.uimanager.C0448h0;
import kotlin.jvm.internal.DefaultConstructorMarker;
import r.v;
import t2.j;
import x.AbstractC0715a;

/* JADX INFO: loaded from: classes.dex */
public final class a extends AbstractC0715a {

    /* JADX INFO: renamed from: T, reason: collision with root package name */
    public static final b f7786T = new b(null);

    /* JADX INFO: renamed from: Q, reason: collision with root package name */
    private int f7787Q;

    /* JADX INFO: renamed from: R, reason: collision with root package name */
    private int f7788R;

    /* JADX INFO: renamed from: S, reason: collision with root package name */
    private boolean f7789S;

    /* JADX INFO: renamed from: com.facebook.react.views.drawer.a$a, reason: collision with other inner class name */
    public static final class C0115a extends C0252a {
        C0115a() {
        }

        @Override // androidx.core.view.C0252a
        public void f(View view, AccessibilityEvent accessibilityEvent) {
            j.f(view, "host");
            j.f(accessibilityEvent, "event");
            super.f(view, accessibilityEvent);
            Object tag = view.getTag(AbstractC0339k.f5583g);
            if (tag instanceof C0448h0.d) {
                accessibilityEvent.setClassName(C0448h0.d.e((C0448h0.d) tag));
            }
        }

        @Override // androidx.core.view.C0252a
        public void g(View view, v vVar) {
            j.f(view, "host");
            j.f(vVar, "info");
            super.g(view, vVar);
            C0448h0.d dVarD = C0448h0.d.d(view);
            if (dVarD != null) {
                vVar.p0(C0448h0.d.e(dVarD));
            }
        }
    }

    public static final class b {
        public /* synthetic */ b(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private b() {
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(ReactContext reactContext) {
        super(reactContext);
        j.f(reactContext, "reactContext");
        this.f7787Q = 8388611;
        this.f7788R = -1;
        V.X(this, new C0115a());
    }

    public final void V() {
        d(this.f7787Q);
    }

    public final void W() {
        I(this.f7787Q);
    }

    public final void X() {
        if (getChildCount() == 2) {
            View childAt = getChildAt(1);
            ViewGroup.LayoutParams layoutParams = childAt.getLayoutParams();
            j.d(layoutParams, "null cannot be cast to non-null type androidx.drawerlayout.widget.DrawerLayout.LayoutParams");
            AbstractC0715a.e eVar = (AbstractC0715a.e) layoutParams;
            eVar.f10351a = this.f7787Q;
            ((ViewGroup.MarginLayoutParams) eVar).width = this.f7788R;
            childAt.setLayoutParams(eVar);
            childAt.setClickable(true);
        }
    }

    @Override // x.AbstractC0715a, android.view.ViewGroup
    public boolean onInterceptTouchEvent(MotionEvent motionEvent) {
        j.f(motionEvent, "ev");
        try {
            if (!super.onInterceptTouchEvent(motionEvent)) {
                return false;
            }
            m.b(this, motionEvent);
            this.f7789S = true;
            return true;
        } catch (IllegalArgumentException e3) {
            Y.a.J("ReactNative", "Error intercepting touch event.", e3);
            return false;
        }
    }

    @Override // x.AbstractC0715a, android.view.View
    public boolean onTouchEvent(MotionEvent motionEvent) {
        j.f(motionEvent, "ev");
        if (motionEvent.getActionMasked() == 1 && this.f7789S) {
            m.a(this, motionEvent);
            this.f7789S = false;
        }
        return super.onTouchEvent(motionEvent);
    }

    public final void setDrawerPosition$ReactAndroid_release(int i3) {
        this.f7787Q = i3;
        X();
    }

    public final void setDrawerWidth$ReactAndroid_release(int i3) {
        this.f7788R = i3;
        X();
    }
}
