package com.th3rdwave.safeareacontext;

import android.content.Context;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewTreeObserver;

/* JADX INFO: loaded from: classes.dex */
public final class f extends com.facebook.react.views.view.g implements ViewTreeObserver.OnPreDrawListener {

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    private s2.q f8745t;

    /* JADX INFO: renamed from: u, reason: collision with root package name */
    private a f8746u;

    /* JADX INFO: renamed from: v, reason: collision with root package name */
    private c f8747v;

    public f(Context context) {
        super(context);
    }

    private final void F() {
        a aVarE;
        s2.q qVar = this.f8745t;
        if (qVar == null || (aVarE = h.e(this)) == null) {
            return;
        }
        View rootView = getRootView();
        t2.j.d(rootView, "null cannot be cast to non-null type android.view.ViewGroup");
        c cVarA = h.a((ViewGroup) rootView, this);
        if (cVarA == null) {
            return;
        }
        if (t2.j.b(this.f8746u, aVarE) && t2.j.b(this.f8747v, cVarA)) {
            return;
        }
        qVar.a(this, aVarE, cVarA);
        this.f8746u = aVarE;
        this.f8747v = cVarA;
    }

    @Override // com.facebook.react.views.view.g, android.view.ViewGroup, android.view.View
    protected void onAttachedToWindow() {
        super.onAttachedToWindow();
        getViewTreeObserver().addOnPreDrawListener(this);
        F();
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        getViewTreeObserver().removeOnPreDrawListener(this);
    }

    @Override // android.view.ViewTreeObserver.OnPreDrawListener
    public boolean onPreDraw() {
        F();
        return true;
    }

    public final void setOnInsetsChangeHandler(s2.q qVar) {
        this.f8745t = qVar;
        F();
    }
}
