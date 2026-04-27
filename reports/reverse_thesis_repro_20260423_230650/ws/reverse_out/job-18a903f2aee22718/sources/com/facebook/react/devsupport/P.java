package com.facebook.react.devsupport;

import android.app.Activity;
import android.app.Dialog;
import android.graphics.drawable.ColorDrawable;
import android.os.Bundle;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.widget.FrameLayout;
import androidx.core.view.C0271j0;
import c1.AbstractC0343o;

/* JADX INFO: loaded from: classes.dex */
public final class P extends Dialog {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final View f6779b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public P(Activity activity, View view) {
        super(activity, AbstractC0343o.f5649b);
        t2.j.f(activity, "context");
        this.f6779b = view;
        requestWindowFeature(1);
        if (view != null) {
            setContentView(view);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final C0271j0 c(int i3, View view, C0271j0 c0271j0) {
        t2.j.f(view, "view");
        t2.j.f(c0271j0, "windowInsets");
        androidx.core.graphics.b bVarF = c0271j0.f(i3);
        t2.j.e(bVarF, "getInsets(...)");
        ViewGroup.LayoutParams layoutParams = view.getLayoutParams();
        t2.j.d(layoutParams, "null cannot be cast to non-null type android.widget.FrameLayout.LayoutParams");
        ((FrameLayout.LayoutParams) layoutParams).setMargins(bVarF.f4321a, bVarF.f4322b, bVarF.f4323c, bVarF.f4324d);
        return C0271j0.f4470b;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final C0271j0 d(s2.p pVar, View view, C0271j0 c0271j0) {
        t2.j.f(view, "p0");
        t2.j.f(c0271j0, "p1");
        return (C0271j0) pVar.b(view, c0271j0);
    }

    @Override // android.app.Dialog
    protected void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        Window window = getWindow();
        if (window != null) {
            window.setBackgroundDrawable(new ColorDrawable(-16777216));
        }
        View view = this.f6779b;
        if (view != null) {
            final int iE = C0271j0.m.e() | C0271j0.m.a();
            final s2.p pVar = new s2.p() { // from class: com.facebook.react.devsupport.N
                @Override // s2.p
                public final Object b(Object obj, Object obj2) {
                    return P.c(iE, (View) obj, (C0271j0) obj2);
                }
            };
            androidx.core.view.V.i0(view, new androidx.core.view.E() { // from class: com.facebook.react.devsupport.O
                @Override // androidx.core.view.E
                public final C0271j0 a(View view2, C0271j0 c0271j0) {
                    return P.d(pVar, view2, c0271j0);
                }
            });
        }
    }
}
