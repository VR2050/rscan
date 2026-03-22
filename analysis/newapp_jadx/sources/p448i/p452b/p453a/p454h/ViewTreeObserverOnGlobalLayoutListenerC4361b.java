package p448i.p452b.p453a.p454h;

import android.view.View;
import android.view.ViewTreeObserver;

/* renamed from: i.b.a.h.b */
/* loaded from: classes3.dex */
public class ViewTreeObserverOnGlobalLayoutListenerC4361b implements ViewTreeObserver.OnGlobalLayoutListener {

    /* renamed from: c */
    public int f11270c;

    /* renamed from: e */
    public final /* synthetic */ View f11271e;

    /* renamed from: f */
    public final /* synthetic */ C4360a f11272f;

    public ViewTreeObserverOnGlobalLayoutListenerC4361b(C4360a c4360a, View view) {
        this.f11272f = c4360a;
        this.f11271e = view;
        this.f11270c = C4360a.m4929a(c4360a);
    }

    @Override // android.view.ViewTreeObserver.OnGlobalLayoutListener
    public void onGlobalLayout() {
        int i2;
        this.f11271e.getViewTreeObserver().removeOnGlobalLayoutListener(this);
        C4360a c4360a = this.f11272f;
        if (c4360a.f11259c == null) {
            return;
        }
        int m4929a = C4360a.m4929a(c4360a);
        C4360a c4360a2 = this.f11272f;
        View view = c4360a2.f11259c;
        boolean z = false;
        if (view != null && (c4360a2.f11262f != 1 ? view.getTranslationX() < 0.0f : view.getTranslationY() < 0.0f)) {
            z = true;
        }
        if (!z || (i2 = this.f11270c) == m4929a) {
            return;
        }
        C4360a c4360a3 = this.f11272f;
        int i3 = i2 - m4929a;
        View view2 = c4360a3.f11259c;
        if (view2 == null) {
            return;
        }
        if (c4360a3.f11262f == 1) {
            view2.setTranslationY(view2.getTranslationY() + i3);
        } else {
            view2.setTranslationX(view2.getTranslationX() + i3);
        }
    }
}
