package p448i.p452b.p453a.p454h;

import android.view.View;
import android.view.ViewTreeObserver;
import java.util.Map;

/* renamed from: i.b.a.h.c */
/* loaded from: classes3.dex */
public class ViewTreeObserverOnGlobalLayoutListenerC4362c implements ViewTreeObserver.OnGlobalLayoutListener {

    /* renamed from: c */
    public final /* synthetic */ View f11273c;

    /* renamed from: e */
    public final /* synthetic */ Map f11274e;

    /* renamed from: f */
    public final /* synthetic */ C4360a f11275f;

    public ViewTreeObserverOnGlobalLayoutListenerC4362c(C4360a c4360a, View view, Map map) {
        this.f11275f = c4360a;
        this.f11273c = view;
        this.f11274e = map;
    }

    @Override // android.view.ViewTreeObserver.OnGlobalLayoutListener
    public void onGlobalLayout() {
        this.f11273c.getViewTreeObserver().removeOnGlobalLayoutListener(this);
        C4360a c4360a = this.f11275f;
        if (c4360a.f11259c == null) {
            return;
        }
        c4360a.m4933e().requestLayout();
        this.f11275f.m4930b(this.f11274e);
    }
}
