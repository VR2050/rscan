package p005b.p177i.p178a.p182j;

import android.view.ViewTreeObserver;
import com.drake.brv.layoutmanager.HoverLinearLayoutManager;

/* renamed from: b.i.a.j.b */
/* loaded from: classes.dex */
public class ViewTreeObserverOnGlobalLayoutListenerC1859b implements ViewTreeObserver.OnGlobalLayoutListener {

    /* renamed from: c */
    public final /* synthetic */ ViewTreeObserver f2861c;

    /* renamed from: e */
    public final /* synthetic */ HoverLinearLayoutManager f2862e;

    public ViewTreeObserverOnGlobalLayoutListenerC1859b(HoverLinearLayoutManager hoverLinearLayoutManager, ViewTreeObserver viewTreeObserver) {
        this.f2862e = hoverLinearLayoutManager;
        this.f2861c = viewTreeObserver;
    }

    @Override // android.view.ViewTreeObserver.OnGlobalLayoutListener
    public void onGlobalLayout() {
        this.f2861c.removeOnGlobalLayoutListener(this);
        HoverLinearLayoutManager hoverLinearLayoutManager = this.f2862e;
        int i2 = hoverLinearLayoutManager.f8990i;
        if (i2 != -1) {
            hoverLinearLayoutManager.scrollToPositionWithOffset(i2, hoverLinearLayoutManager.f8991j);
            HoverLinearLayoutManager hoverLinearLayoutManager2 = this.f2862e;
            hoverLinearLayoutManager2.f8990i = -1;
            hoverLinearLayoutManager2.f8991j = Integer.MIN_VALUE;
        }
    }
}
