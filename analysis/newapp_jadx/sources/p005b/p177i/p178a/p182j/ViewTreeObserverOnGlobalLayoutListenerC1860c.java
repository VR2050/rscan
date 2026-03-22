package p005b.p177i.p178a.p182j;

import android.view.ViewTreeObserver;
import com.drake.brv.layoutmanager.HoverStaggeredGridLayoutManager;

/* renamed from: b.i.a.j.c */
/* loaded from: classes.dex */
public class ViewTreeObserverOnGlobalLayoutListenerC1860c implements ViewTreeObserver.OnGlobalLayoutListener {

    /* renamed from: c */
    public final /* synthetic */ ViewTreeObserver f2863c;

    /* renamed from: e */
    public final /* synthetic */ HoverStaggeredGridLayoutManager f2864e;

    public ViewTreeObserverOnGlobalLayoutListenerC1860c(HoverStaggeredGridLayoutManager hoverStaggeredGridLayoutManager, ViewTreeObserver viewTreeObserver) {
        this.f2864e = hoverStaggeredGridLayoutManager;
        this.f2863c = viewTreeObserver;
    }

    @Override // android.view.ViewTreeObserver.OnGlobalLayoutListener
    public void onGlobalLayout() {
        this.f2863c.removeOnGlobalLayoutListener(this);
        HoverStaggeredGridLayoutManager hoverStaggeredGridLayoutManager = this.f2864e;
        int i2 = hoverStaggeredGridLayoutManager.f9003i;
        if (i2 != -1) {
            hoverStaggeredGridLayoutManager.scrollToPositionWithOffset(i2, hoverStaggeredGridLayoutManager.f9004j);
            HoverStaggeredGridLayoutManager hoverStaggeredGridLayoutManager2 = this.f2864e;
            hoverStaggeredGridLayoutManager2.f9003i = -1;
            hoverStaggeredGridLayoutManager2.f9004j = Integer.MIN_VALUE;
        }
    }
}
