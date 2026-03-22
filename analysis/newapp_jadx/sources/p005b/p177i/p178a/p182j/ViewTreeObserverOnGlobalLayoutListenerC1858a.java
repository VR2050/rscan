package p005b.p177i.p178a.p182j;

import android.view.ViewTreeObserver;
import com.drake.brv.layoutmanager.HoverGridLayoutManager;

/* renamed from: b.i.a.j.a */
/* loaded from: classes.dex */
public class ViewTreeObserverOnGlobalLayoutListenerC1858a implements ViewTreeObserver.OnGlobalLayoutListener {

    /* renamed from: c */
    public final /* synthetic */ ViewTreeObserver f2859c;

    /* renamed from: e */
    public final /* synthetic */ HoverGridLayoutManager f2860e;

    public ViewTreeObserverOnGlobalLayoutListenerC1858a(HoverGridLayoutManager hoverGridLayoutManager, ViewTreeObserver viewTreeObserver) {
        this.f2860e = hoverGridLayoutManager;
        this.f2859c = viewTreeObserver;
    }

    @Override // android.view.ViewTreeObserver.OnGlobalLayoutListener
    public void onGlobalLayout() {
        this.f2859c.removeOnGlobalLayoutListener(this);
        HoverGridLayoutManager hoverGridLayoutManager = this.f2860e;
        int i2 = hoverGridLayoutManager.f8978i;
        if (i2 != -1) {
            hoverGridLayoutManager.scrollToPositionWithOffset(i2, hoverGridLayoutManager.f8979j);
            HoverGridLayoutManager hoverGridLayoutManager2 = this.f2860e;
            hoverGridLayoutManager2.f8978i = -1;
            hoverGridLayoutManager2.f8979j = Integer.MIN_VALUE;
        }
    }
}
