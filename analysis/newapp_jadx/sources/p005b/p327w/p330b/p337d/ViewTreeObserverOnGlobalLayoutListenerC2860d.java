package p005b.p327w.p330b.p337d;

import android.graphics.Rect;
import android.view.View;
import android.view.ViewTreeObserver;
import android.view.Window;

/* renamed from: b.w.b.d.d */
/* loaded from: classes2.dex */
public final class ViewTreeObserverOnGlobalLayoutListenerC2860d implements ViewTreeObserver.OnGlobalLayoutListener {

    /* renamed from: c */
    public final /* synthetic */ Window f7791c;

    /* renamed from: e */
    public final /* synthetic */ int[] f7792e;

    /* renamed from: f */
    public final /* synthetic */ View f7793f;

    /* renamed from: g */
    public final /* synthetic */ int f7794g;

    public ViewTreeObserverOnGlobalLayoutListenerC2860d(Window window, int[] iArr, View view, int i2) {
        this.f7791c = window;
        this.f7792e = iArr;
        this.f7793f = view;
        this.f7794g = i2;
    }

    @Override // android.view.ViewTreeObserver.OnGlobalLayoutListener
    public void onGlobalLayout() {
        int i2;
        int m3303a = C2861e.m3303a(this.f7791c);
        if (this.f7792e[0] != m3303a) {
            View view = this.f7793f;
            int paddingLeft = view.getPaddingLeft();
            int paddingTop = this.f7793f.getPaddingTop();
            int paddingRight = this.f7793f.getPaddingRight();
            int i3 = this.f7794g;
            View decorView = this.f7791c.getDecorView();
            Rect rect = new Rect();
            decorView.getWindowVisibleDisplayFrame(rect);
            decorView.getBottom();
            int abs = Math.abs(decorView.getBottom() - rect.bottom);
            if (abs <= C2861e.m3305c() + C2861e.m3304b()) {
                C2861e.f7795a = abs;
                i2 = 0;
            } else {
                i2 = abs - C2861e.f7795a;
            }
            view.setPadding(paddingLeft, paddingTop, paddingRight, i3 + i2);
            this.f7792e[0] = m3303a;
        }
    }
}
