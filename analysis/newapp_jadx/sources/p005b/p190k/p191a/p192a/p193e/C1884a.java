package p005b.p190k.p191a.p192a.p193e;

import android.graphics.Canvas;
import android.view.View;
import com.github.anzewei.parallaxbacklayout.widget.ParallaxBackLayout;

/* renamed from: b.k.a.a.e.a */
/* loaded from: classes.dex */
public class C1884a implements InterfaceC1885b {
    @Override // p005b.p190k.p191a.p192a.p193e.InterfaceC1885b
    /* renamed from: a */
    public void mo1233a(Canvas canvas, ParallaxBackLayout parallaxBackLayout, View view) {
        int edgeFlag = parallaxBackLayout.getEdgeFlag();
        if (edgeFlag == 1) {
            canvas.clipRect(0, 0, view.getLeft(), view.getBottom());
            return;
        }
        if (edgeFlag == 4) {
            canvas.clipRect(0, 0, view.getRight(), parallaxBackLayout.getSystemTop() + view.getTop());
        } else if (edgeFlag == 2) {
            canvas.clipRect(view.getRight(), 0, parallaxBackLayout.getWidth(), view.getBottom());
        } else if (edgeFlag == 8) {
            canvas.clipRect(0, view.getBottom(), view.getRight(), parallaxBackLayout.getHeight());
        }
    }
}
