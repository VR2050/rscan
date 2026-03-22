package p005b.p190k.p191a.p192a.p193e;

import android.graphics.Canvas;
import android.view.View;
import com.github.anzewei.parallaxbacklayout.widget.ParallaxBackLayout;

/* renamed from: b.k.a.a.e.d */
/* loaded from: classes.dex */
public class C1887d implements InterfaceC1885b {
    @Override // p005b.p190k.p191a.p192a.p193e.InterfaceC1885b
    /* renamed from: a */
    public void mo1233a(Canvas canvas, ParallaxBackLayout parallaxBackLayout, View view) {
        int edgeFlag = parallaxBackLayout.getEdgeFlag();
        int width = parallaxBackLayout.getWidth();
        int height = parallaxBackLayout.getHeight();
        int systemLeft = parallaxBackLayout.getSystemLeft();
        int systemTop = parallaxBackLayout.getSystemTop();
        if (edgeFlag == 1) {
            canvas.translate((view.getLeft() - view.getWidth()) - systemLeft, 0.0f);
            return;
        }
        if (edgeFlag == 4) {
            canvas.translate(0.0f, (view.getTop() - view.getHeight()) + systemTop);
            return;
        }
        if (edgeFlag == 2) {
            canvas.translate(view.getRight() - systemLeft, 0.0f);
            canvas.clipRect(systemLeft, 0, width, height);
        } else if (edgeFlag == 8) {
            canvas.translate(0.0f, view.getBottom() - systemTop);
            canvas.clipRect(0, systemTop, view.getRight(), height);
        }
    }
}
