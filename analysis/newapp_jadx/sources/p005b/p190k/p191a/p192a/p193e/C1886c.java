package p005b.p190k.p191a.p192a.p193e;

import android.graphics.Canvas;
import android.view.View;
import com.github.anzewei.parallaxbacklayout.widget.ParallaxBackLayout;

/* renamed from: b.k.a.a.e.c */
/* loaded from: classes.dex */
public class C1886c implements InterfaceC1885b {
    @Override // p005b.p190k.p191a.p192a.p193e.InterfaceC1885b
    /* renamed from: a */
    public void mo1233a(Canvas canvas, ParallaxBackLayout parallaxBackLayout, View view) {
        int edgeFlag = parallaxBackLayout.getEdgeFlag();
        int width = parallaxBackLayout.getWidth();
        int height = parallaxBackLayout.getHeight();
        int systemLeft = parallaxBackLayout.getSystemLeft();
        int systemTop = parallaxBackLayout.getSystemTop();
        if (edgeFlag == 1) {
            int left = (view.getLeft() - width) / 2;
            canvas.translate(left, 0.0f);
            canvas.clipRect(0, 0, left + width, view.getBottom());
            return;
        }
        if (edgeFlag == 4) {
            int top = (view.getTop() - view.getHeight()) / 2;
            canvas.translate(0.0f, top);
            canvas.clipRect(0, 0, view.getRight(), view.getHeight() + top + systemTop);
        } else {
            if (edgeFlag == 2) {
                int width2 = ((view.getWidth() + view.getLeft()) - systemLeft) / 2;
                canvas.translate(width2, 0.0f);
                canvas.clipRect(width2 + systemLeft, 0, width, view.getBottom());
                return;
            }
            if (edgeFlag == 8) {
                int bottom = (view.getBottom() - systemTop) / 2;
                canvas.translate(0.0f, bottom);
                canvas.clipRect(0, bottom + systemTop, view.getRight(), height);
            }
        }
    }
}
