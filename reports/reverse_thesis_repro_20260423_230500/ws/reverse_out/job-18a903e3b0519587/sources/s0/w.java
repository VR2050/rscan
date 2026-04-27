package s0;

import android.graphics.Matrix;
import android.graphics.Rect;

/* JADX INFO: loaded from: classes.dex */
class w extends p {

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    public static final q f10130l = new w();

    private w() {
    }

    @Override // s0.p
    public void b(Matrix matrix, Rect rect, int i3, int i4, float f3, float f4, float f5, float f6) {
        float fMin = Math.min(f5, f6);
        float fWidth = rect.left + (rect.width() - (i3 * fMin));
        float fHeight = rect.top + (rect.height() - (i4 * fMin));
        matrix.setScale(fMin, fMin);
        matrix.postTranslate((int) (fWidth + 0.5f), (int) (fHeight + 0.5f));
    }

    public String toString() {
        return "fit_end";
    }
}
