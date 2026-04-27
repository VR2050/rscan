package s0;

import android.graphics.Matrix;
import android.graphics.Rect;

/* JADX INFO: loaded from: classes.dex */
class y extends p {

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    public static final q f10132l = new y();

    private y() {
    }

    @Override // s0.p
    public void b(Matrix matrix, Rect rect, int i3, int i4, float f3, float f4, float f5, float f6) {
        float f7 = rect.left;
        float fHeight = rect.top + ((rect.height() - (i4 * f5)) * 0.5f);
        matrix.setScale(f5, f5);
        matrix.postTranslate((int) (f7 + 0.5f), (int) (fHeight + 0.5f));
    }

    public String toString() {
        return "fit_x";
    }
}
