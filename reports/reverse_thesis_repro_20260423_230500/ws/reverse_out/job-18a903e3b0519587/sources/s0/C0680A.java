package s0;

import android.graphics.Matrix;
import android.graphics.Rect;

/* JADX INFO: renamed from: s0.A, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
class C0680A extends p {

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    public static final q f9987l = new C0680A();

    private C0680A() {
    }

    @Override // s0.p
    public void b(Matrix matrix, Rect rect, int i3, int i4, float f3, float f4, float f5, float f6) {
        float fWidth = rect.left + ((rect.width() - (i3 * f6)) * 0.5f);
        float f7 = rect.top;
        matrix.setScale(f6, f6);
        matrix.postTranslate((int) (fWidth + 0.5f), (int) (f7 + 0.5f));
    }

    public String toString() {
        return "fit_y";
    }
}
