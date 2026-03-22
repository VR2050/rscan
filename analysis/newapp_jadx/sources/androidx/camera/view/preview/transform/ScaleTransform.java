package androidx.camera.view.preview.transform;

import android.view.View;
import androidx.annotation.NonNull;
import androidx.camera.view.preview.transform.transformation.ScaleTransformation;

/* loaded from: classes.dex */
public final class ScaleTransform {

    public interface FloatBiFunction {
        float apply(float f2, float f3);
    }

    private ScaleTransform() {
    }

    private static ScaleTransformation computeScale(@NonNull View view, @NonNull View view2, @NonNull FloatBiFunction floatBiFunction, int i2) {
        float scaleX;
        float height;
        float scaleY;
        if (view.getWidth() == 0 || view.getHeight() == 0 || view2.getWidth() == 0 || view2.getHeight() == 0) {
            return new ScaleTransformation(1.0f);
        }
        int rotationDegrees = (int) RotationTransform.getRotationDegrees(view2, i2);
        if (rotationDegrees == 0 || rotationDegrees == 180) {
            scaleX = view2.getScaleX() * view2.getWidth();
            height = view2.getHeight();
            scaleY = view2.getScaleY();
        } else {
            scaleX = view2.getScaleY() * view2.getHeight();
            height = view2.getWidth();
            scaleY = view2.getScaleX();
        }
        return new ScaleTransformation(floatBiFunction.apply(view.getWidth() / scaleX, view.getHeight() / (scaleY * height)));
    }

    public static ScaleTransformation fill(@NonNull View view, @NonNull View view2, int i2) {
        return computeScale(view, view2, new FloatBiFunction() { // from class: e.a.c.u.a.b
            @Override // androidx.camera.view.preview.transform.ScaleTransform.FloatBiFunction
            public final float apply(float f2, float f3) {
                return Math.max(f2, f3);
            }
        }, i2);
    }

    public static ScaleTransformation fit(@NonNull View view, @NonNull View view2, int i2) {
        return computeScale(view, view2, new FloatBiFunction() { // from class: e.a.c.u.a.a
            @Override // androidx.camera.view.preview.transform.ScaleTransform.FloatBiFunction
            public final float apply(float f2, float f3) {
                return Math.min(f2, f3);
            }
        }, i2);
    }
}
