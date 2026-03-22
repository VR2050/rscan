package androidx.camera.view.preview.transform;

import android.util.Pair;
import android.util.Size;
import android.view.View;
import androidx.annotation.NonNull;
import androidx.camera.view.preview.transform.transformation.PreviewCorrectionTransformation;

/* loaded from: classes.dex */
public final class PreviewCorrector {
    private PreviewCorrector() {
    }

    private static Pair<Float, Float> getCorrectionScale(@NonNull View view, @NonNull View view2, @NonNull Size size, boolean z) {
        int width;
        int height;
        if (view.getWidth() == 0 || view.getHeight() == 0 || view2.getWidth() == 0 || view2.getHeight() == 0 || size.getWidth() == 0 || size.getHeight() == 0) {
            return new Pair<>(Float.valueOf(1.0f), Float.valueOf(1.0f));
        }
        if (z) {
            width = size.getHeight();
            height = size.getWidth();
        } else {
            width = size.getWidth();
            height = size.getHeight();
        }
        return new Pair<>(Float.valueOf(width / view2.getWidth()), Float.valueOf(height / view2.getHeight()));
    }

    @NonNull
    public static PreviewCorrectionTransformation getCorrectionTransformation(@NonNull View view, @NonNull View view2, @NonNull Size size, boolean z, int i2) {
        int rotationDegrees = (int) RotationTransform.getRotationDegrees(view2, i2);
        Pair<Float, Float> correctionScale = getCorrectionScale(view, view2, size, z);
        return new PreviewCorrectionTransformation(((Float) correctionScale.first).floatValue(), ((Float) correctionScale.second).floatValue(), -rotationDegrees);
    }
}
