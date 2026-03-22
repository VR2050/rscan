package androidx.camera.view.preview.transform;

import android.util.Pair;
import android.view.View;
import androidx.annotation.NonNull;
import androidx.camera.view.preview.transform.transformation.TranslationTransformation;

/* loaded from: classes.dex */
public final class TranslationTransform {
    private TranslationTransform() {
    }

    public static TranslationTransformation center(@NonNull View view, @NonNull View view2) {
        if (view2.getWidth() == 0 || view2.getHeight() == 0) {
            return new TranslationTransformation(0.0f, 0.0f);
        }
        int width = view.getWidth() / 2;
        int height = view.getHeight() / 2;
        return new TranslationTransformation(reverseIfRTLLayout(view2, width - (view2.getWidth() / 2)), height - (view2.getHeight() / 2));
    }

    public static TranslationTransformation end(@NonNull View view, @NonNull View view2, @NonNull Pair<Float, Float> pair, int i2) {
        int i3;
        int i4;
        if (view2.getWidth() == 0 || view2.getHeight() == 0) {
            return new TranslationTransformation(0.0f, 0.0f);
        }
        int width = view.getWidth();
        int height = view.getHeight();
        int floatValue = (int) (((Float) pair.first).floatValue() * view2.getWidth());
        int floatValue2 = (int) (((Float) pair.second).floatValue() * view2.getHeight());
        int rotationDegrees = (int) RotationTransform.getRotationDegrees(view2, i2);
        if (rotationDegrees == 0 || rotationDegrees == 180) {
            i3 = width - (floatValue / 2);
            i4 = height - (floatValue2 / 2);
        } else {
            i3 = width - (floatValue2 / 2);
            i4 = height - (floatValue / 2);
        }
        return new TranslationTransformation(reverseIfRTLLayout(view2, i3 - (view2.getWidth() / 2)), i4 - (view2.getHeight() / 2));
    }

    private static int reverseIfRTLLayout(@NonNull View view, int i2) {
        return view.getLayoutDirection() == 1 ? -i2 : i2;
    }

    public static TranslationTransformation start(@NonNull View view, @NonNull Pair<Float, Float> pair, int i2) {
        int i3;
        int i4;
        if (view.getWidth() == 0 || view.getHeight() == 0) {
            return new TranslationTransformation(0.0f, 0.0f);
        }
        int floatValue = (int) (((Float) pair.first).floatValue() * view.getWidth());
        int floatValue2 = (int) (((Float) pair.second).floatValue() * view.getHeight());
        int rotationDegrees = (int) RotationTransform.getRotationDegrees(view, i2);
        if (rotationDegrees == 0 || rotationDegrees == 180) {
            i3 = floatValue / 2;
            i4 = floatValue2 / 2;
        } else {
            int i5 = floatValue / 2;
            i3 = floatValue2 / 2;
            i4 = i5;
        }
        return new TranslationTransformation(reverseIfRTLLayout(view, i3 - (view.getWidth() / 2)), i4 - (view.getHeight() / 2));
    }
}
