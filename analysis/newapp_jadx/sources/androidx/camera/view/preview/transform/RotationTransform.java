package androidx.camera.view.preview.transform;

import android.view.View;
import androidx.annotation.NonNull;

/* loaded from: classes.dex */
public final class RotationTransform {
    public static final int ROTATION_AUTOMATIC = -1;

    private RotationTransform() {
    }

    public static float getRotationDegrees(@NonNull View view, int i2) {
        return i2 != -1 ? SurfaceRotation.rotationDegreesFromSurfaceRotation(i2) : getRotationDegrees(view);
    }

    public static float getRotationDegrees(@NonNull View view) {
        if (view.getDisplay() == null) {
            return 0.0f;
        }
        return SurfaceRotation.rotationDegreesFromSurfaceRotation(r0.getRotation());
    }
}
