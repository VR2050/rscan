package androidx.camera.core.impl.utils;

import androidx.camera.core.Logger;
import com.luck.picture.lib.widget.longimage.SubsamplingScaleImageView;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public final class CameraOrientationUtil {
    private static final String TAG = "CameraOrientationUtil";

    private CameraOrientationUtil() {
    }

    public static int degreesToSurfaceRotation(int i2) {
        if (i2 == 0) {
            return 0;
        }
        if (i2 == 90) {
            return 1;
        }
        if (i2 == 180) {
            return 2;
        }
        if (i2 == 270) {
            return 3;
        }
        throw new IllegalStateException(C1499a.m626l("Invalid sensor rotation: ", i2));
    }

    public static int getRelativeImageRotation(int i2, int i3, boolean z) {
        int i4 = z ? ((i3 - i2) + 360) % 360 : (i3 + i2) % 360;
        if (Logger.isDebugEnabled(TAG)) {
            Logger.m123d(TAG, String.format("getRelativeImageRotation: destRotationDegrees=%s, sourceRotationDegrees=%s, isOppositeFacing=%s, result=%s", Integer.valueOf(i2), Integer.valueOf(i3), Boolean.valueOf(z), Integer.valueOf(i4)));
        }
        return i4;
    }

    public static int surfaceRotationToDegrees(int i2) {
        if (i2 == 0) {
            return 0;
        }
        if (i2 == 1) {
            return 90;
        }
        if (i2 == 2) {
            return 180;
        }
        if (i2 == 3) {
            return SubsamplingScaleImageView.ORIENTATION_270;
        }
        throw new IllegalArgumentException(C1499a.m626l("Unsupported surface rotation: ", i2));
    }
}
