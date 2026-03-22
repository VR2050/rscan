package androidx.camera.view.preview.transform;

import com.luck.picture.lib.widget.longimage.SubsamplingScaleImageView;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public final class SurfaceRotation {
    private SurfaceRotation() {
    }

    public static int rotationDegreesFromSurfaceRotation(int i2) {
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
        throw new UnsupportedOperationException(C1499a.m626l("Unsupported surface rotation constant: ", i2));
    }
}
