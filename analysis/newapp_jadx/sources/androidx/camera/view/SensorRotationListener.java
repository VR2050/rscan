package androidx.camera.view;

import android.content.Context;
import android.view.OrientationEventListener;
import androidx.annotation.NonNull;
import androidx.annotation.RestrictTo;

@RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
/* loaded from: classes.dex */
public abstract class SensorRotationListener extends OrientationEventListener {
    public static final int INVALID_SURFACE_ROTATION = -1;
    private int mRotation;

    public SensorRotationListener(@NonNull Context context) {
        super(context);
        this.mRotation = -1;
    }

    @Override // android.view.OrientationEventListener
    public void onOrientationChanged(int i2) {
        if (i2 == -1) {
            return;
        }
        int i3 = (i2 >= 315 || i2 < 45) ? 0 : i2 >= 225 ? 1 : i2 >= 135 ? 2 : 3;
        if (this.mRotation != i3) {
            this.mRotation = i3;
            onRotationChanged(i3);
        }
    }

    public abstract void onRotationChanged(int i2);
}
