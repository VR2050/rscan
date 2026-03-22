package androidx.camera.view.preview.transform;

import android.util.Size;
import android.view.View;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RestrictTo;
import androidx.camera.view.PreviewView;
import androidx.camera.view.preview.transform.transformation.Transformation;

@RestrictTo({RestrictTo.Scope.LIBRARY})
/* loaded from: classes.dex */
public final class PreviewTransform {
    private static final PreviewView.ScaleType DEFAULT_SCALE_TYPE = PreviewView.ScaleType.FILL_CENTER;

    @Nullable
    private Transformation mCurrentTransformation;

    @NonNull
    private PreviewView.ScaleType mScaleType = DEFAULT_SCALE_TYPE;
    private boolean mSensorDimensionFlipNeeded = true;
    private int mDeviceRotation = -1;

    private void applyScaleTypeInternal(@NonNull View view, @NonNull View view2, @NonNull PreviewView.ScaleType scaleType, int i2) {
        applyTransformation(view2, Transformation.getTransformation(view2).add(ScaleTypeTransform.getTransformation(view, view2, scaleType, i2)));
    }

    private void applyTransformation(@NonNull View view, @NonNull Transformation transformation) {
        view.setX(0.0f);
        view.setY(0.0f);
        view.setScaleX(transformation.getScaleX());
        view.setScaleY(transformation.getScaleY());
        view.setTranslationX(transformation.getTransX());
        view.setTranslationY(transformation.getTransY());
        view.setRotation(transformation.getRotation());
        this.mCurrentTransformation = transformation;
    }

    private void correctPreview(@NonNull View view, @NonNull View view2, @NonNull Size size) {
        applyTransformation(view2, PreviewCorrector.getCorrectionTransformation(view, view2, size, this.mSensorDimensionFlipNeeded, this.mDeviceRotation));
    }

    private void resetPreview(@NonNull View view) {
        applyTransformation(view, new Transformation());
    }

    public void applyCurrentScaleType(@NonNull View view, @NonNull View view2, @NonNull Size size) {
        resetPreview(view2);
        correctPreview(view, view2, size);
        applyScaleTypeInternal(view, view2, this.mScaleType, this.mDeviceRotation);
    }

    @Nullable
    public Transformation getCurrentTransformation() {
        return this.mCurrentTransformation;
    }

    public int getDeviceRotation() {
        return this.mDeviceRotation;
    }

    @NonNull
    public PreviewView.ScaleType getScaleType() {
        return this.mScaleType;
    }

    public boolean isSensorDimensionFlipNeeded() {
        return this.mSensorDimensionFlipNeeded;
    }

    public void setDeviceRotation(int i2) {
        this.mDeviceRotation = i2;
    }

    public void setScaleType(@NonNull PreviewView.ScaleType scaleType) {
        this.mScaleType = scaleType;
    }

    public void setSensorDimensionFlipNeeded(boolean z) {
        this.mSensorDimensionFlipNeeded = z;
    }
}
