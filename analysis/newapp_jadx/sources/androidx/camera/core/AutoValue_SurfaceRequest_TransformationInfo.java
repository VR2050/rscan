package androidx.camera.core;

import android.graphics.Rect;
import androidx.annotation.NonNull;
import androidx.annotation.RestrictTo;
import androidx.camera.core.SurfaceRequest;
import java.util.Objects;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public final class AutoValue_SurfaceRequest_TransformationInfo extends SurfaceRequest.TransformationInfo {
    private final Rect cropRect;
    private final int rotationDegrees;
    private final int targetRotation;

    public AutoValue_SurfaceRequest_TransformationInfo(Rect rect, int i2, int i3) {
        Objects.requireNonNull(rect, "Null cropRect");
        this.cropRect = rect;
        this.rotationDegrees = i2;
        this.targetRotation = i3;
    }

    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof SurfaceRequest.TransformationInfo)) {
            return false;
        }
        SurfaceRequest.TransformationInfo transformationInfo = (SurfaceRequest.TransformationInfo) obj;
        return this.cropRect.equals(transformationInfo.getCropRect()) && this.rotationDegrees == transformationInfo.getRotationDegrees() && this.targetRotation == transformationInfo.getTargetRotation();
    }

    @Override // androidx.camera.core.SurfaceRequest.TransformationInfo
    @NonNull
    public Rect getCropRect() {
        return this.cropRect;
    }

    @Override // androidx.camera.core.SurfaceRequest.TransformationInfo
    public int getRotationDegrees() {
        return this.rotationDegrees;
    }

    @Override // androidx.camera.core.SurfaceRequest.TransformationInfo
    @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
    public int getTargetRotation() {
        return this.targetRotation;
    }

    public int hashCode() {
        return ((((this.cropRect.hashCode() ^ 1000003) * 1000003) ^ this.rotationDegrees) * 1000003) ^ this.targetRotation;
    }

    public String toString() {
        StringBuilder m586H = C1499a.m586H("TransformationInfo{cropRect=");
        m586H.append(this.cropRect);
        m586H.append(", rotationDegrees=");
        m586H.append(this.rotationDegrees);
        m586H.append(", targetRotation=");
        return C1499a.m580B(m586H, this.targetRotation, "}");
    }
}
