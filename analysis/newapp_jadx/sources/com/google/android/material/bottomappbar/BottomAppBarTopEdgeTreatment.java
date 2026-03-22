package com.google.android.material.bottomappbar;

import androidx.annotation.FloatRange;
import androidx.annotation.NonNull;
import androidx.annotation.RestrictTo;
import com.google.android.material.shape.EdgeTreatment;
import com.google.android.material.shape.ShapePath;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes2.dex */
public class BottomAppBarTopEdgeTreatment extends EdgeTreatment implements Cloneable {
    private static final int ANGLE_LEFT = 180;
    private static final int ANGLE_UP = 270;
    private static final int ARC_HALF = 180;
    private static final int ARC_QUARTER = 90;
    private float cradleVerticalOffset;
    private float fabDiameter;
    private float fabMargin;
    private float horizontalOffset;
    private float roundedCornerRadius;

    public BottomAppBarTopEdgeTreatment(float f2, float f3, float f4) {
        this.fabMargin = f2;
        this.roundedCornerRadius = f3;
        setCradleVerticalOffset(f4);
        this.horizontalOffset = 0.0f;
    }

    public float getCradleVerticalOffset() {
        return this.cradleVerticalOffset;
    }

    @Override // com.google.android.material.shape.EdgeTreatment
    public void getEdgePath(float f2, float f3, float f4, @NonNull ShapePath shapePath) {
        float f5 = this.fabDiameter;
        if (f5 == 0.0f) {
            shapePath.lineTo(f2, 0.0f);
            return;
        }
        float f6 = ((this.fabMargin * 2.0f) + f5) / 2.0f;
        float f7 = f4 * this.roundedCornerRadius;
        float f8 = f3 + this.horizontalOffset;
        float m627m = C1499a.m627m(1.0f, f4, f6, this.cradleVerticalOffset * f4);
        if (m627m / f6 >= 1.0f) {
            shapePath.lineTo(f2, 0.0f);
            return;
        }
        float f9 = f6 + f7;
        float f10 = m627m + f7;
        float sqrt = (float) Math.sqrt((f9 * f9) - (f10 * f10));
        float f11 = f8 - sqrt;
        float f12 = f8 + sqrt;
        float degrees = (float) Math.toDegrees(Math.atan(sqrt / f10));
        float f13 = 90.0f - degrees;
        shapePath.lineTo(f11, 0.0f);
        float f14 = f7 * 2.0f;
        shapePath.addArc(f11 - f7, 0.0f, f11 + f7, f14, 270.0f, degrees);
        shapePath.addArc(f8 - f6, (-f6) - m627m, f8 + f6, f6 - m627m, 180.0f - f13, (f13 * 2.0f) - 180.0f);
        shapePath.addArc(f12 - f7, 0.0f, f12 + f7, f14, 270.0f - degrees, degrees);
        shapePath.lineTo(f2, 0.0f);
    }

    public float getFabCradleMargin() {
        return this.fabMargin;
    }

    public float getFabCradleRoundedCornerRadius() {
        return this.roundedCornerRadius;
    }

    @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
    public float getFabDiameter() {
        return this.fabDiameter;
    }

    @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
    public float getHorizontalOffset() {
        return this.horizontalOffset;
    }

    public void setCradleVerticalOffset(@FloatRange(from = 0.0d) float f2) {
        if (f2 < 0.0f) {
            throw new IllegalArgumentException("cradleVerticalOffset must be positive.");
        }
        this.cradleVerticalOffset = f2;
    }

    public void setFabCradleMargin(float f2) {
        this.fabMargin = f2;
    }

    public void setFabCradleRoundedCornerRadius(float f2) {
        this.roundedCornerRadius = f2;
    }

    @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
    public void setFabDiameter(float f2) {
        this.fabDiameter = f2;
    }

    public void setHorizontalOffset(float f2) {
        this.horizontalOffset = f2;
    }
}
