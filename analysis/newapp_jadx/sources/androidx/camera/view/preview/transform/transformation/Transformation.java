package androidx.camera.view.preview.transform.transformation;

import android.view.View;
import androidx.annotation.NonNull;
import androidx.annotation.RestrictTo;

@RestrictTo({RestrictTo.Scope.LIBRARY})
/* loaded from: classes.dex */
public class Transformation {
    private final float mRotation;
    private final float mScaleX;
    private final float mScaleY;
    private final float mTransX;
    private final float mTransY;

    public Transformation() {
        this(1.0f, 1.0f, 0.0f, 0.0f, 0.0f);
    }

    @NonNull
    public static Transformation getTransformation(@NonNull View view) {
        return new Transformation(view.getScaleX(), view.getScaleY(), view.getTranslationX(), view.getTranslationY(), view.getRotation());
    }

    @NonNull
    public Transformation add(@NonNull Transformation transformation) {
        return new Transformation(transformation.mScaleX * this.mScaleX, transformation.mScaleY * this.mScaleY, transformation.mTransX + this.mTransX, transformation.mTransY + this.mTransY, this.mRotation + transformation.mRotation);
    }

    public float getRotation() {
        return this.mRotation;
    }

    public float getScaleX() {
        return this.mScaleX;
    }

    public float getScaleY() {
        return this.mScaleY;
    }

    public float getTransX() {
        return this.mTransX;
    }

    public float getTransY() {
        return this.mTransY;
    }

    @NonNull
    public Transformation subtract(@NonNull Transformation transformation) {
        return new Transformation(this.mScaleX / transformation.mScaleX, this.mScaleY / transformation.mScaleY, this.mTransX - transformation.mTransX, this.mTransY - transformation.mTransY, this.mRotation - transformation.mRotation);
    }

    public Transformation(float f2, float f3, float f4, float f5, float f6) {
        this.mScaleX = f2;
        this.mScaleY = f3;
        this.mTransX = f4;
        this.mTransY = f5;
        this.mRotation = f6;
    }
}
