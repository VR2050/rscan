package androidx.core.graphics;

import android.graphics.Matrix;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p005b.p310s.p311a.C2743m;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0018\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u0014\n\u0002\b\u0002\n\u0002\u0010\u0007\n\u0002\b\r\u001a\u001c\u0010\u0002\u001a\u00020\u0000*\u00020\u00002\u0006\u0010\u0001\u001a\u00020\u0000H\u0086\n¢\u0006\u0004\b\u0002\u0010\u0003\u001a\u0014\u0010\u0005\u001a\u00020\u0004*\u00020\u0000H\u0086\b¢\u0006\u0004\b\u0005\u0010\u0006\u001a!\u0010\n\u001a\u00020\u00002\b\b\u0002\u0010\b\u001a\u00020\u00072\b\b\u0002\u0010\t\u001a\u00020\u0007¢\u0006\u0004\b\n\u0010\u000b\u001a!\u0010\u000e\u001a\u00020\u00002\b\b\u0002\u0010\f\u001a\u00020\u00072\b\b\u0002\u0010\r\u001a\u00020\u0007¢\u0006\u0004\b\u000e\u0010\u000b\u001a)\u0010\u0012\u001a\u00020\u00002\u0006\u0010\u000f\u001a\u00020\u00072\b\b\u0002\u0010\u0010\u001a\u00020\u00072\b\b\u0002\u0010\u0011\u001a\u00020\u0007¢\u0006\u0004\b\u0012\u0010\u0013¨\u0006\u0014"}, m5311d2 = {"Landroid/graphics/Matrix;", C2743m.f7506a, "times", "(Landroid/graphics/Matrix;Landroid/graphics/Matrix;)Landroid/graphics/Matrix;", "", "values", "(Landroid/graphics/Matrix;)[F", "", "tx", "ty", "translationMatrix", "(FF)Landroid/graphics/Matrix;", "sx", "sy", "scaleMatrix", "degrees", "px", "py", "rotationMatrix", "(FFF)Landroid/graphics/Matrix;", "core-ktx_release"}, m5312k = 2, m5313mv = {1, 5, 1})
/* loaded from: classes.dex */
public final class MatrixKt {
    @NotNull
    public static final Matrix rotationMatrix(float f2, float f3, float f4) {
        Matrix matrix = new Matrix();
        matrix.setRotate(f2, f3, f4);
        return matrix;
    }

    public static /* synthetic */ Matrix rotationMatrix$default(float f2, float f3, float f4, int i2, Object obj) {
        if ((i2 & 2) != 0) {
            f3 = 0.0f;
        }
        if ((i2 & 4) != 0) {
            f4 = 0.0f;
        }
        return rotationMatrix(f2, f3, f4);
    }

    @NotNull
    public static final Matrix scaleMatrix(float f2, float f3) {
        Matrix matrix = new Matrix();
        matrix.setScale(f2, f3);
        return matrix;
    }

    public static /* synthetic */ Matrix scaleMatrix$default(float f2, float f3, int i2, Object obj) {
        if ((i2 & 1) != 0) {
            f2 = 1.0f;
        }
        if ((i2 & 2) != 0) {
            f3 = 1.0f;
        }
        return scaleMatrix(f2, f3);
    }

    @NotNull
    public static final Matrix times(@NotNull Matrix matrix, @NotNull Matrix m2) {
        Intrinsics.checkNotNullParameter(matrix, "<this>");
        Intrinsics.checkNotNullParameter(m2, "m");
        Matrix matrix2 = new Matrix(matrix);
        matrix2.preConcat(m2);
        return matrix2;
    }

    @NotNull
    public static final Matrix translationMatrix(float f2, float f3) {
        Matrix matrix = new Matrix();
        matrix.setTranslate(f2, f3);
        return matrix;
    }

    public static /* synthetic */ Matrix translationMatrix$default(float f2, float f3, int i2, Object obj) {
        if ((i2 & 1) != 0) {
            f2 = 0.0f;
        }
        if ((i2 & 2) != 0) {
            f3 = 0.0f;
        }
        return translationMatrix(f2, f3);
    }

    @NotNull
    public static final float[] values(@NotNull Matrix matrix) {
        Intrinsics.checkNotNullParameter(matrix, "<this>");
        float[] fArr = new float[9];
        matrix.getValues(fArr);
        return fArr;
    }
}
