package androidx.camera.view;

import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Matrix;
import android.graphics.Paint;
import android.graphics.Rect;
import android.graphics.RectF;
import android.util.Size;
import android.util.SizeF;
import android.view.Display;
import android.view.TextureView;
import android.view.View;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.VisibleForTesting;
import androidx.annotation.experimental.UseExperimental;
import androidx.camera.core.ExperimentalUseCaseGroup;
import androidx.camera.core.Logger;
import androidx.camera.core.SurfaceRequest;
import androidx.camera.view.PreviewView;
import androidx.core.util.Preconditions;
import com.luck.picture.lib.widget.longimage.SubsamplingScaleImageView;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public final class PreviewTransformation {
    private static final PreviewView.ScaleType DEFAULT_SCALE_TYPE = PreviewView.ScaleType.FILL_CENTER;
    private static final int FLOAT_NUMBER_PER_VERTEX = 2;
    private static final String TAG = "PreviewTransform";
    private boolean mIsFrontCamera;
    private int mPreviewRotationDegrees;
    private Size mResolution;
    private PreviewView.ScaleType mScaleType = DEFAULT_SCALE_TYPE;
    private Rect mSurfaceCropRect;
    private int mTargetRotation;

    /* renamed from: androidx.camera.view.PreviewTransformation$1 */
    public static /* synthetic */ class C02151 {
        public static final /* synthetic */ int[] $SwitchMap$androidx$camera$view$PreviewView$ScaleType;

        static {
            PreviewView.ScaleType.values();
            int[] iArr = new int[6];
            $SwitchMap$androidx$camera$view$PreviewView$ScaleType = iArr;
            try {
                iArr[PreviewView.ScaleType.FIT_CENTER.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                $SwitchMap$androidx$camera$view$PreviewView$ScaleType[PreviewView.ScaleType.FILL_CENTER.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                $SwitchMap$androidx$camera$view$PreviewView$ScaleType[PreviewView.ScaleType.FIT_END.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            try {
                $SwitchMap$androidx$camera$view$PreviewView$ScaleType[PreviewView.ScaleType.FILL_END.ordinal()] = 4;
            } catch (NoSuchFieldError unused4) {
            }
            try {
                $SwitchMap$androidx$camera$view$PreviewView$ScaleType[PreviewView.ScaleType.FIT_START.ordinal()] = 5;
            } catch (NoSuchFieldError unused5) {
            }
            try {
                $SwitchMap$androidx$camera$view$PreviewView$ScaleType[PreviewView.ScaleType.FILL_START.ordinal()] = 6;
            } catch (NoSuchFieldError unused6) {
            }
        }
    }

    private static float[] createRotatedVertices(float[] fArr, int i2) {
        float[] fArr2 = new float[fArr.length];
        int i3 = ((-i2) / 90) * 2;
        for (int i4 = 0; i4 < fArr.length; i4++) {
            int length = (i4 + i3) % fArr.length;
            if (length < 0) {
                length += fArr.length;
            }
            fArr2[length] = fArr[i4];
        }
        return fArr2;
    }

    private static RectF flipHorizontally(RectF rectF, float f2) {
        float f3 = f2 + f2;
        return new RectF(f3 - rectF.right, rectF.top, f3 - rectF.left, rectF.bottom);
    }

    private SizeF getRotatedCropRectSize() {
        Preconditions.checkNotNull(this.mSurfaceCropRect);
        return is90or270(this.mPreviewRotationDegrees) ? new SizeF(this.mSurfaceCropRect.height(), this.mSurfaceCropRect.width()) : new SizeF(this.mSurfaceCropRect.width(), this.mSurfaceCropRect.height());
    }

    private Matrix getSurfaceToPreviewViewMatrix(Size size, int i2) {
        Preconditions.checkState(isTransformationInfoReady());
        Matrix matrix = new Matrix();
        matrix.setPolyToPoly(rectToVertices(new RectF(this.mSurfaceCropRect)), 0, createRotatedVertices(isCropRectAspectRatioMatchPreviewView(size) ? sizeToVertices(size) : rectToVertices(getPreviewViewCropRectForMismatchedAspectRatios(size, i2)), this.mPreviewRotationDegrees), 0, 4);
        if (this.mIsFrontCamera) {
            if (is90or270(this.mPreviewRotationDegrees)) {
                matrix.preScale(1.0f, -1.0f, this.mSurfaceCropRect.centerX(), this.mSurfaceCropRect.centerY());
            } else {
                matrix.preScale(-1.0f, 1.0f, this.mSurfaceCropRect.centerX(), this.mSurfaceCropRect.centerY());
            }
        }
        return matrix;
    }

    private RectF getTransformedSurfaceRect(Size size, int i2) {
        Preconditions.checkState(isTransformationInfoReady());
        Matrix surfaceToPreviewViewMatrix = getSurfaceToPreviewViewMatrix(size, i2);
        float[] sizeToVertices = sizeToVertices(this.mResolution);
        surfaceToPreviewViewMatrix.mapPoints(sizeToVertices);
        return verticesToRect(sizeToVertices);
    }

    private static boolean is90or270(int i2) {
        if (i2 == 90 || i2 == 270) {
            return true;
        }
        if (i2 == 0 || i2 == 180) {
            return false;
        }
        throw new IllegalArgumentException(C1499a.m626l("Invalid rotation degrees: ", i2));
    }

    private boolean isTransformationInfoReady() {
        return (this.mSurfaceCropRect == null || this.mResolution == null) ? false : true;
    }

    private static float max(float f2, float f3, float f4, float f5) {
        return Math.max(Math.max(f2, f3), Math.max(f4, f5));
    }

    private static float min(float f2, float f3, float f4, float f5) {
        return Math.min(Math.min(f2, f3), Math.min(f4, f5));
    }

    private static float[] rectToVertices(RectF rectF) {
        float f2 = rectF.left;
        float f3 = rectF.top;
        float f4 = rectF.right;
        float f5 = rectF.bottom;
        return new float[]{f2, f3, f4, f3, f4, f5, f2, f5};
    }

    public static int rotationValueToRotationDegrees(int i2) {
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
        throw new IllegalStateException(C1499a.m626l("Unexpected rotation value ", i2));
    }

    /* JADX WARN: Removed duplicated region for block: B:15:0x003a  */
    /* JADX WARN: Removed duplicated region for block: B:21:0x0046  */
    /* JADX WARN: Removed duplicated region for block: B:24:0x004a  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private static void setMatrixRectToRect(android.graphics.Matrix r3, android.graphics.RectF r4, android.graphics.RectF r5, androidx.camera.view.PreviewView.ScaleType r6) {
        /*
            int r0 = r6.ordinal()
            r1 = 1
            if (r0 == 0) goto L34
            if (r0 == r1) goto L31
            r2 = 2
            if (r0 == r2) goto L2e
            r2 = 3
            if (r0 == r2) goto L34
            r2 = 4
            if (r0 == r2) goto L31
            r2 = 5
            if (r0 == r2) goto L2e
            java.lang.StringBuilder r0 = new java.lang.StringBuilder
            r0.<init>()
            java.lang.String r2 = "Unexpected crop rect: "
            r0.append(r2)
            r0.append(r6)
            java.lang.String r0 = r0.toString()
            java.lang.String r2 = "PreviewTransform"
            androidx.camera.core.Logger.m125e(r2, r0)
            android.graphics.Matrix$ScaleToFit r0 = android.graphics.Matrix.ScaleToFit.FILL
            goto L36
        L2e:
            android.graphics.Matrix$ScaleToFit r0 = android.graphics.Matrix.ScaleToFit.END
            goto L36
        L31:
            android.graphics.Matrix$ScaleToFit r0 = android.graphics.Matrix.ScaleToFit.CENTER
            goto L36
        L34:
            android.graphics.Matrix$ScaleToFit r0 = android.graphics.Matrix.ScaleToFit.START
        L36:
            androidx.camera.view.PreviewView$ScaleType r2 = androidx.camera.view.PreviewView.ScaleType.FIT_CENTER
            if (r6 == r2) goto L44
            androidx.camera.view.PreviewView$ScaleType r2 = androidx.camera.view.PreviewView.ScaleType.FIT_START
            if (r6 == r2) goto L44
            androidx.camera.view.PreviewView$ScaleType r2 = androidx.camera.view.PreviewView.ScaleType.FIT_END
            if (r6 != r2) goto L43
            goto L44
        L43:
            r1 = 0
        L44:
            if (r1 == 0) goto L4a
            r3.setRectToRect(r4, r5, r0)
            goto L50
        L4a:
            r3.setRectToRect(r5, r4, r0)
            r3.invert(r3)
        L50:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.camera.view.PreviewTransformation.setMatrixRectToRect(android.graphics.Matrix, android.graphics.RectF, android.graphics.RectF, androidx.camera.view.PreviewView$ScaleType):void");
    }

    @VisibleForTesting
    public static float[] sizeToVertices(Size size) {
        return new float[]{0.0f, 0.0f, size.getWidth(), 0.0f, size.getWidth(), size.getHeight(), 0.0f, size.getHeight()};
    }

    private static RectF verticesToRect(float[] fArr) {
        return new RectF(min(fArr[0], fArr[2], fArr[4], fArr[6]), min(fArr[1], fArr[3], fArr[5], fArr[7]), max(fArr[0], fArr[2], fArr[4], fArr[6]), max(fArr[1], fArr[3], fArr[5], fArr[7]));
    }

    public Bitmap createTransformedBitmap(@NonNull Bitmap bitmap, Size size, int i2) {
        if (!isTransformationInfoReady()) {
            return bitmap;
        }
        Matrix textureViewCorrectionMatrix = getTextureViewCorrectionMatrix();
        RectF transformedSurfaceRect = getTransformedSurfaceRect(size, i2);
        Bitmap createBitmap = Bitmap.createBitmap(size.getWidth(), size.getHeight(), bitmap.getConfig());
        Canvas canvas = new Canvas(createBitmap);
        Matrix matrix = new Matrix();
        matrix.postConcat(textureViewCorrectionMatrix);
        matrix.postScale(transformedSurfaceRect.width() / this.mResolution.getWidth(), transformedSurfaceRect.height() / this.mResolution.getHeight());
        matrix.postTranslate(transformedSurfaceRect.left, transformedSurfaceRect.top);
        canvas.drawBitmap(bitmap, matrix, new Paint(7));
        return createBitmap;
    }

    public RectF getPreviewViewCropRectForMismatchedAspectRatios(Size size, int i2) {
        RectF rectF = new RectF(0.0f, 0.0f, size.getWidth(), size.getHeight());
        SizeF rotatedCropRectSize = getRotatedCropRectSize();
        RectF rectF2 = new RectF(0.0f, 0.0f, rotatedCropRectSize.getWidth(), rotatedCropRectSize.getHeight());
        Matrix matrix = new Matrix();
        setMatrixRectToRect(matrix, rectF2, rectF, this.mScaleType);
        matrix.mapRect(rectF2);
        return i2 == 1 ? flipHorizontally(rectF2, size.getWidth() / 2.0f) : rectF2;
    }

    @Nullable
    public Matrix getPreviewViewToNormalizedSurfaceMatrix(Size size, int i2) {
        if (!isTransformationInfoReady()) {
            return null;
        }
        Matrix matrix = new Matrix();
        getSurfaceToPreviewViewMatrix(size, i2).invert(matrix);
        Matrix matrix2 = new Matrix();
        matrix2.setRectToRect(new RectF(0.0f, 0.0f, this.mResolution.getWidth(), this.mResolution.getHeight()), new RectF(0.0f, 0.0f, 1.0f, 1.0f), Matrix.ScaleToFit.FILL);
        matrix.postConcat(matrix2);
        return matrix;
    }

    public PreviewView.ScaleType getScaleType() {
        return this.mScaleType;
    }

    @VisibleForTesting
    public Matrix getTextureViewCorrectionMatrix() {
        Preconditions.checkState(isTransformationInfoReady());
        Matrix matrix = new Matrix();
        float[] sizeToVertices = sizeToVertices(this.mResolution);
        matrix.setPolyToPoly(sizeToVertices, 0, createRotatedVertices(sizeToVertices, -rotationValueToRotationDegrees(this.mTargetRotation)), 0, 4);
        return matrix;
    }

    @VisibleForTesting
    public boolean isCropRectAspectRatioMatchPreviewView(Size size) {
        float width = size.getWidth() / size.getHeight();
        SizeF rotatedCropRectSize = getRotatedCropRectSize();
        return width >= (rotatedCropRectSize.getWidth() - 0.5f) / (rotatedCropRectSize.getHeight() + 0.5f) && width <= (rotatedCropRectSize.getWidth() + 0.5f) / (rotatedCropRectSize.getHeight() - 0.5f);
    }

    public void setScaleType(PreviewView.ScaleType scaleType) {
        this.mScaleType = scaleType;
    }

    @UseExperimental(markerClass = ExperimentalUseCaseGroup.class)
    public void setTransformationInfo(@NonNull SurfaceRequest.TransformationInfo transformationInfo, Size size, boolean z) {
        Logger.m123d(TAG, "Transformation info set: " + transformationInfo + " " + size + " " + z);
        this.mSurfaceCropRect = transformationInfo.getCropRect();
        this.mPreviewRotationDegrees = transformationInfo.getRotationDegrees();
        this.mTargetRotation = transformationInfo.getTargetRotation();
        this.mResolution = size;
        this.mIsFrontCamera = z;
    }

    public void transformView(Size size, int i2, @NonNull View view) {
        if (isTransformationInfoReady()) {
            if (view instanceof TextureView) {
                ((TextureView) view).setTransform(getTextureViewCorrectionMatrix());
            } else {
                Display display = view.getDisplay();
                if (display != null && display.getRotation() != this.mTargetRotation) {
                    Logger.m125e(TAG, "Non-display rotation not supported with SurfaceView / PERFORMANCE mode.");
                }
            }
            RectF transformedSurfaceRect = getTransformedSurfaceRect(size, i2);
            view.setPivotX(0.0f);
            view.setPivotY(0.0f);
            view.setScaleX(transformedSurfaceRect.width() / this.mResolution.getWidth());
            view.setScaleY(transformedSurfaceRect.height() / this.mResolution.getHeight());
            view.setTranslationX(transformedSurfaceRect.left - view.getLeft());
            view.setTranslationY(transformedSurfaceRect.top - view.getTop());
        }
    }
}
