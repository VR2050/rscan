package org.webrtc.mozi;

import android.graphics.Point;
import android.opengl.Matrix;
import android.view.View;

/* JADX INFO: loaded from: classes3.dex */
public class RendererCommon {
    private static float BALANCED_VISIBLE_FRACTION = 0.5625f;

    public interface GlDrawer {
        void drawOes(int i, float[] fArr, int i2, int i3, int i4, int i5, int i6, int i7);

        void drawOes2(int i, float[] fArr, float[] fArr2, int i2, int i3, int i4, int i5, int i6, int i7);

        void drawRgb(int i, float[] fArr, int i2, int i3, int i4, int i5, int i6, int i7);

        void drawRgb2(int i, float[] fArr, float[] fArr2, int i2, int i3, int i4, int i5, int i6, int i7);

        void drawYuv(int[] iArr, float[] fArr, int i, int i2, int i3, int i4, int i5, int i6);

        void drawYuv2(int[] iArr, float[] fArr, float[] fArr2, int i, int i2, int i3, int i4, int i5, int i6, int i7);

        void release();
    }

    public interface RendererEvents {
        void onFirstFrameRendered();

        void onFrameResolutionChanged(int i, int i2, int i3);
    }

    public enum ScalingType {
        SCALE_ASPECT_FIT,
        SCALE_ASPECT_FILL,
        SCALE_ASPECT_BALANCED,
        SCALE_FILL
    }

    public static class VideoLayoutMeasure {
        protected ScalingType scalingTypeMatchOrientationH = ScalingType.SCALE_ASPECT_BALANCED;
        protected ScalingType scalingTypeMismatchOrientationH = ScalingType.SCALE_ASPECT_BALANCED;
        protected ScalingType scalingTypeMatchOrientationV = ScalingType.SCALE_ASPECT_BALANCED;
        protected ScalingType scalingTypeMismatchOrientationV = ScalingType.SCALE_ASPECT_BALANCED;

        public void setScalingType(ScalingType scalingType) {
            setScalingType(scalingType, scalingType);
        }

        public void setScalingType(ScalingType scalingTypeMatchOrientation, ScalingType scalingTypeMismatchOrientation) {
            setScalingType(scalingTypeMatchOrientation, scalingTypeMismatchOrientation, scalingTypeMatchOrientation, scalingTypeMismatchOrientation);
        }

        public void setScalingType(ScalingType scalingTypeMatchOrientationH, ScalingType scalingTypeMismatchOrientationH, ScalingType scalingTypeMatchOrientationV, ScalingType scalingTypeMismatchOrientationV) {
            this.scalingTypeMatchOrientationH = scalingTypeMatchOrientationH;
            this.scalingTypeMismatchOrientationH = scalingTypeMismatchOrientationH;
            this.scalingTypeMatchOrientationV = scalingTypeMatchOrientationV;
            this.scalingTypeMismatchOrientationV = scalingTypeMismatchOrientationV;
        }

        public Point measure(int widthSpec, int heightSpec) {
            int maxWidth = View.getDefaultSize(Integer.MAX_VALUE, widthSpec);
            int maxHeight = View.getDefaultSize(Integer.MAX_VALUE, heightSpec);
            return new Point(maxWidth, maxHeight);
        }

        public Point measure(int widthSpec, int heightSpec, int frameWidth, int frameHeight) {
            int maxWidth = View.getDefaultSize(Integer.MAX_VALUE, widthSpec);
            int maxHeight = View.getDefaultSize(Integer.MAX_VALUE, heightSpec);
            if (frameWidth == 0 || frameHeight == 0 || maxWidth == 0 || maxHeight == 0) {
                return new Point(maxWidth, maxHeight);
            }
            float frameAspect = frameWidth / frameHeight;
            float displayAspect = maxWidth / maxHeight;
            ScalingType matchScalingType = frameWidth > frameHeight ? this.scalingTypeMatchOrientationH : this.scalingTypeMatchOrientationV;
            ScalingType mismatchScalingType = frameWidth > frameHeight ? this.scalingTypeMismatchOrientationH : this.scalingTypeMismatchOrientationV;
            ScalingType scalingType = ((frameAspect > 1.0f ? 1 : (frameAspect == 1.0f ? 0 : -1)) > 0) == (displayAspect > 1.0f) ? matchScalingType : mismatchScalingType;
            Point layoutSize = RendererCommon.getDisplaySize(scalingType, frameAspect, maxWidth, maxHeight);
            if (View.MeasureSpec.getMode(widthSpec) == 1073741824) {
                layoutSize.x = maxWidth;
            }
            if (View.MeasureSpec.getMode(heightSpec) == 1073741824) {
                layoutSize.y = maxHeight;
            }
            return layoutSize;
        }
    }

    public static float[] getLayoutMatrix(boolean mirror, float videoAspectRatio, float displayAspectRatio) {
        float scaleX = 1.0f;
        float scaleY = 1.0f;
        if (displayAspectRatio > videoAspectRatio) {
            scaleY = videoAspectRatio / displayAspectRatio;
        } else {
            scaleX = displayAspectRatio / videoAspectRatio;
        }
        if (mirror) {
            scaleX *= -1.0f;
        }
        float[] matrix = new float[16];
        Matrix.setIdentityM(matrix, 0);
        Matrix.scaleM(matrix, 0, scaleX, scaleY, 1.0f);
        adjustOrigin(matrix);
        return matrix;
    }

    public static android.graphics.Matrix convertMatrixToAndroidGraphicsMatrix(float[] matrix4x4) {
        float[] values = {matrix4x4[0], matrix4x4[4], matrix4x4[12], matrix4x4[1], matrix4x4[5], matrix4x4[13], matrix4x4[3], matrix4x4[7], matrix4x4[15]};
        android.graphics.Matrix matrix = new android.graphics.Matrix();
        matrix.setValues(values);
        return matrix;
    }

    public static float[] convertMatrixFromAndroidGraphicsMatrix(android.graphics.Matrix matrix) {
        float[] values = new float[9];
        matrix.getValues(values);
        float[] matrix4x4 = {values[0], values[3], 0.0f, values[6], values[1], values[4], 0.0f, values[7], 0.0f, 0.0f, 1.0f, 0.0f, values[2], values[5], 0.0f, values[8]};
        return matrix4x4;
    }

    public static Point getDisplaySize(ScalingType scalingType, float videoAspectRatio, int maxDisplayWidth, int maxDisplayHeight) {
        return getDisplaySize(convertScalingTypeToVisibleFraction(scalingType), videoAspectRatio, maxDisplayWidth, maxDisplayHeight);
    }

    private static void adjustOrigin(float[] matrix) {
        matrix[12] = matrix[12] - ((matrix[0] + matrix[4]) * 0.5f);
        matrix[13] = matrix[13] - ((matrix[1] + matrix[5]) * 0.5f);
        matrix[12] = matrix[12] + 0.5f;
        matrix[13] = matrix[13] + 0.5f;
    }

    /* JADX INFO: renamed from: org.webrtc.mozi.RendererCommon$1, reason: invalid class name */
    static /* synthetic */ class AnonymousClass1 {
        static final /* synthetic */ int[] $SwitchMap$org$webrtc$mozi$RendererCommon$ScalingType;

        static {
            int[] iArr = new int[ScalingType.values().length];
            $SwitchMap$org$webrtc$mozi$RendererCommon$ScalingType = iArr;
            try {
                iArr[ScalingType.SCALE_ASPECT_FIT.ordinal()] = 1;
            } catch (NoSuchFieldError e) {
            }
            try {
                $SwitchMap$org$webrtc$mozi$RendererCommon$ScalingType[ScalingType.SCALE_ASPECT_FILL.ordinal()] = 2;
            } catch (NoSuchFieldError e2) {
            }
            try {
                $SwitchMap$org$webrtc$mozi$RendererCommon$ScalingType[ScalingType.SCALE_FILL.ordinal()] = 3;
            } catch (NoSuchFieldError e3) {
            }
            try {
                $SwitchMap$org$webrtc$mozi$RendererCommon$ScalingType[ScalingType.SCALE_ASPECT_BALANCED.ordinal()] = 4;
            } catch (NoSuchFieldError e4) {
            }
        }
    }

    private static float convertScalingTypeToVisibleFraction(ScalingType scalingType) {
        int i = AnonymousClass1.$SwitchMap$org$webrtc$mozi$RendererCommon$ScalingType[scalingType.ordinal()];
        if (i == 1) {
            return 1.0f;
        }
        if (i == 2 || i == 3) {
            return 0.0f;
        }
        if (i == 4) {
            return BALANCED_VISIBLE_FRACTION;
        }
        throw new IllegalArgumentException();
    }

    private static Point getDisplaySize(float minVisibleFraction, float videoAspectRatio, int maxDisplayWidth, int maxDisplayHeight) {
        if (minVisibleFraction == 0.0f || videoAspectRatio == 0.0f) {
            return new Point(maxDisplayWidth, maxDisplayHeight);
        }
        int width = Math.min(maxDisplayWidth, Math.round((maxDisplayHeight / minVisibleFraction) * videoAspectRatio));
        int height = Math.min(maxDisplayHeight, Math.round((maxDisplayWidth / minVisibleFraction) / videoAspectRatio));
        return new Point(width, height);
    }
}
