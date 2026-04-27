package im.uwrkaxlmjj.ui.components;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.ColorFilter;
import android.graphics.Matrix;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.SurfaceTexture;
import android.graphics.drawable.Drawable;
import android.opengl.GLES20;
import android.opengl.GLUtils;
import android.os.Build;
import android.os.Looper;
import android.view.MotionEvent;
import android.view.TextureView;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.exifinterface.media.ExifInterface;
import androidx.recyclerview.widget.ItemTouchHelper;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.king.zxing.util.CodeUtils;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.BuildVars;
import im.uwrkaxlmjj.messenger.DispatchQueue;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MediaController;
import im.uwrkaxlmjj.messenger.Utilities;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.cells.PhotoEditRadioCell;
import im.uwrkaxlmjj.ui.cells.PhotoEditToolCell;
import im.uwrkaxlmjj.ui.components.PhotoEditorSeekBar;
import im.uwrkaxlmjj.ui.components.PhotoFilterBlurControl;
import im.uwrkaxlmjj.ui.components.PhotoFilterCurvesControl;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.FloatBuffer;
import java.util.ArrayList;
import java.util.concurrent.CountDownLatch;
import javax.microedition.khronos.egl.EGL10;
import javax.microedition.khronos.egl.EGLConfig;
import javax.microedition.khronos.egl.EGLContext;
import javax.microedition.khronos.egl.EGLDisplay;
import javax.microedition.khronos.egl.EGLSurface;
import javax.microedition.khronos.opengles.GL;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class PhotoFilterView extends FrameLayout {
    private static final int curveDataStep = 2;
    private static final int curveGranularity = 100;
    private Bitmap bitmapToEdit;
    private float blurAngle;
    private PhotoFilterBlurControl blurControl;
    private float blurExcludeBlurSize;
    private Point blurExcludePoint;
    private float blurExcludeSize;
    private ImageView blurItem;
    private FrameLayout blurLayout;
    private TextView blurLinearButton;
    private TextView blurOffButton;
    private TextView blurRadialButton;
    private int blurType;
    private TextView cancelTextView;
    private int contrastTool;
    private float contrastValue;
    private ImageView curveItem;
    private FrameLayout curveLayout;
    private RadioButton[] curveRadioButton;
    private PhotoFilterCurvesControl curvesControl;
    private CurvesToolValue curvesToolValue;
    private TextView doneTextView;
    private EGLThread eglThread;
    private int enhanceTool;
    private float enhanceValue;
    private int exposureTool;
    private float exposureValue;
    private int fadeTool;
    private float fadeValue;
    private int grainTool;
    private float grainValue;
    private int highlightsTool;
    private float highlightsValue;
    private MediaController.SavedFilterState lastState;
    private int orientation;
    private RecyclerListView recyclerListView;
    private int saturationTool;
    private float saturationValue;
    private int selectedTool;
    private int shadowsTool;
    private float shadowsValue;
    private int sharpenTool;
    private float sharpenValue;
    private boolean showOriginal;
    private TextureView textureView;
    private int tintHighlightsColor;
    private int tintHighlightsTool;
    private int tintShadowsColor;
    private int tintShadowsTool;
    private FrameLayout toolsView;
    private ImageView tuneItem;
    private int vignetteTool;
    private float vignetteValue;
    private int warmthTool;
    private float warmthValue;

    public static class CurvesValue {
        public float[] cachedDataPoints;
        public float blacksLevel = 0.0f;
        public float shadowsLevel = 25.0f;
        public float midtonesLevel = 50.0f;
        public float highlightsLevel = 75.0f;
        public float whitesLevel = 100.0f;
        public float previousBlacksLevel = 0.0f;
        public float previousShadowsLevel = 25.0f;
        public float previousMidtonesLevel = 50.0f;
        public float previousHighlightsLevel = 75.0f;
        public float previousWhitesLevel = 100.0f;

        public float[] getDataPoints() {
            if (this.cachedDataPoints == null) {
                interpolateCurve();
            }
            return this.cachedDataPoints;
        }

        public void saveValues() {
            this.previousBlacksLevel = this.blacksLevel;
            this.previousShadowsLevel = this.shadowsLevel;
            this.previousMidtonesLevel = this.midtonesLevel;
            this.previousHighlightsLevel = this.highlightsLevel;
            this.previousWhitesLevel = this.whitesLevel;
        }

        public void restoreValues() {
            this.blacksLevel = this.previousBlacksLevel;
            this.shadowsLevel = this.previousShadowsLevel;
            this.midtonesLevel = this.previousMidtonesLevel;
            this.highlightsLevel = this.previousHighlightsLevel;
            this.whitesLevel = this.previousWhitesLevel;
            interpolateCurve();
        }

        public float[] interpolateCurve() {
            float f = this.blacksLevel;
            int i = 1;
            float f2 = 0.5f;
            float f3 = this.whitesLevel;
            float[] points = {-0.001f, f / 100.0f, 0.0f, f / 100.0f, 0.25f, this.shadowsLevel / 100.0f, 0.5f, this.midtonesLevel / 100.0f, 0.75f, this.highlightsLevel / 100.0f, 1.0f, f3 / 100.0f, 1.001f, f3 / 100.0f};
            int i2 = 100;
            ArrayList<Float> dataPoints = new ArrayList<>(100);
            ArrayList<Float> interpolatedPoints = new ArrayList<>(100);
            interpolatedPoints.add(Float.valueOf(points[0]));
            interpolatedPoints.add(Float.valueOf(points[1]));
            int index = 1;
            while (index < (points.length / 2) - 2) {
                float point0x = points[(index - 1) * 2];
                float point0y = points[((index - 1) * 2) + i];
                float point1x = points[index * 2];
                float point1y = points[(index * 2) + 1];
                float point2x = points[(index + 1) * 2];
                float point2y = points[((index + 1) * 2) + 1];
                float point3x = points[(index + 2) * 2];
                float point3y = points[((index + 2) * 2) + 1];
                int i3 = 1;
                while (i3 < i2) {
                    float t = i3 * 0.01f;
                    float tt = t * t;
                    float ttt = tt * t;
                    float pix = ((point1x * 2.0f) + ((point2x - point0x) * t) + (((((point0x * 2.0f) - (point1x * 5.0f)) + (point2x * 4.0f)) - point3x) * tt) + (((((point1x * 3.0f) - point0x) - (point2x * 3.0f)) + point3x) * ttt)) * f2;
                    float piy = Math.max(0.0f, Math.min(1.0f, ((point1y * 2.0f) + ((point2y - point0y) * t) + (((((2.0f * point0y) - (5.0f * point1y)) + (4.0f * point2y)) - point3y) * tt) + (((((point1y * 3.0f) - point0y) - (3.0f * point2y)) + point3y) * ttt)) * f2));
                    if (pix > point0x) {
                        interpolatedPoints.add(Float.valueOf(pix));
                        interpolatedPoints.add(Float.valueOf(piy));
                    }
                    if ((i3 - 1) % 2 == 0) {
                        dataPoints.add(Float.valueOf(piy));
                    }
                    i3++;
                    f2 = 0.5f;
                    i2 = 100;
                }
                interpolatedPoints.add(Float.valueOf(point2x));
                interpolatedPoints.add(Float.valueOf(point2y));
                index++;
                f2 = 0.5f;
                i = 1;
                i2 = 100;
            }
            interpolatedPoints.add(Float.valueOf(points[12]));
            interpolatedPoints.add(Float.valueOf(points[13]));
            this.cachedDataPoints = new float[dataPoints.size()];
            int a = 0;
            while (true) {
                float[] fArr = this.cachedDataPoints;
                if (a >= fArr.length) {
                    break;
                }
                fArr[a] = dataPoints.get(a).floatValue();
                a++;
            }
            int a2 = interpolatedPoints.size();
            float[] retValue = new float[a2];
            for (int a3 = 0; a3 < retValue.length; a3++) {
                retValue[a3] = interpolatedPoints.get(a3).floatValue();
            }
            return retValue;
        }

        public boolean isDefault() {
            return ((double) Math.abs(this.blacksLevel - 0.0f)) < 1.0E-5d && ((double) Math.abs(this.shadowsLevel - 25.0f)) < 1.0E-5d && ((double) Math.abs(this.midtonesLevel - 50.0f)) < 1.0E-5d && ((double) Math.abs(this.highlightsLevel - 75.0f)) < 1.0E-5d && ((double) Math.abs(this.whitesLevel - 100.0f)) < 1.0E-5d;
        }
    }

    public static class CurvesToolValue {
        public static final int CurvesTypeBlue = 3;
        public static final int CurvesTypeGreen = 2;
        public static final int CurvesTypeLuminance = 0;
        public static final int CurvesTypeRed = 1;
        public int activeType;
        public ByteBuffer curveBuffer;
        public CurvesValue luminanceCurve = new CurvesValue();
        public CurvesValue redCurve = new CurvesValue();
        public CurvesValue greenCurve = new CurvesValue();
        public CurvesValue blueCurve = new CurvesValue();

        public CurvesToolValue() {
            ByteBuffer byteBufferAllocateDirect = ByteBuffer.allocateDirect(CodeUtils.DEFAULT_REQ_HEIGHT);
            this.curveBuffer = byteBufferAllocateDirect;
            byteBufferAllocateDirect.order(ByteOrder.LITTLE_ENDIAN);
        }

        public void fillBuffer() {
            this.curveBuffer.position(0);
            float[] luminanceCurveData = this.luminanceCurve.getDataPoints();
            float[] redCurveData = this.redCurve.getDataPoints();
            float[] greenCurveData = this.greenCurve.getDataPoints();
            float[] blueCurveData = this.blueCurve.getDataPoints();
            for (int a = 0; a < 200; a++) {
                this.curveBuffer.put((byte) (redCurveData[a] * 255.0f));
                this.curveBuffer.put((byte) (greenCurveData[a] * 255.0f));
                this.curveBuffer.put((byte) (blueCurveData[a] * 255.0f));
                this.curveBuffer.put((byte) (luminanceCurveData[a] * 255.0f));
            }
            this.curveBuffer.position(0);
        }

        public boolean shouldBeSkipped() {
            return this.luminanceCurve.isDefault() && this.redCurve.isDefault() && this.greenCurve.isDefault() && this.blueCurve.isDefault();
        }
    }

    public class EGLThread extends DispatchQueue {
        private static final int PGPhotoEnhanceHistogramBins = 256;
        private static final int PGPhotoEnhanceSegments = 4;
        private static final String blurFragmentShaderCode = "uniform sampler2D sourceImage;varying highp vec2 blurCoordinates[9];void main() {lowp vec4 sum = vec4(0.0);sum += texture2D(sourceImage, blurCoordinates[0]) * 0.133571;sum += texture2D(sourceImage, blurCoordinates[1]) * 0.233308;sum += texture2D(sourceImage, blurCoordinates[2]) * 0.233308;sum += texture2D(sourceImage, blurCoordinates[3]) * 0.135928;sum += texture2D(sourceImage, blurCoordinates[4]) * 0.135928;sum += texture2D(sourceImage, blurCoordinates[5]) * 0.051383;sum += texture2D(sourceImage, blurCoordinates[6]) * 0.051383;sum += texture2D(sourceImage, blurCoordinates[7]) * 0.012595;sum += texture2D(sourceImage, blurCoordinates[8]) * 0.012595;gl_FragColor = sum;}";
        private static final String blurVertexShaderCode = "attribute vec4 position;attribute vec4 inputTexCoord;uniform highp float texelWidthOffset;uniform highp float texelHeightOffset;varying vec2 blurCoordinates[9];void main() {gl_Position = position;vec2 singleStepOffset = vec2(texelWidthOffset, texelHeightOffset);blurCoordinates[0] = inputTexCoord.xy;blurCoordinates[1] = inputTexCoord.xy + singleStepOffset * 1.458430;blurCoordinates[2] = inputTexCoord.xy - singleStepOffset * 1.458430;blurCoordinates[3] = inputTexCoord.xy + singleStepOffset * 3.403985;blurCoordinates[4] = inputTexCoord.xy - singleStepOffset * 3.403985;blurCoordinates[5] = inputTexCoord.xy + singleStepOffset * 5.351806;blurCoordinates[6] = inputTexCoord.xy - singleStepOffset * 5.351806;blurCoordinates[7] = inputTexCoord.xy + singleStepOffset * 7.302940;blurCoordinates[8] = inputTexCoord.xy - singleStepOffset * 7.302940;}";
        private static final String enhanceFragmentShaderCode = "precision highp float;varying vec2 texCoord;uniform sampler2D sourceImage;uniform sampler2D inputImageTexture2;uniform float intensity;float enhance(float value) {const vec2 offset = vec2(0.001953125, 0.03125);value = value + offset.x;vec2 coord = (clamp(texCoord, 0.125, 1.0 - 0.125001) - 0.125) * 4.0;vec2 frac = fract(coord);coord = floor(coord);float p00 = float(coord.y * 4.0 + coord.x) * 0.0625 + offset.y;float p01 = float(coord.y * 4.0 + coord.x + 1.0) * 0.0625 + offset.y;float p10 = float((coord.y + 1.0) * 4.0 + coord.x) * 0.0625 + offset.y;float p11 = float((coord.y + 1.0) * 4.0 + coord.x + 1.0) * 0.0625 + offset.y;vec3 c00 = texture2D(inputImageTexture2, vec2(value, p00)).rgb;vec3 c01 = texture2D(inputImageTexture2, vec2(value, p01)).rgb;vec3 c10 = texture2D(inputImageTexture2, vec2(value, p10)).rgb;vec3 c11 = texture2D(inputImageTexture2, vec2(value, p11)).rgb;float c1 = ((c00.r - c00.g) / (c00.b - c00.g));float c2 = ((c01.r - c01.g) / (c01.b - c01.g));float c3 = ((c10.r - c10.g) / (c10.b - c10.g));float c4 = ((c11.r - c11.g) / (c11.b - c11.g));float c1_2 = mix(c1, c2, frac.x);float c3_4 = mix(c3, c4, frac.x);return mix(c1_2, c3_4, frac.y);}vec3 hsv_to_rgb(vec3 c) {vec4 K = vec4(1.0, 2.0 / 3.0, 1.0 / 3.0, 3.0);vec3 p = abs(fract(c.xxx + K.xyz) * 6.0 - K.www);return c.z * mix(K.xxx, clamp(p - K.xxx, 0.0, 1.0), c.y);}void main() {vec4 texel = texture2D(sourceImage, texCoord);vec4 hsv = texel;hsv.y = min(1.0, hsv.y * 1.2);hsv.z = min(1.0, enhance(hsv.z) * 1.1);gl_FragColor = vec4(hsv_to_rgb(mix(texel.xyz, hsv.xyz, intensity)), texel.w);}";
        private static final String linearBlurFragmentShaderCode = "varying highp vec2 texCoord;uniform sampler2D sourceImage;uniform sampler2D inputImageTexture2;uniform lowp float excludeSize;uniform lowp vec2 excludePoint;uniform lowp float excludeBlurSize;uniform highp float angle;uniform highp float aspectRatio;void main() {lowp vec4 sharpImageColor = texture2D(sourceImage, texCoord);lowp vec4 blurredImageColor = texture2D(inputImageTexture2, texCoord);highp vec2 texCoordToUse = vec2(texCoord.x, (texCoord.y * aspectRatio + 0.5 - 0.5 * aspectRatio));highp float distanceFromCenter = abs((texCoordToUse.x - excludePoint.x) * aspectRatio * cos(angle) + (texCoordToUse.y - excludePoint.y) * sin(angle));gl_FragColor = mix(sharpImageColor, blurredImageColor, smoothstep(excludeSize - excludeBlurSize, excludeSize, distanceFromCenter));}";
        private static final String radialBlurFragmentShaderCode = "varying highp vec2 texCoord;uniform sampler2D sourceImage;uniform sampler2D inputImageTexture2;uniform lowp float excludeSize;uniform lowp vec2 excludePoint;uniform lowp float excludeBlurSize;uniform highp float aspectRatio;void main() {lowp vec4 sharpImageColor = texture2D(sourceImage, texCoord);lowp vec4 blurredImageColor = texture2D(inputImageTexture2, texCoord);highp vec2 texCoordToUse = vec2(texCoord.x, (texCoord.y * aspectRatio + 0.5 - 0.5 * aspectRatio));highp float distanceFromCenter = distance(excludePoint, texCoordToUse);gl_FragColor = mix(sharpImageColor, blurredImageColor, smoothstep(excludeSize - excludeBlurSize, excludeSize, distanceFromCenter));}";
        private static final String rgbToHsvFragmentShaderCode = "precision highp float;varying vec2 texCoord;uniform sampler2D sourceImage;vec3 rgb_to_hsv(vec3 c) {vec4 K = vec4(0.0, -1.0 / 3.0, 2.0 / 3.0, -1.0);vec4 p = c.g < c.b ? vec4(c.bg, K.wz) : vec4(c.gb, K.xy);vec4 q = c.r < p.x ? vec4(p.xyw, c.r) : vec4(c.r, p.yzx);float d = q.x - min(q.w, q.y);float e = 1.0e-10;return vec3(abs(q.z + (q.w - q.y) / (6.0 * d + e)), d / (q.x + e), q.x);}void main() {vec4 texel = texture2D(sourceImage, texCoord);gl_FragColor = vec4(rgb_to_hsv(texel.rgb), texel.a);}";
        private static final String sharpenFragmentShaderCode = "precision highp float;varying vec2 texCoord;varying vec2 leftTexCoord;varying vec2 rightTexCoord;varying vec2 topTexCoord;varying vec2 bottomTexCoord;uniform sampler2D sourceImage;uniform float sharpen;void main() {vec4 result = texture2D(sourceImage, texCoord);vec3 leftTextureColor = texture2D(sourceImage, leftTexCoord).rgb;vec3 rightTextureColor = texture2D(sourceImage, rightTexCoord).rgb;vec3 topTextureColor = texture2D(sourceImage, topTexCoord).rgb;vec3 bottomTextureColor = texture2D(sourceImage, bottomTexCoord).rgb;result.rgb = result.rgb * (1.0 + 4.0 * sharpen) - (leftTextureColor + rightTextureColor + topTextureColor + bottomTextureColor) * sharpen;gl_FragColor = result;}";
        private static final String sharpenVertexShaderCode = "attribute vec4 position;attribute vec2 inputTexCoord;varying vec2 texCoord;uniform highp float inputWidth;uniform highp float inputHeight;varying vec2 leftTexCoord;varying vec2 rightTexCoord;varying vec2 topTexCoord;varying vec2 bottomTexCoord;void main() {gl_Position = position;texCoord = inputTexCoord;highp vec2 widthStep = vec2(1.0 / inputWidth, 0.0);highp vec2 heightStep = vec2(0.0, 1.0 / inputHeight);leftTexCoord = inputTexCoord - widthStep;rightTexCoord = inputTexCoord + widthStep;topTexCoord = inputTexCoord + heightStep;bottomTexCoord = inputTexCoord - heightStep;}";
        private static final String simpleFragmentShaderCode = "varying highp vec2 texCoord;uniform sampler2D sourceImage;void main() {gl_FragColor = texture2D(sourceImage, texCoord);}";
        private static final String simpleVertexShaderCode = "attribute vec4 position;attribute vec2 inputTexCoord;varying vec2 texCoord;void main() {gl_Position = position;texCoord = inputTexCoord;}";
        private static final String toolsFragmentShaderCode = "varying highp vec2 texCoord;uniform sampler2D sourceImage;uniform highp float width;uniform highp float height;uniform sampler2D curvesImage;uniform lowp float skipTone;uniform lowp float shadows;const mediump vec3 hsLuminanceWeighting = vec3(0.3, 0.3, 0.3);uniform lowp float highlights;uniform lowp float contrast;uniform lowp float fadeAmount;const mediump vec3 satLuminanceWeighting = vec3(0.2126, 0.7152, 0.0722);uniform lowp float saturation;uniform lowp float shadowsTintIntensity;uniform lowp float highlightsTintIntensity;uniform lowp vec3 shadowsTintColor;uniform lowp vec3 highlightsTintColor;uniform lowp float exposure;uniform lowp float warmth;uniform lowp float grain;const lowp float permTexUnit = 1.0 / 256.0;const lowp float permTexUnitHalf = 0.5 / 256.0;const lowp float grainsize = 2.3;uniform lowp float vignette;highp float getLuma(highp vec3 rgbP) {return (0.299 * rgbP.r) + (0.587 * rgbP.g) + (0.114 * rgbP.b);}lowp vec3 rgbToHsv(lowp vec3 c) {highp vec4 K = vec4(0.0, -1.0 / 3.0, 2.0 / 3.0, -1.0);highp vec4 p = c.g < c.b ? vec4(c.bg, K.wz) : vec4(c.gb, K.xy);highp vec4 q = c.r < p.x ? vec4(p.xyw, c.r) : vec4(c.r, p.yzx);highp float d = q.x - min(q.w, q.y);highp float e = 1.0e-10;return vec3(abs(q.z + (q.w - q.y) / (6.0 * d + e)), d / (q.x + e), q.x);}lowp vec3 hsvToRgb(lowp vec3 c) {highp vec4 K = vec4(1.0, 2.0 / 3.0, 1.0 / 3.0, 3.0);highp vec3 p = abs(fract(c.xxx + K.xyz) * 6.0 - K.www);return c.z * mix(K.xxx, clamp(p - K.xxx, 0.0, 1.0), c.y);}highp vec3 rgbToHsl(highp vec3 color) {highp vec3 hsl;highp float fmin = min(min(color.r, color.g), color.b);highp float fmax = max(max(color.r, color.g), color.b);highp float delta = fmax - fmin;hsl.z = (fmax + fmin) / 2.0;if (delta == 0.0) {hsl.x = 0.0;hsl.y = 0.0;} else {if (hsl.z < 0.5) {hsl.y = delta / (fmax + fmin);} else {hsl.y = delta / (2.0 - fmax - fmin);}highp float deltaR = (((fmax - color.r) / 6.0) + (delta / 2.0)) / delta;highp float deltaG = (((fmax - color.g) / 6.0) + (delta / 2.0)) / delta;highp float deltaB = (((fmax - color.b) / 6.0) + (delta / 2.0)) / delta;if (color.r == fmax) {hsl.x = deltaB - deltaG;} else if (color.g == fmax) {hsl.x = (1.0 / 3.0) + deltaR - deltaB;} else if (color.b == fmax) {hsl.x = (2.0 / 3.0) + deltaG - deltaR;}if (hsl.x < 0.0) {hsl.x += 1.0;} else if (hsl.x > 1.0) {hsl.x -= 1.0;}}return hsl;}highp float hueToRgb(highp float f1, highp float f2, highp float hue) {if (hue < 0.0) {hue += 1.0;} else if (hue > 1.0) {hue -= 1.0;}highp float res;if ((6.0 * hue) < 1.0) {res = f1 + (f2 - f1) * 6.0 * hue;} else if ((2.0 * hue) < 1.0) {res = f2;} else if ((3.0 * hue) < 2.0) {res = f1 + (f2 - f1) * ((2.0 / 3.0) - hue) * 6.0;} else {res = f1;} return res;}highp vec3 hslToRgb(highp vec3 hsl) {if (hsl.y == 0.0) {return vec3(hsl.z);} else {highp float f2;if (hsl.z < 0.5) {f2 = hsl.z * (1.0 + hsl.y);} else {f2 = (hsl.z + hsl.y) - (hsl.y * hsl.z);}highp float f1 = 2.0 * hsl.z - f2;return vec3(hueToRgb(f1, f2, hsl.x + (1.0/3.0)), hueToRgb(f1, f2, hsl.x), hueToRgb(f1, f2, hsl.x - (1.0/3.0)));}}highp vec3 rgbToYuv(highp vec3 inP) {highp float luma = getLuma(inP);return vec3(luma, (1.0 / 1.772) * (inP.b - luma), (1.0 / 1.402) * (inP.r - luma));}lowp vec3 yuvToRgb(highp vec3 inP) {return vec3(1.402 * inP.b + inP.r, (inP.r - (0.299 * 1.402 / 0.587) * inP.b - (0.114 * 1.772 / 0.587) * inP.g), 1.772 * inP.g + inP.r);}lowp float easeInOutSigmoid(lowp float value, lowp float strength) {if (value > 0.5) {return 1.0 - pow(2.0 - 2.0 * value, 1.0 / (1.0 - strength)) * 0.5;} else {return pow(2.0 * value, 1.0 / (1.0 - strength)) * 0.5;}}lowp vec3 applyLuminanceCurve(lowp vec3 pixel) {highp float index = floor(clamp(pixel.z / (1.0 / 200.0), 0.0, 199.0));pixel.y = mix(0.0, pixel.y, smoothstep(0.0, 0.1, pixel.z) * (1.0 - smoothstep(0.8, 1.0, pixel.z)));pixel.z = texture2D(curvesImage, vec2(1.0 / 200.0 * index, 0)).a;return pixel;}lowp vec3 applyRGBCurve(lowp vec3 pixel) {highp float index = floor(clamp(pixel.r / (1.0 / 200.0), 0.0, 199.0));pixel.r = texture2D(curvesImage, vec2(1.0 / 200.0 * index, 0)).r;index = floor(clamp(pixel.g / (1.0 / 200.0), 0.0, 199.0));pixel.g = clamp(texture2D(curvesImage, vec2(1.0 / 200.0 * index, 0)).g, 0.0, 1.0);index = floor(clamp(pixel.b / (1.0 / 200.0), 0.0, 199.0));pixel.b = clamp(texture2D(curvesImage, vec2(1.0 / 200.0 * index, 0)).b, 0.0, 1.0);return pixel;}highp vec3 fadeAdjust(highp vec3 color, highp float fadeVal) {return (color * (1.0 - fadeVal)) + ((color + (vec3(-0.9772) * pow(vec3(color), vec3(3.0)) + vec3(1.708) * pow(vec3(color), vec3(2.0)) + vec3(-0.1603) * vec3(color) + vec3(0.2878) - color * vec3(0.9))) * fadeVal);}lowp vec3 tintRaiseShadowsCurve(lowp vec3 color) {return vec3(-0.003671) * pow(color, vec3(3.0)) + vec3(0.3842) * pow(color, vec3(2.0)) + vec3(0.3764) * color + vec3(0.2515);}lowp vec3 tintShadows(lowp vec3 texel, lowp vec3 tintColor, lowp float tintAmount) {return clamp(mix(texel, mix(texel, tintRaiseShadowsCurve(texel), tintColor), tintAmount), 0.0, 1.0);} lowp vec3 tintHighlights(lowp vec3 texel, lowp vec3 tintColor, lowp float tintAmount) {return clamp(mix(texel, mix(texel, vec3(1.0) - tintRaiseShadowsCurve(vec3(1.0) - texel), (vec3(1.0) - tintColor)), tintAmount), 0.0, 1.0);}highp vec4 rnm(in highp vec2 tc) {highp float noise = sin(dot(tc, vec2(12.9898, 78.233))) * 43758.5453;return vec4(fract(noise), fract(noise * 1.2154), fract(noise * 1.3453), fract(noise * 1.3647)) * 2.0 - 1.0;}highp float fade(in highp float t) {return t * t * t * (t * (t * 6.0 - 15.0) + 10.0);}highp float pnoise3D(in highp vec3 p) {highp vec3 pi = permTexUnit * floor(p) + permTexUnitHalf;highp vec3 pf = fract(p);highp float perm = rnm(pi.xy).a;highp float n000 = dot(rnm(vec2(perm, pi.z)).rgb * 4.0 - 1.0, pf);highp float n001 = dot(rnm(vec2(perm, pi.z + permTexUnit)).rgb * 4.0 - 1.0, pf - vec3(0.0, 0.0, 1.0));perm = rnm(pi.xy + vec2(0.0, permTexUnit)).a;highp float n010 = dot(rnm(vec2(perm, pi.z)).rgb * 4.0 - 1.0, pf - vec3(0.0, 1.0, 0.0));highp float n011 = dot(rnm(vec2(perm, pi.z + permTexUnit)).rgb * 4.0 - 1.0, pf - vec3(0.0, 1.0, 1.0));perm = rnm(pi.xy + vec2(permTexUnit, 0.0)).a;highp float n100 = dot(rnm(vec2(perm, pi.z)).rgb * 4.0 - 1.0, pf - vec3(1.0, 0.0, 0.0));highp float n101 = dot(rnm(vec2(perm, pi.z + permTexUnit)).rgb * 4.0 - 1.0, pf - vec3(1.0, 0.0, 1.0));perm = rnm(pi.xy + vec2(permTexUnit, permTexUnit)).a;highp float n110 = dot(rnm(vec2(perm, pi.z)).rgb * 4.0 - 1.0, pf - vec3(1.0, 1.0, 0.0));highp float n111 = dot(rnm(vec2(perm, pi.z + permTexUnit)).rgb * 4.0 - 1.0, pf - vec3(1.0, 1.0, 1.0));highp vec4 n_x = mix(vec4(n000, n001, n010, n011), vec4(n100, n101, n110, n111), fade(pf.x));highp vec2 n_xy = mix(n_x.xy, n_x.zw, fade(pf.y));return mix(n_xy.x, n_xy.y, fade(pf.z));}lowp vec2 coordRot(in lowp vec2 tc, in lowp float angle) {return vec2(((tc.x * 2.0 - 1.0) * cos(angle) - (tc.y * 2.0 - 1.0) * sin(angle)) * 0.5 + 0.5, ((tc.y * 2.0 - 1.0) * cos(angle) + (tc.x * 2.0 - 1.0) * sin(angle)) * 0.5 + 0.5);}void main() {lowp vec4 source = texture2D(sourceImage, texCoord);lowp vec4 result = source;const lowp float toolEpsilon = 0.005;if (skipTone < toolEpsilon) {result = vec4(applyRGBCurve(hslToRgb(applyLuminanceCurve(rgbToHsl(result.rgb)))), result.a);}mediump float hsLuminance = dot(result.rgb, hsLuminanceWeighting);mediump float shadow = clamp((pow(hsLuminance, 1.0 / shadows) + (-0.76) * pow(hsLuminance, 2.0 / shadows)) - hsLuminance, 0.0, 1.0);mediump float highlight = clamp((1.0 - (pow(1.0 - hsLuminance, 1.0 / (2.0 - highlights)) + (-0.8) * pow(1.0 - hsLuminance, 2.0 / (2.0 - highlights)))) - hsLuminance, -1.0, 0.0);lowp vec3 hsresult = vec3(0.0, 0.0, 0.0) + ((hsLuminance + shadow + highlight) - 0.0) * ((result.rgb - vec3(0.0, 0.0, 0.0)) / (hsLuminance - 0.0));mediump float contrastedLuminance = ((hsLuminance - 0.5) * 1.5) + 0.5;mediump float whiteInterp = contrastedLuminance * contrastedLuminance * contrastedLuminance;mediump float whiteTarget = clamp(highlights, 1.0, 2.0) - 1.0;hsresult = mix(hsresult, vec3(1.0), whiteInterp * whiteTarget);mediump float invContrastedLuminance = 1.0 - contrastedLuminance;mediump float blackInterp = invContrastedLuminance * invContrastedLuminance * invContrastedLuminance;mediump float blackTarget = 1.0 - clamp(shadows, 0.0, 1.0);hsresult = mix(hsresult, vec3(0.0), blackInterp * blackTarget);result = vec4(hsresult.rgb, result.a);result = vec4(clamp(((result.rgb - vec3(0.5)) * contrast + vec3(0.5)), 0.0, 1.0), result.a);if (abs(fadeAmount) > toolEpsilon) {result.rgb = fadeAdjust(result.rgb, fadeAmount);}lowp float satLuminance = dot(result.rgb, satLuminanceWeighting);lowp vec3 greyScaleColor = vec3(satLuminance);result = vec4(clamp(mix(greyScaleColor, result.rgb, saturation), 0.0, 1.0), result.a);if (abs(shadowsTintIntensity) > toolEpsilon) {result.rgb = tintShadows(result.rgb, shadowsTintColor, shadowsTintIntensity * 2.0);}if (abs(highlightsTintIntensity) > toolEpsilon) {result.rgb = tintHighlights(result.rgb, highlightsTintColor, highlightsTintIntensity * 2.0);}if (abs(exposure) > toolEpsilon) {mediump float mag = exposure * 1.045;mediump float exppower = 1.0 + abs(mag);if (mag < 0.0) {exppower = 1.0 / exppower;}result.r = 1.0 - pow((1.0 - result.r), exppower);result.g = 1.0 - pow((1.0 - result.g), exppower);result.b = 1.0 - pow((1.0 - result.b), exppower);}if (abs(warmth) > toolEpsilon) {highp vec3 yuvVec;if (warmth > 0.0 ) {yuvVec = vec3(0.1765, -0.1255, 0.0902);} else {yuvVec = -vec3(0.0588, 0.1569, -0.1255);}highp vec3 yuvColor = rgbToYuv(result.rgb);highp float luma = yuvColor.r;highp float curveScale = sin(luma * 3.14159);yuvColor += 0.375 * warmth * curveScale * yuvVec;result.rgb = yuvToRgb(yuvColor);}if (abs(grain) > toolEpsilon) {highp vec3 rotOffset = vec3(1.425, 3.892, 5.835);highp vec2 rotCoordsR = coordRot(texCoord, rotOffset.x);highp vec3 noise = vec3(pnoise3D(vec3(rotCoordsR * vec2(width / grainsize, height / grainsize),0.0)));lowp vec3 lumcoeff = vec3(0.299,0.587,0.114);lowp float luminance = dot(result.rgb, lumcoeff);lowp float lum = smoothstep(0.2, 0.0, luminance);lum += luminance;noise = mix(noise,vec3(0.0),pow(lum,4.0));result.rgb = result.rgb + noise * grain;}if (abs(vignette) > toolEpsilon) {const lowp float midpoint = 0.7;const lowp float fuzziness = 0.62;lowp float radDist = length(texCoord - 0.5) / sqrt(0.5);lowp float mag = easeInOutSigmoid(radDist * midpoint, fuzziness) * vignette * 0.645;result.rgb = mix(pow(result.rgb, vec3(1.0 / (1.0 - mag))), vec3(0.0), mag * mag);}gl_FragColor = result;}";
        private final int EGL_CONTEXT_CLIENT_VERSION;
        private final int EGL_OPENGL_ES2_BIT;
        private int blurHeightHandle;
        private int blurInputTexCoordHandle;
        private int blurPositionHandle;
        private int blurShaderProgram;
        private int blurSourceImageHandle;
        private int blurWidthHandle;
        private boolean blured;
        private int contrastHandle;
        private Bitmap currentBitmap;
        private int[] curveTextures;
        private int curvesImageHandle;
        private Runnable drawRunnable;
        private EGL10 egl10;
        private EGLConfig eglConfig;
        private EGLContext eglContext;
        private EGLDisplay eglDisplay;
        private EGLSurface eglSurface;
        private int enhanceInputImageTexture2Handle;
        private int enhanceInputTexCoordHandle;
        private int enhanceIntensityHandle;
        private int enhancePositionHandle;
        private int enhanceShaderProgram;
        private int enhanceSourceImageHandle;
        private int[] enhanceTextures;
        private int exposureHandle;
        private int fadeAmountHandle;
        private GL gl;
        private int grainHandle;
        private int heightHandle;
        private int highlightsHandle;
        private int highlightsTintColorHandle;
        private int highlightsTintIntensityHandle;
        private boolean hsvGenerated;
        private boolean initied;
        private int inputTexCoordHandle;
        private long lastRenderCallTime;
        private int linearBlurAngleHandle;
        private int linearBlurAspectRatioHandle;
        private int linearBlurExcludeBlurSizeHandle;
        private int linearBlurExcludePointHandle;
        private int linearBlurExcludeSizeHandle;
        private int linearBlurInputTexCoordHandle;
        private int linearBlurPositionHandle;
        private int linearBlurShaderProgram;
        private int linearBlurSourceImage2Handle;
        private int linearBlurSourceImageHandle;
        private boolean needUpdateBlurTexture;
        private int positionHandle;
        private int radialBlurAspectRatioHandle;
        private int radialBlurExcludeBlurSizeHandle;
        private int radialBlurExcludePointHandle;
        private int radialBlurExcludeSizeHandle;
        private int radialBlurInputTexCoordHandle;
        private int radialBlurPositionHandle;
        private int radialBlurShaderProgram;
        private int radialBlurSourceImage2Handle;
        private int radialBlurSourceImageHandle;
        private int renderBufferHeight;
        private int renderBufferWidth;
        private int[] renderFrameBuffer;
        private int[] renderTexture;
        private int rgbToHsvInputTexCoordHandle;
        private int rgbToHsvPositionHandle;
        private int rgbToHsvShaderProgram;
        private int rgbToHsvSourceImageHandle;
        private int saturationHandle;
        private int shadowsHandle;
        private int shadowsTintColorHandle;
        private int shadowsTintIntensityHandle;
        private int sharpenHandle;
        private int sharpenHeightHandle;
        private int sharpenInputTexCoordHandle;
        private int sharpenPositionHandle;
        private int sharpenShaderProgram;
        private int sharpenSourceImageHandle;
        private int sharpenWidthHandle;
        private int simpleInputTexCoordHandle;
        private int simplePositionHandle;
        private int simpleShaderProgram;
        private int simpleSourceImageHandle;
        private int skipToneHandle;
        private int sourceImageHandle;
        private volatile int surfaceHeight;
        private SurfaceTexture surfaceTexture;
        private volatile int surfaceWidth;
        private FloatBuffer textureBuffer;
        private int toolsShaderProgram;
        private FloatBuffer vertexBuffer;
        private FloatBuffer vertexInvertBuffer;
        private int vignetteHandle;
        private int warmthHandle;
        private int widthHandle;

        public EGLThread(SurfaceTexture surface, Bitmap bitmap) {
            super("EGLThread");
            this.EGL_CONTEXT_CLIENT_VERSION = 12440;
            this.EGL_OPENGL_ES2_BIT = 4;
            this.needUpdateBlurTexture = true;
            this.enhanceTextures = new int[2];
            this.renderTexture = new int[3];
            this.renderFrameBuffer = new int[3];
            this.curveTextures = new int[1];
            this.drawRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.components.PhotoFilterView.EGLThread.1
                @Override // java.lang.Runnable
                public void run() {
                    if (EGLThread.this.initied) {
                        if ((EGLThread.this.eglContext.equals(EGLThread.this.egl10.eglGetCurrentContext()) && EGLThread.this.eglSurface.equals(EGLThread.this.egl10.eglGetCurrentSurface(12377))) || EGLThread.this.egl10.eglMakeCurrent(EGLThread.this.eglDisplay, EGLThread.this.eglSurface, EGLThread.this.eglSurface, EGLThread.this.eglContext)) {
                            GLES20.glViewport(0, 0, EGLThread.this.renderBufferWidth, EGLThread.this.renderBufferHeight);
                            EGLThread.this.drawEnhancePass();
                            EGLThread.this.drawSharpenPass();
                            EGLThread.this.drawCustomParamsPass();
                            EGLThread eGLThread = EGLThread.this;
                            eGLThread.blured = eGLThread.drawBlurPass();
                            GLES20.glViewport(0, 0, EGLThread.this.surfaceWidth, EGLThread.this.surfaceHeight);
                            GLES20.glBindFramebuffer(36160, 0);
                            GLES20.glClear(0);
                            GLES20.glUseProgram(EGLThread.this.simpleShaderProgram);
                            GLES20.glActiveTexture(33984);
                            GLES20.glBindTexture(3553, EGLThread.this.renderTexture[!EGLThread.this.blured ? 1 : 0]);
                            GLES20.glUniform1i(EGLThread.this.simpleSourceImageHandle, 0);
                            GLES20.glEnableVertexAttribArray(EGLThread.this.simpleInputTexCoordHandle);
                            GLES20.glVertexAttribPointer(EGLThread.this.simpleInputTexCoordHandle, 2, 5126, false, 8, (Buffer) EGLThread.this.textureBuffer);
                            GLES20.glEnableVertexAttribArray(EGLThread.this.simplePositionHandle);
                            GLES20.glVertexAttribPointer(EGLThread.this.simplePositionHandle, 2, 5126, false, 8, (Buffer) EGLThread.this.vertexBuffer);
                            GLES20.glDrawArrays(5, 0, 4);
                            EGLThread.this.egl10.eglSwapBuffers(EGLThread.this.eglDisplay, EGLThread.this.eglSurface);
                            return;
                        }
                        if (BuildVars.LOGS_ENABLED) {
                            FileLog.e("eglMakeCurrent failed " + GLUtils.getEGLErrorString(EGLThread.this.egl10.eglGetError()));
                        }
                    }
                }
            };
            this.surfaceTexture = surface;
            this.currentBitmap = bitmap;
        }

        private int loadShader(int type, String shaderCode) {
            int shader = GLES20.glCreateShader(type);
            GLES20.glShaderSource(shader, shaderCode);
            GLES20.glCompileShader(shader);
            int[] compileStatus = new int[1];
            GLES20.glGetShaderiv(shader, 35713, compileStatus, 0);
            if (compileStatus[0] == 0) {
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.e(GLES20.glGetShaderInfoLog(shader));
                }
                GLES20.glDeleteShader(shader);
                return 0;
            }
            return shader;
        }

        private boolean initGL() {
            EGL10 egl10 = (EGL10) EGLContext.getEGL();
            this.egl10 = egl10;
            EGLDisplay eGLDisplayEglGetDisplay = egl10.eglGetDisplay(EGL10.EGL_DEFAULT_DISPLAY);
            this.eglDisplay = eGLDisplayEglGetDisplay;
            if (eGLDisplayEglGetDisplay == EGL10.EGL_NO_DISPLAY) {
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.e("eglGetDisplay failed " + GLUtils.getEGLErrorString(this.egl10.eglGetError()));
                }
                finish();
                return false;
            }
            int[] version = new int[2];
            if (!this.egl10.eglInitialize(this.eglDisplay, version)) {
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.e("eglInitialize failed " + GLUtils.getEGLErrorString(this.egl10.eglGetError()));
                }
                finish();
                return false;
            }
            int[] configsCount = new int[1];
            EGLConfig[] configs = new EGLConfig[1];
            int[] configSpec = {12352, 4, 12324, 8, 12323, 8, 12322, 8, 12321, 8, 12325, 0, 12326, 0, 12344};
            if (!this.egl10.eglChooseConfig(this.eglDisplay, configSpec, configs, 1, configsCount)) {
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.e("eglChooseConfig failed " + GLUtils.getEGLErrorString(this.egl10.eglGetError()));
                }
                finish();
                return false;
            }
            if (configsCount[0] > 0) {
                EGLConfig eGLConfig = configs[0];
                this.eglConfig = eGLConfig;
                int[] attrib_list = {12440, 2, 12344};
                EGLContext eGLContextEglCreateContext = this.egl10.eglCreateContext(this.eglDisplay, eGLConfig, EGL10.EGL_NO_CONTEXT, attrib_list);
                this.eglContext = eGLContextEglCreateContext;
                if (eGLContextEglCreateContext == null) {
                    if (BuildVars.LOGS_ENABLED) {
                        FileLog.e("eglCreateContext failed " + GLUtils.getEGLErrorString(this.egl10.eglGetError()));
                    }
                    finish();
                    return false;
                }
                SurfaceTexture surfaceTexture = this.surfaceTexture;
                if (surfaceTexture instanceof SurfaceTexture) {
                    EGLSurface eGLSurfaceEglCreateWindowSurface = this.egl10.eglCreateWindowSurface(this.eglDisplay, this.eglConfig, surfaceTexture, null);
                    this.eglSurface = eGLSurfaceEglCreateWindowSurface;
                    if (eGLSurfaceEglCreateWindowSurface == null || eGLSurfaceEglCreateWindowSurface == EGL10.EGL_NO_SURFACE) {
                        if (BuildVars.LOGS_ENABLED) {
                            FileLog.e("createWindowSurface failed " + GLUtils.getEGLErrorString(this.egl10.eglGetError()));
                        }
                        finish();
                        return false;
                    }
                    EGL10 egl102 = this.egl10;
                    EGLDisplay eGLDisplay = this.eglDisplay;
                    EGLSurface eGLSurface = this.eglSurface;
                    if (egl102.eglMakeCurrent(eGLDisplay, eGLSurface, eGLSurface, this.eglContext)) {
                        this.gl = this.eglContext.getGL();
                        float[] squareCoordinates = {-1.0f, 1.0f, 1.0f, 1.0f, -1.0f, -1.0f, 1.0f, -1.0f};
                        ByteBuffer bb = ByteBuffer.allocateDirect(squareCoordinates.length * 4);
                        bb.order(ByteOrder.nativeOrder());
                        FloatBuffer floatBufferAsFloatBuffer = bb.asFloatBuffer();
                        this.vertexBuffer = floatBufferAsFloatBuffer;
                        floatBufferAsFloatBuffer.put(squareCoordinates);
                        this.vertexBuffer.position(0);
                        float[] squareCoordinates2 = {-1.0f, -1.0f, 1.0f, -1.0f, -1.0f, 1.0f, 1.0f, 1.0f};
                        ByteBuffer bb2 = ByteBuffer.allocateDirect(squareCoordinates2.length * 4);
                        bb2.order(ByteOrder.nativeOrder());
                        FloatBuffer floatBufferAsFloatBuffer2 = bb2.asFloatBuffer();
                        this.vertexInvertBuffer = floatBufferAsFloatBuffer2;
                        floatBufferAsFloatBuffer2.put(squareCoordinates2);
                        this.vertexInvertBuffer.position(0);
                        float[] textureCoordinates = {0.0f, 0.0f, 1.0f, 0.0f, 0.0f, 1.0f, 1.0f, 1.0f};
                        ByteBuffer bb3 = ByteBuffer.allocateDirect(textureCoordinates.length * 4);
                        bb3.order(ByteOrder.nativeOrder());
                        FloatBuffer floatBufferAsFloatBuffer3 = bb3.asFloatBuffer();
                        this.textureBuffer = floatBufferAsFloatBuffer3;
                        floatBufferAsFloatBuffer3.put(textureCoordinates);
                        this.textureBuffer.position(0);
                        GLES20.glGenTextures(1, this.curveTextures, 0);
                        GLES20.glGenTextures(2, this.enhanceTextures, 0);
                        int vertexShader = loadShader(35633, simpleVertexShaderCode);
                        int fragmentShader = loadShader(35632, toolsFragmentShaderCode);
                        if (vertexShader != 0 && fragmentShader != 0) {
                            int iGlCreateProgram = GLES20.glCreateProgram();
                            this.toolsShaderProgram = iGlCreateProgram;
                            GLES20.glAttachShader(iGlCreateProgram, vertexShader);
                            GLES20.glAttachShader(this.toolsShaderProgram, fragmentShader);
                            GLES20.glBindAttribLocation(this.toolsShaderProgram, 0, "position");
                            GLES20.glBindAttribLocation(this.toolsShaderProgram, 1, "inputTexCoord");
                            GLES20.glLinkProgram(this.toolsShaderProgram);
                            int[] linkStatus = new int[1];
                            GLES20.glGetProgramiv(this.toolsShaderProgram, 35714, linkStatus, 0);
                            if (linkStatus[0] != 0) {
                                this.positionHandle = GLES20.glGetAttribLocation(this.toolsShaderProgram, "position");
                                this.inputTexCoordHandle = GLES20.glGetAttribLocation(this.toolsShaderProgram, "inputTexCoord");
                                this.sourceImageHandle = GLES20.glGetUniformLocation(this.toolsShaderProgram, "sourceImage");
                                this.shadowsHandle = GLES20.glGetUniformLocation(this.toolsShaderProgram, "shadows");
                                this.highlightsHandle = GLES20.glGetUniformLocation(this.toolsShaderProgram, "highlights");
                                this.exposureHandle = GLES20.glGetUniformLocation(this.toolsShaderProgram, "exposure");
                                this.contrastHandle = GLES20.glGetUniformLocation(this.toolsShaderProgram, "contrast");
                                this.saturationHandle = GLES20.glGetUniformLocation(this.toolsShaderProgram, "saturation");
                                this.warmthHandle = GLES20.glGetUniformLocation(this.toolsShaderProgram, "warmth");
                                this.vignetteHandle = GLES20.glGetUniformLocation(this.toolsShaderProgram, "vignette");
                                this.grainHandle = GLES20.glGetUniformLocation(this.toolsShaderProgram, "grain");
                                this.widthHandle = GLES20.glGetUniformLocation(this.toolsShaderProgram, "width");
                                this.heightHandle = GLES20.glGetUniformLocation(this.toolsShaderProgram, "height");
                                this.curvesImageHandle = GLES20.glGetUniformLocation(this.toolsShaderProgram, "curvesImage");
                                this.skipToneHandle = GLES20.glGetUniformLocation(this.toolsShaderProgram, "skipTone");
                                this.fadeAmountHandle = GLES20.glGetUniformLocation(this.toolsShaderProgram, "fadeAmount");
                                this.shadowsTintIntensityHandle = GLES20.glGetUniformLocation(this.toolsShaderProgram, "shadowsTintIntensity");
                                this.highlightsTintIntensityHandle = GLES20.glGetUniformLocation(this.toolsShaderProgram, "highlightsTintIntensity");
                                this.shadowsTintColorHandle = GLES20.glGetUniformLocation(this.toolsShaderProgram, "shadowsTintColor");
                                this.highlightsTintColorHandle = GLES20.glGetUniformLocation(this.toolsShaderProgram, "highlightsTintColor");
                            } else {
                                GLES20.glDeleteProgram(this.toolsShaderProgram);
                                this.toolsShaderProgram = 0;
                            }
                            int vertexShader2 = loadShader(35633, sharpenVertexShaderCode);
                            int fragmentShader2 = loadShader(35632, sharpenFragmentShaderCode);
                            if (vertexShader2 != 0 && fragmentShader2 != 0) {
                                int iGlCreateProgram2 = GLES20.glCreateProgram();
                                this.sharpenShaderProgram = iGlCreateProgram2;
                                GLES20.glAttachShader(iGlCreateProgram2, vertexShader2);
                                GLES20.glAttachShader(this.sharpenShaderProgram, fragmentShader2);
                                GLES20.glBindAttribLocation(this.sharpenShaderProgram, 0, "position");
                                GLES20.glBindAttribLocation(this.sharpenShaderProgram, 1, "inputTexCoord");
                                GLES20.glLinkProgram(this.sharpenShaderProgram);
                                int[] linkStatus2 = new int[1];
                                GLES20.glGetProgramiv(this.sharpenShaderProgram, 35714, linkStatus2, 0);
                                if (linkStatus2[0] != 0) {
                                    this.sharpenPositionHandle = GLES20.glGetAttribLocation(this.sharpenShaderProgram, "position");
                                    this.sharpenInputTexCoordHandle = GLES20.glGetAttribLocation(this.sharpenShaderProgram, "inputTexCoord");
                                    this.sharpenSourceImageHandle = GLES20.glGetUniformLocation(this.sharpenShaderProgram, "sourceImage");
                                    this.sharpenWidthHandle = GLES20.glGetUniformLocation(this.sharpenShaderProgram, "inputWidth");
                                    this.sharpenHeightHandle = GLES20.glGetUniformLocation(this.sharpenShaderProgram, "inputHeight");
                                    this.sharpenHandle = GLES20.glGetUniformLocation(this.sharpenShaderProgram, "sharpen");
                                } else {
                                    GLES20.glDeleteProgram(this.sharpenShaderProgram);
                                    this.sharpenShaderProgram = 0;
                                }
                                int vertexShader3 = loadShader(35633, blurVertexShaderCode);
                                int fragmentShader3 = loadShader(35632, blurFragmentShaderCode);
                                if (vertexShader3 != 0 && fragmentShader3 != 0) {
                                    int iGlCreateProgram3 = GLES20.glCreateProgram();
                                    this.blurShaderProgram = iGlCreateProgram3;
                                    GLES20.glAttachShader(iGlCreateProgram3, vertexShader3);
                                    GLES20.glAttachShader(this.blurShaderProgram, fragmentShader3);
                                    GLES20.glBindAttribLocation(this.blurShaderProgram, 0, "position");
                                    GLES20.glBindAttribLocation(this.blurShaderProgram, 1, "inputTexCoord");
                                    GLES20.glLinkProgram(this.blurShaderProgram);
                                    int[] linkStatus3 = new int[1];
                                    GLES20.glGetProgramiv(this.blurShaderProgram, 35714, linkStatus3, 0);
                                    if (linkStatus3[0] != 0) {
                                        this.blurPositionHandle = GLES20.glGetAttribLocation(this.blurShaderProgram, "position");
                                        this.blurInputTexCoordHandle = GLES20.glGetAttribLocation(this.blurShaderProgram, "inputTexCoord");
                                        this.blurSourceImageHandle = GLES20.glGetUniformLocation(this.blurShaderProgram, "sourceImage");
                                        this.blurWidthHandle = GLES20.glGetUniformLocation(this.blurShaderProgram, "texelWidthOffset");
                                        this.blurHeightHandle = GLES20.glGetUniformLocation(this.blurShaderProgram, "texelHeightOffset");
                                    } else {
                                        GLES20.glDeleteProgram(this.blurShaderProgram);
                                        this.blurShaderProgram = 0;
                                    }
                                    int vertexShader4 = loadShader(35633, simpleVertexShaderCode);
                                    int fragmentShader4 = loadShader(35632, linearBlurFragmentShaderCode);
                                    if (vertexShader4 != 0 && fragmentShader4 != 0) {
                                        int iGlCreateProgram4 = GLES20.glCreateProgram();
                                        this.linearBlurShaderProgram = iGlCreateProgram4;
                                        GLES20.glAttachShader(iGlCreateProgram4, vertexShader4);
                                        GLES20.glAttachShader(this.linearBlurShaderProgram, fragmentShader4);
                                        GLES20.glBindAttribLocation(this.linearBlurShaderProgram, 0, "position");
                                        GLES20.glBindAttribLocation(this.linearBlurShaderProgram, 1, "inputTexCoord");
                                        GLES20.glLinkProgram(this.linearBlurShaderProgram);
                                        int[] linkStatus4 = new int[1];
                                        GLES20.glGetProgramiv(this.linearBlurShaderProgram, 35714, linkStatus4, 0);
                                        if (linkStatus4[0] != 0) {
                                            this.linearBlurPositionHandle = GLES20.glGetAttribLocation(this.linearBlurShaderProgram, "position");
                                            this.linearBlurInputTexCoordHandle = GLES20.glGetAttribLocation(this.linearBlurShaderProgram, "inputTexCoord");
                                            this.linearBlurSourceImageHandle = GLES20.glGetUniformLocation(this.linearBlurShaderProgram, "sourceImage");
                                            this.linearBlurSourceImage2Handle = GLES20.glGetUniformLocation(this.linearBlurShaderProgram, "inputImageTexture2");
                                            this.linearBlurExcludeSizeHandle = GLES20.glGetUniformLocation(this.linearBlurShaderProgram, "excludeSize");
                                            this.linearBlurExcludePointHandle = GLES20.glGetUniformLocation(this.linearBlurShaderProgram, "excludePoint");
                                            this.linearBlurExcludeBlurSizeHandle = GLES20.glGetUniformLocation(this.linearBlurShaderProgram, "excludeBlurSize");
                                            this.linearBlurAngleHandle = GLES20.glGetUniformLocation(this.linearBlurShaderProgram, "angle");
                                            this.linearBlurAspectRatioHandle = GLES20.glGetUniformLocation(this.linearBlurShaderProgram, "aspectRatio");
                                        } else {
                                            GLES20.glDeleteProgram(this.linearBlurShaderProgram);
                                            this.linearBlurShaderProgram = 0;
                                        }
                                        int vertexShader5 = loadShader(35633, simpleVertexShaderCode);
                                        int fragmentShader5 = loadShader(35632, radialBlurFragmentShaderCode);
                                        if (vertexShader5 != 0 && fragmentShader5 != 0) {
                                            int iGlCreateProgram5 = GLES20.glCreateProgram();
                                            this.radialBlurShaderProgram = iGlCreateProgram5;
                                            GLES20.glAttachShader(iGlCreateProgram5, vertexShader5);
                                            GLES20.glAttachShader(this.radialBlurShaderProgram, fragmentShader5);
                                            GLES20.glBindAttribLocation(this.radialBlurShaderProgram, 0, "position");
                                            GLES20.glBindAttribLocation(this.radialBlurShaderProgram, 1, "inputTexCoord");
                                            GLES20.glLinkProgram(this.radialBlurShaderProgram);
                                            int[] linkStatus5 = new int[1];
                                            GLES20.glGetProgramiv(this.radialBlurShaderProgram, 35714, linkStatus5, 0);
                                            if (linkStatus5[0] != 0) {
                                                this.radialBlurPositionHandle = GLES20.glGetAttribLocation(this.radialBlurShaderProgram, "position");
                                                this.radialBlurInputTexCoordHandle = GLES20.glGetAttribLocation(this.radialBlurShaderProgram, "inputTexCoord");
                                                this.radialBlurSourceImageHandle = GLES20.glGetUniformLocation(this.radialBlurShaderProgram, "sourceImage");
                                                this.radialBlurSourceImage2Handle = GLES20.glGetUniformLocation(this.radialBlurShaderProgram, "inputImageTexture2");
                                                this.radialBlurExcludeSizeHandle = GLES20.glGetUniformLocation(this.radialBlurShaderProgram, "excludeSize");
                                                this.radialBlurExcludePointHandle = GLES20.glGetUniformLocation(this.radialBlurShaderProgram, "excludePoint");
                                                this.radialBlurExcludeBlurSizeHandle = GLES20.glGetUniformLocation(this.radialBlurShaderProgram, "excludeBlurSize");
                                                this.radialBlurAspectRatioHandle = GLES20.glGetUniformLocation(this.radialBlurShaderProgram, "aspectRatio");
                                            } else {
                                                GLES20.glDeleteProgram(this.radialBlurShaderProgram);
                                                this.radialBlurShaderProgram = 0;
                                            }
                                            int vertexShader6 = loadShader(35633, simpleVertexShaderCode);
                                            int fragmentShader6 = loadShader(35632, rgbToHsvFragmentShaderCode);
                                            if (vertexShader6 != 0 && fragmentShader6 != 0) {
                                                int iGlCreateProgram6 = GLES20.glCreateProgram();
                                                this.rgbToHsvShaderProgram = iGlCreateProgram6;
                                                GLES20.glAttachShader(iGlCreateProgram6, vertexShader6);
                                                GLES20.glAttachShader(this.rgbToHsvShaderProgram, fragmentShader6);
                                                GLES20.glBindAttribLocation(this.rgbToHsvShaderProgram, 0, "position");
                                                GLES20.glBindAttribLocation(this.rgbToHsvShaderProgram, 1, "inputTexCoord");
                                                GLES20.glLinkProgram(this.rgbToHsvShaderProgram);
                                                int[] linkStatus6 = new int[1];
                                                GLES20.glGetProgramiv(this.rgbToHsvShaderProgram, 35714, linkStatus6, 0);
                                                if (linkStatus6[0] != 0) {
                                                    this.rgbToHsvPositionHandle = GLES20.glGetAttribLocation(this.rgbToHsvShaderProgram, "position");
                                                    this.rgbToHsvInputTexCoordHandle = GLES20.glGetAttribLocation(this.rgbToHsvShaderProgram, "inputTexCoord");
                                                    this.rgbToHsvSourceImageHandle = GLES20.glGetUniformLocation(this.rgbToHsvShaderProgram, "sourceImage");
                                                } else {
                                                    GLES20.glDeleteProgram(this.rgbToHsvShaderProgram);
                                                    this.rgbToHsvShaderProgram = 0;
                                                }
                                                int vertexShader7 = loadShader(35633, simpleVertexShaderCode);
                                                int fragmentShader7 = loadShader(35632, enhanceFragmentShaderCode);
                                                if (vertexShader7 != 0 && fragmentShader7 != 0) {
                                                    int iGlCreateProgram7 = GLES20.glCreateProgram();
                                                    this.enhanceShaderProgram = iGlCreateProgram7;
                                                    GLES20.glAttachShader(iGlCreateProgram7, vertexShader7);
                                                    GLES20.glAttachShader(this.enhanceShaderProgram, fragmentShader7);
                                                    GLES20.glBindAttribLocation(this.enhanceShaderProgram, 0, "position");
                                                    GLES20.glBindAttribLocation(this.enhanceShaderProgram, 1, "inputTexCoord");
                                                    GLES20.glLinkProgram(this.enhanceShaderProgram);
                                                    int[] linkStatus7 = new int[1];
                                                    GLES20.glGetProgramiv(this.enhanceShaderProgram, 35714, linkStatus7, 0);
                                                    if (linkStatus7[0] != 0) {
                                                        this.enhancePositionHandle = GLES20.glGetAttribLocation(this.enhanceShaderProgram, "position");
                                                        this.enhanceInputTexCoordHandle = GLES20.glGetAttribLocation(this.enhanceShaderProgram, "inputTexCoord");
                                                        this.enhanceSourceImageHandle = GLES20.glGetUniformLocation(this.enhanceShaderProgram, "sourceImage");
                                                        this.enhanceIntensityHandle = GLES20.glGetUniformLocation(this.enhanceShaderProgram, "intensity");
                                                        this.enhanceInputImageTexture2Handle = GLES20.glGetUniformLocation(this.enhanceShaderProgram, "inputImageTexture2");
                                                    } else {
                                                        GLES20.glDeleteProgram(this.enhanceShaderProgram);
                                                        this.enhanceShaderProgram = 0;
                                                    }
                                                    int vertexShader8 = loadShader(35633, simpleVertexShaderCode);
                                                    int fragmentShader8 = loadShader(35632, simpleFragmentShaderCode);
                                                    if (vertexShader8 != 0 && fragmentShader8 != 0) {
                                                        int iGlCreateProgram8 = GLES20.glCreateProgram();
                                                        this.simpleShaderProgram = iGlCreateProgram8;
                                                        GLES20.glAttachShader(iGlCreateProgram8, vertexShader8);
                                                        GLES20.glAttachShader(this.simpleShaderProgram, fragmentShader8);
                                                        GLES20.glBindAttribLocation(this.simpleShaderProgram, 0, "position");
                                                        GLES20.glBindAttribLocation(this.simpleShaderProgram, 1, "inputTexCoord");
                                                        GLES20.glLinkProgram(this.simpleShaderProgram);
                                                        int[] linkStatus8 = new int[1];
                                                        GLES20.glGetProgramiv(this.simpleShaderProgram, 35714, linkStatus8, 0);
                                                        if (linkStatus8[0] != 0) {
                                                            this.simplePositionHandle = GLES20.glGetAttribLocation(this.simpleShaderProgram, "position");
                                                            this.simpleInputTexCoordHandle = GLES20.glGetAttribLocation(this.simpleShaderProgram, "inputTexCoord");
                                                            this.simpleSourceImageHandle = GLES20.glGetUniformLocation(this.simpleShaderProgram, "sourceImage");
                                                        } else {
                                                            GLES20.glDeleteProgram(this.simpleShaderProgram);
                                                            this.simpleShaderProgram = 0;
                                                        }
                                                        Bitmap bitmap = this.currentBitmap;
                                                        if (bitmap != null && !bitmap.isRecycled()) {
                                                            loadTexture(this.currentBitmap);
                                                            return true;
                                                        }
                                                        return true;
                                                    }
                                                    finish();
                                                    return false;
                                                }
                                                finish();
                                                return false;
                                            }
                                            finish();
                                            return false;
                                        }
                                        finish();
                                        return false;
                                    }
                                    finish();
                                    return false;
                                }
                                finish();
                                return false;
                            }
                            finish();
                            return false;
                        }
                        finish();
                        return false;
                    }
                    if (BuildVars.LOGS_ENABLED) {
                        FileLog.e("eglMakeCurrent failed " + GLUtils.getEGLErrorString(this.egl10.eglGetError()));
                    }
                    finish();
                    return false;
                }
                finish();
                return false;
            }
            if (BuildVars.LOGS_ENABLED) {
                FileLog.e("eglConfig not initialized");
            }
            finish();
            return false;
        }

        public void finish() {
            if (this.eglSurface != null) {
                this.egl10.eglMakeCurrent(this.eglDisplay, EGL10.EGL_NO_SURFACE, EGL10.EGL_NO_SURFACE, EGL10.EGL_NO_CONTEXT);
                this.egl10.eglDestroySurface(this.eglDisplay, this.eglSurface);
                this.eglSurface = null;
            }
            EGLContext eGLContext = this.eglContext;
            if (eGLContext != null) {
                this.egl10.eglDestroyContext(this.eglDisplay, eGLContext);
                this.eglContext = null;
            }
            EGLDisplay eGLDisplay = this.eglDisplay;
            if (eGLDisplay != null) {
                this.egl10.eglTerminate(eGLDisplay);
                this.eglDisplay = null;
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void drawEnhancePass() {
            if (!this.hsvGenerated) {
                GLES20.glBindFramebuffer(36160, this.renderFrameBuffer[0]);
                GLES20.glFramebufferTexture2D(36160, 36064, 3553, this.renderTexture[0], 0);
                GLES20.glClear(0);
                GLES20.glUseProgram(this.rgbToHsvShaderProgram);
                GLES20.glActiveTexture(33984);
                GLES20.glBindTexture(3553, this.renderTexture[1]);
                GLES20.glUniform1i(this.rgbToHsvSourceImageHandle, 0);
                GLES20.glEnableVertexAttribArray(this.rgbToHsvInputTexCoordHandle);
                GLES20.glVertexAttribPointer(this.rgbToHsvInputTexCoordHandle, 2, 5126, false, 8, (Buffer) this.textureBuffer);
                GLES20.glEnableVertexAttribArray(this.rgbToHsvPositionHandle);
                GLES20.glVertexAttribPointer(this.rgbToHsvPositionHandle, 2, 5126, false, 8, (Buffer) this.vertexBuffer);
                GLES20.glDrawArrays(5, 0, 4);
                ByteBuffer hsvBuffer = ByteBuffer.allocateDirect(this.renderBufferWidth * this.renderBufferHeight * 4);
                GLES20.glReadPixels(0, 0, this.renderBufferWidth, this.renderBufferHeight, 6408, 5121, hsvBuffer);
                GLES20.glBindTexture(3553, this.enhanceTextures[0]);
                GLES20.glTexParameteri(3553, 10241, 9729);
                GLES20.glTexParameteri(3553, 10240, 9729);
                GLES20.glTexParameteri(3553, 10242, 33071);
                GLES20.glTexParameteri(3553, 10243, 33071);
                GLES20.glTexImage2D(3553, 0, 6408, this.renderBufferWidth, this.renderBufferHeight, 0, 6408, 5121, hsvBuffer);
                ByteBuffer buffer = null;
                try {
                    buffer = ByteBuffer.allocateDirect(16384);
                } catch (Exception e) {
                    e = e;
                }
                try {
                    Utilities.calcCDT(hsvBuffer, this.renderBufferWidth, this.renderBufferHeight, buffer);
                } catch (Exception e2) {
                    e = e2;
                    FileLog.e(e);
                }
                GLES20.glBindTexture(3553, this.enhanceTextures[1]);
                GLES20.glTexParameteri(3553, 10241, 9729);
                GLES20.glTexParameteri(3553, 10240, 9729);
                GLES20.glTexParameteri(3553, 10242, 33071);
                GLES20.glTexParameteri(3553, 10243, 33071);
                GLES20.glTexImage2D(3553, 0, 6408, 256, 16, 0, 6408, 5121, buffer);
                this.hsvGenerated = true;
            }
            GLES20.glBindFramebuffer(36160, this.renderFrameBuffer[1]);
            GLES20.glFramebufferTexture2D(36160, 36064, 3553, this.renderTexture[1], 0);
            GLES20.glClear(0);
            GLES20.glUseProgram(this.enhanceShaderProgram);
            GLES20.glActiveTexture(33984);
            GLES20.glBindTexture(3553, this.enhanceTextures[0]);
            GLES20.glUniform1i(this.enhanceSourceImageHandle, 0);
            GLES20.glActiveTexture(33985);
            GLES20.glBindTexture(3553, this.enhanceTextures[1]);
            GLES20.glUniform1i(this.enhanceInputImageTexture2Handle, 1);
            if (!PhotoFilterView.this.showOriginal) {
                GLES20.glUniform1f(this.enhanceIntensityHandle, PhotoFilterView.this.getEnhanceValue());
            } else {
                GLES20.glUniform1f(this.enhanceIntensityHandle, 0.0f);
            }
            GLES20.glEnableVertexAttribArray(this.enhanceInputTexCoordHandle);
            GLES20.glVertexAttribPointer(this.enhanceInputTexCoordHandle, 2, 5126, false, 8, (Buffer) this.textureBuffer);
            GLES20.glEnableVertexAttribArray(this.enhancePositionHandle);
            GLES20.glVertexAttribPointer(this.enhancePositionHandle, 2, 5126, false, 8, (Buffer) this.vertexBuffer);
            GLES20.glDrawArrays(5, 0, 4);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void drawSharpenPass() {
            GLES20.glBindFramebuffer(36160, this.renderFrameBuffer[0]);
            GLES20.glFramebufferTexture2D(36160, 36064, 3553, this.renderTexture[0], 0);
            GLES20.glClear(0);
            GLES20.glUseProgram(this.sharpenShaderProgram);
            GLES20.glActiveTexture(33984);
            GLES20.glBindTexture(3553, this.renderTexture[1]);
            GLES20.glUniform1i(this.sharpenSourceImageHandle, 0);
            if (!PhotoFilterView.this.showOriginal) {
                GLES20.glUniform1f(this.sharpenHandle, PhotoFilterView.this.getSharpenValue());
            } else {
                GLES20.glUniform1f(this.sharpenHandle, 0.0f);
            }
            GLES20.glUniform1f(this.sharpenWidthHandle, this.renderBufferWidth);
            GLES20.glUniform1f(this.sharpenHeightHandle, this.renderBufferHeight);
            GLES20.glEnableVertexAttribArray(this.sharpenInputTexCoordHandle);
            GLES20.glVertexAttribPointer(this.sharpenInputTexCoordHandle, 2, 5126, false, 8, (Buffer) this.textureBuffer);
            GLES20.glEnableVertexAttribArray(this.sharpenPositionHandle);
            GLES20.glVertexAttribPointer(this.sharpenPositionHandle, 2, 5126, false, 8, (Buffer) this.vertexInvertBuffer);
            GLES20.glDrawArrays(5, 0, 4);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void drawCustomParamsPass() {
            GLES20.glBindFramebuffer(36160, this.renderFrameBuffer[1]);
            GLES20.glFramebufferTexture2D(36160, 36064, 3553, this.renderTexture[1], 0);
            GLES20.glClear(0);
            GLES20.glUseProgram(this.toolsShaderProgram);
            GLES20.glActiveTexture(33984);
            GLES20.glBindTexture(3553, this.renderTexture[0]);
            GLES20.glUniform1i(this.sourceImageHandle, 0);
            if (!PhotoFilterView.this.showOriginal) {
                GLES20.glUniform1f(this.shadowsHandle, PhotoFilterView.this.getShadowsValue());
                GLES20.glUniform1f(this.highlightsHandle, PhotoFilterView.this.getHighlightsValue());
                GLES20.glUniform1f(this.exposureHandle, PhotoFilterView.this.getExposureValue());
                GLES20.glUniform1f(this.contrastHandle, PhotoFilterView.this.getContrastValue());
                GLES20.glUniform1f(this.saturationHandle, PhotoFilterView.this.getSaturationValue());
                GLES20.glUniform1f(this.warmthHandle, PhotoFilterView.this.getWarmthValue());
                GLES20.glUniform1f(this.vignetteHandle, PhotoFilterView.this.getVignetteValue());
                GLES20.glUniform1f(this.grainHandle, PhotoFilterView.this.getGrainValue());
                GLES20.glUniform1f(this.fadeAmountHandle, PhotoFilterView.this.getFadeValue());
                GLES20.glUniform3f(this.highlightsTintColorHandle, ((PhotoFilterView.this.tintHighlightsColor >> 16) & 255) / 255.0f, ((PhotoFilterView.this.tintHighlightsColor >> 8) & 255) / 255.0f, (PhotoFilterView.this.tintHighlightsColor & 255) / 255.0f);
                GLES20.glUniform1f(this.highlightsTintIntensityHandle, PhotoFilterView.this.getTintHighlightsIntensityValue());
                GLES20.glUniform3f(this.shadowsTintColorHandle, ((PhotoFilterView.this.tintShadowsColor >> 16) & 255) / 255.0f, ((PhotoFilterView.this.tintShadowsColor >> 8) & 255) / 255.0f, (PhotoFilterView.this.tintShadowsColor & 255) / 255.0f);
                GLES20.glUniform1f(this.shadowsTintIntensityHandle, PhotoFilterView.this.getTintShadowsIntensityValue());
                boolean skipTone = PhotoFilterView.this.curvesToolValue.shouldBeSkipped();
                GLES20.glUniform1f(this.skipToneHandle, skipTone ? 1.0f : 0.0f);
                if (!skipTone) {
                    PhotoFilterView.this.curvesToolValue.fillBuffer();
                    GLES20.glActiveTexture(33985);
                    GLES20.glBindTexture(3553, this.curveTextures[0]);
                    GLES20.glTexParameteri(3553, 10241, 9729);
                    GLES20.glTexParameteri(3553, 10240, 9729);
                    GLES20.glTexParameteri(3553, 10242, 33071);
                    GLES20.glTexParameteri(3553, 10243, 33071);
                    GLES20.glTexImage2D(3553, 0, 6408, ItemTouchHelper.Callback.DEFAULT_DRAG_ANIMATION_DURATION, 1, 0, 6408, 5121, PhotoFilterView.this.curvesToolValue.curveBuffer);
                    GLES20.glUniform1i(this.curvesImageHandle, 1);
                }
            } else {
                GLES20.glUniform1f(this.shadowsHandle, 1.0f);
                GLES20.glUniform1f(this.highlightsHandle, 1.0f);
                GLES20.glUniform1f(this.exposureHandle, 0.0f);
                GLES20.glUniform1f(this.contrastHandle, 1.0f);
                GLES20.glUniform1f(this.saturationHandle, 1.0f);
                GLES20.glUniform1f(this.warmthHandle, 0.0f);
                GLES20.glUniform1f(this.vignetteHandle, 0.0f);
                GLES20.glUniform1f(this.grainHandle, 0.0f);
                GLES20.glUniform1f(this.fadeAmountHandle, 0.0f);
                GLES20.glUniform3f(this.highlightsTintColorHandle, 0.0f, 0.0f, 0.0f);
                GLES20.glUniform1f(this.highlightsTintIntensityHandle, 0.0f);
                GLES20.glUniform3f(this.shadowsTintColorHandle, 0.0f, 0.0f, 0.0f);
                GLES20.glUniform1f(this.shadowsTintIntensityHandle, 0.0f);
                GLES20.glUniform1f(this.skipToneHandle, 1.0f);
            }
            GLES20.glUniform1f(this.widthHandle, this.renderBufferWidth);
            GLES20.glUniform1f(this.heightHandle, this.renderBufferHeight);
            GLES20.glEnableVertexAttribArray(this.inputTexCoordHandle);
            GLES20.glVertexAttribPointer(this.inputTexCoordHandle, 2, 5126, false, 8, (Buffer) this.textureBuffer);
            GLES20.glEnableVertexAttribArray(this.positionHandle);
            GLES20.glVertexAttribPointer(this.positionHandle, 2, 5126, false, 8, (Buffer) this.vertexInvertBuffer);
            GLES20.glDrawArrays(5, 0, 4);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public boolean drawBlurPass() {
            if (PhotoFilterView.this.showOriginal || PhotoFilterView.this.blurType == 0) {
                return false;
            }
            if (this.needUpdateBlurTexture) {
                GLES20.glUseProgram(this.blurShaderProgram);
                GLES20.glUniform1i(this.blurSourceImageHandle, 0);
                GLES20.glEnableVertexAttribArray(this.blurInputTexCoordHandle);
                GLES20.glVertexAttribPointer(this.blurInputTexCoordHandle, 2, 5126, false, 8, (Buffer) this.textureBuffer);
                GLES20.glEnableVertexAttribArray(this.blurPositionHandle);
                GLES20.glVertexAttribPointer(this.blurPositionHandle, 2, 5126, false, 8, (Buffer) this.vertexInvertBuffer);
                GLES20.glBindFramebuffer(36160, this.renderFrameBuffer[0]);
                GLES20.glFramebufferTexture2D(36160, 36064, 3553, this.renderTexture[0], 0);
                GLES20.glClear(0);
                GLES20.glActiveTexture(33984);
                GLES20.glBindTexture(3553, this.renderTexture[1]);
                GLES20.glUniform1f(this.blurWidthHandle, 0.0f);
                GLES20.glUniform1f(this.blurHeightHandle, 1.0f / this.renderBufferHeight);
                GLES20.glDrawArrays(5, 0, 4);
                GLES20.glBindFramebuffer(36160, this.renderFrameBuffer[2]);
                GLES20.glFramebufferTexture2D(36160, 36064, 3553, this.renderTexture[2], 0);
                GLES20.glClear(0);
                GLES20.glActiveTexture(33984);
                GLES20.glBindTexture(3553, this.renderTexture[0]);
                GLES20.glUniform1f(this.blurWidthHandle, 1.0f / this.renderBufferWidth);
                GLES20.glUniform1f(this.blurHeightHandle, 0.0f);
                GLES20.glDrawArrays(5, 0, 4);
                this.needUpdateBlurTexture = false;
            }
            GLES20.glBindFramebuffer(36160, this.renderFrameBuffer[0]);
            GLES20.glFramebufferTexture2D(36160, 36064, 3553, this.renderTexture[0], 0);
            GLES20.glClear(0);
            if (PhotoFilterView.this.blurType != 1) {
                if (PhotoFilterView.this.blurType == 2) {
                    GLES20.glUseProgram(this.linearBlurShaderProgram);
                    GLES20.glUniform1i(this.linearBlurSourceImageHandle, 0);
                    GLES20.glUniform1i(this.linearBlurSourceImage2Handle, 1);
                    GLES20.glUniform1f(this.linearBlurExcludeSizeHandle, PhotoFilterView.this.blurExcludeSize);
                    GLES20.glUniform1f(this.linearBlurExcludeBlurSizeHandle, PhotoFilterView.this.blurExcludeBlurSize);
                    GLES20.glUniform1f(this.linearBlurAngleHandle, PhotoFilterView.this.blurAngle);
                    GLES20.glUniform2f(this.linearBlurExcludePointHandle, PhotoFilterView.this.blurExcludePoint.x, PhotoFilterView.this.blurExcludePoint.y);
                    GLES20.glUniform1f(this.linearBlurAspectRatioHandle, this.renderBufferHeight / this.renderBufferWidth);
                    GLES20.glEnableVertexAttribArray(this.linearBlurInputTexCoordHandle);
                    GLES20.glVertexAttribPointer(this.linearBlurInputTexCoordHandle, 2, 5126, false, 8, (Buffer) this.textureBuffer);
                    GLES20.glEnableVertexAttribArray(this.linearBlurPositionHandle);
                    GLES20.glVertexAttribPointer(this.linearBlurPositionHandle, 2, 5126, false, 8, (Buffer) this.vertexInvertBuffer);
                }
            } else {
                GLES20.glUseProgram(this.radialBlurShaderProgram);
                GLES20.glUniform1i(this.radialBlurSourceImageHandle, 0);
                GLES20.glUniform1i(this.radialBlurSourceImage2Handle, 1);
                GLES20.glUniform1f(this.radialBlurExcludeSizeHandle, PhotoFilterView.this.blurExcludeSize);
                GLES20.glUniform1f(this.radialBlurExcludeBlurSizeHandle, PhotoFilterView.this.blurExcludeBlurSize);
                GLES20.glUniform2f(this.radialBlurExcludePointHandle, PhotoFilterView.this.blurExcludePoint.x, PhotoFilterView.this.blurExcludePoint.y);
                GLES20.glUniform1f(this.radialBlurAspectRatioHandle, this.renderBufferHeight / this.renderBufferWidth);
                GLES20.glEnableVertexAttribArray(this.radialBlurInputTexCoordHandle);
                GLES20.glVertexAttribPointer(this.radialBlurInputTexCoordHandle, 2, 5126, false, 8, (Buffer) this.textureBuffer);
                GLES20.glEnableVertexAttribArray(this.radialBlurPositionHandle);
                GLES20.glVertexAttribPointer(this.radialBlurPositionHandle, 2, 5126, false, 8, (Buffer) this.vertexInvertBuffer);
            }
            GLES20.glActiveTexture(33984);
            GLES20.glBindTexture(3553, this.renderTexture[1]);
            GLES20.glActiveTexture(33985);
            GLES20.glBindTexture(3553, this.renderTexture[2]);
            GLES20.glDrawArrays(5, 0, 4);
            return true;
        }

        private Bitmap getRenderBufferBitmap() {
            ByteBuffer buffer = ByteBuffer.allocateDirect(this.renderBufferWidth * this.renderBufferHeight * 4);
            GLES20.glReadPixels(0, 0, this.renderBufferWidth, this.renderBufferHeight, 6408, 5121, buffer);
            Bitmap bitmap = Bitmap.createBitmap(this.renderBufferWidth, this.renderBufferHeight, Bitmap.Config.ARGB_8888);
            bitmap.copyPixelsFromBuffer(buffer);
            return bitmap;
        }

        public Bitmap getTexture() {
            if (!this.initied) {
                return null;
            }
            final CountDownLatch countDownLatch = new CountDownLatch(1);
            final Bitmap[] object = new Bitmap[1];
            try {
                postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$PhotoFilterView$EGLThread$3QYZR_8WIHYboCf65xp5PNG6Wl4
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$getTexture$0$PhotoFilterView$EGLThread(object, countDownLatch);
                    }
                });
                countDownLatch.await();
            } catch (Exception e) {
                FileLog.e(e);
            }
            return object[0];
        }

        public /* synthetic */ void lambda$getTexture$0$PhotoFilterView$EGLThread(Bitmap[] bitmapArr, CountDownLatch countDownLatch) {
            GLES20.glBindFramebuffer(36160, this.renderFrameBuffer[1]);
            GLES20.glFramebufferTexture2D(36160, 36064, 3553, this.renderTexture[1 ^ (this.blured ? 1 : 0)], 0);
            GLES20.glClear(0);
            bitmapArr[0] = getRenderBufferBitmap();
            countDownLatch.countDown();
            GLES20.glBindFramebuffer(36160, 0);
            GLES20.glClear(0);
        }

        private Bitmap createBitmap(Bitmap bitmap, int w, int h, float scale) {
            Matrix matrix = new Matrix();
            matrix.setScale(scale, scale);
            matrix.postRotate(PhotoFilterView.this.orientation);
            return Bitmap.createBitmap(bitmap, 0, 0, bitmap.getWidth(), bitmap.getHeight(), matrix, true);
        }

        private void loadTexture(Bitmap bitmap) {
            this.renderBufferWidth = bitmap.getWidth();
            this.renderBufferHeight = bitmap.getHeight();
            float maxSize = AndroidUtilities.getPhotoSize();
            if (this.renderBufferWidth > maxSize || this.renderBufferHeight > maxSize || PhotoFilterView.this.orientation % 360 != 0) {
                float scale = 1.0f;
                if (this.renderBufferWidth > maxSize || this.renderBufferHeight > maxSize) {
                    float scaleX = maxSize / bitmap.getWidth();
                    float scaleY = maxSize / bitmap.getHeight();
                    if (scaleX < scaleY) {
                        this.renderBufferWidth = (int) maxSize;
                        this.renderBufferHeight = (int) (bitmap.getHeight() * scaleX);
                        scale = scaleX;
                    } else {
                        this.renderBufferHeight = (int) maxSize;
                        this.renderBufferWidth = (int) (bitmap.getWidth() * scaleY);
                        scale = scaleY;
                    }
                }
                if (PhotoFilterView.this.orientation % 360 == 90 || PhotoFilterView.this.orientation % 360 == 270) {
                    int temp = this.renderBufferWidth;
                    this.renderBufferWidth = this.renderBufferHeight;
                    this.renderBufferHeight = temp;
                }
                int temp2 = this.renderBufferWidth;
                this.currentBitmap = createBitmap(bitmap, temp2, this.renderBufferHeight, scale);
            }
            GLES20.glGenFramebuffers(3, this.renderFrameBuffer, 0);
            GLES20.glGenTextures(3, this.renderTexture, 0);
            GLES20.glBindTexture(3553, this.renderTexture[0]);
            GLES20.glTexParameteri(3553, 10241, 9729);
            GLES20.glTexParameteri(3553, 10240, 9729);
            GLES20.glTexParameteri(3553, 10242, 33071);
            GLES20.glTexParameteri(3553, 10243, 33071);
            GLES20.glTexImage2D(3553, 0, 6408, this.renderBufferWidth, this.renderBufferHeight, 0, 6408, 5121, null);
            GLES20.glBindTexture(3553, this.renderTexture[1]);
            GLES20.glTexParameteri(3553, 10241, 9729);
            GLES20.glTexParameteri(3553, 10240, 9729);
            GLES20.glTexParameteri(3553, 10242, 33071);
            GLES20.glTexParameteri(3553, 10243, 33071);
            GLUtils.texImage2D(3553, 0, this.currentBitmap, 0);
            GLES20.glBindTexture(3553, this.renderTexture[2]);
            GLES20.glTexParameteri(3553, 10241, 9729);
            GLES20.glTexParameteri(3553, 10240, 9729);
            GLES20.glTexParameteri(3553, 10242, 33071);
            GLES20.glTexParameteri(3553, 10243, 33071);
            GLES20.glTexImage2D(3553, 0, 6408, this.renderBufferWidth, this.renderBufferHeight, 0, 6408, 5121, null);
        }

        public void shutdown() {
            postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$PhotoFilterView$EGLThread$ZSnH1cxavCIzLb7njIzK0M07yl0
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$shutdown$1$PhotoFilterView$EGLThread();
                }
            });
        }

        public /* synthetic */ void lambda$shutdown$1$PhotoFilterView$EGLThread() {
            finish();
            this.currentBitmap = null;
            Looper looper = Looper.myLooper();
            if (looper != null) {
                looper.quit();
            }
        }

        public void setSurfaceTextureSize(int width, int height) {
            this.surfaceWidth = width;
            this.surfaceHeight = height;
        }

        @Override // im.uwrkaxlmjj.messenger.DispatchQueue, java.lang.Thread, java.lang.Runnable
        public void run() {
            this.initied = initGL();
            super.run();
        }

        public void requestRender(boolean updateBlur) {
            requestRender(updateBlur, false);
        }

        public void requestRender(final boolean updateBlur, final boolean force) {
            postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$PhotoFilterView$EGLThread$ivr1HpslXuV4x-b6tGoGiL9UAUI
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$requestRender$2$PhotoFilterView$EGLThread(updateBlur, force);
                }
            });
        }

        public /* synthetic */ void lambda$requestRender$2$PhotoFilterView$EGLThread(boolean updateBlur, boolean force) {
            if (!this.needUpdateBlurTexture) {
                this.needUpdateBlurTexture = updateBlur;
            }
            long newTime = System.currentTimeMillis();
            if (force || Math.abs(this.lastRenderCallTime - newTime) > 30) {
                this.lastRenderCallTime = newTime;
                this.drawRunnable.run();
            }
        }
    }

    public PhotoFilterView(Context context, Bitmap bitmap, int rotation, MediaController.SavedFilterState state) {
        super(context);
        this.enhanceTool = 0;
        this.exposureTool = 1;
        this.contrastTool = 2;
        this.saturationTool = 3;
        this.warmthTool = 4;
        this.fadeTool = 5;
        this.highlightsTool = 6;
        this.shadowsTool = 7;
        this.vignetteTool = 8;
        this.grainTool = 9;
        this.sharpenTool = 10;
        this.tintShadowsTool = 11;
        this.tintHighlightsTool = 12;
        this.curveRadioButton = new RadioButton[4];
        if (state != null) {
            this.enhanceValue = state.enhanceValue;
            this.exposureValue = state.exposureValue;
            this.contrastValue = state.contrastValue;
            this.warmthValue = state.warmthValue;
            this.saturationValue = state.saturationValue;
            this.fadeValue = state.fadeValue;
            this.tintShadowsColor = state.tintShadowsColor;
            this.tintHighlightsColor = state.tintHighlightsColor;
            this.highlightsValue = state.highlightsValue;
            this.shadowsValue = state.shadowsValue;
            this.vignetteValue = state.vignetteValue;
            this.grainValue = state.grainValue;
            this.blurType = state.blurType;
            this.sharpenValue = state.sharpenValue;
            this.curvesToolValue = state.curvesToolValue;
            this.blurExcludeSize = state.blurExcludeSize;
            this.blurExcludePoint = state.blurExcludePoint;
            this.blurExcludeBlurSize = state.blurExcludeBlurSize;
            this.blurAngle = state.blurAngle;
            this.lastState = state;
        } else {
            this.curvesToolValue = new CurvesToolValue();
            this.blurExcludeSize = 0.35f;
            this.blurExcludePoint = new Point(0.5f, 0.5f);
            this.blurExcludeBlurSize = 0.15f;
            this.blurAngle = 1.5707964f;
        }
        this.bitmapToEdit = bitmap;
        this.orientation = rotation;
        TextureView textureView = new TextureView(context);
        this.textureView = textureView;
        addView(textureView, LayoutHelper.createFrame(-1, -1, 51));
        this.textureView.setVisibility(4);
        this.textureView.setSurfaceTextureListener(new AnonymousClass1());
        PhotoFilterBlurControl photoFilterBlurControl = new PhotoFilterBlurControl(context);
        this.blurControl = photoFilterBlurControl;
        photoFilterBlurControl.setVisibility(4);
        addView(this.blurControl, LayoutHelper.createFrame(-1, -1, 51));
        this.blurControl.setDelegate(new PhotoFilterBlurControl.PhotoFilterLinearBlurControlDelegate() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$PhotoFilterView$N9DcYjIMAkcD6_1fxNqinuORqM0
            @Override // im.uwrkaxlmjj.ui.components.PhotoFilterBlurControl.PhotoFilterLinearBlurControlDelegate
            public final void valueChanged(Point point, float f, float f2, float f3) {
                this.f$0.lambda$new$0$PhotoFilterView(point, f, f2, f3);
            }
        });
        PhotoFilterCurvesControl photoFilterCurvesControl = new PhotoFilterCurvesControl(context, this.curvesToolValue);
        this.curvesControl = photoFilterCurvesControl;
        photoFilterCurvesControl.setDelegate(new PhotoFilterCurvesControl.PhotoFilterCurvesControlDelegate() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$PhotoFilterView$DkhZc1eNiOUOgHidXn5QyZKP4ks
            @Override // im.uwrkaxlmjj.ui.components.PhotoFilterCurvesControl.PhotoFilterCurvesControlDelegate
            public final void valueChanged() {
                this.f$0.lambda$new$1$PhotoFilterView();
            }
        });
        this.curvesControl.setVisibility(4);
        addView(this.curvesControl, LayoutHelper.createFrame(-1, -1, 51));
        FrameLayout frameLayout = new FrameLayout(context);
        this.toolsView = frameLayout;
        addView(frameLayout, LayoutHelper.createFrame(-1, 186, 83));
        FrameLayout frameLayout2 = new FrameLayout(context);
        frameLayout2.setBackgroundColor(-16777216);
        this.toolsView.addView(frameLayout2, LayoutHelper.createFrame(-1, 48, 83));
        TextView textView = new TextView(context);
        this.cancelTextView = textView;
        textView.setTextSize(1, 14.0f);
        this.cancelTextView.setTextColor(-1);
        this.cancelTextView.setGravity(17);
        this.cancelTextView.setBackgroundDrawable(Theme.createSelectorDrawable(Theme.ACTION_BAR_PICKER_SELECTOR_COLOR, 0));
        this.cancelTextView.setPadding(AndroidUtilities.dp(20.0f), 0, AndroidUtilities.dp(20.0f), 0);
        this.cancelTextView.setText(LocaleController.getString("Cancel", R.string.Cancel).toUpperCase());
        this.cancelTextView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        frameLayout2.addView(this.cancelTextView, LayoutHelper.createFrame(-2, -1, 51));
        TextView textView2 = new TextView(context);
        this.doneTextView = textView2;
        textView2.setTextSize(1, 14.0f);
        this.doneTextView.setTextColor(-11420173);
        this.doneTextView.setGravity(17);
        this.doneTextView.setBackgroundDrawable(Theme.createSelectorDrawable(Theme.ACTION_BAR_PICKER_SELECTOR_COLOR, 0));
        this.doneTextView.setPadding(AndroidUtilities.dp(20.0f), 0, AndroidUtilities.dp(20.0f), 0);
        this.doneTextView.setText(LocaleController.getString("Done", R.string.Done).toUpperCase());
        this.doneTextView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        frameLayout2.addView(this.doneTextView, LayoutHelper.createFrame(-2, -1, 53));
        LinearLayout linearLayout = new LinearLayout(context);
        frameLayout2.addView(linearLayout, LayoutHelper.createFrame(-2, -1, 1));
        ImageView imageView = new ImageView(context);
        this.tuneItem = imageView;
        imageView.setScaleType(ImageView.ScaleType.CENTER);
        this.tuneItem.setImageResource(R.drawable.photo_tools);
        this.tuneItem.setColorFilter(new PorterDuffColorFilter(-9649153, PorterDuff.Mode.MULTIPLY));
        this.tuneItem.setBackgroundDrawable(Theme.createSelectorDrawable(Theme.ACTION_BAR_WHITE_SELECTOR_COLOR));
        linearLayout.addView(this.tuneItem, LayoutHelper.createLinear(56, 48));
        this.tuneItem.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$PhotoFilterView$bRAhGLdJMe7zmdzTMn9yMBYtDNs
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$new$2$PhotoFilterView(view);
            }
        });
        ImageView imageView2 = new ImageView(context);
        this.blurItem = imageView2;
        imageView2.setScaleType(ImageView.ScaleType.CENTER);
        this.blurItem.setImageResource(R.drawable.tool_blur);
        this.blurItem.setBackgroundDrawable(Theme.createSelectorDrawable(Theme.ACTION_BAR_WHITE_SELECTOR_COLOR));
        linearLayout.addView(this.blurItem, LayoutHelper.createLinear(56, 48));
        this.blurItem.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$PhotoFilterView$d9vri662sVB_JTjbOaOcpz-6zko
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$new$3$PhotoFilterView(view);
            }
        });
        ImageView imageView3 = new ImageView(context);
        this.curveItem = imageView3;
        imageView3.setScaleType(ImageView.ScaleType.CENTER);
        this.curveItem.setImageResource(R.drawable.tool_curve);
        this.curveItem.setBackgroundDrawable(Theme.createSelectorDrawable(Theme.ACTION_BAR_WHITE_SELECTOR_COLOR));
        linearLayout.addView(this.curveItem, LayoutHelper.createLinear(56, 48));
        this.curveItem.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$PhotoFilterView$Q0PO8tJSRrTGIDIbI989bY3eJJw
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$new$4$PhotoFilterView(view);
            }
        });
        this.recyclerListView = new RecyclerListView(context);
        LinearLayoutManager layoutManager = new LinearLayoutManager(context);
        layoutManager.setOrientation(1);
        this.recyclerListView.setLayoutManager(layoutManager);
        this.recyclerListView.setClipToPadding(false);
        this.recyclerListView.setOverScrollMode(2);
        this.recyclerListView.setAdapter(new ToolsAdapter(context));
        this.toolsView.addView(this.recyclerListView, LayoutHelper.createFrame(-1, 120, 51));
        FrameLayout frameLayout3 = new FrameLayout(context);
        this.curveLayout = frameLayout3;
        frameLayout3.setVisibility(4);
        this.toolsView.addView(this.curveLayout, LayoutHelper.createFrame(-1.0f, 78.0f, 1, 0.0f, 40.0f, 0.0f, 0.0f));
        LinearLayout linearLayout2 = new LinearLayout(context);
        linearLayout2.setOrientation(0);
        this.curveLayout.addView(linearLayout2, LayoutHelper.createFrame(-2, -2, 1));
        int a = 0;
        while (a < 4) {
            FrameLayout frameLayout1 = new FrameLayout(context);
            frameLayout1.setTag(Integer.valueOf(a));
            this.curveRadioButton[a] = new RadioButton(context);
            this.curveRadioButton[a].setSize(AndroidUtilities.dp(20.0f));
            frameLayout1.addView(this.curveRadioButton[a], LayoutHelper.createFrame(30, 30, 49));
            TextView curveTextView = new TextView(context);
            curveTextView.setTextSize(1, 12.0f);
            curveTextView.setGravity(16);
            if (a != 0) {
                if (a == 1) {
                    String str = LocaleController.getString("CurvesRed", R.string.CurvesRed);
                    curveTextView.setText(str.substring(0, 1).toUpperCase() + str.substring(1).toLowerCase());
                    curveTextView.setTextColor(-1684147);
                    this.curveRadioButton[a].setColor(-1684147, -1684147);
                } else if (a == 2) {
                    String str2 = LocaleController.getString("CurvesGreen", R.string.CurvesGreen);
                    curveTextView.setText(str2.substring(0, 1).toUpperCase() + str2.substring(1).toLowerCase());
                    curveTextView.setTextColor(-10831009);
                    this.curveRadioButton[a].setColor(-10831009, -10831009);
                } else if (a == 3) {
                    String str3 = LocaleController.getString("CurvesBlue", R.string.CurvesBlue);
                    curveTextView.setText(str3.substring(0, 1).toUpperCase() + str3.substring(1).toLowerCase());
                    curveTextView.setTextColor(-12734994);
                    this.curveRadioButton[a].setColor(-12734994, -12734994);
                }
            } else {
                String str4 = LocaleController.getString("CurvesAll", R.string.CurvesAll);
                curveTextView.setText(str4.substring(0, 1).toUpperCase() + str4.substring(1).toLowerCase());
                curveTextView.setTextColor(-1);
                this.curveRadioButton[a].setColor(-1, -1);
            }
            frameLayout1.addView(curveTextView, LayoutHelper.createFrame(-2.0f, -2.0f, 49, 0.0f, 38.0f, 0.0f, 0.0f));
            linearLayout2.addView(frameLayout1, LayoutHelper.createLinear(-2, -2, a == 0 ? 0.0f : 30.0f, 0.0f, 0.0f, 0.0f));
            frameLayout1.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$PhotoFilterView$uFcf-9VrGHFxPdMiaOnP5MMuLoY
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    this.f$0.lambda$new$5$PhotoFilterView(view);
                }
            });
            a++;
        }
        FrameLayout frameLayout4 = new FrameLayout(context);
        this.blurLayout = frameLayout4;
        frameLayout4.setVisibility(4);
        this.toolsView.addView(this.blurLayout, LayoutHelper.createFrame(280.0f, 60.0f, 1, 0.0f, 40.0f, 0.0f, 0.0f));
        TextView textView3 = new TextView(context);
        this.blurOffButton = textView3;
        textView3.setCompoundDrawablePadding(AndroidUtilities.dp(2.0f));
        this.blurOffButton.setTextSize(1, 13.0f);
        this.blurOffButton.setGravity(1);
        this.blurOffButton.setText(LocaleController.getString("BlurOff", R.string.BlurOff));
        this.blurLayout.addView(this.blurOffButton, LayoutHelper.createFrame(80, 60.0f));
        this.blurOffButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$PhotoFilterView$rGUKkMp_-aQETg_TYGz-jxkehpg
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$new$6$PhotoFilterView(view);
            }
        });
        TextView textView4 = new TextView(context);
        this.blurRadialButton = textView4;
        textView4.setCompoundDrawablePadding(AndroidUtilities.dp(2.0f));
        this.blurRadialButton.setTextSize(1, 13.0f);
        this.blurRadialButton.setGravity(1);
        this.blurRadialButton.setText(LocaleController.getString("BlurRadial", R.string.BlurRadial));
        this.blurLayout.addView(this.blurRadialButton, LayoutHelper.createFrame(80.0f, 80.0f, 51, 100.0f, 0.0f, 0.0f, 0.0f));
        this.blurRadialButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$PhotoFilterView$st9hxNM1abO2IoytLAVRIkCzxNs
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$new$7$PhotoFilterView(view);
            }
        });
        TextView textView5 = new TextView(context);
        this.blurLinearButton = textView5;
        textView5.setCompoundDrawablePadding(AndroidUtilities.dp(2.0f));
        this.blurLinearButton.setTextSize(1, 13.0f);
        this.blurLinearButton.setGravity(1);
        this.blurLinearButton.setText(LocaleController.getString("BlurLinear", R.string.BlurLinear));
        this.blurLayout.addView(this.blurLinearButton, LayoutHelper.createFrame(80.0f, 80.0f, 51, 200.0f, 0.0f, 0.0f, 0.0f));
        this.blurLinearButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$PhotoFilterView$4AH4JvMnI9FRVUxNJ9kdu2dlouo
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$new$8$PhotoFilterView(view);
            }
        });
        updateSelectedBlurType();
        if (Build.VERSION.SDK_INT >= 21) {
            ((FrameLayout.LayoutParams) this.textureView.getLayoutParams()).topMargin = AndroidUtilities.statusBarHeight;
            ((FrameLayout.LayoutParams) this.curvesControl.getLayoutParams()).topMargin = AndroidUtilities.statusBarHeight;
        }
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.components.PhotoFilterView$1, reason: invalid class name */
    class AnonymousClass1 implements TextureView.SurfaceTextureListener {
        AnonymousClass1() {
        }

        @Override // android.view.TextureView.SurfaceTextureListener
        public void onSurfaceTextureAvailable(SurfaceTexture surface, int width, int height) {
            if (PhotoFilterView.this.eglThread == null && surface != null) {
                PhotoFilterView photoFilterView = PhotoFilterView.this;
                PhotoFilterView photoFilterView2 = PhotoFilterView.this;
                photoFilterView.eglThread = photoFilterView2.new EGLThread(surface, photoFilterView2.bitmapToEdit);
                PhotoFilterView.this.eglThread.setSurfaceTextureSize(width, height);
                PhotoFilterView.this.eglThread.requestRender(true, true);
            }
        }

        @Override // android.view.TextureView.SurfaceTextureListener
        public void onSurfaceTextureSizeChanged(SurfaceTexture surface, int width, int height) {
            if (PhotoFilterView.this.eglThread != null) {
                PhotoFilterView.this.eglThread.setSurfaceTextureSize(width, height);
                PhotoFilterView.this.eglThread.requestRender(false, true);
                PhotoFilterView.this.eglThread.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$PhotoFilterView$1$Ll7nxttodaAdRsFtDtI3dhmYyCI
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$onSurfaceTextureSizeChanged$0$PhotoFilterView$1();
                    }
                });
            }
        }

        public /* synthetic */ void lambda$onSurfaceTextureSizeChanged$0$PhotoFilterView$1() {
            if (PhotoFilterView.this.eglThread != null) {
                PhotoFilterView.this.eglThread.requestRender(false, true);
            }
        }

        @Override // android.view.TextureView.SurfaceTextureListener
        public boolean onSurfaceTextureDestroyed(SurfaceTexture surface) {
            if (PhotoFilterView.this.eglThread != null) {
                PhotoFilterView.this.eglThread.shutdown();
                PhotoFilterView.this.eglThread = null;
                return true;
            }
            return true;
        }

        @Override // android.view.TextureView.SurfaceTextureListener
        public void onSurfaceTextureUpdated(SurfaceTexture surface) {
        }
    }

    public /* synthetic */ void lambda$new$0$PhotoFilterView(Point centerPoint, float falloff, float size, float angle) {
        this.blurExcludeSize = size;
        this.blurExcludePoint = centerPoint;
        this.blurExcludeBlurSize = falloff;
        this.blurAngle = angle;
        EGLThread eGLThread = this.eglThread;
        if (eGLThread != null) {
            eGLThread.requestRender(false);
        }
    }

    public /* synthetic */ void lambda$new$1$PhotoFilterView() {
        EGLThread eGLThread = this.eglThread;
        if (eGLThread != null) {
            eGLThread.requestRender(false);
        }
    }

    public /* synthetic */ void lambda$new$2$PhotoFilterView(View v) {
        this.selectedTool = 0;
        this.tuneItem.setColorFilter(new PorterDuffColorFilter(-9649153, PorterDuff.Mode.MULTIPLY));
        this.blurItem.setColorFilter((ColorFilter) null);
        this.curveItem.setColorFilter((ColorFilter) null);
        switchMode();
    }

    public /* synthetic */ void lambda$new$3$PhotoFilterView(View v) {
        this.selectedTool = 1;
        this.tuneItem.setColorFilter((ColorFilter) null);
        this.blurItem.setColorFilter(new PorterDuffColorFilter(-9649153, PorterDuff.Mode.MULTIPLY));
        this.curveItem.setColorFilter((ColorFilter) null);
        switchMode();
    }

    public /* synthetic */ void lambda$new$4$PhotoFilterView(View v) {
        this.selectedTool = 2;
        this.tuneItem.setColorFilter((ColorFilter) null);
        this.blurItem.setColorFilter((ColorFilter) null);
        this.curveItem.setColorFilter(new PorterDuffColorFilter(-9649153, PorterDuff.Mode.MULTIPLY));
        switchMode();
    }

    public /* synthetic */ void lambda$new$5$PhotoFilterView(View v) {
        int num = ((Integer) v.getTag()).intValue();
        this.curvesToolValue.activeType = num;
        int a1 = 0;
        while (a1 < 4) {
            this.curveRadioButton[a1].setChecked(a1 == num, true);
            a1++;
        }
        this.curvesControl.invalidate();
    }

    public /* synthetic */ void lambda$new$6$PhotoFilterView(View v) {
        this.blurType = 0;
        updateSelectedBlurType();
        this.blurControl.setVisibility(4);
        EGLThread eGLThread = this.eglThread;
        if (eGLThread != null) {
            eGLThread.requestRender(false);
        }
    }

    public /* synthetic */ void lambda$new$7$PhotoFilterView(View v) {
        this.blurType = 1;
        updateSelectedBlurType();
        this.blurControl.setVisibility(0);
        this.blurControl.setType(1);
        EGLThread eGLThread = this.eglThread;
        if (eGLThread != null) {
            eGLThread.requestRender(false);
        }
    }

    public /* synthetic */ void lambda$new$8$PhotoFilterView(View v) {
        this.blurType = 2;
        updateSelectedBlurType();
        this.blurControl.setVisibility(0);
        this.blurControl.setType(0);
        EGLThread eGLThread = this.eglThread;
        if (eGLThread != null) {
            eGLThread.requestRender(false);
        }
    }

    private void updateSelectedBlurType() {
        int i = this.blurType;
        if (i == 0) {
            Drawable drawable = this.blurOffButton.getContext().getResources().getDrawable(R.drawable.blur_off).mutate();
            drawable.setColorFilter(new PorterDuffColorFilter(-11420173, PorterDuff.Mode.MULTIPLY));
            this.blurOffButton.setCompoundDrawablesWithIntrinsicBounds((Drawable) null, drawable, (Drawable) null, (Drawable) null);
            this.blurOffButton.setTextColor(-11420173);
            this.blurRadialButton.setCompoundDrawablesWithIntrinsicBounds(0, R.drawable.blur_radial, 0, 0);
            this.blurRadialButton.setTextColor(-1);
            this.blurLinearButton.setCompoundDrawablesWithIntrinsicBounds(0, R.drawable.blur_linear, 0, 0);
            this.blurLinearButton.setTextColor(-1);
            return;
        }
        if (i == 1) {
            this.blurOffButton.setCompoundDrawablesWithIntrinsicBounds(0, R.drawable.blur_off, 0, 0);
            this.blurOffButton.setTextColor(-1);
            Drawable drawable2 = this.blurOffButton.getContext().getResources().getDrawable(R.drawable.blur_radial).mutate();
            drawable2.setColorFilter(new PorterDuffColorFilter(-11420173, PorterDuff.Mode.MULTIPLY));
            this.blurRadialButton.setCompoundDrawablesWithIntrinsicBounds((Drawable) null, drawable2, (Drawable) null, (Drawable) null);
            this.blurRadialButton.setTextColor(-11420173);
            this.blurLinearButton.setCompoundDrawablesWithIntrinsicBounds(0, R.drawable.blur_linear, 0, 0);
            this.blurLinearButton.setTextColor(-1);
            return;
        }
        if (i == 2) {
            this.blurOffButton.setCompoundDrawablesWithIntrinsicBounds(0, R.drawable.blur_off, 0, 0);
            this.blurOffButton.setTextColor(-1);
            this.blurRadialButton.setCompoundDrawablesWithIntrinsicBounds(0, R.drawable.blur_radial, 0, 0);
            this.blurRadialButton.setTextColor(-1);
            Drawable drawable3 = this.blurOffButton.getContext().getResources().getDrawable(R.drawable.blur_linear).mutate();
            drawable3.setColorFilter(new PorterDuffColorFilter(-11420173, PorterDuff.Mode.MULTIPLY));
            this.blurLinearButton.setCompoundDrawablesWithIntrinsicBounds((Drawable) null, drawable3, (Drawable) null, (Drawable) null);
            this.blurLinearButton.setTextColor(-11420173);
        }
    }

    public MediaController.SavedFilterState getSavedFilterState() {
        MediaController.SavedFilterState state = new MediaController.SavedFilterState();
        state.enhanceValue = this.enhanceValue;
        state.exposureValue = this.exposureValue;
        state.contrastValue = this.contrastValue;
        state.warmthValue = this.warmthValue;
        state.saturationValue = this.saturationValue;
        state.fadeValue = this.fadeValue;
        state.tintShadowsColor = this.tintShadowsColor;
        state.tintHighlightsColor = this.tintHighlightsColor;
        state.highlightsValue = this.highlightsValue;
        state.shadowsValue = this.shadowsValue;
        state.vignetteValue = this.vignetteValue;
        state.grainValue = this.grainValue;
        state.blurType = this.blurType;
        state.sharpenValue = this.sharpenValue;
        state.curvesToolValue = this.curvesToolValue;
        state.blurExcludeSize = this.blurExcludeSize;
        state.blurExcludePoint = this.blurExcludePoint;
        state.blurExcludeBlurSize = this.blurExcludeBlurSize;
        state.blurAngle = this.blurAngle;
        return state;
    }

    public boolean hasChanges() {
        MediaController.SavedFilterState savedFilterState = this.lastState;
        return savedFilterState != null ? (this.enhanceValue == savedFilterState.enhanceValue && this.contrastValue == this.lastState.contrastValue && this.highlightsValue == this.lastState.highlightsValue && this.exposureValue == this.lastState.exposureValue && this.warmthValue == this.lastState.warmthValue && this.saturationValue == this.lastState.saturationValue && this.vignetteValue == this.lastState.vignetteValue && this.shadowsValue == this.lastState.shadowsValue && this.grainValue == this.lastState.grainValue && this.sharpenValue == this.lastState.sharpenValue && this.fadeValue == this.lastState.fadeValue && this.tintHighlightsColor == this.lastState.tintHighlightsColor && this.tintShadowsColor == this.lastState.tintShadowsColor && this.curvesToolValue.shouldBeSkipped()) ? false : true : (this.enhanceValue == 0.0f && this.contrastValue == 0.0f && this.highlightsValue == 0.0f && this.exposureValue == 0.0f && this.warmthValue == 0.0f && this.saturationValue == 0.0f && this.vignetteValue == 0.0f && this.shadowsValue == 0.0f && this.grainValue == 0.0f && this.sharpenValue == 0.0f && this.fadeValue == 0.0f && this.tintHighlightsColor == 0 && this.tintShadowsColor == 0 && this.curvesToolValue.shouldBeSkipped()) ? false : true;
    }

    public void onTouch(MotionEvent event) {
        if (event.getActionMasked() == 0 || event.getActionMasked() == 5) {
            FrameLayout.LayoutParams layoutParams = (FrameLayout.LayoutParams) this.textureView.getLayoutParams();
            if (layoutParams != null && event.getX() >= layoutParams.leftMargin && event.getY() >= layoutParams.topMargin && event.getX() <= layoutParams.leftMargin + layoutParams.width && event.getY() <= layoutParams.topMargin + layoutParams.height) {
                setShowOriginal(true);
                return;
            }
            return;
        }
        if (event.getActionMasked() == 1 || event.getActionMasked() == 6) {
            setShowOriginal(false);
        }
    }

    private void setShowOriginal(boolean value) {
        if (this.showOriginal == value) {
            return;
        }
        this.showOriginal = value;
        EGLThread eGLThread = this.eglThread;
        if (eGLThread != null) {
            eGLThread.requestRender(false);
        }
    }

    public void switchMode() {
        int i = this.selectedTool;
        if (i == 0) {
            this.blurControl.setVisibility(4);
            this.blurLayout.setVisibility(4);
            this.curveLayout.setVisibility(4);
            this.curvesControl.setVisibility(4);
            this.recyclerListView.setVisibility(0);
            return;
        }
        if (i == 1) {
            this.recyclerListView.setVisibility(4);
            this.curveLayout.setVisibility(4);
            this.curvesControl.setVisibility(4);
            this.blurLayout.setVisibility(0);
            if (this.blurType != 0) {
                this.blurControl.setVisibility(0);
            }
            updateSelectedBlurType();
            return;
        }
        if (i == 2) {
            this.recyclerListView.setVisibility(4);
            this.blurLayout.setVisibility(4);
            this.blurControl.setVisibility(4);
            this.curveLayout.setVisibility(0);
            this.curvesControl.setVisibility(0);
            this.curvesToolValue.activeType = 0;
            int a = 0;
            while (a < 4) {
                this.curveRadioButton[a].setChecked(a == 0, false);
                a++;
            }
        }
    }

    public void shutdown() {
        EGLThread eGLThread = this.eglThread;
        if (eGLThread != null) {
            eGLThread.shutdown();
            this.eglThread = null;
        }
        this.textureView.setVisibility(8);
    }

    public void init() {
        this.textureView.setVisibility(0);
    }

    public Bitmap getBitmap() {
        EGLThread eGLThread = this.eglThread;
        if (eGLThread != null) {
            return eGLThread.getTexture();
        }
        return null;
    }

    private void fixLayout(int viewWidth, int viewHeight) {
        float bitmapW;
        float bitmapH;
        float bitmapW2;
        float bitmapH2;
        if (this.bitmapToEdit == null) {
            return;
        }
        int viewWidth2 = viewWidth - AndroidUtilities.dp(28.0f);
        int viewHeight2 = viewHeight - (AndroidUtilities.dp(214.0f) + (Build.VERSION.SDK_INT >= 21 ? AndroidUtilities.statusBarHeight : 0));
        int i = this.orientation;
        if (i % 360 == 90 || i % 360 == 270) {
            bitmapW = this.bitmapToEdit.getHeight();
            bitmapH = this.bitmapToEdit.getWidth();
        } else {
            bitmapW = this.bitmapToEdit.getWidth();
            bitmapH = this.bitmapToEdit.getHeight();
        }
        float scaleX = viewWidth2 / bitmapW;
        float scaleY = viewHeight2 / bitmapH;
        if (scaleX > scaleY) {
            bitmapH2 = viewHeight2;
            bitmapW2 = (int) Math.ceil(bitmapW * scaleY);
        } else {
            bitmapW2 = viewWidth2;
            bitmapH2 = (int) Math.ceil(bitmapH * scaleX);
        }
        int bitmapX = (int) Math.ceil(((viewWidth2 - bitmapW2) / 2.0f) + AndroidUtilities.dp(14.0f));
        int bitmapY = (int) Math.ceil(((viewHeight2 - bitmapH2) / 2.0f) + AndroidUtilities.dp(14.0f) + (Build.VERSION.SDK_INT >= 21 ? AndroidUtilities.statusBarHeight : 0));
        FrameLayout.LayoutParams layoutParams = (FrameLayout.LayoutParams) this.textureView.getLayoutParams();
        layoutParams.leftMargin = bitmapX;
        layoutParams.topMargin = bitmapY;
        layoutParams.width = (int) bitmapW2;
        layoutParams.height = (int) bitmapH2;
        this.curvesControl.setActualArea(bitmapX, bitmapY - (Build.VERSION.SDK_INT >= 21 ? AndroidUtilities.statusBarHeight : 0), layoutParams.width, layoutParams.height);
        this.blurControl.setActualAreaSize(layoutParams.width, layoutParams.height);
        ((FrameLayout.LayoutParams) this.blurControl.getLayoutParams()).height = AndroidUtilities.dp(38.0f) + viewHeight2;
        ((FrameLayout.LayoutParams) this.curvesControl.getLayoutParams()).height = AndroidUtilities.dp(28.0f) + viewHeight2;
        if (AndroidUtilities.isTablet()) {
            int total = AndroidUtilities.dp(86.0f) * 10;
            FrameLayout.LayoutParams layoutParams2 = (FrameLayout.LayoutParams) this.recyclerListView.getLayoutParams();
            if (total < viewWidth2) {
                layoutParams2.width = total;
                layoutParams2.leftMargin = (viewWidth2 - total) / 2;
            } else {
                layoutParams2.width = -1;
                layoutParams2.leftMargin = 0;
            }
        }
    }

    @Override // android.widget.FrameLayout, android.view.View
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        fixLayout(View.MeasureSpec.getSize(widthMeasureSpec), View.MeasureSpec.getSize(heightMeasureSpec));
        super.onMeasure(widthMeasureSpec, heightMeasureSpec);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public float getShadowsValue() {
        return ((this.shadowsValue * 0.55f) + 100.0f) / 100.0f;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public float getHighlightsValue() {
        return ((this.highlightsValue * 0.75f) + 100.0f) / 100.0f;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public float getEnhanceValue() {
        return this.enhanceValue / 100.0f;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public float getExposureValue() {
        return this.exposureValue / 100.0f;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public float getContrastValue() {
        return ((this.contrastValue / 100.0f) * 0.3f) + 1.0f;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public float getWarmthValue() {
        return this.warmthValue / 100.0f;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public float getVignetteValue() {
        return this.vignetteValue / 100.0f;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public float getSharpenValue() {
        return ((this.sharpenValue / 100.0f) * 0.6f) + 0.11f;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public float getGrainValue() {
        return (this.grainValue / 100.0f) * 0.04f;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public float getFadeValue() {
        return this.fadeValue / 100.0f;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public float getTintHighlightsIntensityValue() {
        if (this.tintHighlightsColor == 0) {
            return 0.0f;
        }
        return 50.0f / 100.0f;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public float getTintShadowsIntensityValue() {
        if (this.tintShadowsColor == 0) {
            return 0.0f;
        }
        return 50.0f / 100.0f;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public float getSaturationValue() {
        float parameterValue = this.saturationValue / 100.0f;
        if (parameterValue > 0.0f) {
            parameterValue *= 1.05f;
        }
        return 1.0f + parameterValue;
    }

    public FrameLayout getToolsView() {
        return this.toolsView;
    }

    public TextView getDoneTextView() {
        return this.doneTextView;
    }

    public TextView getCancelTextView() {
        return this.cancelTextView;
    }

    public class ToolsAdapter extends RecyclerListView.SelectionAdapter {
        private Context mContext;

        public ToolsAdapter(Context context) {
            this.mContext = context;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            return 13;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public long getItemId(int i) {
            return i;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup viewGroup, int i) {
            View view;
            if (i == 0) {
                PhotoEditToolCell cell = new PhotoEditToolCell(this.mContext);
                view = cell;
                cell.setSeekBarDelegate(new PhotoEditorSeekBar.PhotoEditorSeekBarDelegate() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$PhotoFilterView$ToolsAdapter$K6TWZGS5In654AO6rcxnGFgYDGU
                    @Override // im.uwrkaxlmjj.ui.components.PhotoEditorSeekBar.PhotoEditorSeekBarDelegate
                    public final void onProgressChanged(int i2, int i3) {
                        this.f$0.lambda$onCreateViewHolder$0$PhotoFilterView$ToolsAdapter(i2, i3);
                    }
                });
            } else {
                view = new PhotoEditRadioCell(this.mContext);
                view.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$PhotoFilterView$ToolsAdapter$gk0WBehA0ueZUSPWyx_NnsiR98c
                    @Override // android.view.View.OnClickListener
                    public final void onClick(View view2) {
                        this.f$0.lambda$onCreateViewHolder$1$PhotoFilterView$ToolsAdapter(view2);
                    }
                });
            }
            return new RecyclerListView.Holder(view);
        }

        public /* synthetic */ void lambda$onCreateViewHolder$0$PhotoFilterView$ToolsAdapter(int i1, int progress) {
            if (i1 == PhotoFilterView.this.enhanceTool) {
                PhotoFilterView.this.enhanceValue = progress;
            } else if (i1 == PhotoFilterView.this.highlightsTool) {
                PhotoFilterView.this.highlightsValue = progress;
            } else if (i1 == PhotoFilterView.this.contrastTool) {
                PhotoFilterView.this.contrastValue = progress;
            } else if (i1 == PhotoFilterView.this.exposureTool) {
                PhotoFilterView.this.exposureValue = progress;
            } else if (i1 == PhotoFilterView.this.warmthTool) {
                PhotoFilterView.this.warmthValue = progress;
            } else if (i1 == PhotoFilterView.this.saturationTool) {
                PhotoFilterView.this.saturationValue = progress;
            } else if (i1 == PhotoFilterView.this.vignetteTool) {
                PhotoFilterView.this.vignetteValue = progress;
            } else if (i1 == PhotoFilterView.this.shadowsTool) {
                PhotoFilterView.this.shadowsValue = progress;
            } else if (i1 == PhotoFilterView.this.grainTool) {
                PhotoFilterView.this.grainValue = progress;
            } else if (i1 == PhotoFilterView.this.sharpenTool) {
                PhotoFilterView.this.sharpenValue = progress;
            } else if (i1 == PhotoFilterView.this.fadeTool) {
                PhotoFilterView.this.fadeValue = progress;
            }
            if (PhotoFilterView.this.eglThread != null) {
                PhotoFilterView.this.eglThread.requestRender(true);
            }
        }

        public /* synthetic */ void lambda$onCreateViewHolder$1$PhotoFilterView$ToolsAdapter(View v) {
            PhotoEditRadioCell cell = (PhotoEditRadioCell) v;
            Integer row = (Integer) cell.getTag();
            if (row.intValue() == PhotoFilterView.this.tintShadowsTool) {
                PhotoFilterView.this.tintShadowsColor = cell.getCurrentColor();
            } else {
                PhotoFilterView.this.tintHighlightsColor = cell.getCurrentColor();
            }
            if (PhotoFilterView.this.eglThread != null) {
                PhotoFilterView.this.eglThread.requestRender(false);
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return false;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int i) {
            int itemViewType = holder.getItemViewType();
            if (itemViewType != 0) {
                if (itemViewType == 1) {
                    PhotoEditRadioCell cell = (PhotoEditRadioCell) holder.itemView;
                    cell.setTag(Integer.valueOf(i));
                    if (i == PhotoFilterView.this.tintShadowsTool) {
                        cell.setIconAndTextAndValue(LocaleController.getString("TintShadows", R.string.TintShadows), 0, PhotoFilterView.this.tintShadowsColor);
                        return;
                    } else {
                        if (i == PhotoFilterView.this.tintHighlightsTool) {
                            cell.setIconAndTextAndValue(LocaleController.getString("TintHighlights", R.string.TintHighlights), 0, PhotoFilterView.this.tintHighlightsColor);
                            return;
                        }
                        return;
                    }
                }
                return;
            }
            PhotoEditToolCell cell2 = (PhotoEditToolCell) holder.itemView;
            cell2.setTag(Integer.valueOf(i));
            if (i == PhotoFilterView.this.enhanceTool) {
                cell2.setIconAndTextAndValue(LocaleController.getString("Enhance", R.string.Enhance), PhotoFilterView.this.enhanceValue, 0, 100);
                return;
            }
            if (i == PhotoFilterView.this.highlightsTool) {
                cell2.setIconAndTextAndValue(LocaleController.getString("Highlights", R.string.Highlights), PhotoFilterView.this.highlightsValue, -100, 100);
                return;
            }
            if (i == PhotoFilterView.this.contrastTool) {
                cell2.setIconAndTextAndValue(LocaleController.getString(ExifInterface.TAG_CONTRAST, R.string.Contrast), PhotoFilterView.this.contrastValue, -100, 100);
                return;
            }
            if (i == PhotoFilterView.this.exposureTool) {
                cell2.setIconAndTextAndValue(LocaleController.getString("Exposure", R.string.Exposure), PhotoFilterView.this.exposureValue, -100, 100);
                return;
            }
            if (i == PhotoFilterView.this.warmthTool) {
                cell2.setIconAndTextAndValue(LocaleController.getString("Warmth", R.string.Warmth), PhotoFilterView.this.warmthValue, -100, 100);
                return;
            }
            if (i == PhotoFilterView.this.saturationTool) {
                cell2.setIconAndTextAndValue(LocaleController.getString(ExifInterface.TAG_SATURATION, R.string.Saturation), PhotoFilterView.this.saturationValue, -100, 100);
                return;
            }
            if (i == PhotoFilterView.this.vignetteTool) {
                cell2.setIconAndTextAndValue(LocaleController.getString("Vignette", R.string.Vignette), PhotoFilterView.this.vignetteValue, 0, 100);
                return;
            }
            if (i == PhotoFilterView.this.shadowsTool) {
                cell2.setIconAndTextAndValue(LocaleController.getString("Shadows", R.string.Shadows), PhotoFilterView.this.shadowsValue, -100, 100);
                return;
            }
            if (i == PhotoFilterView.this.grainTool) {
                cell2.setIconAndTextAndValue(LocaleController.getString("Grain", R.string.Grain), PhotoFilterView.this.grainValue, 0, 100);
            } else if (i == PhotoFilterView.this.sharpenTool) {
                cell2.setIconAndTextAndValue(LocaleController.getString("Sharpen", R.string.Sharpen), PhotoFilterView.this.sharpenValue, 0, 100);
            } else if (i == PhotoFilterView.this.fadeTool) {
                cell2.setIconAndTextAndValue(LocaleController.getString("Fade", R.string.Fade), PhotoFilterView.this.fadeValue, 0, 100);
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            if (position == PhotoFilterView.this.tintShadowsTool || position == PhotoFilterView.this.tintHighlightsTool) {
                return 1;
            }
            return 0;
        }
    }
}
