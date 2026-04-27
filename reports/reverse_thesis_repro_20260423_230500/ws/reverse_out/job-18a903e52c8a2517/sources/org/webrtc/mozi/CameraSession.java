package org.webrtc.mozi;

import android.content.Context;
import android.graphics.Matrix;
import android.view.WindowManager;
import java.util.List;
import org.webrtc.mozi.CameraEnumerationAndroid;
import org.webrtc.mozi.VideoFrame;
import org.webrtc.mozi.WindowRotationContextHelper;

/* JADX INFO: loaded from: classes3.dex */
abstract class CameraSession {
    private static final String TAG = "CameraSession";
    static int sCachedDisplayRotation = 0;
    protected boolean autoFocusingEnabled;
    protected boolean mMirror;
    protected boolean stabilizationAllowSoftware;
    protected boolean stabilizationEnabled;
    private CameraSessionData mCameraSessionData = new CameraSessionData();
    protected int windowRotation = -1;
    protected int extraDeviceRotation = 0;

    interface CreateSessionCallback {
        void onDone(CameraSession cameraSession);

        void onFailure(FailureType failureType, String str);
    }

    interface Events {
        void onCameraClosed(CameraSession cameraSession);

        void onCameraDisconnected(CameraSession cameraSession);

        void onCameraError(CameraSession cameraSession, String str);

        void onCameraOpening();

        void onFrameCaptured(CameraSession cameraSession, VideoFrame videoFrame);
    }

    enum FailureType {
        ERROR,
        DISCONNECTED
    }

    public abstract int getCameraRotation();

    abstract void stop();

    CameraSession() {
    }

    static int getDeviceOrientation(Context context) {
        int displayRotation;
        WindowRotationContextHelper.WindowContext windowContext = WindowRotationContextHelper.getWindowContext();
        try {
            if (windowContext != null) {
                displayRotation = windowContext.getWindowRotation();
            } else {
                Context wrapContext = WindowRotationContextHelper.wrapGetRotationContext(context);
                WindowManager wm = (WindowManager) wrapContext.getSystemService("window");
                displayRotation = wm.getDefaultDisplay().getRotation();
            }
            sCachedDisplayRotation = displayRotation;
        } catch (Throwable e) {
            Logging.w(TAG, "Cannot get display rotation", e);
            displayRotation = sCachedDisplayRotation;
        }
        if (displayRotation == 1) {
            return 90;
        }
        if (displayRotation == 2) {
            return JavaScreenCapturer.DEGREE_180;
        }
        if (displayRotation == 3) {
            return JavaScreenCapturer.DEGREE_270;
        }
        return 0;
    }

    static VideoFrame.TextureBuffer createTextureBufferWithModifiedTransformMatrix(TextureBufferImpl buffer, boolean mirror, int rotation) {
        Matrix transformMatrix = new Matrix();
        transformMatrix.preTranslate(0.5f, 0.5f);
        if (mirror) {
            transformMatrix.preScale(-1.0f, 1.0f);
        }
        transformMatrix.preRotate(rotation);
        transformMatrix.preTranslate(-0.5f, -0.5f);
        int width = (rotation == 0 || rotation == 180) ? buffer.getWidth() : buffer.getHeight();
        int height = (rotation == 0 || rotation == 180) ? buffer.getHeight() : buffer.getWidth();
        return buffer.applyTransformMatrix(transformMatrix, width, height);
    }

    public static TextureBufferImpl createTextureBufferWithModifiedTransformMatrix(TextureBufferImpl buffer, boolean isFacingFront, int cameraOrientation, boolean horizontalMirror, int frameRotation, int extraRotation) {
        int textureRotation = buffer.getTextureRotation();
        Matrix preTransformMatrix = new Matrix();
        preTransformMatrix.postTranslate(-0.5f, -0.5f);
        preTransformMatrix.postRotate(extraRotation);
        preTransformMatrix.postTranslate(0.5f, 0.5f);
        Matrix postTransformMatrix = new Matrix();
        postTransformMatrix.postTranslate(-0.5f, -0.5f);
        if (isFacingFront) {
            if ((cameraOrientation + textureRotation) % JavaScreenCapturer.DEGREE_180 != 0) {
                postTransformMatrix.postScale(1.0f, -1.0f);
            } else {
                postTransformMatrix.postScale(-1.0f, 1.0f);
            }
        }
        if (horizontalMirror) {
            if (((cameraOrientation + textureRotation) + frameRotation) % JavaScreenCapturer.DEGREE_180 != 0) {
                postTransformMatrix.postScale(1.0f, -1.0f);
            } else {
                postTransformMatrix.postScale(-1.0f, 1.0f);
            }
        }
        postTransformMatrix.postTranslate(0.5f, 0.5f);
        int totalRotation = cameraOrientation + extraRotation;
        int width = totalRotation % JavaScreenCapturer.DEGREE_180 == 0 ? buffer.getWidth() : buffer.getHeight();
        int height = totalRotation % JavaScreenCapturer.DEGREE_180 == 0 ? buffer.getHeight() : buffer.getWidth();
        return buffer.applyTransformMatrix(preTransformMatrix, postTransformMatrix, width, height);
    }

    static VideoFrame.TextureBuffer createTextureBufferWithModifiedTransformMatrix(TextureBufferImpl buffer, boolean xMirror, boolean yMirror, int rotation) {
        Matrix transformMatrix = new Matrix();
        transformMatrix.preTranslate(0.5f, 0.5f);
        transformMatrix.preRotate(rotation);
        if (xMirror || yMirror) {
            float sx = xMirror ? -1.0f : 1.0f;
            float sy = yMirror ? -1.0f : 1.0f;
            transformMatrix.preScale(sx, sy);
        }
        transformMatrix.preTranslate(-0.5f, -0.5f);
        int width = (rotation == 0 || rotation == 180) ? buffer.getWidth() : buffer.getHeight();
        int height = (rotation == 0 || rotation == 180) ? buffer.getHeight() : buffer.getWidth();
        return buffer.applyTransformMatrix(transformMatrix, width, height);
    }

    public void setFormatData(CameraEnumerationAndroid.CaptureFormat targetFormat, CameraEnumerationAndroid.CaptureFormat actualFormat) {
        this.mCameraSessionData.setTargetFormat(targetFormat);
        this.mCameraSessionData.setActualFormat(actualFormat);
    }

    public void setSupportInfo(List<CameraEnumerationAndroid.CaptureFormat.FramerateRange> supportRange, List<Size> supportSize) {
        this.mCameraSessionData.setSupportRange(supportRange);
        this.mCameraSessionData.setSupportSize(supportSize);
    }

    public CameraSessionData getCameraSessionData() {
        return this.mCameraSessionData;
    }

    public void setExtraDeviceRotation(int extraDeviceRotation) {
        this.extraDeviceRotation = extraDeviceRotation;
    }

    public void setWindowRotation(int rotation) {
        this.windowRotation = rotation;
    }

    public void setMirror(boolean mirror) {
        this.mMirror = mirror;
    }

    public void setStabilizationEnabled(boolean enabled, boolean allowSoftware) {
        this.stabilizationEnabled = enabled;
        this.stabilizationAllowSoftware = allowSoftware;
    }

    public void setAutoFocusingEnabled(boolean enabled) {
        this.autoFocusingEnabled = enabled;
    }

    public int setCameraZoom(float zoom) {
        return -1;
    }

    public int setCameraFlash(boolean enabled) {
        return -1;
    }

    public boolean isCameraFocusPointSupported() {
        return false;
    }

    public int setCameraFocusPoint(float x, float y) {
        return -1;
    }

    public boolean isCameraExposurePointSupported() {
        return false;
    }

    public int setCameraExposurePoint(float x, float y) {
        return -1;
    }

    public boolean isCameraAutoFocusFaceModeSupported() {
        return false;
    }

    public int setCameraAutoFocusFaceModeEnable(boolean enabled) {
        return -1;
    }

    public int setCameraExposureValue(float value) {
        return -1;
    }

    public float getCameraMinExposureValue() {
        return 0.0f;
    }

    public float getCameraMaxExposureValue() {
        return 0.0f;
    }
}
