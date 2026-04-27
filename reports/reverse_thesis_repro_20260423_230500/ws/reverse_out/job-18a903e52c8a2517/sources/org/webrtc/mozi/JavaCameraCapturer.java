package org.webrtc.mozi;

import android.app.Activity;
import android.app.Application;
import android.content.Context;
import android.hardware.camera2.CameraManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.Process;
import android.view.Display;
import android.view.OrientationEventListener;
import android.view.WindowManager;
import org.webrtc.mozi.CameraVideoCapturer;
import org.webrtc.mozi.VideoFrame;

/* JADX INFO: loaded from: classes3.dex */
public class JavaCameraCapturer implements CapturerObserver, CameraVideoCapturer.CameraEventsHandler {
    public static final int DEGREE_90 = 90;
    private static final String TAG = "JavaCameraCapturer";
    private Object mCameraCallback;
    private CameraCapturer mCapturer;
    private CameraConfig mConfig;
    private Context mContext;
    private int mFps;
    private Handler mHandler;
    private int mHeight;
    private boolean mIsFrontFacing;
    private long mNativeHandler;
    private OrientationEventListener mOrientationListener;
    private SurfaceTextureHelper mSurfaceTextureHelper;
    private int mWidth;
    private boolean mCapturing = false;
    private long mCaptureStartTimeNs = 0;
    private String mCameraId = "";
    private int mOrientation = 0;
    private int mDeviceOrientation = 0;
    private boolean mEnablePreviewCallback = false;
    private long mLastFrameTimeNs = 0;
    private boolean mStopByOther = false;
    private float currentExposureValue = 0.0f;
    private float minExposureCompensation = 0.0f;
    private float maxExposureCompensation = 0.0f;
    private Application.ActivityLifecycleCallbacks mLifecycleCallback = new Application.ActivityLifecycleCallbacks() { // from class: org.webrtc.mozi.JavaCameraCapturer.3
        @Override // android.app.Application.ActivityLifecycleCallbacks
        public void onActivityCreated(Activity activity, Bundle savedInstanceState) {
            Logging.i(JavaCameraCapturer.TAG, "onActivityCreated");
        }

        @Override // android.app.Application.ActivityLifecycleCallbacks
        public void onActivityStarted(Activity activity) {
            Logging.i(JavaCameraCapturer.TAG, "onActivityStarted");
        }

        @Override // android.app.Application.ActivityLifecycleCallbacks
        public void onActivityResumed(Activity activity) {
            Logging.i(JavaCameraCapturer.TAG, "onActivityResumed capturing:" + JavaCameraCapturer.this.mCapturing + ", stop:" + JavaCameraCapturer.this.mStopByOther);
            if (JavaCameraCapturer.this.mCapturing && JavaCameraCapturer.this.mStopByOther) {
                Logging.i(JavaCameraCapturer.TAG, "restart as stop by system camera unavailable");
                JavaCameraCapturer.this.mStopByOther = false;
                JavaCameraCapturer.this.mCapturer.stopCapture();
                JavaCameraCapturer.this.mCapturer.startCapture(JavaCameraCapturer.this.mWidth, JavaCameraCapturer.this.mHeight, JavaCameraCapturer.this.mFps);
            }
        }

        @Override // android.app.Application.ActivityLifecycleCallbacks
        public void onActivityPaused(Activity activity) {
            Logging.i(JavaCameraCapturer.TAG, "onActivityPaused");
        }

        @Override // android.app.Application.ActivityLifecycleCallbacks
        public void onActivityStopped(Activity activity) {
            Logging.i(JavaCameraCapturer.TAG, "onActivityStopped");
        }

        @Override // android.app.Application.ActivityLifecycleCallbacks
        public void onActivitySaveInstanceState(Activity activity, Bundle outState) {
            Logging.i(JavaCameraCapturer.TAG, "onActivitySaveInstanceState");
        }

        @Override // android.app.Application.ActivityLifecycleCallbacks
        public void onActivityDestroyed(Activity activity) {
            Logging.i(JavaCameraCapturer.TAG, "onActivityDestroyed");
        }
    };

    private static native int nativeOnData(long j, byte[] bArr, long j2, boolean z, int i, int i2, int i3);

    private static native int nativeOnNV21Frame(long j, int i, int i2, int i3, int i4, long j2, VideoFrame.Buffer buffer);

    private static native int nativeOnStarted(long j);

    private static native int nativeOnStopped(long j);

    private static native int nativeOnTexture(long j, int i, int i2, int i3, int i4, long j2, VideoFrame.Buffer buffer);

    public JavaCameraCapturer(long nativeHandler) {
        this.mNativeHandler = 0L;
        Logging.d(TAG, "JavaCameraCapturer " + nativeHandler);
        this.mNativeHandler = nativeHandler;
        this.mHandler = new Handler(Looper.getMainLooper());
    }

    public void init(boolean isFrontFacing, boolean captureToTexture, SurfaceTextureHelper surfaceTextureHelper) {
        Logging.d(TAG, "JavaCameraCapturer " + isFrontFacing + ", " + captureToTexture);
        Context applicationContext = ContextUtils.getApplicationContext();
        this.mContext = applicationContext;
        enableOrientationListener(applicationContext, true);
        String deviceName = "";
        if (1 == 0) {
            deviceName = getDeviceName(captureToTexture, isFrontFacing);
        }
        CameraConfig cameraConfig = new CameraConfig();
        cameraConfig.isFixCameraNumberAnr = true;
        cameraConfig.isFixSwitchCamera = true;
        Camera1Capturer camera1Capturer = new Camera1Capturer(deviceName, isFrontFacing, this, captureToTexture, cameraConfig);
        this.mCapturer = camera1Capturer;
        this.mConfig = cameraConfig;
        this.mSurfaceTextureHelper = surfaceTextureHelper;
        this.mIsFrontFacing = isFrontFacing;
        camera1Capturer.initialize(surfaceTextureHelper, this.mContext, this);
        boolean z = this.mEnablePreviewCallback;
        if (z) {
            Camera1Capturer camera1Cap = (Camera1Capturer) this.mCapturer;
            camera1Cap.setEnableDoubleCallback(z);
        }
        registerCameraCallback();
        Application app = (Application) this.mContext.getApplicationContext();
        if (app != null) {
            Logging.d(TAG, "registerActivityLifecycleCallbacks");
            app.registerActivityLifecycleCallbacks(this.mLifecycleCallback);
        }
    }

    public void initWithId(String cameraId, boolean captureToTexture, SurfaceTextureHelper surfaceTextureHelper) {
        Logging.d(TAG, "JavaCameraCapturer(id) " + cameraId + ", " + captureToTexture);
        Context applicationContext = ContextUtils.getApplicationContext();
        this.mContext = applicationContext;
        enableOrientationListener(applicationContext, true);
        boolean isFrontFacing = getCameraDirection(captureToTexture, cameraId) == 1;
        this.mCameraId = extractCameraIdFromName(cameraId);
        CameraConfig cameraConfig = new CameraConfig();
        cameraConfig.isFixCameraNumberAnr = true;
        cameraConfig.isFixSwitchCamera = true;
        Camera1Capturer camera1Capturer = new Camera1Capturer(cameraId, isFrontFacing, this, captureToTexture, cameraConfig);
        this.mCapturer = camera1Capturer;
        this.mConfig = cameraConfig;
        this.mSurfaceTextureHelper = surfaceTextureHelper;
        this.mIsFrontFacing = isFrontFacing;
        camera1Capturer.initialize(surfaceTextureHelper, this.mContext, this);
        boolean z = this.mEnablePreviewCallback;
        if (z) {
            Camera1Capturer camera1Cap = (Camera1Capturer) this.mCapturer;
            camera1Cap.setEnableDoubleCallback(z);
        }
        Application app = (Application) this.mContext.getApplicationContext();
        if (app != null) {
            Logging.d(TAG, "registerActivityLifecycleCallbacks");
            app.registerActivityLifecycleCallbacks(this.mLifecycleCallback);
        }
        registerCameraCallback();
    }

    private void registerCameraCallback() {
        if (Build.VERSION.SDK_INT >= 21) {
            if (this.mCameraCallback != null) {
                unregisterCameraCallback();
            }
            CameraManager manager = (CameraManager) this.mContext.getApplicationContext().getSystemService("camera");
            CameraManager.AvailabilityCallback availabilityCallback = new CameraManager.AvailabilityCallback() { // from class: org.webrtc.mozi.JavaCameraCapturer.1
                @Override // android.hardware.camera2.CameraManager.AvailabilityCallback
                public void onCameraAvailable(String cameraId) {
                    super.onCameraAvailable(cameraId);
                    Logging.i(JavaCameraCapturer.TAG, "onCameraAvailable camera off id=" + cameraId + ", current " + JavaCameraCapturer.this.mCameraId);
                    if (JavaCameraCapturer.this.mCameraId.equals(cameraId) && JavaCameraCapturer.this.mCapturing) {
                        JavaCameraCapturer.this.mStopByOther = true;
                    }
                }

                @Override // android.hardware.camera2.CameraManager.AvailabilityCallback
                public void onCameraUnavailable(String cameraId) {
                    super.onCameraUnavailable(cameraId);
                    Logging.i(JavaCameraCapturer.TAG, "onCameraUnavailable camera on id=" + cameraId);
                    if (JavaCameraCapturer.this.mCameraId.equals(cameraId) && JavaCameraCapturer.this.mCapturing) {
                        JavaCameraCapturer.this.mStopByOther = false;
                    }
                }
            };
            this.mCameraCallback = availabilityCallback;
            manager.registerAvailabilityCallback(availabilityCallback, this.mHandler);
        }
    }

    private void unregisterCameraCallback() {
        if (Build.VERSION.SDK_INT >= 21 && this.mCameraCallback != null) {
            CameraManager manager = (CameraManager) this.mContext.getApplicationContext().getSystemService("camera");
            manager.unregisterAvailabilityCallback((CameraManager.AvailabilityCallback) this.mCameraCallback);
            this.mCameraCallback = null;
        }
    }

    public int startCapture(int width, int height, int fps) {
        Logging.d(TAG, "start " + width + "x" + height + ", fps:" + fps);
        this.mWidth = width;
        this.mHeight = height;
        this.mFps = fps;
        if (this.mCapturer == null) {
            Logging.d(TAG, "startCapture: capture null, start fail");
            return -1;
        }
        if (this.mCapturing || !isCameraPermissionGranted()) {
            Logging.d(TAG, "startCapture: capturing or permission not granted");
            return -1;
        }
        this.mCapturer.startCapture(width, height, fps);
        this.mCapturing = true;
        this.mCaptureStartTimeNs = System.nanoTime();
        updateViewOrientation();
        return 0;
    }

    public void stopCapture() {
        if (!this.mCapturing) {
            return;
        }
        this.mCapturer.stopCapture();
        this.mCapturing = false;
        this.mCaptureStartTimeNs = 0L;
    }

    public boolean isStarting() {
        return this.mCapturer.isOpening();
    }

    public boolean isCapturing() {
        return this.mCapturing;
    }

    public void switchCamera() {
        if (this.mCapturing) {
            this.mCapturer.switchCamera(null);
        }
    }

    public void setDeviceOrientationMode(int orientation) {
        CameraSession session;
        Logging.d(TAG, "SetDeviceOrientationMode " + orientation);
        if (this.mCapturing && (session = this.mCapturer.getCameraSession()) != null) {
            session.setWindowRotation(orientation);
        }
    }

    public int setCameraZoom(float zoom) {
        CameraSession session;
        Logging.d(TAG, "setCameraZoom " + zoom);
        if (this.mCapturing && (session = this.mCapturer.getCameraSession()) != null) {
            return session.setCameraZoom(zoom);
        }
        return -1;
    }

    public int setCameraFlash(boolean enabled) {
        CameraSession session;
        Logging.d(TAG, "setCameraFlash " + enabled);
        if (this.mCapturing && (session = this.mCapturer.getCameraSession()) != null) {
            return session.setCameraFlash(enabled);
        }
        return -1;
    }

    public boolean isCameraFocusPointSupported() {
        CameraSession session;
        if (this.mCapturing && (session = this.mCapturer.getCameraSession()) != null) {
            return session.isCameraFocusPointSupported();
        }
        return false;
    }

    public int setCameraFocusPoint(float x, float y) {
        CameraSession session;
        Logging.d(TAG, "setCameraFocusPoint " + x + " " + y);
        if (this.mCapturing && (session = this.mCapturer.getCameraSession()) != null) {
            return session.setCameraFocusPoint(x, y);
        }
        return -1;
    }

    public boolean isCameraExposurePointSupported() {
        CameraSession session;
        if (this.mCapturing && (session = this.mCapturer.getCameraSession()) != null) {
            return session.isCameraExposurePointSupported();
        }
        return false;
    }

    public int setCameraExposurePoint(float x, float y) {
        CameraSession session;
        Logging.d(TAG, "setCameraExposurePoint " + x + " " + y);
        if (this.mCapturing && (session = this.mCapturer.getCameraSession()) != null) {
            return session.setCameraExposurePoint(x, y);
        }
        return -1;
    }

    public boolean isCameraAutoFocusFaceModeSupported() {
        CameraSession session;
        if (this.mCapturing && (session = this.mCapturer.getCameraSession()) != null) {
            return session.isCameraAutoFocusFaceModeSupported();
        }
        return false;
    }

    public int setCameraAutoFocusFaceModeEnable(boolean enabled) {
        CameraSession session;
        Logging.d(TAG, "setCameraAutoFocusFaceModeEnable " + enabled);
        if (this.mCapturing && (session = this.mCapturer.getCameraSession()) != null) {
            return session.setCameraAutoFocusFaceModeEnable(enabled);
        }
        return -1;
    }

    public int setCameraExposureValue(float value) {
        CameraSession session;
        Logging.d(TAG, "setCameraExposureValue " + value);
        if (this.mCapturing && (session = this.mCapturer.getCameraSession()) != null) {
            int ret = session.setCameraExposureValue(value);
            if (ret == 0) {
                this.currentExposureValue = value;
            }
            return ret;
        }
        return -1;
    }

    public float getCameraExposureValue() {
        return this.currentExposureValue;
    }

    public float getCameraMinExposureValue() {
        CameraSession session = this.mCapturer.getCameraSession();
        if (session != null) {
            this.minExposureCompensation = session.getCameraMinExposureValue();
        }
        return this.minExposureCompensation;
    }

    public float getCameraMaxExposureValue() {
        CameraSession session = this.mCapturer.getCameraSession();
        if (session != null) {
            this.maxExposureCompensation = session.getCameraMaxExposureValue();
        }
        return this.maxExposureCompensation;
    }

    public boolean setCameraStabilizationMode(int mode) {
        Logging.d(TAG, "setCameraStablilizationMode " + mode);
        return false;
    }

    public void dispose() {
        Logging.d(TAG, "dispose");
        enableOrientationListener(this.mContext, false);
        if (this.mCameraCallback != null) {
            unregisterCameraCallback();
        }
        Application app = (Application) this.mContext.getApplicationContext();
        if (app != null) {
            Logging.d(TAG, "unregisterActivityLifecycleCallbacks");
            app.unregisterActivityLifecycleCallbacks(this.mLifecycleCallback);
        }
        CameraCapturer cameraCapturer = this.mCapturer;
        if (cameraCapturer != null) {
            cameraCapturer.dispose();
            this.mCapturer = null;
        }
        SurfaceTextureHelper surfaceTextureHelper = this.mSurfaceTextureHelper;
        if (surfaceTextureHelper != null) {
            surfaceTextureHelper.dispose();
            this.mSurfaceTextureHelper = null;
        }
        this.mOrientation = 0;
        this.mEnablePreviewCallback = false;
    }

    public int getCameraDirection(boolean z, String str) {
        Camera1Enumerator camera1Enumerator = new Camera1Enumerator(z);
        for (String str2 : camera1Enumerator.getDeviceNames()) {
            if (str.equals(str2)) {
                return camera1Enumerator.isFrontFacing(str2) ? 1 : 0;
            }
        }
        return -1;
    }

    private static String getDeviceName(boolean captureToTexture, boolean frontFacing) {
        CameraEnumerator enumerator = new Camera1Enumerator(captureToTexture);
        String deviceName = null;
        String[] deviceNames = enumerator.getDeviceNames();
        int length = deviceNames.length;
        int i = 0;
        while (true) {
            if (i >= length) {
                break;
            }
            String device = deviceNames[i];
            if (frontFacing != enumerator.isFrontFacing(device)) {
                i++;
            } else {
                deviceName = device;
                break;
            }
        }
        return deviceName == null ? enumerator.getDeviceNames()[0] : deviceName;
    }

    private String extractCameraIdFromName(String name) {
        int idx = name.indexOf(",");
        return name.substring("Camera ".length(), idx);
    }

    private boolean isCameraPermissionGranted() {
        return this.mContext.checkPermission("android.permission.CAMERA", Process.myPid(), Process.myUid()) == 0;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateViewOrientation() {
        CameraSession session;
        Context context = this.mContext;
        if (context != null) {
            WindowManager windowManager = (WindowManager) context.getSystemService("window");
            Display display = windowManager != null ? windowManager.getDefaultDisplay() : null;
            if (display == null) {
                Logging.e(TAG, "updateViewOrientation display is null!");
                return;
            }
            int orientation = display.getRotation() * 90;
            if (orientation != this.mOrientation) {
                Logging.d(TAG, "updateViewOrientation display getRotation " + orientation);
                this.mOrientation = orientation;
                CameraCapturer cameraCapturer = this.mCapturer;
                if (cameraCapturer != null && this.mCapturing && (session = cameraCapturer.getCameraSession()) != null && (session instanceof Camera1Session)) {
                    Camera1Session camera1Session = (Camera1Session) session;
                    camera1Session.setWindowRotation(this.mOrientation);
                }
                CameraCapturer cameraCapturer2 = this.mCapturer;
                if (cameraCapturer2 != null && (cameraCapturer2 instanceof Camera1Capturer)) {
                    Camera1Capturer camera1Cap = (Camera1Capturer) cameraCapturer2;
                    camera1Cap.setWindowRotation(orientation);
                    return;
                }
                return;
            }
            return;
        }
        Logging.e(TAG, "[v]updateViewOrientation context is null");
    }

    private void updateDeviceOrientation(int orientationDegree) {
        int orientation = 0;
        if (orientationDegree > 340 || orientationDegree < 20) {
            orientation = 0;
        } else if (orientationDegree > 70 && orientationDegree < 110) {
            orientation = JavaScreenCapturer.DEGREE_270;
        } else if (orientationDegree > 160 && orientationDegree < 200) {
            orientation = JavaScreenCapturer.DEGREE_180;
        } else if (orientationDegree > 250 && orientationDegree < 290) {
            orientation = 90;
        }
        if (this.mDeviceOrientation != orientation) {
            Logging.d(TAG, "updateDeviceOrientation " + orientation);
            this.mDeviceOrientation = orientation;
        }
    }

    private void enableOrientationListener(Context context, boolean enable) {
        if (enable) {
            if (this.mOrientationListener == null) {
                this.mOrientationListener = new OrientationEventListener(context, 2) { // from class: org.webrtc.mozi.JavaCameraCapturer.2
                    @Override // android.view.OrientationEventListener
                    public void onOrientationChanged(int orientation) {
                        if (orientation != -1) {
                            if (orientation > 340 || orientation < 20 || ((orientation > 70 && orientation < 110) || ((orientation > 160 && orientation < 200) || (orientation > 250 && orientation < 290)))) {
                                JavaCameraCapturer.this.updateViewOrientation();
                            }
                        }
                    }
                };
            }
            if (!this.mOrientationListener.canDetectOrientation()) {
                Logging.w(TAG, "[v]Can't Detect Orientation");
                return;
            } else {
                this.mOrientationListener.enable();
                return;
            }
        }
        OrientationEventListener orientationEventListener = this.mOrientationListener;
        if (orientationEventListener != null) {
            orientationEventListener.disable();
            Logging.d(TAG, "[v]enableOrientation disable");
            this.mOrientationListener = null;
        }
    }

    public void setPreviewCallbackEnable(boolean enable) {
        Logging.d(TAG, "setPreviewCallbackEnable " + enable);
        this.mEnablePreviewCallback = enable;
        CameraCapturer cameraCapturer = this.mCapturer;
        if (cameraCapturer != null && (cameraCapturer instanceof Camera1Capturer)) {
            Camera1Capturer camera1Cap = (Camera1Capturer) cameraCapturer;
            camera1Cap.setEnableDoubleCallback(enable);
        }
    }

    @Override // org.webrtc.mozi.CameraVideoCapturer.CameraEventsHandler
    public void onCameraError(CameraSessionData cameraSessionData, String s) {
        Logging.d(TAG, "onCameraError " + s);
    }

    @Override // org.webrtc.mozi.CameraVideoCapturer.CameraEventsHandler
    public void onCameraDisconnected(CameraSessionData cameraSessionData) {
        Logging.d(TAG, "onCameraDisconnected");
    }

    @Override // org.webrtc.mozi.CameraVideoCapturer.CameraEventsHandler
    public void onCameraFreezed(String s) {
        Logging.d(TAG, "onCameraFreezed " + s);
    }

    @Override // org.webrtc.mozi.CameraVideoCapturer.CameraEventsHandler
    public void onCameraOpening(String s) {
        Logging.d(TAG, "onCameraOpening " + s);
        this.mCameraId = extractCameraIdFromName(s);
    }

    @Override // org.webrtc.mozi.CameraVideoCapturer.CameraEventsHandler
    public void onFirstFrameAvailable(CameraSessionData cameraSessionData) {
        Logging.d(TAG, "onFirstFrameAvailable");
    }

    @Override // org.webrtc.mozi.CameraVideoCapturer.CameraEventsHandler
    public void onCameraClosed() {
        Logging.d(TAG, "onCameraClosed");
    }

    @Override // org.webrtc.mozi.CapturerObserver
    public void onCapturerStarted(boolean success) {
        nativeOnStarted(this.mNativeHandler);
    }

    @Override // org.webrtc.mozi.CapturerObserver
    public void onCapturerStopped() {
        nativeOnStopped(this.mNativeHandler);
    }

    @Override // org.webrtc.mozi.CapturerObserver
    public void onFrameCaptured(VideoFrame frame) {
        VideoFrame.Buffer buffer = frame.getBuffer();
        this.mLastFrameTimeNs = System.nanoTime();
        if (buffer instanceof VideoFrame.TextureBuffer) {
            nativeOnTexture(this.mNativeHandler, frame.getBuffer().getWidth(), frame.getBuffer().getHeight(), frame.getRotation(), frame.getExtraRotation(), frame.getTimestampNs(), frame.getBuffer());
        } else if (buffer instanceof NV21Buffer) {
            nativeOnNV21Frame(this.mNativeHandler, frame.getBuffer().getWidth(), frame.getBuffer().getHeight(), frame.getRotation(), frame.getExtraRotation(), frame.getTimestampNs(), frame.getBuffer());
        }
    }

    @Override // org.webrtc.mozi.CapturerObserver
    public void onCaptureThreadChanged() {
    }

    @Override // org.webrtc.mozi.CapturerObserver
    public void setOutputFormatRequest(int width, int height, int fps) {
    }
}
