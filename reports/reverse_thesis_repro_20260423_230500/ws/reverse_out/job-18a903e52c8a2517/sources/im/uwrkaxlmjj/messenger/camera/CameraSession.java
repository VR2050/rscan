package im.uwrkaxlmjj.messenger.camera;

import android.content.SharedPreferences;
import android.graphics.Rect;
import android.hardware.Camera;
import android.media.CamcorderProfile;
import android.media.MediaRecorder;
import android.os.Build;
import android.view.OrientationEventListener;
import android.view.WindowManager;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.BuildVars;
import im.uwrkaxlmjj.messenger.FileLog;
import java.util.ArrayList;
import org.webrtc.mozi.JavaScreenCapturer;

/* JADX INFO: loaded from: classes2.dex */
public class CameraSession {
    public static final int ORIENTATION_HYSTERESIS = 5;
    protected CameraInfo cameraInfo;
    private String currentFlashMode;
    private int currentOrientation;
    private float currentZoom;
    private int diffOrientation;
    private boolean initied;
    private boolean isVideo;
    private int jpegOrientation;
    private int maxZoom;
    private boolean meteringAreaSupported;
    private OrientationEventListener orientationEventListener;
    private final int pictureFormat;
    private final Size pictureSize;
    private final Size previewSize;
    private boolean sameTakePictureOrientation;
    private int lastOrientation = -1;
    private int lastDisplayOrientation = -1;
    private boolean flipFront = true;
    private Camera.AutoFocusCallback autoFocusCallback = new Camera.AutoFocusCallback() { // from class: im.uwrkaxlmjj.messenger.camera.-$$Lambda$CameraSession$58ornDMcE2spTWRdcXMMPB0-Gdk
        @Override // android.hardware.Camera.AutoFocusCallback
        public final void onAutoFocus(boolean z, Camera camera) {
            CameraSession.lambda$new$0(z, camera);
        }
    };

    static /* synthetic */ void lambda$new$0(boolean success, Camera camera) {
    }

    public CameraSession(CameraInfo info, Size preview, Size picture, int format) {
        this.previewSize = preview;
        this.pictureSize = picture;
        this.pictureFormat = format;
        this.cameraInfo = info;
        SharedPreferences sharedPreferences = ApplicationLoader.applicationContext.getSharedPreferences("camera", 0);
        this.currentFlashMode = sharedPreferences.getString(this.cameraInfo.frontCamera != 0 ? "flashMode_front" : "flashMode", "off");
        OrientationEventListener orientationEventListener = new OrientationEventListener(ApplicationLoader.applicationContext) { // from class: im.uwrkaxlmjj.messenger.camera.CameraSession.1
            @Override // android.view.OrientationEventListener
            public void onOrientationChanged(int orientation) {
                if (CameraSession.this.orientationEventListener == null || !CameraSession.this.initied || orientation == -1) {
                    return;
                }
                CameraSession cameraSession = CameraSession.this;
                cameraSession.jpegOrientation = cameraSession.roundOrientation(orientation, cameraSession.jpegOrientation);
                WindowManager mgr = (WindowManager) ApplicationLoader.applicationContext.getSystemService("window");
                int rotation = mgr.getDefaultDisplay().getRotation();
                if (CameraSession.this.lastOrientation != CameraSession.this.jpegOrientation || rotation != CameraSession.this.lastDisplayOrientation) {
                    if (!CameraSession.this.isVideo) {
                        CameraSession.this.configurePhotoCamera();
                    }
                    CameraSession.this.lastDisplayOrientation = rotation;
                    CameraSession cameraSession2 = CameraSession.this;
                    cameraSession2.lastOrientation = cameraSession2.jpegOrientation;
                }
            }
        };
        this.orientationEventListener = orientationEventListener;
        if (orientationEventListener.canDetectOrientation()) {
            this.orientationEventListener.enable();
        } else {
            this.orientationEventListener.disable();
            this.orientationEventListener = null;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public int roundOrientation(int orientation, int orientationHistory) {
        int dist;
        if (orientationHistory == -1) {
            dist = 1;
        } else {
            int dist2 = Math.abs(orientation - orientationHistory);
            dist = Math.min(dist2, 360 - dist2) >= 50 ? 1 : 0;
        }
        if (dist != 0) {
            return (((orientation + 45) / 90) * 90) % 360;
        }
        return orientationHistory;
    }

    public void checkFlashMode(String mode) {
        ArrayList<String> modes = CameraController.getInstance().availableFlashModes;
        if (modes.contains(this.currentFlashMode)) {
            return;
        }
        this.currentFlashMode = mode;
        configurePhotoCamera();
        SharedPreferences sharedPreferences = ApplicationLoader.applicationContext.getSharedPreferences("camera", 0);
        sharedPreferences.edit().putString(this.cameraInfo.frontCamera != 0 ? "flashMode_front" : "flashMode", mode).commit();
    }

    public void setCurrentFlashMode(String mode) {
        this.currentFlashMode = mode;
        configurePhotoCamera();
        SharedPreferences sharedPreferences = ApplicationLoader.applicationContext.getSharedPreferences("camera", 0);
        sharedPreferences.edit().putString(this.cameraInfo.frontCamera != 0 ? "flashMode_front" : "flashMode", mode).commit();
    }

    public String getCurrentFlashMode() {
        return this.currentFlashMode;
    }

    public String getNextFlashMode() {
        ArrayList<String> modes = CameraController.getInstance().availableFlashModes;
        for (int a = 0; a < modes.size(); a++) {
            String mode = modes.get(a);
            if (mode.equals(this.currentFlashMode)) {
                if (a < modes.size() - 1) {
                    return modes.get(a + 1);
                }
                return modes.get(0);
            }
        }
        return this.currentFlashMode;
    }

    public void setInitied() {
        this.initied = true;
    }

    public boolean isInitied() {
        return this.initied;
    }

    public int getCurrentOrientation() {
        return this.currentOrientation;
    }

    public boolean isFlipFront() {
        return this.flipFront;
    }

    public void setFlipFront(boolean value) {
        this.flipFront = value;
    }

    public int getWorldAngle() {
        return this.diffOrientation;
    }

    public boolean isSameTakePictureOrientation() {
        return this.sameTakePictureOrientation;
    }

    protected void configureRoundCamera() {
        int temp;
        int degrees;
        try {
            this.isVideo = true;
            Camera camera = this.cameraInfo.camera;
            if (camera != null) {
                Camera.CameraInfo info = new Camera.CameraInfo();
                Camera.Parameters params = null;
                try {
                    params = camera.getParameters();
                } catch (Exception e) {
                    FileLog.e(e);
                }
                Camera.getCameraInfo(this.cameraInfo.getCameraId(), info);
                int displayOrientation = getDisplayOrientation(info, true);
                if ("samsung".equals(Build.MANUFACTURER) && "sf2wifixx".equals(Build.PRODUCT)) {
                    degrees = 0;
                } else {
                    int degrees2 = 0;
                    if (displayOrientation != 0) {
                        if (displayOrientation != 1) {
                            if (displayOrientation != 2) {
                                if (displayOrientation == 3) {
                                    degrees2 = JavaScreenCapturer.DEGREE_270;
                                }
                            } else {
                                degrees2 = JavaScreenCapturer.DEGREE_180;
                            }
                        } else {
                            degrees2 = 90;
                        }
                    } else {
                        degrees2 = 0;
                    }
                    if (info.orientation % 90 != 0) {
                        info.orientation = 0;
                    }
                    if (info.facing == 1) {
                        int temp2 = (info.orientation + degrees2) % 360;
                        temp = (360 - temp2) % 360;
                    } else {
                        temp = ((info.orientation - degrees2) + 360) % 360;
                    }
                    degrees = temp;
                }
                this.currentOrientation = degrees;
                camera.setDisplayOrientation(degrees);
                this.diffOrientation = this.currentOrientation - displayOrientation;
                if (params != null) {
                    if (BuildVars.LOGS_ENABLED) {
                        FileLog.d("set preview size = " + this.previewSize.getWidth() + " " + this.previewSize.getHeight());
                    }
                    params.setPreviewSize(this.previewSize.getWidth(), this.previewSize.getHeight());
                    if (BuildVars.LOGS_ENABLED) {
                        FileLog.d("set picture size = " + this.pictureSize.getWidth() + " " + this.pictureSize.getHeight());
                    }
                    params.setPictureSize(this.pictureSize.getWidth(), this.pictureSize.getHeight());
                    params.setPictureFormat(this.pictureFormat);
                    params.setRecordingHint(true);
                    if (params.getSupportedFocusModes().contains("continuous-video")) {
                        params.setFocusMode("continuous-video");
                    } else if (params.getSupportedFocusModes().contains("auto")) {
                        params.setFocusMode("auto");
                    }
                    int outputOrientation = 0;
                    if (this.jpegOrientation != -1) {
                        if (info.facing == 1) {
                            outputOrientation = ((info.orientation - this.jpegOrientation) + 360) % 360;
                        } else {
                            outputOrientation = (info.orientation + this.jpegOrientation) % 360;
                        }
                    }
                    try {
                        params.setRotation(outputOrientation);
                        if (info.facing == 1) {
                            this.sameTakePictureOrientation = (360 - displayOrientation) % 360 == outputOrientation;
                        } else {
                            this.sameTakePictureOrientation = displayOrientation == outputOrientation;
                        }
                    } catch (Exception e2) {
                    }
                    params.setFlashMode("off");
                    try {
                        camera.setParameters(params);
                    } catch (Exception e3) {
                    }
                    if (params.getMaxNumMeteringAreas() > 0) {
                        this.meteringAreaSupported = true;
                    }
                }
            }
        } catch (Throwable e4) {
            FileLog.e(e4);
        }
    }

    protected void configurePhotoCamera() {
        int temp;
        int degrees;
        try {
            Camera camera = this.cameraInfo.camera;
            if (camera != null) {
                Camera.CameraInfo info = new Camera.CameraInfo();
                Camera.Parameters params = null;
                try {
                    params = camera.getParameters();
                } catch (Exception e) {
                    FileLog.e(e);
                }
                Camera.getCameraInfo(this.cameraInfo.getCameraId(), info);
                int displayOrientation = getDisplayOrientation(info, true);
                if ("samsung".equals(Build.MANUFACTURER) && "sf2wifixx".equals(Build.PRODUCT)) {
                    degrees = 0;
                } else {
                    int degrees2 = 0;
                    if (displayOrientation != 0) {
                        if (displayOrientation != 1) {
                            if (displayOrientation != 2) {
                                if (displayOrientation == 3) {
                                    degrees2 = JavaScreenCapturer.DEGREE_270;
                                }
                            } else {
                                degrees2 = JavaScreenCapturer.DEGREE_180;
                            }
                        } else {
                            degrees2 = 90;
                        }
                    } else {
                        degrees2 = 0;
                    }
                    if (info.orientation % 90 != 0) {
                        info.orientation = 0;
                    }
                    if (info.facing == 1) {
                        int temp2 = (info.orientation + degrees2) % 360;
                        temp = (360 - temp2) % 360;
                    } else {
                        temp = ((info.orientation - degrees2) + 360) % 360;
                    }
                    degrees = temp;
                }
                this.currentOrientation = degrees;
                camera.setDisplayOrientation(degrees);
                if (params != null) {
                    params.setPreviewSize(this.previewSize.getWidth(), this.previewSize.getHeight());
                    params.setPictureSize(this.pictureSize.getWidth(), this.pictureSize.getHeight());
                    params.setPictureFormat(this.pictureFormat);
                    params.setJpegQuality(100);
                    params.setJpegThumbnailQuality(100);
                    int maxZoom = params.getMaxZoom();
                    this.maxZoom = maxZoom;
                    params.setZoom((int) (this.currentZoom * maxZoom));
                    if (params.getSupportedFocusModes().contains("continuous-picture")) {
                        params.setFocusMode("continuous-picture");
                    }
                    int outputOrientation = 0;
                    if (this.jpegOrientation != -1) {
                        if (info.facing == 1) {
                            outputOrientation = ((info.orientation - this.jpegOrientation) + 360) % 360;
                        } else {
                            outputOrientation = (info.orientation + this.jpegOrientation) % 360;
                        }
                    }
                    try {
                        params.setRotation(outputOrientation);
                        if (info.facing == 1) {
                            this.sameTakePictureOrientation = (360 - displayOrientation) % 360 == outputOrientation;
                        } else {
                            this.sameTakePictureOrientation = displayOrientation == outputOrientation;
                        }
                    } catch (Exception e2) {
                    }
                    params.setFlashMode(this.currentFlashMode);
                    try {
                        camera.setParameters(params);
                    } catch (Exception e3) {
                    }
                    if (params.getMaxNumMeteringAreas() > 0) {
                        this.meteringAreaSupported = true;
                    }
                }
            }
        } catch (Throwable e4) {
            FileLog.e(e4);
        }
    }

    protected void focusToRect(Rect focusRect, Rect meteringRect) {
        try {
            Camera camera = this.cameraInfo.camera;
            if (camera != null) {
                camera.cancelAutoFocus();
                Camera.Parameters parameters = null;
                try {
                    parameters = camera.getParameters();
                } catch (Exception e) {
                    FileLog.e(e);
                }
                if (parameters != null) {
                    parameters.setFocusMode("auto");
                    ArrayList<Camera.Area> meteringAreas = new ArrayList<>();
                    meteringAreas.add(new Camera.Area(focusRect, 1000));
                    parameters.setFocusAreas(meteringAreas);
                    if (this.meteringAreaSupported) {
                        ArrayList<Camera.Area> meteringAreas2 = new ArrayList<>();
                        meteringAreas2.add(new Camera.Area(meteringRect, 1000));
                        parameters.setMeteringAreas(meteringAreas2);
                    }
                    try {
                        camera.setParameters(parameters);
                        camera.autoFocus(this.autoFocusCallback);
                    } catch (Exception e2) {
                        FileLog.e(e2);
                    }
                }
            }
        } catch (Exception e3) {
            FileLog.e(e3);
        }
    }

    protected int getMaxZoom() {
        return this.maxZoom;
    }

    protected void setZoom(float value) {
        this.currentZoom = value;
        configurePhotoCamera();
    }

    protected void configureRecorder(int quality, MediaRecorder recorder) {
        Camera.CameraInfo info = new Camera.CameraInfo();
        Camera.getCameraInfo(this.cameraInfo.cameraId, info);
        getDisplayOrientation(info, false);
        int outputOrientation = 0;
        if (this.jpegOrientation != -1) {
            if (info.facing == 1) {
                outputOrientation = ((info.orientation - this.jpegOrientation) + 360) % 360;
            } else {
                outputOrientation = (info.orientation + this.jpegOrientation) % 360;
            }
        }
        recorder.setOrientationHint(outputOrientation);
        int highProfile = getHigh();
        boolean canGoHigh = CamcorderProfile.hasProfile(this.cameraInfo.cameraId, highProfile);
        boolean canGoLow = CamcorderProfile.hasProfile(this.cameraInfo.cameraId, 0);
        if (canGoHigh && (quality == 1 || !canGoLow)) {
            recorder.setProfile(CamcorderProfile.get(this.cameraInfo.cameraId, highProfile));
        } else if (canGoLow) {
            recorder.setProfile(CamcorderProfile.get(this.cameraInfo.cameraId, 0));
        } else {
            throw new IllegalStateException("cannot find valid CamcorderProfile");
        }
        this.isVideo = true;
    }

    protected void stopVideoRecording() {
        this.isVideo = false;
        configurePhotoCamera();
    }

    private int getHigh() {
        if ("LGE".equals(Build.MANUFACTURER) && "g3_tmo_us".equals(Build.PRODUCT)) {
            return 4;
        }
        return 1;
    }

    private int getDisplayOrientation(Camera.CameraInfo info, boolean isStillCapture) {
        WindowManager mgr = (WindowManager) ApplicationLoader.applicationContext.getSystemService("window");
        int rotation = mgr.getDefaultDisplay().getRotation();
        int degrees = 0;
        if (rotation != 0) {
            if (rotation == 1) {
                degrees = 90;
            } else if (rotation == 2) {
                degrees = JavaScreenCapturer.DEGREE_180;
            } else if (rotation == 3) {
                degrees = JavaScreenCapturer.DEGREE_270;
            }
        } else {
            degrees = 0;
        }
        if (info.facing == 1) {
            int displayOrientation = (info.orientation + degrees) % 360;
            int displayOrientation2 = (360 - displayOrientation) % 360;
            if (!isStillCapture && displayOrientation2 == 90) {
                displayOrientation2 = JavaScreenCapturer.DEGREE_270;
            }
            if (!isStillCapture && "Huawei".equals(Build.MANUFACTURER) && "angler".equals(Build.PRODUCT) && displayOrientation2 == 270) {
                return 90;
            }
            return displayOrientation2;
        }
        int displayOrientation3 = ((info.orientation - degrees) + 360) % 360;
        return displayOrientation3;
    }

    public int getDisplayOrientation() {
        try {
            Camera.CameraInfo info = new Camera.CameraInfo();
            Camera.getCameraInfo(this.cameraInfo.getCameraId(), info);
            return getDisplayOrientation(info, true);
        } catch (Exception e) {
            FileLog.e(e);
            return 0;
        }
    }

    public void setPreviewCallback(Camera.PreviewCallback callback) {
        this.cameraInfo.camera.setPreviewCallback(callback);
    }

    public void setOneShotPreviewCallback(Camera.PreviewCallback callback) {
        CameraInfo cameraInfo = this.cameraInfo;
        if (cameraInfo != null && cameraInfo.camera != null) {
            this.cameraInfo.camera.setOneShotPreviewCallback(callback);
        }
    }

    public void destroy() {
        this.initied = false;
        OrientationEventListener orientationEventListener = this.orientationEventListener;
        if (orientationEventListener != null) {
            orientationEventListener.disable();
            this.orientationEventListener = null;
        }
    }
}
