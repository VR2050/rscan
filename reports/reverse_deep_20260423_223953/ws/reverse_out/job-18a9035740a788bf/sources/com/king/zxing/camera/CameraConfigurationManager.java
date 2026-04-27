package com.king.zxing.camera;

import android.content.Context;
import android.content.SharedPreferences;
import android.graphics.Point;
import android.hardware.Camera;
import android.preference.PreferenceManager;
import android.view.Display;
import android.view.WindowManager;
import com.king.zxing.Preferences;
import com.king.zxing.camera.open.CameraFacing;
import com.king.zxing.camera.open.OpenCamera;
import com.king.zxing.util.LogUtils;
import org.webrtc.mozi.JavaScreenCapturer;

/* JADX INFO: loaded from: classes3.dex */
final class CameraConfigurationManager {
    private Point bestPreviewSize;
    private Point cameraResolution;
    private final Context context;
    private int cwNeededRotation;
    private int cwRotationFromDisplayToCamera;
    private Point previewSizeOnScreen;
    private Point screenResolution;

    CameraConfigurationManager(Context context) {
        this.context = context;
    }

    void initFromCameraParameters(OpenCamera camera) {
        int cwRotationFromNaturalToDisplay;
        Camera.Parameters parameters = camera.getCamera().getParameters();
        WindowManager manager = (WindowManager) this.context.getSystemService("window");
        Display display = manager.getDefaultDisplay();
        int displayRotation = display.getRotation();
        if (displayRotation != 0) {
            if (displayRotation == 1) {
                cwRotationFromNaturalToDisplay = 90;
            } else if (displayRotation == 2) {
                cwRotationFromNaturalToDisplay = JavaScreenCapturer.DEGREE_180;
            } else if (displayRotation == 3) {
                cwRotationFromNaturalToDisplay = JavaScreenCapturer.DEGREE_270;
            } else if (displayRotation % 90 == 0) {
                cwRotationFromNaturalToDisplay = (displayRotation + 360) % 360;
            } else {
                throw new IllegalArgumentException("Bad rotation: " + displayRotation);
            }
        } else {
            cwRotationFromNaturalToDisplay = 0;
        }
        LogUtils.i("Display at: " + cwRotationFromNaturalToDisplay);
        int cwRotationFromNaturalToCamera = camera.getOrientation();
        LogUtils.i("Camera at: " + cwRotationFromNaturalToCamera);
        if (camera.getFacing() == CameraFacing.FRONT) {
            cwRotationFromNaturalToCamera = (360 - cwRotationFromNaturalToCamera) % 360;
            LogUtils.i("Front camera overriden to: " + cwRotationFromNaturalToCamera);
        }
        this.cwRotationFromDisplayToCamera = ((cwRotationFromNaturalToCamera + 360) - cwRotationFromNaturalToDisplay) % 360;
        LogUtils.i("Final display orientation: " + this.cwRotationFromDisplayToCamera);
        if (camera.getFacing() == CameraFacing.FRONT) {
            LogUtils.i("Compensating rotation for front camera");
            this.cwNeededRotation = (360 - this.cwRotationFromDisplayToCamera) % 360;
        } else {
            this.cwNeededRotation = this.cwRotationFromDisplayToCamera;
        }
        LogUtils.i("Clockwise rotation from display to camera: " + this.cwNeededRotation);
        Point theScreenResolution = new Point();
        display.getSize(theScreenResolution);
        this.screenResolution = theScreenResolution;
        LogUtils.i("Screen resolution in current orientation: " + this.screenResolution);
        this.cameraResolution = CameraConfigurationUtils.findBestPreviewSizeValue(parameters, this.screenResolution);
        LogUtils.i("Camera resolution: " + this.cameraResolution);
        this.bestPreviewSize = CameraConfigurationUtils.findBestPreviewSizeValue(parameters, this.screenResolution);
        LogUtils.i("Best available preview size: " + this.bestPreviewSize);
        boolean isScreenPortrait = this.screenResolution.x < this.screenResolution.y;
        boolean isPreviewSizePortrait = this.bestPreviewSize.x < this.bestPreviewSize.y;
        if (isScreenPortrait == isPreviewSizePortrait) {
            this.previewSizeOnScreen = this.bestPreviewSize;
        } else {
            this.previewSizeOnScreen = new Point(this.bestPreviewSize.y, this.bestPreviewSize.x);
        }
        LogUtils.i("Preview size on screen: " + this.previewSizeOnScreen);
    }

    void setDesiredCameraParameters(OpenCamera camera, boolean safeMode) {
        Camera theCamera = camera.getCamera();
        Camera.Parameters parameters = theCamera.getParameters();
        if (parameters == null) {
            LogUtils.w("Device error: no camera parameters are available. Proceeding without configuration.");
            return;
        }
        LogUtils.i("Initial camera parameters: " + parameters.flatten());
        if (safeMode) {
            LogUtils.w("In camera config safe mode -- most settings will not be honored");
        }
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this.context);
        if (parameters.isZoomSupported()) {
            parameters.setZoom(parameters.getMaxZoom() / 10);
        }
        initializeTorch(parameters, prefs, safeMode);
        CameraConfigurationUtils.setFocus(parameters, prefs.getBoolean(Preferences.KEY_AUTO_FOCUS, true), prefs.getBoolean(Preferences.KEY_DISABLE_CONTINUOUS_FOCUS, true), safeMode);
        if (!safeMode) {
            if (prefs.getBoolean(Preferences.KEY_INVERT_SCAN, false)) {
                CameraConfigurationUtils.setInvertColor(parameters);
            }
            if (!prefs.getBoolean(Preferences.KEY_DISABLE_BARCODE_SCENE_MODE, true)) {
                CameraConfigurationUtils.setBarcodeSceneMode(parameters);
            }
            if (!prefs.getBoolean(Preferences.KEY_DISABLE_METERING, true)) {
                CameraConfigurationUtils.setVideoStabilization(parameters);
                CameraConfigurationUtils.setFocusArea(parameters);
                CameraConfigurationUtils.setMetering(parameters);
            }
            parameters.setRecordingHint(true);
        }
        parameters.setPreviewSize(this.bestPreviewSize.x, this.bestPreviewSize.y);
        theCamera.setParameters(parameters);
        theCamera.setDisplayOrientation(this.cwRotationFromDisplayToCamera);
        Camera.Parameters afterParameters = theCamera.getParameters();
        Camera.Size afterSize = afterParameters.getPreviewSize();
        if (afterSize != null) {
            if (this.bestPreviewSize.x != afterSize.width || this.bestPreviewSize.y != afterSize.height) {
                LogUtils.w("Camera said it supported preview size " + this.bestPreviewSize.x + 'x' + this.bestPreviewSize.y + ", but after setting it, preview size is " + afterSize.width + 'x' + afterSize.height);
                this.bestPreviewSize.x = afterSize.width;
                this.bestPreviewSize.y = afterSize.height;
            }
        }
    }

    Point getBestPreviewSize() {
        return this.bestPreviewSize;
    }

    Point getPreviewSizeOnScreen() {
        return this.previewSizeOnScreen;
    }

    Point getCameraResolution() {
        return this.cameraResolution;
    }

    Point getScreenResolution() {
        return this.screenResolution;
    }

    int getCWNeededRotation() {
        return this.cwNeededRotation;
    }

    boolean getTorchState(Camera camera) {
        Camera.Parameters parameters;
        if (camera == null || (parameters = camera.getParameters()) == null) {
            return false;
        }
        String flashMode = parameters.getFlashMode();
        return "on".equals(flashMode) || "torch".equals(flashMode);
    }

    void setTorch(Camera camera, boolean newSetting) {
        Camera.Parameters parameters = camera.getParameters();
        doSetTorch(parameters, newSetting, false);
        camera.setParameters(parameters);
    }

    private void initializeTorch(Camera.Parameters parameters, SharedPreferences prefs, boolean safeMode) {
        boolean currentSetting = FrontLightMode.readPref(prefs) == FrontLightMode.ON;
        doSetTorch(parameters, currentSetting, safeMode);
    }

    private void doSetTorch(Camera.Parameters parameters, boolean newSetting, boolean safeMode) {
        CameraConfigurationUtils.setTorch(parameters, newSetting);
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this.context);
        if (!safeMode && !prefs.getBoolean(Preferences.KEY_DISABLE_EXPOSURE, true)) {
            CameraConfigurationUtils.setBestExposure(parameters, newSetting);
        }
    }
}
