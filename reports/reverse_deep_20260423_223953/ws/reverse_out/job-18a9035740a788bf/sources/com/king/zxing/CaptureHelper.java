package com.king.zxing;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.Rect;
import android.graphics.RectF;
import android.hardware.Camera;
import android.view.MotionEvent;
import android.view.SurfaceHolder;
import android.view.SurfaceView;
import android.view.View;
import androidx.fragment.app.Fragment;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.DecodeHintType;
import com.google.zxing.Result;
import com.king.zxing.camera.CameraManager;
import com.king.zxing.camera.FrontLightMode;
import com.king.zxing.util.LogUtils;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/* JADX INFO: loaded from: classes3.dex */
public class CaptureHelper implements CaptureLifecycle, CaptureTouchEvent, CaptureManager, SurfaceHolder.Callback {
    private static final int DEVIATION = 6;
    private Activity activity;
    private AmbientLightManager ambientLightManager;
    private BeepManager beepManager;
    private float brightEnoughLux;
    private CameraManager cameraManager;
    private CaptureHandler captureHandler;
    private String characterSet;
    private Collection<BarcodeFormat> decodeFormats;
    private Map<DecodeHintType, Object> decodeHints;
    private int framingRectHorizontalOffset;
    private float framingRectRatio;
    private int framingRectVerticalOffset;
    private boolean hasCameraFlash;
    private boolean hasSurface;
    private InactivityTimer inactivityTimer;
    private boolean isAutoRestartPreviewAndDecode;
    private boolean isContinuousScan;
    private boolean isFullScreenScan;
    private boolean isPlayBeep;
    private boolean isReturnBitmap;
    private boolean isSupportAutoZoom;
    private boolean isSupportLuminanceInvert;
    private boolean isSupportVerticalCode;
    private boolean isSupportZoom;
    private boolean isVibrate;
    private View ivTorch;
    private float oldDistance;
    private OnCaptureCallback onCaptureCallback;
    private OnCaptureListener onCaptureListener;
    private SurfaceHolder surfaceHolder;
    private SurfaceView surfaceView;
    private float tooDarkLux;
    private ViewfinderView viewfinderView;

    @Deprecated
    public CaptureHelper(Fragment fragment, SurfaceView surfaceView, ViewfinderView viewfinderView) {
        this(fragment, surfaceView, viewfinderView, (View) null);
    }

    public CaptureHelper(Fragment fragment, SurfaceView surfaceView, ViewfinderView viewfinderView, View ivTorch) {
        this(fragment.getActivity(), surfaceView, viewfinderView, ivTorch);
    }

    @Deprecated
    public CaptureHelper(Activity activity, SurfaceView surfaceView, ViewfinderView viewfinderView) {
        this(activity, surfaceView, viewfinderView, (View) null);
    }

    public CaptureHelper(Activity activity, SurfaceView surfaceView, ViewfinderView viewfinderView, View ivTorch) {
        this.isSupportZoom = true;
        this.isSupportAutoZoom = true;
        this.isSupportLuminanceInvert = false;
        this.isContinuousScan = false;
        this.isAutoRestartPreviewAndDecode = true;
        this.framingRectRatio = 0.9f;
        this.tooDarkLux = 45.0f;
        this.brightEnoughLux = 100.0f;
        this.activity = activity;
        this.surfaceView = surfaceView;
        this.viewfinderView = viewfinderView;
        this.ivTorch = ivTorch;
    }

    @Override // com.king.zxing.CaptureLifecycle
    public void onCreate() {
        this.surfaceHolder = this.surfaceView.getHolder();
        this.hasSurface = false;
        this.inactivityTimer = new InactivityTimer(this.activity);
        this.beepManager = new BeepManager(this.activity);
        this.ambientLightManager = new AmbientLightManager(this.activity);
        this.hasCameraFlash = this.activity.getPackageManager().hasSystemFeature("android.hardware.camera.flash");
        initCameraManager();
        this.onCaptureListener = new OnCaptureListener() { // from class: com.king.zxing.-$$Lambda$CaptureHelper$M1LKX0hZL5VGLrV8hfodXcHppF8
            @Override // com.king.zxing.OnCaptureListener
            public final void onHandleDecode(Result result, Bitmap bitmap, float f) {
                this.f$0.lambda$onCreate$0$CaptureHelper(result, bitmap, f);
            }
        };
        this.beepManager.setPlayBeep(this.isPlayBeep);
        this.beepManager.setVibrate(this.isVibrate);
        this.ambientLightManager.setTooDarkLux(this.tooDarkLux);
        this.ambientLightManager.setBrightEnoughLux(this.brightEnoughLux);
    }

    public /* synthetic */ void lambda$onCreate$0$CaptureHelper(Result result, Bitmap barcode, float scaleFactor) {
        this.inactivityTimer.onActivity();
        this.beepManager.playBeepSoundAndVibrate();
        onResult(result, barcode, scaleFactor);
    }

    @Override // com.king.zxing.CaptureLifecycle
    public void onResume() {
        this.beepManager.updatePrefs();
        this.inactivityTimer.onResume();
        if (this.hasSurface) {
            initCamera(this.surfaceHolder);
        } else {
            this.surfaceHolder.addCallback(this);
        }
        this.ambientLightManager.start(this.cameraManager);
    }

    @Override // com.king.zxing.CaptureLifecycle
    public void onPause() {
        CaptureHandler captureHandler = this.captureHandler;
        if (captureHandler != null) {
            captureHandler.quitSynchronously();
            this.captureHandler = null;
        }
        this.inactivityTimer.onPause();
        this.ambientLightManager.stop();
        this.beepManager.close();
        this.cameraManager.closeDriver();
        if (!this.hasSurface) {
            this.surfaceHolder.removeCallback(this);
        }
        View view = this.ivTorch;
        if (view != null && view.getVisibility() == 0) {
            this.ivTorch.setSelected(false);
            this.ivTorch.setVisibility(4);
        }
    }

    @Override // com.king.zxing.CaptureLifecycle
    public void onDestroy() {
        this.inactivityTimer.shutdown();
    }

    @Override // com.king.zxing.CaptureTouchEvent
    public boolean onTouchEvent(MotionEvent event) {
        Camera camera;
        if (!this.isSupportZoom || !this.cameraManager.isOpen() || (camera = this.cameraManager.getOpenCamera().getCamera()) == null || event.getPointerCount() <= 1) {
            return false;
        }
        int action = event.getAction() & 255;
        if (action == 2) {
            float newDistance = calcFingerSpacing(event);
            float f = this.oldDistance;
            if (newDistance > f + 6.0f) {
                handleZoom(true, camera);
            } else if (newDistance < f - 6.0f) {
                handleZoom(false, camera);
            }
            this.oldDistance = newDistance;
        } else if (action == 5) {
            this.oldDistance = calcFingerSpacing(event);
        }
        return true;
    }

    private void initCameraManager() {
        CameraManager cameraManager = new CameraManager(this.activity);
        this.cameraManager = cameraManager;
        cameraManager.setFullScreenScan(this.isFullScreenScan);
        this.cameraManager.setFramingRectRatio(this.framingRectRatio);
        this.cameraManager.setFramingRectVerticalOffset(this.framingRectVerticalOffset);
        this.cameraManager.setFramingRectHorizontalOffset(this.framingRectHorizontalOffset);
        View view = this.ivTorch;
        if (view != null && this.hasCameraFlash) {
            view.setOnClickListener(new View.OnClickListener() { // from class: com.king.zxing.-$$Lambda$CaptureHelper$i8cvNEWL6OlZjVbzRDtr3lazGZc
                @Override // android.view.View.OnClickListener
                public final void onClick(View view2) {
                    this.f$0.lambda$initCameraManager$1$CaptureHelper(view2);
                }
            });
            this.cameraManager.setOnSensorListener(new CameraManager.OnSensorListener() { // from class: com.king.zxing.-$$Lambda$CaptureHelper$qZVOqVqKk6calUaIsNPo5S2Svww
                @Override // com.king.zxing.camera.CameraManager.OnSensorListener
                public final void onSensorChanged(boolean z, boolean z2, float f) {
                    this.f$0.lambda$initCameraManager$2$CaptureHelper(z, z2, f);
                }
            });
            this.cameraManager.setOnTorchListener(new CameraManager.OnTorchListener() { // from class: com.king.zxing.-$$Lambda$CaptureHelper$rpoAt43hjil8ox87CgThrHqtLBQ
                @Override // com.king.zxing.camera.CameraManager.OnTorchListener
                public final void onTorchChanged(boolean z) {
                    this.f$0.lambda$initCameraManager$3$CaptureHelper(z);
                }
            });
        }
    }

    public /* synthetic */ void lambda$initCameraManager$1$CaptureHelper(View v) {
        CameraManager cameraManager = this.cameraManager;
        if (cameraManager != null) {
            cameraManager.setTorch(!this.ivTorch.isSelected());
        }
    }

    public /* synthetic */ void lambda$initCameraManager$2$CaptureHelper(boolean torch, boolean tooDark, float ambientLightLux) {
        if (tooDark) {
            if (this.ivTorch.getVisibility() != 0) {
                this.ivTorch.setVisibility(0);
            }
        } else if (!torch && this.ivTorch.getVisibility() == 0) {
            this.ivTorch.setVisibility(4);
        }
    }

    public /* synthetic */ void lambda$initCameraManager$3$CaptureHelper(boolean torch) {
        this.ivTorch.setSelected(torch);
    }

    private void initCamera(SurfaceHolder surfaceHolder) {
        if (surfaceHolder == null) {
            throw new IllegalStateException("No SurfaceHolder provided");
        }
        if (this.cameraManager.isOpen()) {
            LogUtils.w("initCamera() while already open -- late SurfaceView callback?");
            return;
        }
        try {
            this.cameraManager.openDriver(surfaceHolder);
            if (this.captureHandler == null) {
                CaptureHandler captureHandler = new CaptureHandler(this.activity, this.viewfinderView, this.onCaptureListener, this.decodeFormats, this.decodeHints, this.characterSet, this.cameraManager);
                this.captureHandler = captureHandler;
                captureHandler.setSupportVerticalCode(this.isSupportVerticalCode);
                this.captureHandler.setReturnBitmap(this.isReturnBitmap);
                this.captureHandler.setSupportAutoZoom(this.isSupportAutoZoom);
                this.captureHandler.setSupportLuminanceInvert(this.isSupportLuminanceInvert);
            }
        } catch (IOException ioe) {
            LogUtils.w(ioe);
        } catch (RuntimeException e) {
            LogUtils.w("Unexpected error initializing camera", e);
        }
    }

    @Override // android.view.SurfaceHolder.Callback
    public void surfaceCreated(SurfaceHolder holder) {
        if (holder == null) {
            LogUtils.w("*** WARNING *** surfaceCreated() gave us a null surface!");
        }
        if (!this.hasSurface) {
            this.hasSurface = true;
            initCamera(holder);
        }
    }

    @Override // android.view.SurfaceHolder.Callback
    public void surfaceChanged(SurfaceHolder holder, int format, int width, int height) {
    }

    @Override // android.view.SurfaceHolder.Callback
    public void surfaceDestroyed(SurfaceHolder holder) {
        this.hasSurface = false;
    }

    private void handleZoom(boolean isZoomIn, Camera camera) {
        Camera.Parameters params = camera.getParameters();
        if (params.isZoomSupported()) {
            int maxZoom = params.getMaxZoom();
            int zoom = params.getZoom();
            if (isZoomIn && zoom < maxZoom) {
                zoom++;
            } else if (zoom > 0) {
                zoom--;
            }
            params.setZoom(zoom);
            camera.setParameters(params);
            return;
        }
        LogUtils.i("zoom not supported");
    }

    @Deprecated
    private void focusOnTouch(MotionEvent event, Camera camera) {
        Camera.Parameters params = camera.getParameters();
        Camera.Size previewSize = params.getPreviewSize();
        Rect focusRect = calcTapArea(event.getRawX(), event.getRawY(), 1.0f, previewSize);
        Rect meteringRect = calcTapArea(event.getRawX(), event.getRawY(), 1.5f, previewSize);
        Camera.Parameters parameters = camera.getParameters();
        if (parameters.getMaxNumFocusAreas() > 0) {
            List<Camera.Area> focusAreas = new ArrayList<>();
            focusAreas.add(new Camera.Area(focusRect, 600));
            parameters.setFocusAreas(focusAreas);
        }
        if (parameters.getMaxNumMeteringAreas() > 0) {
            List<Camera.Area> meteringAreas = new ArrayList<>();
            meteringAreas.add(new Camera.Area(meteringRect, 600));
            parameters.setMeteringAreas(meteringAreas);
        }
        final String currentFocusMode = params.getFocusMode();
        params.setFocusMode("macro");
        camera.setParameters(params);
        camera.autoFocus(new Camera.AutoFocusCallback() { // from class: com.king.zxing.-$$Lambda$CaptureHelper$ylDXELNLTSPjWjiWiDjfyhgXJhc
            @Override // android.hardware.Camera.AutoFocusCallback
            public final void onAutoFocus(boolean z, Camera camera2) {
                CaptureHelper.lambda$focusOnTouch$4(currentFocusMode, z, camera2);
            }
        });
    }

    static /* synthetic */ void lambda$focusOnTouch$4(String currentFocusMode, boolean success, Camera camera1) {
        Camera.Parameters params1 = camera1.getParameters();
        params1.setFocusMode(currentFocusMode);
        camera1.setParameters(params1);
    }

    private float calcFingerSpacing(MotionEvent event) {
        float x = event.getX(0) - event.getX(1);
        float y = event.getY(0) - event.getY(1);
        return (float) Math.sqrt((x * x) + (y * y));
    }

    private Rect calcTapArea(float x, float y, float coefficient, Camera.Size previewSize) {
        int areaSize = Float.valueOf(200.0f * coefficient).intValue();
        int centerX = (int) (((x / previewSize.width) * 2000.0f) - 1000.0f);
        int centerY = (int) (((y / previewSize.height) * 2000.0f) - 1000.0f);
        int left = clamp(centerX - (areaSize / 2), -1000, 1000);
        int top = clamp(centerY - (areaSize / 2), -1000, 1000);
        RectF rectF = new RectF(left, top, left + areaSize, top + areaSize);
        return new Rect(Math.round(rectF.left), Math.round(rectF.top), Math.round(rectF.right), Math.round(rectF.bottom));
    }

    private int clamp(int x, int min, int max) {
        if (x > max) {
            return max;
        }
        if (x < min) {
            return min;
        }
        return x;
    }

    public void restartPreviewAndDecode() {
        CaptureHandler captureHandler = this.captureHandler;
        if (captureHandler != null) {
            captureHandler.restartPreviewAndDecode();
        }
    }

    public void onResult(Result result, Bitmap barcode, float scaleFactor) {
        onResult(result);
    }

    public void onResult(Result result) {
        CaptureHandler captureHandler;
        final String text = result.getText();
        if (this.isContinuousScan) {
            OnCaptureCallback onCaptureCallback = this.onCaptureCallback;
            if (onCaptureCallback != null) {
                onCaptureCallback.onResultCallback(text);
            }
            if (this.isAutoRestartPreviewAndDecode) {
                restartPreviewAndDecode();
                return;
            }
            return;
        }
        if (this.isPlayBeep && (captureHandler = this.captureHandler) != null) {
            captureHandler.postDelayed(new Runnable() { // from class: com.king.zxing.-$$Lambda$CaptureHelper$qeCs8VHWSPAGjlauoPkYu9qs5NM
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onResult$5$CaptureHelper(text);
                }
            }, 100L);
            return;
        }
        OnCaptureCallback onCaptureCallback2 = this.onCaptureCallback;
        if (onCaptureCallback2 != null && onCaptureCallback2.onResultCallback(text)) {
            return;
        }
        Intent intent = new Intent();
        intent.putExtra("SCAN_RESULT", text);
        this.activity.setResult(-1, intent);
        this.activity.finish();
    }

    public /* synthetic */ void lambda$onResult$5$CaptureHelper(String text) {
        OnCaptureCallback onCaptureCallback = this.onCaptureCallback;
        if (onCaptureCallback != null && onCaptureCallback.onResultCallback(text)) {
            return;
        }
        Intent intent = new Intent();
        intent.putExtra("SCAN_RESULT", text);
        this.activity.setResult(-1, intent);
        this.activity.finish();
    }

    public CaptureHelper continuousScan(boolean isContinuousScan) {
        this.isContinuousScan = isContinuousScan;
        return this;
    }

    public CaptureHelper autoRestartPreviewAndDecode(boolean isAutoRestartPreviewAndDecode) {
        this.isAutoRestartPreviewAndDecode = isAutoRestartPreviewAndDecode;
        return this;
    }

    public CaptureHelper playBeep(boolean playBeep) {
        this.isPlayBeep = playBeep;
        BeepManager beepManager = this.beepManager;
        if (beepManager != null) {
            beepManager.setPlayBeep(playBeep);
        }
        return this;
    }

    public CaptureHelper vibrate(boolean vibrate) {
        this.isVibrate = vibrate;
        BeepManager beepManager = this.beepManager;
        if (beepManager != null) {
            beepManager.setVibrate(vibrate);
        }
        return this;
    }

    public CaptureHelper supportZoom(boolean supportZoom) {
        this.isSupportZoom = supportZoom;
        return this;
    }

    public CaptureHelper decodeFormats(Collection<BarcodeFormat> decodeFormats) {
        this.decodeFormats = decodeFormats;
        return this;
    }

    public CaptureHelper decodeHints(Map<DecodeHintType, Object> decodeHints) {
        this.decodeHints = decodeHints;
        return this;
    }

    public CaptureHelper decodeHint(DecodeHintType key, Object value) {
        if (this.decodeHints == null) {
            this.decodeHints = new EnumMap(DecodeHintType.class);
        }
        this.decodeHints.put(key, value);
        return this;
    }

    public CaptureHelper characterSet(String characterSet) {
        this.characterSet = characterSet;
        return this;
    }

    public CaptureHelper supportVerticalCode(boolean supportVerticalCode) {
        this.isSupportVerticalCode = supportVerticalCode;
        CaptureHandler captureHandler = this.captureHandler;
        if (captureHandler != null) {
            captureHandler.setSupportVerticalCode(supportVerticalCode);
        }
        return this;
    }

    public CaptureHelper frontLightMode(FrontLightMode mode) {
        FrontLightMode.put(this.activity, mode);
        if (this.ivTorch != null && mode != FrontLightMode.AUTO) {
            this.ivTorch.setVisibility(4);
        }
        return this;
    }

    public CaptureHelper tooDarkLux(float tooDarkLux) {
        this.tooDarkLux = tooDarkLux;
        AmbientLightManager ambientLightManager = this.ambientLightManager;
        if (ambientLightManager != null) {
            ambientLightManager.setTooDarkLux(tooDarkLux);
        }
        return this;
    }

    public CaptureHelper brightEnoughLux(float brightEnoughLux) {
        this.brightEnoughLux = brightEnoughLux;
        AmbientLightManager ambientLightManager = this.ambientLightManager;
        if (ambientLightManager != null) {
            ambientLightManager.setTooDarkLux(this.tooDarkLux);
        }
        return this;
    }

    public CaptureHelper returnBitmap(boolean returnBitmap) {
        this.isReturnBitmap = returnBitmap;
        CaptureHandler captureHandler = this.captureHandler;
        if (captureHandler != null) {
            captureHandler.setReturnBitmap(returnBitmap);
        }
        return this;
    }

    public CaptureHelper supportAutoZoom(boolean supportAutoZoom) {
        this.isSupportAutoZoom = supportAutoZoom;
        CaptureHandler captureHandler = this.captureHandler;
        if (captureHandler != null) {
            captureHandler.setSupportAutoZoom(supportAutoZoom);
        }
        return this;
    }

    public CaptureHelper supportLuminanceInvert(boolean supportLuminanceInvert) {
        this.isSupportLuminanceInvert = supportLuminanceInvert;
        CaptureHandler captureHandler = this.captureHandler;
        if (captureHandler != null) {
            captureHandler.setSupportLuminanceInvert(supportLuminanceInvert);
        }
        return this;
    }

    public CaptureHelper fullScreenScan(boolean fullScreenScan) {
        this.isFullScreenScan = fullScreenScan;
        CameraManager cameraManager = this.cameraManager;
        if (cameraManager != null) {
            cameraManager.setFullScreenScan(fullScreenScan);
        }
        return this;
    }

    public CaptureHelper framingRectRatio(float framingRectRatio) {
        this.framingRectRatio = framingRectRatio;
        CameraManager cameraManager = this.cameraManager;
        if (cameraManager != null) {
            cameraManager.setFramingRectRatio(framingRectRatio);
        }
        return this;
    }

    public CaptureHelper framingRectVerticalOffset(int framingRectVerticalOffset) {
        this.framingRectVerticalOffset = framingRectVerticalOffset;
        CameraManager cameraManager = this.cameraManager;
        if (cameraManager != null) {
            cameraManager.setFramingRectVerticalOffset(framingRectVerticalOffset);
        }
        return this;
    }

    public CaptureHelper framingRectHorizontalOffset(int framingRectHorizontalOffset) {
        this.framingRectHorizontalOffset = framingRectHorizontalOffset;
        CameraManager cameraManager = this.cameraManager;
        if (cameraManager != null) {
            cameraManager.setFramingRectHorizontalOffset(framingRectHorizontalOffset);
        }
        return this;
    }

    public CaptureHelper setOnCaptureCallback(OnCaptureCallback callback) {
        this.onCaptureCallback = callback;
        return this;
    }

    @Override // com.king.zxing.CaptureManager
    public CameraManager getCameraManager() {
        return this.cameraManager;
    }

    @Override // com.king.zxing.CaptureManager
    public BeepManager getBeepManager() {
        return this.beepManager;
    }

    @Override // com.king.zxing.CaptureManager
    public AmbientLightManager getAmbientLightManager() {
        return this.ambientLightManager;
    }

    @Override // com.king.zxing.CaptureManager
    public InactivityTimer getInactivityTimer() {
        return this.inactivityTimer;
    }
}
