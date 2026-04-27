package com.king.zxing.camera;

import android.content.Context;
import android.graphics.Point;
import android.graphics.Rect;
import android.hardware.Camera;
import android.os.Handler;
import android.view.SurfaceHolder;
import com.google.zxing.PlanarYUVLuminanceSource;
import com.king.zxing.camera.open.OpenCamera;
import com.king.zxing.camera.open.OpenCameraInterface;
import com.king.zxing.util.LogUtils;
import java.io.IOException;

/* JADX INFO: loaded from: classes3.dex */
public final class CameraManager {
    private static final int MAX_FRAME_HEIGHT = 675;
    private static final int MAX_FRAME_WIDTH = 1200;
    private static final int MIN_FRAME_HEIGHT = 240;
    private static final int MIN_FRAME_WIDTH = 240;
    private AutoFocusManager autoFocusManager;
    private OpenCamera camera;
    private final CameraConfigurationManager configManager;
    private final Context context;
    private Rect framingRect;
    private int framingRectHorizontalOffset;
    private Rect framingRectInPreview;
    private float framingRectRatio;
    private int framingRectVerticalOffset;
    private boolean initialized;
    private boolean isFullScreenScan;
    private boolean isTorch;
    private OnSensorListener onSensorListener;
    private OnTorchListener onTorchListener;
    private final PreviewCallback previewCallback;
    private boolean previewing;
    private int requestedCameraId = -1;
    private int requestedFramingRectHeight;
    private int requestedFramingRectWidth;

    public interface OnSensorListener {
        void onSensorChanged(boolean z, boolean z2, float f);
    }

    public interface OnTorchListener {
        void onTorchChanged(boolean z);
    }

    public CameraManager(Context context) {
        this.context = context.getApplicationContext();
        this.configManager = new CameraConfigurationManager(context);
        this.previewCallback = new PreviewCallback(this.configManager);
    }

    public void openDriver(SurfaceHolder holder) throws IOException {
        int i;
        OpenCamera theCamera = this.camera;
        if (theCamera == null) {
            theCamera = OpenCameraInterface.open(this.requestedCameraId);
            if (theCamera == null) {
                throw new IOException("Camera.open() failed to return object from driver");
            }
            this.camera = theCamera;
        }
        if (!this.initialized) {
            this.initialized = true;
            this.configManager.initFromCameraParameters(theCamera);
            int i2 = this.requestedFramingRectWidth;
            if (i2 > 0 && (i = this.requestedFramingRectHeight) > 0) {
                setManualFramingRect(i2, i);
                this.requestedFramingRectWidth = 0;
                this.requestedFramingRectHeight = 0;
            }
        }
        Camera cameraObject = theCamera.getCamera();
        Camera.Parameters parameters = cameraObject.getParameters();
        String parametersFlattened = parameters == null ? null : parameters.flatten();
        try {
            this.configManager.setDesiredCameraParameters(theCamera, false);
        } catch (RuntimeException e) {
            LogUtils.w("Camera rejected parameters. Setting only minimal safe-mode parameters");
            LogUtils.i("Resetting to saved camera params: " + parametersFlattened);
            if (parametersFlattened != null) {
                Camera.Parameters parameters2 = cameraObject.getParameters();
                parameters2.unflatten(parametersFlattened);
                try {
                    cameraObject.setParameters(parameters2);
                    this.configManager.setDesiredCameraParameters(theCamera, true);
                } catch (RuntimeException e2) {
                    LogUtils.w("Camera rejected even safe-mode parameters! No configuration");
                }
            }
        }
        cameraObject.setPreviewDisplay(holder);
    }

    public synchronized boolean isOpen() {
        return this.camera != null;
    }

    public OpenCamera getOpenCamera() {
        return this.camera;
    }

    public void closeDriver() {
        OpenCamera openCamera = this.camera;
        if (openCamera != null) {
            openCamera.getCamera().release();
            this.camera = null;
            this.framingRect = null;
            this.framingRectInPreview = null;
        }
        this.isTorch = false;
        OnTorchListener onTorchListener = this.onTorchListener;
        if (onTorchListener != null) {
            onTorchListener.onTorchChanged(false);
        }
    }

    public void startPreview() {
        OpenCamera theCamera = this.camera;
        if (theCamera != null && !this.previewing) {
            theCamera.getCamera().startPreview();
            this.previewing = true;
            this.autoFocusManager = new AutoFocusManager(this.context, theCamera.getCamera());
        }
    }

    public void stopPreview() {
        AutoFocusManager autoFocusManager = this.autoFocusManager;
        if (autoFocusManager != null) {
            autoFocusManager.stop();
            this.autoFocusManager = null;
        }
        OpenCamera openCamera = this.camera;
        if (openCamera != null && this.previewing) {
            openCamera.getCamera().stopPreview();
            this.previewCallback.setHandler(null, 0);
            this.previewing = false;
        }
    }

    public synchronized void setTorch(boolean newSetting) {
        OpenCamera theCamera = this.camera;
        if (theCamera != null && newSetting != this.configManager.getTorchState(theCamera.getCamera())) {
            boolean wasAutoFocusManager = this.autoFocusManager != null;
            if (wasAutoFocusManager) {
                this.autoFocusManager.stop();
                this.autoFocusManager = null;
            }
            this.isTorch = newSetting;
            this.configManager.setTorch(theCamera.getCamera(), newSetting);
            if (wasAutoFocusManager) {
                AutoFocusManager autoFocusManager = new AutoFocusManager(this.context, theCamera.getCamera());
                this.autoFocusManager = autoFocusManager;
                autoFocusManager.start();
            }
            if (this.onTorchListener != null) {
                this.onTorchListener.onTorchChanged(newSetting);
            }
        }
    }

    public synchronized void requestPreviewFrame(Handler handler, int message) {
        OpenCamera theCamera = this.camera;
        if (theCamera != null && this.previewing) {
            this.previewCallback.setHandler(handler, message);
            theCamera.getCamera().setOneShotPreviewCallback(this.previewCallback);
        }
    }

    public synchronized Rect getFramingRect() {
        if (this.framingRect == null) {
            if (this.camera == null) {
                return null;
            }
            Point point = this.configManager.getCameraResolution();
            if (point == null) {
                return null;
            }
            int width = point.x;
            int height = point.y;
            if (this.isFullScreenScan) {
                this.framingRect = new Rect(0, 0, width, height);
            } else {
                int size = (int) (Math.min(width, height) * this.framingRectRatio);
                int leftOffset = ((width - size) / 2) + this.framingRectHorizontalOffset;
                int topOffset = ((height - size) / 2) + this.framingRectVerticalOffset;
                this.framingRect = new Rect(leftOffset, topOffset, leftOffset + size, topOffset + size);
            }
        }
        return this.framingRect;
    }

    public synchronized Rect getFramingRectInPreview() {
        if (this.framingRectInPreview == null) {
            Rect framingRect = getFramingRect();
            if (framingRect == null) {
                return null;
            }
            Rect rect = new Rect(framingRect);
            Point cameraResolution = this.configManager.getCameraResolution();
            Point screenResolution = this.configManager.getScreenResolution();
            if (cameraResolution != null && screenResolution != null) {
                rect.left = (rect.left * cameraResolution.y) / screenResolution.x;
                rect.right = (rect.right * cameraResolution.y) / screenResolution.x;
                rect.top = (rect.top * cameraResolution.x) / screenResolution.y;
                rect.bottom = (rect.bottom * cameraResolution.x) / screenResolution.y;
                this.framingRectInPreview = rect;
            }
            return null;
        }
        return this.framingRectInPreview;
    }

    public void setFullScreenScan(boolean fullScreenScan) {
        this.isFullScreenScan = fullScreenScan;
    }

    public void setFramingRectRatio(float framingRectRatio) {
        this.framingRectRatio = framingRectRatio;
    }

    public void setFramingRectVerticalOffset(int framingRectVerticalOffset) {
        this.framingRectVerticalOffset = framingRectVerticalOffset;
    }

    public void setFramingRectHorizontalOffset(int framingRectHorizontalOffset) {
        this.framingRectHorizontalOffset = framingRectHorizontalOffset;
    }

    public Point getCameraResolution() {
        return this.configManager.getCameraResolution();
    }

    public Point getScreenResolution() {
        return this.configManager.getScreenResolution();
    }

    public synchronized void setManualCameraId(int cameraId) {
        this.requestedCameraId = cameraId;
    }

    public synchronized void setManualFramingRect(int width, int height) {
        if (this.initialized) {
            Point screenResolution = this.configManager.getScreenResolution();
            if (width > screenResolution.x) {
                width = screenResolution.x;
            }
            if (height > screenResolution.y) {
                height = screenResolution.y;
            }
            int leftOffset = (screenResolution.x - width) / 2;
            int topOffset = (screenResolution.y - height) / 2;
            this.framingRect = new Rect(leftOffset, topOffset, leftOffset + width, topOffset + height);
            LogUtils.d("Calculated manual framing rect: " + this.framingRect);
            this.framingRectInPreview = null;
        } else {
            this.requestedFramingRectWidth = width;
            this.requestedFramingRectHeight = height;
        }
    }

    public PlanarYUVLuminanceSource buildLuminanceSource(byte[] data, int width, int height) {
        Rect rect = getFramingRectInPreview();
        if (rect == null) {
            return null;
        }
        if (!this.isFullScreenScan) {
            int size = (int) (Math.min(width, height) * this.framingRectRatio);
            int left = ((width - size) / 2) + this.framingRectHorizontalOffset;
            int top = ((height - size) / 2) + this.framingRectVerticalOffset;
            return new PlanarYUVLuminanceSource(data, width, height, left, top, size, size, false);
        }
        return new PlanarYUVLuminanceSource(data, width, height, 0, 0, width, height, false);
    }

    public void setOnTorchListener(OnTorchListener listener) {
        this.onTorchListener = listener;
    }

    public void setOnSensorListener(OnSensorListener listener) {
        this.onSensorListener = listener;
    }

    public void sensorChanged(boolean tooDark, float ambientLightLux) {
        OnSensorListener onSensorListener = this.onSensorListener;
        if (onSensorListener != null) {
            onSensorListener.onSensorChanged(this.isTorch, tooDark, ambientLightLux);
        }
    }
}
