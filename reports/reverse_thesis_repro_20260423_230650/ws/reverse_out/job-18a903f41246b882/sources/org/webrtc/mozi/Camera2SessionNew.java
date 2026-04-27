package org.webrtc.mozi;

import android.content.Context;
import android.graphics.Rect;
import android.hardware.camera2.CameraAccessException;
import android.hardware.camera2.CameraCaptureSession;
import android.hardware.camera2.CameraCharacteristics;
import android.hardware.camera2.CameraDevice;
import android.hardware.camera2.CameraManager;
import android.hardware.camera2.CaptureFailure;
import android.hardware.camera2.CaptureRequest;
import android.media.Image;
import android.media.ImageReader;
import android.os.Handler;
import android.os.SystemClock;
import android.util.Range;
import android.view.Surface;
import com.google.android.exoplayer2.text.ttml.TtmlNode;
import com.snail.antifake.deviceid.ShellAdbUtils;
import com.zhy.http.okhttp.OkHttpUtils;
import java.nio.ByteBuffer;
import java.nio.ReadOnlyBufferException;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;
import javax.annotation.Nullable;
import org.webrtc.mozi.CameraEnumerationAndroid;
import org.webrtc.mozi.CameraSession;

/* JADX INFO: loaded from: classes3.dex */
class Camera2SessionNew extends CameraSession {
    private static final String TAG = "Camera2Session";
    private final Context applicationContext;
    private final CameraSession.CreateSessionCallback callback;
    private CameraCharacteristics cameraCharacteristics;

    @Nullable
    private CameraDevice cameraDevice;
    private final String cameraId;
    private final CameraManager cameraManager;
    private int cameraOrientation;
    private final Handler cameraThreadHandler;
    private CameraEnumerationAndroid.CaptureFormat captureFormat;
    private CaptureRequest.Builder captureRequestBuilder;

    @Nullable
    private CameraCaptureSession captureSession;
    private final long constructionTimeNs;
    private final CameraSession.Events events;
    private int fpsUnitFactor;
    private final int frameRate;
    private final int height;
    private boolean isCameraFrontFacing;
    private boolean noFrameRotation;
    private byte[] nv21Buffer;

    @Nullable
    private Surface surface;
    private final SurfaceTextureHelper surfaceTextureHelper;
    private final int width;
    private ImageReader yuvImageReader;

    @Nullable
    private Surface yuvImageSurface;
    private static final Histogram camera2StartTimeMsHistogram = Histogram.createCounts("WebRTC.Android.Camera2.StartTimeMs", 1, 10000, 50);
    private static final Histogram camera2StopTimeMsHistogram = Histogram.createCounts("WebRTC.Android.Camera2.StopTimeMs", 1, 10000, 50);
    private static final Histogram camera2ResolutionHistogram = Histogram.createEnumeration("WebRTC.Android.Camera2.Resolution", CameraEnumerationAndroid.COMMON_RESOLUTIONS.size());
    private SessionState state = SessionState.RUNNING;
    private boolean firstFrameReported = false;
    private volatile boolean enableDoubleCallback = false;
    private volatile FrameBufferCallback frameBufferCallback = null;
    private long lastLogFrameRotationTime = 0;

    interface FrameBufferCallback {
        void onBufferCaptured(NV21Buffer nV21Buffer);
    }

    /* JADX INFO: Access modifiers changed from: private */
    enum SessionState {
        RUNNING,
        STOPPED
    }

    private class CameraStateCallback extends CameraDevice.StateCallback {
        private CameraStateCallback() {
        }

        private String getErrorDescription(int errorCode) {
            if (errorCode == 1) {
                return "Camera device is in use already.";
            }
            if (errorCode == 2) {
                return "Camera device could not be opened because there are too many other open camera devices.";
            }
            if (errorCode == 3) {
                return "Camera device could not be opened due to a device policy.";
            }
            if (errorCode == 4) {
                return "Camera device has encountered a fatal error.";
            }
            if (errorCode == 5) {
                return "Camera service has encountered a fatal error.";
            }
            return "Unknown camera error: " + errorCode;
        }

        @Override // android.hardware.camera2.CameraDevice.StateCallback
        public void onDisconnected(CameraDevice camera) {
            Camera2SessionNew.this.checkIsOnCameraThread();
            boolean startFailure = Camera2SessionNew.this.captureSession == null && Camera2SessionNew.this.state != SessionState.STOPPED;
            Camera2SessionNew.this.state = SessionState.STOPPED;
            Camera2SessionNew.this.stopInternal();
            if (startFailure) {
                Camera2SessionNew.this.callback.onFailure(CameraSession.FailureType.DISCONNECTED, "Camera disconnected / evicted.");
            } else {
                Camera2SessionNew.this.events.onCameraDisconnected(Camera2SessionNew.this);
            }
        }

        @Override // android.hardware.camera2.CameraDevice.StateCallback
        public void onError(CameraDevice camera, int errorCode) {
            Camera2SessionNew.this.checkIsOnCameraThread();
            Camera2SessionNew.this.reportError(getErrorDescription(errorCode));
        }

        @Override // android.hardware.camera2.CameraDevice.StateCallback
        public void onOpened(CameraDevice camera) {
            Camera2SessionNew.this.checkIsOnCameraThread();
            Logging.d(Camera2SessionNew.TAG, "Camera opened.");
            Camera2SessionNew.this.cameraDevice = camera;
            Camera2SessionNew.this.surfaceTextureHelper.setTextureSize(Camera2SessionNew.this.captureFormat.width, Camera2SessionNew.this.captureFormat.height);
            Camera2SessionNew.this.surface = new Surface(Camera2SessionNew.this.surfaceTextureHelper.getSurfaceTexture());
            Camera2SessionNew camera2SessionNew = Camera2SessionNew.this;
            camera2SessionNew.yuvImageReader = ImageReader.newInstance(camera2SessionNew.captureFormat.width, Camera2SessionNew.this.captureFormat.height, 35, 2);
            Camera2SessionNew.this.yuvImageReader.setOnImageAvailableListener(new YuvImageCapturedCallback(), Camera2SessionNew.this.cameraThreadHandler);
            Camera2SessionNew camera2SessionNew2 = Camera2SessionNew.this;
            camera2SessionNew2.yuvImageSurface = camera2SessionNew2.yuvImageReader.getSurface();
            try {
                camera.createCaptureSession(Arrays.asList(Camera2SessionNew.this.surface, Camera2SessionNew.this.yuvImageSurface), new CaptureSessionCallback(), Camera2SessionNew.this.cameraThreadHandler);
            } catch (CameraAccessException e) {
                Camera2SessionNew.this.reportError("Failed to create capture session. " + e);
            }
        }

        @Override // android.hardware.camera2.CameraDevice.StateCallback
        public void onClosed(CameraDevice camera) {
            Camera2SessionNew.this.checkIsOnCameraThread();
            Logging.d(Camera2SessionNew.TAG, "Camera device closed.");
            Camera2SessionNew.this.events.onCameraClosed(Camera2SessionNew.this);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public byte[] yuv_420_888ToNV21(Image image) {
        int width = image.getWidth();
        int height = image.getHeight();
        int ySize = width * height;
        int uvSize = (width * height) / 4;
        int targetLength = ySize + (uvSize * 2);
        byte[] bArr = this.nv21Buffer;
        if (bArr == null || bArr.length != targetLength) {
            this.nv21Buffer = new byte[targetLength];
            Logging.d(TAG, "Buffer length changed.");
        }
        ByteBuffer yBuffer = image.getPlanes()[0].getBuffer();
        ByteBuffer uBuffer = image.getPlanes()[1].getBuffer();
        ByteBuffer vBuffer = image.getPlanes()[2].getBuffer();
        int rowStride = image.getPlanes()[0].getRowStride();
        if (image.getPlanes()[0].getPixelStride() != 1) {
            return null;
        }
        int pos = 0;
        if (rowStride == width) {
            yBuffer.get(this.nv21Buffer, 0, ySize);
            pos = 0 + ySize;
        } else {
            int yBufferPos = -rowStride;
            while (pos < ySize) {
                yBufferPos += rowStride;
                yBuffer.position(yBufferPos);
                yBuffer.get(this.nv21Buffer, pos, width);
                pos += width;
            }
        }
        int rowStride2 = image.getPlanes()[2].getRowStride();
        int pixelStride = image.getPlanes()[2].getPixelStride();
        if (rowStride2 != image.getPlanes()[1].getRowStride() || pixelStride != image.getPlanes()[1].getPixelStride()) {
            return null;
        }
        if (pixelStride == 2 && rowStride2 == width && uBuffer.get(0) == vBuffer.get(1)) {
            byte savePixel = vBuffer.get(1);
            try {
                vBuffer.put(1, (byte) (~savePixel));
                if (uBuffer.get(0) == ((byte) (~savePixel))) {
                    vBuffer.put(1, savePixel);
                    vBuffer.position(0);
                    uBuffer.position(0);
                    vBuffer.get(this.nv21Buffer, ySize, 1);
                    uBuffer.get(this.nv21Buffer, ySize + 1, uBuffer.remaining());
                    return this.nv21Buffer;
                }
            } catch (ReadOnlyBufferException e) {
            }
            vBuffer.put(1, savePixel);
        }
        for (int row = 0; row < height / 2; row++) {
            for (int col = 0; col < width / 2; col++) {
                int vuPos = (col * pixelStride) + (row * rowStride2);
                int pos2 = pos + 1;
                this.nv21Buffer[pos] = vBuffer.get(vuPos);
                pos = pos2 + 1;
                this.nv21Buffer[pos2] = uBuffer.get(vuPos);
            }
        }
        return this.nv21Buffer;
    }

    /* JADX INFO: Access modifiers changed from: private */
    class YuvImageCapturedCallback implements ImageReader.OnImageAvailableListener {
        volatile boolean imageInUsed;

        private YuvImageCapturedCallback() {
        }

        @Override // android.media.ImageReader.OnImageAvailableListener
        public void onImageAvailable(ImageReader reader) {
            Camera2SessionNew.this.checkIsOnCameraThread();
            if (Camera2SessionNew.this.state != SessionState.RUNNING) {
                Logging.d(Camera2SessionNew.TAG, "Texture frame captured but camera is no longer running.");
                return;
            }
            long captureTimeNs = TimeUnit.MILLISECONDS.toNanos(SystemClock.elapsedRealtime());
            if (!Camera2SessionNew.this.firstFrameReported) {
                Camera2SessionNew.this.firstFrameReported = true;
                int startTimeMs = (int) TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - Camera2SessionNew.this.constructionTimeNs);
                Camera2SessionNew.camera2StartTimeMsHistogram.addSample(startTimeMs);
            }
            Image image = reader.acquireLatestImage();
            if (image == null) {
                return;
            }
            if (!this.imageInUsed) {
                this.imageInUsed = true;
                byte[] formattedImage = Camera2SessionNew.this.yuv_420_888ToNV21(image);
                NV21Buffer frameBuffer = new NV21Buffer(formattedImage, Camera2SessionNew.this.captureFormat.width, Camera2SessionNew.this.captureFormat.height, Camera2SessionNew$YuvImageCapturedCallback$$Lambda$1.lambdaFactory$(this));
                if (Camera2SessionNew.this.frameBufferCallback != null) {
                    Camera2SessionNew.this.frameBufferCallback.onBufferCaptured(frameBuffer);
                }
                if (Camera2SessionNew.this.enableDoubleCallback) {
                    int deviceRotation = Camera2SessionNew.this.windowRotation >= 0 ? Camera2SessionNew.this.windowRotation : CameraSession.getDeviceOrientation(Camera2SessionNew.this.applicationContext);
                    VideoFrame videoFrame = new VideoFrame(frameBuffer, Camera2SessionNew.this.getFrameOrientation(deviceRotation), captureTimeNs);
                    videoFrame.setExtraRotation(Camera2SessionNew.this.getFrameExtraRotation(deviceRotation));
                    Camera2SessionNew.this.events.onFrameCaptured(Camera2SessionNew.this, videoFrame);
                    videoFrame.release();
                } else {
                    frameBuffer.release();
                }
            }
            image.close();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    class CaptureSessionCallback extends CameraCaptureSession.StateCallback {
        private CaptureSessionCallback() {
        }

        @Override // android.hardware.camera2.CameraCaptureSession.StateCallback
        public void onConfigureFailed(CameraCaptureSession session) {
            Camera2SessionNew.this.checkIsOnCameraThread();
            session.close();
            Camera2SessionNew.this.reportError("Failed to configure capture session.");
        }

        @Override // android.hardware.camera2.CameraCaptureSession.StateCallback
        public void onConfigured(CameraCaptureSession session) {
            Camera2SessionNew.this.checkIsOnCameraThread();
            Logging.d(Camera2SessionNew.TAG, "Camera capture session configured.");
            Camera2SessionNew.this.captureSession = session;
            try {
                session.setRepeatingRequest(Camera2SessionNew.this.buildCaptureRequest(), new CameraCaptureCallback(), Camera2SessionNew.this.cameraThreadHandler);
                Camera2SessionNew.this.surfaceTextureHelper.startListening(Camera2SessionNew$CaptureSessionCallback$$Lambda$1.lambdaFactory$(this));
                Logging.d(Camera2SessionNew.TAG, "Camera device successfully started.");
                Camera2SessionNew.this.callback.onDone(Camera2SessionNew.this);
            } catch (CameraAccessException e) {
                Camera2SessionNew.this.reportError("Failed to start capture request. " + e);
            }
        }

        static /* synthetic */ void lambda$onConfigured$6(CaptureSessionCallback captureSessionCallback, VideoFrame frame) {
            Camera2SessionNew.this.checkIsOnCameraThread();
            if (Camera2SessionNew.this.state != SessionState.RUNNING) {
                Logging.d(Camera2SessionNew.TAG, "Texture frame captured but camera is no longer running.");
                return;
            }
            if (frame != null) {
                if (!Camera2SessionNew.this.firstFrameReported) {
                    Camera2SessionNew.this.firstFrameReported = true;
                    int startTimeMs = (int) TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - Camera2SessionNew.this.constructionTimeNs);
                    Camera2SessionNew.camera2StartTimeMsHistogram.addSample(startTimeMs);
                }
                int deviceRotation = Camera2SessionNew.this.windowRotation >= 0 ? Camera2SessionNew.this.windowRotation : CameraSession.getDeviceOrientation(Camera2SessionNew.this.applicationContext);
                int frameRotation = Camera2SessionNew.this.getFrameOrientation(deviceRotation);
                VideoFrame modifiedFrame = new VideoFrame(CameraSession.createTextureBufferWithModifiedTransformMatrix((TextureBufferImpl) frame.getBuffer(), Camera2SessionNew.this.isCameraFrontFacing, Camera2SessionNew.this.cameraOrientation, Camera2SessionNew.this.mMirror, frameRotation, Camera2SessionNew.this.noFrameRotation ? frameRotation : 0), Camera2SessionNew.this.noFrameRotation ? 0 : frameRotation, frame.getTimestampNs());
                modifiedFrame.setExtraRotation(Camera2SessionNew.this.getFrameExtraRotation(deviceRotation));
                Camera2SessionNew.this.events.onFrameCaptured(Camera2SessionNew.this, modifiedFrame);
                Camera2SessionNew.this.maybeLogFrameRotation(deviceRotation, (TextureBufferImpl) frame.getBuffer(), (TextureBufferImpl) modifiedFrame.getBuffer());
                modifiedFrame.release();
            }
        }
    }

    private static class CameraCaptureCallback extends CameraCaptureSession.CaptureCallback {
        private CameraCaptureCallback() {
        }

        @Override // android.hardware.camera2.CameraCaptureSession.CaptureCallback
        public void onCaptureFailed(CameraCaptureSession session, CaptureRequest request, CaptureFailure failure) {
            Logging.d(Camera2SessionNew.TAG, "Capture failed: " + failure);
        }
    }

    private void chooseStabilizationMode(CaptureRequest.Builder captureRequestBuilder) {
        if (!this.stabilizationEnabled) {
            Logging.d(TAG, "Stabilization not enabled.");
            return;
        }
        int[] availableOpticalStabilization = (int[]) this.cameraCharacteristics.get(CameraCharacteristics.LENS_INFO_AVAILABLE_OPTICAL_STABILIZATION);
        if (availableOpticalStabilization != null) {
            for (int mode : availableOpticalStabilization) {
                if (mode == 1) {
                    captureRequestBuilder.set(CaptureRequest.LENS_OPTICAL_STABILIZATION_MODE, 1);
                    captureRequestBuilder.set(CaptureRequest.CONTROL_VIDEO_STABILIZATION_MODE, 0);
                    Logging.d(TAG, "Using optical stabilization.");
                    return;
                }
            }
        }
        if (this.stabilizationAllowSoftware) {
            int[] availableVideoStabilization = (int[]) this.cameraCharacteristics.get(CameraCharacteristics.CONTROL_AVAILABLE_VIDEO_STABILIZATION_MODES);
            for (int mode2 : availableVideoStabilization) {
                if (mode2 == 1) {
                    captureRequestBuilder.set(CaptureRequest.CONTROL_VIDEO_STABILIZATION_MODE, 1);
                    captureRequestBuilder.set(CaptureRequest.LENS_OPTICAL_STABILIZATION_MODE, 0);
                    Logging.d(TAG, "Using video stabilization.");
                    return;
                }
            }
        }
        Logging.d(TAG, "Stabilization not available.");
    }

    @Override // org.webrtc.mozi.CameraSession
    public void setMirror(boolean mirror) {
        super.setMirror(mirror);
    }

    @Override // org.webrtc.mozi.CameraSession
    public void setStabilizationEnabled(boolean enabled, boolean allowSoftware) {
        super.setStabilizationEnabled(enabled, allowSoftware);
        resetRepeatingRequest();
    }

    @Override // org.webrtc.mozi.CameraSession
    public void setAutoFocusingEnabled(boolean enabled) {
        super.setAutoFocusingEnabled(enabled);
        resetRepeatingRequest();
    }

    private void chooseFocusMode(CaptureRequest.Builder captureRequestBuilder) {
        if (!this.autoFocusingEnabled) {
            Logging.d(TAG, "Auto-focus is not enabled.");
            return;
        }
        int[] availableFocusModes = (int[]) this.cameraCharacteristics.get(CameraCharacteristics.CONTROL_AF_AVAILABLE_MODES);
        for (int mode : availableFocusModes) {
            if (mode == 3) {
                captureRequestBuilder.set(CaptureRequest.CONTROL_AF_MODE, 3);
                Logging.d(TAG, "Using continuous video auto-focus.");
                return;
            }
        }
        Logging.d(TAG, "Auto-focus is not available.");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public CaptureRequest buildCaptureRequest() throws CameraAccessException {
        CaptureRequest.Builder captureRequestBuilder = this.cameraDevice.createCaptureRequest(3);
        captureRequestBuilder.set(CaptureRequest.CONTROL_AE_TARGET_FPS_RANGE, new Range(Integer.valueOf(this.captureFormat.framerate.min / this.fpsUnitFactor), Integer.valueOf(this.captureFormat.framerate.max / this.fpsUnitFactor)));
        captureRequestBuilder.set(CaptureRequest.CONTROL_AE_MODE, 1);
        captureRequestBuilder.set(CaptureRequest.CONTROL_AE_LOCK, false);
        chooseStabilizationMode(captureRequestBuilder);
        chooseFocusMode(captureRequestBuilder);
        captureRequestBuilder.addTarget(this.surface);
        if (this.enableDoubleCallback || this.frameBufferCallback != null) {
            captureRequestBuilder.addTarget(this.yuvImageSurface);
        }
        return captureRequestBuilder.build();
    }

    public static void create(CameraSession.CreateSessionCallback callback, CameraSession.Events events, Context applicationContext, SurfaceTextureHelper surfaceTextureHelper, String cameraId, int width, int height, int frameRate, CameraConfig config) {
        new Camera2SessionNew(callback, events, applicationContext, surfaceTextureHelper, cameraId, width, height, frameRate, config);
    }

    private Camera2SessionNew(CameraSession.CreateSessionCallback callback, CameraSession.Events events, Context applicationContext, SurfaceTextureHelper surfaceTextureHelper, String cameraId, int width, int height, int frameRate, CameraConfig config) {
        boolean z = false;
        Logging.d(TAG, "Create new camera2 session on camera " + cameraId);
        this.constructionTimeNs = System.nanoTime();
        this.cameraThreadHandler = new Handler();
        this.callback = callback;
        this.events = events;
        this.applicationContext = applicationContext;
        this.cameraManager = (CameraManager) applicationContext.getSystemService("camera");
        this.surfaceTextureHelper = surfaceTextureHelper;
        this.cameraId = cameraId;
        this.width = width;
        this.height = height;
        this.frameRate = frameRate;
        if (config != null && config.noFrameRotation) {
            z = true;
        }
        this.noFrameRotation = z;
        start();
    }

    private void start() {
        checkIsOnCameraThread();
        Logging.d(TAG, TtmlNode.START);
        try {
            CameraCharacteristics cameraCharacteristics = this.cameraManager.getCameraCharacteristics(this.cameraId);
            this.cameraCharacteristics = cameraCharacteristics;
            this.cameraOrientation = ((Integer) cameraCharacteristics.get(CameraCharacteristics.SENSOR_ORIENTATION)).intValue();
            this.isCameraFrontFacing = ((Integer) this.cameraCharacteristics.get(CameraCharacteristics.LENS_FACING)).intValue() == 0;
            findCaptureFormat();
            openCamera();
        } catch (CameraAccessException e) {
            reportError("getCameraCharacteristics(): " + e.getMessage());
        }
    }

    private void findCaptureFormat() {
        checkIsOnCameraThread();
        Range<Integer>[] fpsRanges = (Range[]) this.cameraCharacteristics.get(CameraCharacteristics.CONTROL_AE_AVAILABLE_TARGET_FPS_RANGES);
        int fpsUnitFactor = Camera2Enumerator.getFpsUnitFactor(fpsRanges);
        this.fpsUnitFactor = fpsUnitFactor;
        List<CameraEnumerationAndroid.CaptureFormat.FramerateRange> framerateRanges = Camera2Enumerator.convertFramerates(fpsRanges, fpsUnitFactor);
        List<Size> sizes = Camera2Enumerator.getSupportedSizes(this.cameraCharacteristics);
        Logging.d(TAG, "Available preview sizes: " + sizes);
        Logging.d(TAG, "Available fps ranges: " + framerateRanges);
        if (framerateRanges.isEmpty() || sizes.isEmpty()) {
            reportError("No supported capture formats.");
            return;
        }
        int i = this.width;
        int i2 = this.height;
        int i3 = this.frameRate;
        CameraEnumerationAndroid.CaptureFormat targetFormat = new CameraEnumerationAndroid.CaptureFormat(i, i2, new CameraEnumerationAndroid.CaptureFormat.FramerateRange(i3 * 1000, i3 * 1000));
        CameraEnumerationAndroid.setFrameRateDelegate(new CameraFrameRateSelector(TAG));
        CameraEnumerationAndroid.CaptureFormat.FramerateRange bestFpsRange = CameraEnumerationAndroid.getClosestSupportedFramerateRange(framerateRanges, this.frameRate);
        Size bestSize = CameraEnumerationAndroid.getClosestSupportedSize(sizes, this.width, this.height);
        CameraEnumerationAndroid.reportCameraResolution(camera2ResolutionHistogram, bestSize);
        this.captureFormat = new CameraEnumerationAndroid.CaptureFormat(bestSize.width, bestSize.height, bestFpsRange);
        Logging.d(TAG, "Using capture format: " + this.captureFormat);
        setFormatData(targetFormat, this.captureFormat);
        setSupportInfo(framerateRanges, sizes);
    }

    private void openCamera() {
        checkIsOnCameraThread();
        Logging.d(TAG, "Opening camera " + this.cameraId);
        this.events.onCameraOpening();
        try {
            this.cameraManager.openCamera(this.cameraId, new CameraStateCallback(), this.cameraThreadHandler);
        } catch (CameraAccessException e) {
            reportError("Failed to open camera: " + e);
        }
    }

    @Override // org.webrtc.mozi.CameraSession
    public void stop() {
        Logging.d(TAG, "Stop camera2 session on cameraId = [" + this.cameraId + "], by: " + getStackTrace());
        checkIsOnCameraThread();
        if (this.state != SessionState.STOPPED) {
            long stopStartTime = System.nanoTime();
            this.state = SessionState.STOPPED;
            stopInternal();
            int stopTimeMs = (int) TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - stopStartTime);
            camera2StopTimeMsHistogram.addSample(stopTimeMs);
        }
    }

    public static String getStackTrace() {
        StringBuilder sb = new StringBuilder();
        for (StackTraceElement ste : Thread.currentThread().getStackTrace()) {
            sb.append(ste);
            sb.append(ShellAdbUtils.COMMAND_LINE_END);
        }
        return sb.toString();
    }

    @Override // org.webrtc.mozi.CameraSession
    public int getCameraRotation() {
        return this.cameraOrientation;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void stopInternal() {
        Logging.d(TAG, "Stop internal");
        checkIsOnCameraThread();
        this.cameraThreadHandler.removeCallbacksAndMessages(null);
        this.surfaceTextureHelper.stopListening();
        CameraCaptureSession cameraCaptureSession = this.captureSession;
        if (cameraCaptureSession != null) {
            cameraCaptureSession.close();
            this.captureSession = null;
        }
        Surface surface = this.surface;
        if (surface != null) {
            surface.release();
            this.surface = null;
        }
        ImageReader imageReader = this.yuvImageReader;
        if (imageReader != null) {
            imageReader.close();
        }
        Surface surface2 = this.yuvImageSurface;
        if (surface2 != null) {
            surface2.release();
            this.yuvImageSurface = null;
        }
        CameraDevice cameraDevice = this.cameraDevice;
        if (cameraDevice != null) {
            cameraDevice.close();
            this.cameraDevice = null;
        }
        Logging.d(TAG, "Stop done");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void reportError(String error) {
        checkIsOnCameraThread();
        Logging.e(TAG, "Error: " + error);
        boolean startFailure = this.captureSession == null && this.state != SessionState.STOPPED;
        this.state = SessionState.STOPPED;
        stopInternal();
        if (startFailure) {
            this.callback.onFailure(CameraSession.FailureType.ERROR, error);
        } else {
            this.events.onCameraError(this, error);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public int getFrameOrientation(int deviceRotation) {
        int rotation = deviceRotation == 0 ? this.extraDeviceRotation : deviceRotation;
        if (!this.isCameraFrontFacing) {
            rotation = 360 - rotation;
        }
        return rotation % 360;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public int getFrameExtraRotation(int deviceRotation) {
        if (deviceRotation == 0) {
            return this.extraDeviceRotation;
        }
        return 0;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void maybeLogFrameRotation(int deviceRotation, TextureBufferImpl originalFrameBuffer, TextureBufferImpl modifiedFrameBuffer) {
        long time = SystemClock.elapsedRealtime();
        if (time - this.lastLogFrameRotationTime < OkHttpUtils.DEFAULT_MILLISECONDS) {
            return;
        }
        Logging.d(TAG, String.format("log frame rotation, window = %d, camera = %d, extra = %d, original {%dx%d, %s}, modified {%dx%d, %s}", Integer.valueOf(deviceRotation), Integer.valueOf(this.cameraOrientation), Integer.valueOf(this.extraDeviceRotation), Integer.valueOf(originalFrameBuffer.getWidth()), Integer.valueOf(originalFrameBuffer.getHeight()), originalFrameBuffer.getTransformMatrix().toString(), Integer.valueOf(modifiedFrameBuffer.getWidth()), Integer.valueOf(modifiedFrameBuffer.getHeight()), modifiedFrameBuffer.getTransformMatrix().toString()));
        this.lastLogFrameRotationTime = time;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void checkIsOnCameraThread() {
        if (Thread.currentThread() != this.cameraThreadHandler.getLooper().getThread()) {
            throw new IllegalStateException("Wrong thread");
        }
    }

    private void imageToByteArray(Image image, byte[] outputBuffer, int pixelCount) {
        Rect imageCrop = image.getCropRect();
        Image.Plane[] imagePlanes = image.getPlanes();
        int planeIndex = 0;
        while (planeIndex < imagePlanes.length) {
            int outputStride = 0;
            int outputOffset = 0;
            Image.Plane plane = imagePlanes[planeIndex];
            if (planeIndex == 0) {
                outputStride = 1;
                outputOffset = 0;
            } else if (planeIndex != 1) {
                if (planeIndex == 2) {
                    outputStride = 2;
                    outputOffset = pixelCount;
                }
            } else {
                outputStride = 2;
                outputOffset = pixelCount + 1;
            }
            ByteBuffer planeBuffer = plane.getBuffer();
            int rowStride = plane.getRowStride();
            int pixelStride = plane.getPixelStride();
            Rect planeCrop = planeIndex == 0 ? imageCrop : new Rect(imageCrop.left / 2, imageCrop.top / 2, imageCrop.right / 2, imageCrop.bottom / 2);
            int planeWidth = planeCrop.width();
            int planeHeight = planeCrop.height();
            byte[] rowBuffer = new byte[plane.getRowStride()];
            int rowLength = (pixelStride == 1 && outputStride == 1) ? planeWidth : ((planeWidth - 1) * pixelStride) + 1;
            int row = 0;
            while (row < planeHeight) {
                Rect imageCrop2 = imageCrop;
                Image.Plane[] imagePlanes2 = imagePlanes;
                planeBuffer.position(((planeCrop.top + row) * rowStride) + (planeCrop.left * pixelStride));
                if (pixelStride == 1 && outputStride == 1) {
                    planeBuffer.get(outputBuffer, outputOffset, rowLength);
                    outputOffset += rowLength;
                } else {
                    planeBuffer.get(rowBuffer, 0, rowLength);
                    for (int col = 0; col < planeWidth; col++) {
                        outputBuffer[outputOffset] = rowBuffer[col * pixelStride];
                        outputOffset += outputStride;
                    }
                }
                row++;
                imageCrop = imageCrop2;
                imagePlanes = imagePlanes2;
            }
            planeIndex++;
        }
    }

    public void setPreviewCallback(FrameBufferCallback callback) {
        Logging.d(TAG, "setPreviewCallback " + callback);
        this.frameBufferCallback = callback;
        resetRepeatingRequest();
    }

    public void setEnableDoubleCallback(boolean enable) {
        Logging.d(TAG, "setEnableDoubleCallback " + enable);
        this.enableDoubleCallback = enable;
        resetRepeatingRequest();
    }

    private void resetRepeatingRequest() {
        CameraCaptureSession cameraCaptureSession = this.captureSession;
        if (cameraCaptureSession == null) {
            Logging.e(TAG, "resetRepeatingRequest too early");
            return;
        }
        try {
            cameraCaptureSession.setRepeatingRequest(buildCaptureRequest(), new CameraCaptureCallback(), this.cameraThreadHandler);
        } catch (CameraAccessException e) {
            reportError("Failed to start capture request. " + e);
        }
    }
}
