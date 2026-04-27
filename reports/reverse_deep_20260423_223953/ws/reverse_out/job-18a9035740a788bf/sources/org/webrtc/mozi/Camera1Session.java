package org.webrtc.mozi;

import android.content.Context;
import android.graphics.PointF;
import android.graphics.Rect;
import android.hardware.Camera;
import android.os.Build;
import android.os.Handler;
import android.os.SystemClock;
import androidx.recyclerview.widget.ItemTouchHelper;
import com.google.android.exoplayer2.DefaultRenderersFactory;
import com.zhy.http.okhttp.OkHttpUtils;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.webrtc.mozi.CameraEnumerationAndroid;
import org.webrtc.mozi.CameraSession;
import org.webrtc.mozi.VideoFrame;

/* JADX INFO: loaded from: classes3.dex */
class Camera1Session extends CameraSession {
    private static final int NUMBER_OF_CAPTURE_BUFFERS = 3;
    private static final String TAG = "Camera1Session";
    private final Context applicationContext;
    private final Camera camera;
    private final int cameraId;
    private final Handler cameraThreadHandler;
    private final CameraEnumerationAndroid.CaptureFormat captureFormat;
    private final boolean captureToTexture;
    private final long constructionTimeNs;
    private final CameraSession.Events events;
    private Camera.PreviewCallback extraPreviewCallback;
    private final Camera.CameraInfo info;
    private float maxExposureCompensation;
    private float minExposureCompensation;
    private boolean noFrameRotation;
    private SessionState state;
    private final SurfaceTextureHelper surfaceTextureHelper;
    private static final Histogram camera1StartTimeMsHistogram = Histogram.createCounts("WebRTC.Android.Camera1.StartTimeMs", 1, 10000, 50);
    private static final Histogram camera1StopTimeMsHistogram = Histogram.createCounts("WebRTC.Android.Camera1.StopTimeMs", 1, 10000, 50);
    private static final Histogram camera1ResolutionHistogram = Histogram.createEnumeration("WebRTC.Android.Camera1.Resolution", CameraEnumerationAndroid.COMMON_RESOLUTIONS.size());
    private boolean firstFrameReported = false;
    private long lastLogFrameRotationTime = 0;
    private boolean enableDoubleCallback = false;
    private boolean isAutoFocusFaceModeEnabled = false;
    private long lastFocusTime = 0;
    private Camera.FaceDetectionListener mFaceListener = new Camera.FaceDetectionListener() { // from class: org.webrtc.mozi.Camera1Session.2
        @Override // android.hardware.Camera.FaceDetectionListener
        public void onFaceDetection(Camera.Face[] faces, Camera camera) {
            if (faces == null || faces.length == 0 || !Camera1Session.this.isAutoFocusFaceModeEnabled) {
                return;
            }
            long now = System.currentTimeMillis();
            if (now - Camera1Session.this.lastFocusTime < DefaultRenderersFactory.DEFAULT_ALLOWED_VIDEO_JOINING_TIME_MS) {
                return;
            }
            Camera.Face face = faces[0];
            Logging.i(Camera1Session.TAG, "onFaceDetection, face: " + face.id + " midX: " + face.rect.centerX() + " midY: " + face.rect.centerY());
            Camera1Session.this.setFocusInternal(face.rect);
        }
    };

    /* JADX INFO: Access modifiers changed from: private */
    enum SessionState {
        RUNNING,
        STOPPED
    }

    public static void create(CameraSession.CreateSessionCallback callback, CameraSession.Events events, boolean captureToTexture, Context applicationContext, SurfaceTextureHelper surfaceTextureHelper, int cameraId, int width, int height, int framerate, CameraConfig config) {
        Camera camera;
        Camera.Parameters parameters;
        CameraEnumerationAndroid.CaptureFormat captureFormat;
        Size pictureSize;
        long constructionTimeNs = System.nanoTime();
        Logging.d(TAG, "Open camera " + cameraId + ", " + width + "x" + height + ", fps " + framerate);
        events.onCameraOpening();
        CameraEnumerationAndroid.CaptureFormat targetFormat = new CameraEnumerationAndroid.CaptureFormat(width, height, new CameraEnumerationAndroid.CaptureFormat.FramerateRange(framerate * 1000, framerate * 1000));
        try {
            Camera camera2 = Camera.open(cameraId);
            if (camera2 == null) {
                callback.onFailure(CameraSession.FailureType.ERROR, "android.hardware.Camera.open returned null for camera id = " + cameraId);
                return;
            }
            try {
                camera2.setPreviewTexture(surfaceTextureHelper.getSurfaceTexture());
                Camera.CameraInfo info = new Camera.CameraInfo();
                Camera.getCameraInfo(cameraId, info);
                if (McsConfig.newCamera1CaptureFpsLogic()) {
                    Logging.d(TAG, "use newCamera1CaptureFpsLogic");
                    CameraEnumerationAndroid.setFrameRateDelegate(new CameraEnumerationAndroid.FrameRateDelegate() { // from class: org.webrtc.mozi.Camera1Session.1
                        @Override // org.webrtc.mozi.CameraEnumerationAndroid.FrameRateDelegate
                        public CameraEnumerationAndroid.CaptureFormat.FramerateRange getClosestSupportedFramerateRange(List<CameraEnumerationAndroid.CaptureFormat.FramerateRange> supportedFramerates, int requestedFps) {
                            if (supportedFramerates == null || supportedFramerates.size() <= 0) {
                                Logging.d(Camera1Session.TAG, "supportedFramerates null");
                                return null;
                            }
                            int targetFps = requestedFps * 1000;
                            boolean hasHigherFps = false;
                            if (supportedFramerates.size() <= 0) {
                                return null;
                            }
                            CameraEnumerationAndroid.CaptureFormat.FramerateRange range = supportedFramerates.get(0);
                            int minDiff = Math.abs(range.min - targetFps) + Math.abs(range.max - targetFps);
                            CameraEnumerationAndroid.CaptureFormat.FramerateRange targetFpsRange = range;
                            if (range.max >= targetFps) {
                                hasHigherFps = true;
                            }
                            for (int i = 1; i < supportedFramerates.size(); i++) {
                                CameraEnumerationAndroid.CaptureFormat.FramerateRange range2 = supportedFramerates.get(i);
                                if (!hasHigherFps || range2.max >= targetFps) {
                                    int currentDiff = Math.abs(range2.min - targetFps) + Math.abs(range2.max - targetFps);
                                    if (!hasHigherFps && range2.max >= targetFps) {
                                        targetFpsRange = range2;
                                        minDiff = currentDiff;
                                        hasHigherFps = true;
                                    } else if (currentDiff < minDiff) {
                                        targetFpsRange = range2;
                                        minDiff = currentDiff;
                                    }
                                }
                            }
                            return targetFpsRange;
                        }
                    });
                }
                try {
                    parameters = camera2.getParameters();
                    captureFormat = findClosestCaptureFormat(parameters, width, height, framerate);
                    try {
                        pictureSize = findClosestPictureSize(parameters, width, height);
                    } catch (RuntimeException e) {
                        e = e;
                        camera = camera2;
                    }
                } catch (RuntimeException e2) {
                    e = e2;
                    camera = camera2;
                }
                try {
                    updateCameraParameters(camera2, parameters, captureFormat, pictureSize, captureToTexture, config);
                    if (!captureToTexture) {
                        int frameSize = captureFormat.frameSize();
                        for (int i = 0; i < 3; i++) {
                            ByteBuffer buffer = ByteBuffer.allocateDirect(frameSize);
                            camera2.addCallbackBuffer(buffer.array());
                        }
                    }
                    camera2.setDisplayOrientation(0);
                    Camera1Session session = new Camera1Session(events, captureToTexture, applicationContext, surfaceTextureHelper, cameraId, camera2, info, captureFormat, constructionTimeNs);
                    session.setFormatData(targetFormat, captureFormat);
                    try {
                        session.setSupportInfo(Camera1Enumerator.convertFramerates(camera2.getParameters().getSupportedPreviewFpsRange()), Camera1Enumerator.convertSizes(camera2.getParameters().getSupportedPreviewSizes()));
                    } catch (Exception e3) {
                    }
                    session.noFrameRotation = config != null && config.noFrameRotation;
                    callback.onDone(session);
                } catch (RuntimeException e4) {
                    e = e4;
                    camera = camera2;
                    camera.release();
                    callback.onFailure(CameraSession.FailureType.ERROR, e.getMessage());
                }
            } catch (IOException | RuntimeException e5) {
                camera2.release();
                callback.onFailure(CameraSession.FailureType.ERROR, e5.getMessage());
            }
        } catch (RuntimeException e6) {
            callback.onFailure(CameraSession.FailureType.ERROR, e6.getMessage());
        }
    }

    private static void updateCameraParameters(Camera camera, Camera.Parameters parameters, CameraEnumerationAndroid.CaptureFormat captureFormat, Size pictureSize, boolean captureToTexture, CameraConfig config) {
        List<String> focusModes = parameters.getSupportedFocusModes();
        if (McsConfig.newCamera1CaptureFpsLogic()) {
            if (!Build.BRAND.equals("Coolpad") && !Build.BRAND.equals("360") && !Build.BRAND.equals("YOTA") && !Build.MODEL.contains("Redmi") && !Build.MODEL.contains("SM-N9100") && captureFormat.framerate != null) {
                parameters.setPreviewFpsRange(captureFormat.framerate.min, captureFormat.framerate.max);
            }
        } else {
            parameters.setPreviewFpsRange(captureFormat.framerate.min, captureFormat.framerate.max);
        }
        parameters.setPreviewSize(captureFormat.width, captureFormat.height);
        parameters.setPictureSize(pictureSize.width, pictureSize.height);
        if (!captureToTexture) {
            captureFormat.getClass();
            parameters.setPreviewFormat(17);
        }
        if (parameters.isVideoStabilizationSupported()) {
            parameters.setVideoStabilization(true);
        }
        if (focusModes.contains("continuous-video")) {
            parameters.setFocusMode("continuous-video");
        }
        if (config != null && config.isFixAutoExposure) {
            parameters.setAutoExposureLock(false);
        }
        camera.setParameters(parameters);
    }

    private static CameraEnumerationAndroid.CaptureFormat findClosestCaptureFormat(Camera.Parameters parameters, int width, int height, int framerate) {
        List<CameraEnumerationAndroid.CaptureFormat.FramerateRange> supportedFramerates = Camera1Enumerator.convertFramerates(parameters.getSupportedPreviewFpsRange());
        Logging.d(TAG, "Available fps ranges: " + supportedFramerates);
        CameraEnumerationAndroid.CaptureFormat.FramerateRange fpsRange = CameraEnumerationAndroid.getClosestSupportedFramerateRange(supportedFramerates, framerate);
        Size previewSize = CameraEnumerationAndroid.getClosestSupportedSize(Camera1Enumerator.convertSizes(parameters.getSupportedPreviewSizes()), width, height);
        CameraEnumerationAndroid.reportCameraResolution(camera1ResolutionHistogram, previewSize);
        StringBuilder sb = new StringBuilder();
        sb.append("Closest capture format: ");
        sb.append(previewSize.width);
        sb.append("x");
        sb.append(previewSize.height);
        sb.append(fpsRange == null ? " fpsRange null" : fpsRange.toString());
        Logging.d(TAG, sb.toString());
        return new CameraEnumerationAndroid.CaptureFormat(previewSize.width, previewSize.height, fpsRange);
    }

    private static Size findClosestPictureSize(Camera.Parameters parameters, int width, int height) {
        return CameraEnumerationAndroid.getClosestSupportedSize(Camera1Enumerator.convertSizes(parameters.getSupportedPictureSizes()), width, height);
    }

    private Camera1Session(CameraSession.Events events, boolean captureToTexture, Context applicationContext, SurfaceTextureHelper surfaceTextureHelper, int cameraId, Camera camera, Camera.CameraInfo info, CameraEnumerationAndroid.CaptureFormat captureFormat, long constructionTimeNs) {
        this.minExposureCompensation = 0.0f;
        this.maxExposureCompensation = 0.0f;
        Logging.d(TAG, "Create new camera1 session on camera " + cameraId);
        this.cameraThreadHandler = new Handler();
        this.events = events;
        this.captureToTexture = captureToTexture;
        this.applicationContext = applicationContext;
        this.surfaceTextureHelper = surfaceTextureHelper;
        this.cameraId = cameraId;
        this.camera = camera;
        this.info = info;
        this.captureFormat = captureFormat;
        this.constructionTimeNs = constructionTimeNs;
        Camera.Parameters parameters = camera.getParameters();
        this.minExposureCompensation = parameters.getMinExposureCompensation();
        this.maxExposureCompensation = parameters.getMaxExposureCompensation();
        surfaceTextureHelper.setTextureSize(captureFormat.width, captureFormat.height);
        startCapturing();
    }

    @Override // org.webrtc.mozi.CameraSession
    public void stop() {
        Logging.d(TAG, "Stop camera1 session on camera " + this.cameraId);
        checkIsOnCameraThread();
        if (this.state != SessionState.STOPPED) {
            long stopStartTime = System.nanoTime();
            stopInternal();
            int stopTimeMs = (int) TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - stopStartTime);
            camera1StopTimeMsHistogram.addSample(stopTimeMs);
        }
    }

    private void startCapturing() {
        Logging.d(TAG, "Start capturing");
        checkIsOnCameraThread();
        this.state = SessionState.RUNNING;
        this.camera.setErrorCallback(new Camera.ErrorCallback() { // from class: org.webrtc.mozi.Camera1Session.3
            @Override // android.hardware.Camera.ErrorCallback
            public void onError(int error, Camera camera) {
                String errorMessage;
                if (error == 100) {
                    errorMessage = "Camera server died!";
                } else {
                    errorMessage = "Camera error: " + error;
                }
                Logging.e(Camera1Session.TAG, errorMessage);
                Camera1Session.this.stopInternal();
                if (error == 2) {
                    Camera1Session.this.events.onCameraDisconnected(Camera1Session.this);
                } else {
                    Camera1Session.this.events.onCameraError(Camera1Session.this, errorMessage);
                }
            }
        });
        if (this.captureToTexture) {
            listenForTextureFrames();
            if (this.enableDoubleCallback) {
                int frameSize = this.captureFormat.frameSize();
                for (int i = 0; i < 3; i++) {
                    ByteBuffer buffer = ByteBuffer.allocateDirect(frameSize);
                    this.camera.addCallbackBuffer(buffer.array());
                }
                listenForBytebufferFrames();
            }
        } else {
            listenForBytebufferFrames();
        }
        try {
            this.camera.startPreview();
            if (this.isAutoFocusFaceModeEnabled) {
                this.camera.setFaceDetectionListener(this.mFaceListener);
                this.camera.startFaceDetection();
                Logging.d(TAG, "startFaceDetection");
            }
        } catch (RuntimeException e) {
            stopInternal();
            this.events.onCameraError(this, e.getMessage());
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void stopInternal() {
        Logging.d(TAG, "Stop internal");
        checkIsOnCameraThread();
        if (this.state == SessionState.STOPPED) {
            Logging.d(TAG, "Camera is already stopped");
            return;
        }
        this.state = SessionState.STOPPED;
        this.surfaceTextureHelper.stopListening();
        if (this.isAutoFocusFaceModeEnabled) {
            this.camera.stopFaceDetection();
            this.camera.setFaceDetectionListener(null);
            Logging.d(TAG, "stopFaceDetection");
        }
        try {
            this.camera.stopPreview();
            this.camera.release();
        } catch (Throwable e) {
            Logging.e(TAG, "Stop failed", e);
        }
        this.events.onCameraClosed(this);
        Logging.d(TAG, "Stop done");
    }

    private void listenForTextureFrames() {
        this.surfaceTextureHelper.startListening(Camera1Session$$Lambda$1.lambdaFactory$(this));
    }

    static /* synthetic */ void lambda$listenForTextureFrames$0(Camera1Session camera1Session, VideoFrame frame) {
        camera1Session.checkIsOnCameraThread();
        if (camera1Session.state != SessionState.RUNNING) {
            Logging.d(TAG, "Texture frame captured but camera is no longer running.");
            return;
        }
        if (frame == null) {
            return;
        }
        if (!camera1Session.firstFrameReported) {
            int startTimeMs = (int) TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - camera1Session.constructionTimeNs);
            camera1StartTimeMsHistogram.addSample(startTimeMs);
            camera1Session.firstFrameReported = true;
        }
        int deviceRotation = camera1Session.windowRotation >= 0 ? camera1Session.windowRotation : CameraSession.getDeviceOrientation(camera1Session.applicationContext);
        int frameRotation = camera1Session.noFrameRotation ? 0 : camera1Session.getFrameOrientation(deviceRotation);
        VideoFrame modifiedFrame = new VideoFrame(camera1Session.getFrameTextureBuffer(frame, deviceRotation), frameRotation, frame.getTimestampNs());
        modifiedFrame.setExtraRotation(camera1Session.getFrameExtraRotation(deviceRotation));
        camera1Session.maybeLogFrameRotation(deviceRotation);
        camera1Session.events.onFrameCaptured(camera1Session, modifiedFrame);
        modifiedFrame.release();
    }

    /* JADX INFO: renamed from: org.webrtc.mozi.Camera1Session$4, reason: invalid class name */
    class AnonymousClass4 implements Camera.PreviewCallback {
        AnonymousClass4() {
        }

        @Override // android.hardware.Camera.PreviewCallback
        public void onPreviewFrame(byte[] data, Camera callbackCamera) {
            Camera1Session.this.checkIsOnCameraThread();
            if (callbackCamera == Camera1Session.this.camera) {
                if (Camera1Session.this.state != SessionState.RUNNING) {
                    Logging.d(Camera1Session.TAG, "Bytebuffer frame captured but camera is no longer running.");
                    return;
                }
                long captureTimeNs = TimeUnit.MILLISECONDS.toNanos(SystemClock.elapsedRealtime());
                if (!Camera1Session.this.firstFrameReported) {
                    int startTimeMs = (int) TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - Camera1Session.this.constructionTimeNs);
                    Camera1Session.camera1StartTimeMsHistogram.addSample(startTimeMs);
                    Camera1Session.this.firstFrameReported = true;
                }
                VideoFrame.Buffer frameBuffer = new NV21Buffer(data, Camera1Session.this.captureFormat.width, Camera1Session.this.captureFormat.height, Camera1Session$4$$Lambda$1.lambdaFactory$(this, data));
                int deviceRotation = Camera1Session.this.windowRotation >= 0 ? Camera1Session.this.windowRotation : CameraSession.getDeviceOrientation(Camera1Session.this.applicationContext);
                VideoFrame frame = new VideoFrame(frameBuffer, Camera1Session.this.getFrameOrientation(deviceRotation), captureTimeNs);
                frame.setExtraRotation(Camera1Session.this.getFrameExtraRotation(deviceRotation));
                Camera1Session.this.events.onFrameCaptured(Camera1Session.this, frame);
                frame.release();
                return;
            }
            Logging.e(Camera1Session.TAG, "Callback from a different camera. This should never happen.");
        }

        static /* synthetic */ void lambda$null$1(AnonymousClass4 anonymousClass4, byte[] bArr) {
            if (Camera1Session.this.state == SessionState.RUNNING) {
                Camera1Session.this.camera.addCallbackBuffer(bArr);
            }
        }
    }

    private void listenForBytebufferFrames() {
        this.camera.setPreviewCallbackWithBuffer(new AnonymousClass4());
    }

    private VideoFrame.TextureBuffer getFrameTextureBuffer(VideoFrame frame, int deviceRotation) {
        boolean xMirror;
        int rotation = this.noFrameRotation ? (getFrameOrientation(deviceRotation) + getCameraRotation()) % 360 : getCameraRotation();
        if (this.mMirror) {
            int frameOrientation = getFrameOrientation(deviceRotation);
            boolean isFrontFacing = this.info.facing == 1;
            int orientationDiff = Math.abs(frameOrientation - getCameraRotation()) % 360;
            boolean fixMirror = WebrtcGrayConfig.sFixCamera1Mirror;
            if (this.noFrameRotation) {
                if (isFrontFacing) {
                    if (fixMirror) {
                        xMirror = orientationDiff == 90 || orientationDiff == 270;
                        if (orientationDiff == 90 || orientationDiff == 270) {
                            yMirror = true;
                        }
                    } else {
                        xMirror = frameOrientation == 0 || frameOrientation == 180;
                        if (frameOrientation == 0 || frameOrientation == 180) {
                            yMirror = true;
                        }
                    }
                } else {
                    xMirror = true;
                    yMirror = false;
                }
            } else if (isFrontFacing) {
                if (fixMirror) {
                    xMirror = orientationDiff == 90 || orientationDiff == 270;
                    if (orientationDiff == 90 || orientationDiff == 270) {
                        yMirror = true;
                    }
                } else {
                    xMirror = frameOrientation == 0 || frameOrientation == 180;
                    if (frameOrientation == 0 || frameOrientation == 180) {
                        yMirror = true;
                    }
                }
            } else if (fixMirror) {
                xMirror = orientationDiff == 90 || orientationDiff == 270;
                if (orientationDiff == 0 || orientationDiff == 180) {
                    yMirror = true;
                }
            } else {
                xMirror = frameOrientation == 0 || frameOrientation == 180;
                if (frameOrientation == 90 || frameOrientation == 270) {
                    yMirror = true;
                }
            }
            VideoFrame.TextureBuffer textureBuffer = CameraSession.createTextureBufferWithModifiedTransformMatrix((TextureBufferImpl) frame.getBuffer(), xMirror, yMirror, rotation);
            return textureBuffer;
        }
        TextureBufferImpl textureBufferImpl = (TextureBufferImpl) frame.getBuffer();
        yMirror = this.info.facing == 1;
        VideoFrame.TextureBuffer textureBuffer2 = CameraSession.createTextureBufferWithModifiedTransformMatrix(textureBufferImpl, yMirror, rotation);
        return textureBuffer2;
    }

    @Override // org.webrtc.mozi.CameraSession
    public int getCameraRotation() {
        return this.info.orientation;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public int getFrameOrientation(int deviceRotation) {
        int rotation = deviceRotation == 0 ? this.extraDeviceRotation : deviceRotation;
        if (this.info.facing == 0) {
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

    private void maybeLogFrameRotation(int deviceRotation) {
        long time = SystemClock.elapsedRealtime();
        if (time - this.lastLogFrameRotationTime < OkHttpUtils.DEFAULT_MILLISECONDS) {
            return;
        }
        Logging.d(TAG, String.format("log frame rotation, window = %d, camera = %d, extra = %d", Integer.valueOf(deviceRotation), Integer.valueOf(this.info.orientation), Integer.valueOf(this.extraDeviceRotation)));
        this.lastLogFrameRotationTime = time;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void checkIsOnCameraThread() {
        if (Thread.currentThread() != this.cameraThreadHandler.getLooper().getThread()) {
            throw new IllegalStateException("Wrong thread");
        }
    }

    public void setPreviewCallbackWithBuffer(Camera.PreviewCallback cb) {
        if (!this.captureToTexture || cb == this.extraPreviewCallback) {
            return;
        }
        this.extraPreviewCallback = cb;
        if (cb != null) {
            int frameSize = this.captureFormat.frameSize();
            for (int i = 0; i < 3; i++) {
                ByteBuffer buffer = ByteBuffer.allocateDirect(frameSize);
                this.camera.addCallbackBuffer(buffer.array());
            }
        }
        this.camera.setPreviewCallbackWithBuffer(cb);
    }

    public CameraEnumerationAndroid.CaptureFormat getCaptureFormat() {
        return this.captureFormat;
    }

    public void setEnableDoubleCallback(boolean enable) {
        if (this.captureToTexture) {
            Logging.d(TAG, "setEnableDoubleCallback " + enable);
            if (this.enableDoubleCallback != enable) {
                this.enableDoubleCallback = enable;
                if (this.state == SessionState.RUNNING) {
                    if (this.enableDoubleCallback) {
                        int frameSize = this.captureFormat.frameSize();
                        for (int i = 0; i < 3; i++) {
                            ByteBuffer buffer = ByteBuffer.allocateDirect(frameSize);
                            this.camera.addCallbackBuffer(buffer.array());
                        }
                        listenForBytebufferFrames();
                        return;
                    }
                    this.camera.setPreviewCallbackWithBuffer(null);
                    return;
                }
                return;
            }
            return;
        }
        Logging.w(TAG, "setEnableDoubleCallback only work when captureToTexture is true");
    }

    @Override // org.webrtc.mozi.CameraSession
    public int setCameraZoom(float zoom) {
        if (this.state != SessionState.RUNNING) {
            Logging.e(TAG, "setCameraZoom, camera is no longer running.");
            return -1;
        }
        Camera camera = this.camera;
        if (camera != null) {
            Camera.Parameters parameters = camera.getParameters();
            if (parameters.isZoomSupported() && zoom >= 0.0f) {
                int zoomRatio = (int) (100.0f * zoom);
                List<Integer> zoomRatios = parameters.getZoomRatios();
                if (zoomRatios == null) {
                    return -1;
                }
                int zoomLevel = 0;
                int i = 0;
                while (true) {
                    if (i >= zoomRatios.size()) {
                        break;
                    }
                    if (zoomRatio <= zoomRatios.get(i).intValue()) {
                        zoomLevel = i;
                        break;
                    }
                    i++;
                }
                int maxZoom = parameters.getMaxZoom();
                if (zoomLevel > maxZoom) {
                    Logging.e(TAG, "setCameraZoom  max zoom " + maxZoom + "set zoom " + zoom + " failed");
                    return -1;
                }
                Logging.i(TAG, "setCameraZoom set zoomLevel " + zoomLevel);
                parameters.setZoom(zoomLevel);
                try {
                    this.camera.setParameters(parameters);
                    return 0;
                } catch (Throwable th) {
                    Logging.e(TAG, "setCameraZoom set zoom " + zoom + " failed");
                    return 0;
                }
            }
        }
        return -1;
    }

    @Override // org.webrtc.mozi.CameraSession
    public int setCameraFlash(boolean enabled) {
        Camera.Parameters parameters;
        List<String> flashModes;
        if (this.state != SessionState.RUNNING) {
            Logging.e(TAG, "setCameraZoom, camera is no longer running.");
            return -1;
        }
        Camera camera = this.camera;
        if (camera == null || (parameters = camera.getParameters()) == null || (flashModes = parameters.getSupportedFlashModes()) == null) {
            return -1;
        }
        String flashMode = parameters.getFlashMode();
        if (enabled && !"torch".equals(flashMode)) {
            if (!flashModes.contains("torch")) {
                return -1;
            }
            parameters.setFlashMode("torch");
        } else {
            if (enabled || "off".equals(flashMode)) {
                return 0;
            }
            if (!flashModes.contains("off")) {
                return -1;
            }
            parameters.setFlashMode("off");
        }
        try {
            this.camera.setParameters(parameters);
        } catch (Throwable th) {
            Logging.e(TAG, "setCameraFlash " + enabled + " failed");
        }
        return 0;
    }

    @Override // org.webrtc.mozi.CameraSession
    public boolean isCameraFocusPointSupported() {
        Camera.Parameters parameters;
        if (this.state != SessionState.RUNNING) {
            Logging.e(TAG, "isCameraFocusPointSupported, camera is no longer running.");
            return false;
        }
        Camera camera = this.camera;
        return (camera == null || (parameters = camera.getParameters()) == null || parameters.getMaxNumFocusAreas() <= 0) ? false : true;
    }

    @Override // org.webrtc.mozi.CameraSession
    public int setCameraFocusPoint(float xRatio, float yRatio) {
        if (this.camera == null || !isCameraFocusPointSupported()) {
            return -1;
        }
        PointF point = adjustPoint(xRatio, yRatio);
        Logging.e(TAG, "setCameraFocusPoint, [" + point.x + " " + point.y + "]");
        int x = (int) ((point.x * 2000.0f) - 1000.0f);
        int y = (int) ((point.y * 2000.0f) - 1000.0f);
        int left = clamp(x - (ItemTouchHelper.Callback.DEFAULT_DRAG_ANIMATION_DURATION / 2), -1000, 1000);
        int top = clamp(y - (ItemTouchHelper.Callback.DEFAULT_DRAG_ANIMATION_DURATION / 2), -1000, 1000);
        int right = clamp((ItemTouchHelper.Callback.DEFAULT_DRAG_ANIMATION_DURATION / 2) + left, -1000, 1000);
        int bottom = clamp((ItemTouchHelper.Callback.DEFAULT_DRAG_ANIMATION_DURATION / 2) + top, -1000, 1000);
        Rect rect = new Rect(left, top, right, bottom);
        setFocusInternal(rect);
        return 0;
    }

    @Override // org.webrtc.mozi.CameraSession
    public boolean isCameraExposurePointSupported() {
        Camera.Parameters parameters;
        if (this.state != SessionState.RUNNING) {
            Logging.e(TAG, "isCameraExposurePointSupported, camera is no longer running.");
            return false;
        }
        Camera camera = this.camera;
        return (camera == null || (parameters = camera.getParameters()) == null || parameters.getMaxNumMeteringAreas() <= 0) ? false : true;
    }

    @Override // org.webrtc.mozi.CameraSession
    public int setCameraExposurePoint(float xRatio, float yRatio) {
        Camera.Parameters parameters;
        if (this.camera == null || !isCameraExposurePointSupported() || (parameters = this.camera.getParameters()) == null) {
            return -1;
        }
        PointF point = adjustPoint(xRatio, yRatio);
        Logging.e(TAG, "setCameraExposurePoint, [" + point.x + " " + point.y + "]");
        int x = (int) ((point.x * 2000.0f) - 1000.0f);
        int y = (int) ((point.y * 2000.0f) - 1000.0f);
        int left = clamp(x - (ItemTouchHelper.Callback.DEFAULT_DRAG_ANIMATION_DURATION / 2), -1000, 1000);
        int top = clamp(y - (ItemTouchHelper.Callback.DEFAULT_DRAG_ANIMATION_DURATION / 2), -1000, 1000);
        int right = clamp((ItemTouchHelper.Callback.DEFAULT_DRAG_ANIMATION_DURATION / 2) + left, -1000, 1000);
        int bottom = clamp((ItemTouchHelper.Callback.DEFAULT_DRAG_ANIMATION_DURATION / 2) + top, -1000, 1000);
        Camera.Area area = new Camera.Area(new Rect(left, top, right, bottom), 1);
        List<Camera.Area> areas = new ArrayList<>();
        areas.add(area);
        parameters.setMeteringAreas(areas);
        try {
            this.camera.setParameters(parameters);
            return 0;
        } catch (Throwable th) {
            Logging.e(TAG, "setCameraExposurePoint, set focus area failed");
            return -1;
        }
    }

    @Override // org.webrtc.mozi.CameraSession
    public boolean isCameraAutoFocusFaceModeSupported() {
        Camera.Parameters parameters;
        if (this.state != SessionState.RUNNING) {
            Logging.e(TAG, "isCameraAutoFocusFaceModeSupported, camera is no longer running.");
            return false;
        }
        Camera camera = this.camera;
        if (camera == null || (parameters = camera.getParameters()) == null) {
            return false;
        }
        if (parameters.getMaxNumFocusAreas() > 0 && parameters.getMaxNumDetectedFaces() > 0) {
            return true;
        }
        Logging.i(TAG, "isCameraAutoFocusFaceModeSupported, not support");
        return false;
    }

    @Override // org.webrtc.mozi.CameraSession
    public int setCameraAutoFocusFaceModeEnable(boolean enabled) {
        if (!isCameraAutoFocusFaceModeSupported()) {
            return -1;
        }
        Logging.i(TAG, "setCameraAutoFocusFaceModeEnable " + enabled + "," + this.isAutoFocusFaceModeEnabled);
        if (enabled) {
            if (!this.isAutoFocusFaceModeEnabled) {
                try {
                    this.camera.setFaceDetectionListener(this.mFaceListener);
                    this.camera.startFaceDetection();
                    Logging.i(TAG, "start face detection ");
                } catch (Throwable th) {
                    Logging.e(TAG, "setCameraAutoFocusFaceModeEnable, start face detection failed");
                    this.camera.stopFaceDetection();
                    this.camera.setFaceDetectionListener(null);
                    Logging.i(TAG, "stop face detection ");
                    return -1;
                }
            }
        } else if (this.isAutoFocusFaceModeEnabled) {
            this.camera.stopFaceDetection();
            this.camera.setFaceDetectionListener(null);
            Logging.i(TAG, "stop face detection ");
        }
        this.isAutoFocusFaceModeEnabled = enabled;
        return 0;
    }

    @Override // org.webrtc.mozi.CameraSession
    public int setCameraExposureValue(float value) {
        if (value < this.minExposureCompensation || value > this.maxExposureCompensation) {
            return -1;
        }
        this.cameraThreadHandler.post(Camera1Session$$Lambda$2.lambdaFactory$(this, value));
        return 0;
    }

    static /* synthetic */ void lambda$setCameraExposureValue$3(Camera1Session camera1Session, float f) {
        Camera.Parameters parameters;
        Camera camera = camera1Session.camera;
        if (camera == null || (parameters = camera.getParameters()) == null) {
            return;
        }
        parameters.setExposureCompensation(Math.round(f));
        try {
            camera1Session.camera.setParameters(parameters);
        } catch (Throwable th) {
            Logging.e(TAG, "setCameraExposureValue, set exposure compensation failed");
        }
    }

    @Override // org.webrtc.mozi.CameraSession
    public float getCameraMinExposureValue() {
        return this.minExposureCompensation;
    }

    @Override // org.webrtc.mozi.CameraSession
    public float getCameraMaxExposureValue() {
        return this.maxExposureCompensation;
    }

    private PointF adjustPoint(float xRatio, float yRatio) {
        PointF point = new PointF(xRatio, yRatio);
        int deviceRotation = this.windowRotation >= 0 ? this.windowRotation : CameraSession.getDeviceOrientation(this.applicationContext);
        int rotation = getFrameOrientation(deviceRotation);
        if (this.info.facing == 1) {
            if (rotation == 90) {
                point.x = 1.0f - xRatio;
                point.y = yRatio;
            } else if (rotation == 270) {
                point.x = xRatio;
                point.y = 1.0f - yRatio;
            } else if (rotation == 180) {
                point.x = yRatio;
                point.y = xRatio;
            } else {
                point.x = 1.0f - yRatio;
                point.y = 1.0f - xRatio;
            }
        } else if (rotation == 90) {
            point.x = 1.0f - xRatio;
            point.y = 1.0f - yRatio;
        } else if (rotation == 270) {
            point.x = xRatio;
            point.y = yRatio;
        } else if (rotation == 180) {
            point.x = 1.0f - yRatio;
            point.y = xRatio;
        } else {
            point.x = yRatio;
            point.y = 1.0f - xRatio;
        }
        return point;
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

    /* JADX INFO: Access modifiers changed from: private */
    public int setFocusInternal(Rect rect) {
        Camera.Area area = new Camera.Area(rect, 1);
        List<Camera.Area> areas = new ArrayList<>();
        areas.add(area);
        Camera.Parameters parameters = this.camera.getParameters();
        if (parameters == null) {
            return -1;
        }
        parameters.setFocusMode("auto");
        parameters.setFocusAreas(areas);
        try {
            this.camera.setParameters(parameters);
            this.camera.autoFocus(new Camera.AutoFocusCallback() { // from class: org.webrtc.mozi.Camera1Session.5
                @Override // android.hardware.Camera.AutoFocusCallback
                public void onAutoFocus(boolean success, Camera camera) {
                    if (success) {
                        camera.cancelAutoFocus();
                    }
                }
            });
            this.lastFocusTime = System.currentTimeMillis();
            return 0;
        } catch (Throwable th) {
            Logging.e(TAG, "setCameraFocusPoint, set focus area failed");
            return 0;
        }
    }
}
