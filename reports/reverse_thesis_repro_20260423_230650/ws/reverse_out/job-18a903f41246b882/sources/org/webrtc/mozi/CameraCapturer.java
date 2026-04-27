package org.webrtc.mozi;

import android.content.Context;
import android.graphics.Matrix;
import android.hardware.Camera;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import java.util.Arrays;
import javax.annotation.Nullable;
import org.webrtc.mozi.CameraSession;
import org.webrtc.mozi.CameraVideoCapturer;
import org.webrtc.mozi.ImageReaderCore;
import org.webrtc.mozi.VideoFrame;

/* JADX INFO: loaded from: classes3.dex */
abstract class CameraCapturer extends CameraVideoCapturer {
    private static final int MAX_OPEN_CAMERA_ATTEMPTS = 3;
    private static final int OPEN_CAMERA_DELAY_MS = 500;
    private static final int OPEN_CAMERA_TIMEOUT = 10000;
    private static final String TAG = "CameraCapturer";
    private Context applicationContext;
    private final CameraEnumerator cameraEnumerator;
    private String cameraName;

    @Nullable
    private CameraVideoCapturer.CameraStatistics cameraStatistics;

    @Nullable
    private Handler cameraThreadHandler;
    private CapturerObserver capturerObserver;
    protected CameraConfig config;

    @Nullable
    private CameraSession currentSession;

    @Nullable
    private final CameraVideoCapturer.CameraEventsHandler eventsHandler;
    private boolean firstFrameObserved;
    private int framerate;
    private boolean hasStoped;
    private int height;
    private ImageReaderCore.OnImageReaderCoreListener imageListener;
    private boolean isFixStopCameraAnr;
    private volatile boolean isFrontFacing;
    private int openAttemptsRemaining;
    private VideoResolution publishResolution;
    private boolean sessionOpening;

    @Nullable
    private SurfaceTextureHelper surfaceHelper;

    @Nullable
    private CameraVideoCapturer.CameraSwitchHandler switchEventsHandler;
    private final Handler uiThreadHandler;
    private int width;
    private static boolean disable_dummy_render = true;
    private static boolean texture2yuv = false;
    private static boolean needNofityCaptureThreadChange = false;
    private final McsConfigHelper configHelper = new McsConfigHelper(0);
    private DummySurfaceRender dummyRender = null;
    private boolean videoMirror = false;
    private int stored_rotation = 0;
    private long stored_timestamp_ns = 0;
    private int restartAttemptsRemaining = 1;
    private boolean isRestartAttemptsEnable = false;

    @Nullable
    private final CameraSession.CreateSessionCallback createSessionCallback = new CameraSession.CreateSessionCallback() { // from class: org.webrtc.mozi.CameraCapturer.1
        @Override // org.webrtc.mozi.CameraSession.CreateSessionCallback
        public void onDone(CameraSession session) {
            CameraCapturer.this.checkIsOnCameraThread();
            CameraSession cameraSessionNeedClose = null;
            Logging.d(CameraCapturer.TAG, "Create session done. Switch state: " + CameraCapturer.this.switchState);
            CameraCapturer.this.uiThreadHandler.removeCallbacks(CameraCapturer.this.openCameraTimeoutRunnable);
            synchronized (CameraCapturer.this.stateLock) {
                if (CameraCapturer.this.isFixStopCameraAnr && CameraCapturer.this.hasStoped) {
                    cameraSessionNeedClose = session;
                }
                if (CameraCapturer.this.capturerObserver != null) {
                    CameraCapturer.this.capturerObserver.onCapturerStarted(true);
                }
                CameraCapturer.this.sessionOpening = false;
                CameraCapturer.this.currentSession = session;
                CameraCapturer.this.cameraStatistics = new CameraVideoCapturer.CameraStatistics(CameraCapturer.this.surfaceHelper, CameraCapturer.this.eventsHandler);
                CameraCapturer.this.firstFrameObserved = false;
                CameraCapturer.this.restartAttemptsRemaining = 1;
                if (!CameraCapturer.this.isFixStopCameraAnr) {
                    CameraCapturer.this.stateLock.notifyAll();
                }
                if (CameraCapturer.this.switchState != SwitchState.IN_PROGRESS) {
                    if (CameraCapturer.this.switchState == SwitchState.PENDING) {
                        CameraCapturer.this.switchState = SwitchState.IDLE;
                        CameraCapturer.this.switchCameraInternal(CameraCapturer.this.switchEventsHandler);
                    }
                } else {
                    CameraCapturer.this.switchState = SwitchState.IDLE;
                    if (CameraCapturer.this.switchEventsHandler != null) {
                        CameraCapturer.this.switchEventsHandler.onCameraSwitchDone(CameraCapturer.this.cameraEnumerator.isFrontFacing(CameraCapturer.this.cameraName));
                        CameraCapturer.this.switchEventsHandler = null;
                    }
                }
                if (CameraCapturer.this.isFixStopCameraAnr && CameraCapturer.this.hasStoped) {
                    if (cameraSessionNeedClose == CameraCapturer.this.currentSession) {
                        CameraCapturer.this.currentSession = null;
                    } else {
                        cameraSessionNeedClose = null;
                    }
                }
            }
            CameraCapturer.this.onCreateCameraSessionDone(session);
            if (CameraCapturer.this.isFixStopCameraAnr && cameraSessionNeedClose != null) {
                final CameraSession cameraSessionNeedCloseFinal = cameraSessionNeedClose;
                CameraCapturer.this.cameraThreadHandler.post(new Runnable() { // from class: org.webrtc.mozi.CameraCapturer.1.1
                    @Override // java.lang.Runnable
                    public void run() {
                        cameraSessionNeedCloseFinal.stop();
                    }
                });
            }
        }

        @Override // org.webrtc.mozi.CameraSession.CreateSessionCallback
        public void onFailure(CameraSession.FailureType failureType, String error) {
            CameraCapturer.this.checkIsOnCameraThread();
            CameraCapturer.this.uiThreadHandler.removeCallbacks(CameraCapturer.this.openCameraTimeoutRunnable);
            synchronized (CameraCapturer.this.stateLock) {
                if (CameraCapturer.this.capturerObserver != null) {
                    CameraCapturer.this.capturerObserver.onCapturerStarted(false);
                }
                CameraCapturer.access$2010(CameraCapturer.this);
                if (CameraCapturer.this.openAttemptsRemaining <= 0 || (CameraCapturer.this.isFixStopCameraAnr && CameraCapturer.this.hasStoped)) {
                    Logging.w(CameraCapturer.TAG, "Opening camera failed, passing: " + error);
                    CameraCapturer.this.sessionOpening = false;
                    if (!CameraCapturer.this.isFixStopCameraAnr) {
                        CameraCapturer.this.stateLock.notifyAll();
                    }
                    if (CameraCapturer.this.switchState != SwitchState.IDLE) {
                        if (CameraCapturer.this.switchEventsHandler != null) {
                            CameraCapturer.this.switchEventsHandler.onCameraSwitchError(error);
                            CameraCapturer.this.switchEventsHandler = null;
                        }
                        CameraCapturer.this.switchState = SwitchState.IDLE;
                    }
                    CameraSessionData sessionData = CameraCapturer.this.currentSession != null ? CameraCapturer.this.currentSession.getCameraSessionData() : null;
                    if (failureType == CameraSession.FailureType.DISCONNECTED) {
                        CameraCapturer.this.eventsHandler.onCameraDisconnected(sessionData);
                    } else {
                        CameraCapturer.this.eventsHandler.onCameraError(sessionData, error);
                    }
                } else {
                    Logging.w(CameraCapturer.TAG, "Opening camera failed, retry: " + error);
                    CameraCapturer.this.createSessionInternal(500);
                }
            }
        }
    };

    @Nullable
    private final CameraSession.Events cameraSessionEventsHandler = new CameraSession.Events() { // from class: org.webrtc.mozi.CameraCapturer.2
        @Override // org.webrtc.mozi.CameraSession.Events
        public void onCameraOpening() {
            CameraCapturer.this.checkIsOnCameraThread();
            synchronized (CameraCapturer.this.stateLock) {
                if (CameraCapturer.this.currentSession == null) {
                    CameraCapturer.this.eventsHandler.onCameraOpening(CameraCapturer.this.cameraName);
                } else {
                    Logging.w(CameraCapturer.TAG, "onCameraOpening while session was open.");
                }
            }
        }

        @Override // org.webrtc.mozi.CameraSession.Events
        public void onCameraError(CameraSession session, String error) {
            CameraCapturer.this.checkIsOnCameraThread();
            synchronized (CameraCapturer.this.stateLock) {
                if (session == CameraCapturer.this.currentSession) {
                    CameraSessionData sessionData = CameraCapturer.this.currentSession == null ? null : CameraCapturer.this.currentSession.getCameraSessionData();
                    if (CameraCapturer.this.isRestartAttemptsEnable) {
                        if (CameraCapturer.this.restartAttemptsRemaining <= 0) {
                            CameraCapturer.this.eventsHandler.onCameraError(sessionData, error);
                            CameraCapturer.this.stopCapture();
                        } else {
                            CameraCapturer.this.stopCapture();
                            CameraCapturer.this.startCapture(CameraCapturer.this.width, CameraCapturer.this.height, CameraCapturer.this.framerate);
                        }
                        CameraCapturer.access$1410(CameraCapturer.this);
                    } else {
                        CameraCapturer.this.eventsHandler.onCameraError(sessionData, error);
                        CameraCapturer.this.stopCapture();
                    }
                    return;
                }
                Logging.w(CameraCapturer.TAG, "onCameraError from another session: " + error);
            }
        }

        @Override // org.webrtc.mozi.CameraSession.Events
        public void onCameraDisconnected(CameraSession session) {
            CameraCapturer.this.checkIsOnCameraThread();
            synchronized (CameraCapturer.this.stateLock) {
                if (session == CameraCapturer.this.currentSession) {
                    CameraSessionData sessionData = CameraCapturer.this.currentSession == null ? null : CameraCapturer.this.currentSession.getCameraSessionData();
                    CameraCapturer.this.eventsHandler.onCameraDisconnected(sessionData);
                    CameraCapturer.this.stopCapture();
                    return;
                }
                Logging.w(CameraCapturer.TAG, "onCameraDisconnected from another session.");
            }
        }

        @Override // org.webrtc.mozi.CameraSession.Events
        public void onCameraClosed(CameraSession session) {
            CameraCapturer.this.checkIsOnCameraThread();
            synchronized (CameraCapturer.this.stateLock) {
                if (session == CameraCapturer.this.currentSession || CameraCapturer.this.currentSession == null) {
                    CameraCapturer.this.eventsHandler.onCameraClosed();
                } else {
                    Logging.d(CameraCapturer.TAG, "onCameraClosed from another session.");
                }
            }
        }

        @Override // org.webrtc.mozi.CameraSession.Events
        public void onFrameCaptured(CameraSession session, VideoFrame frame) {
            CameraCapturer.this.checkIsOnCameraThread();
            synchronized (CameraCapturer.this.stateLock) {
                if (session == CameraCapturer.this.currentSession) {
                    if (!CameraCapturer.this.firstFrameObserved) {
                        CameraSessionData sessionData = CameraCapturer.this.currentSession == null ? null : CameraCapturer.this.currentSession.getCameraSessionData();
                        CameraCapturer.this.eventsHandler.onFirstFrameAvailable(sessionData);
                        CameraCapturer.this.firstFrameObserved = true;
                    }
                    CameraCapturer.this.cameraStatistics.addFrame(frame);
                    if (CameraCapturer.needNofityCaptureThreadChange) {
                        if (CameraCapturer.this.capturerObserver != null) {
                            CameraCapturer.this.capturerObserver.onCaptureThreadChanged();
                        }
                        boolean unused = CameraCapturer.needNofityCaptureThreadChange = false;
                    }
                    if (CameraCapturer.texture2yuv && (frame.getBuffer() instanceof VideoFrame.TextureBuffer)) {
                        if (CameraCapturer.this.dummyRender == null && Build.VERSION.SDK_INT >= 19 && CameraCapturer.this.surfaceHelper != null) {
                            CameraCapturer.this.dummyRender = new DummySurfaceRender();
                            CameraCapturer.this.dummyRender.init(CameraCapturer.this.surfaceHelper.getEglContext());
                        }
                        if (CameraCapturer.this.dummyRender != null) {
                            TextureBufferImpl tbuf = (TextureBufferImpl) frame.getBuffer();
                            int oesTextureId = tbuf.getTextureId();
                            Matrix mtx2 = tbuf.getTransformMatrix();
                            float[] tran_matrix = RendererCommon.convertMatrixFromAndroidGraphicsMatrix(mtx2);
                            CameraCapturer.this.dummyRender.drawTexture(frame.getBuffer().getWidth(), frame.getBuffer().getHeight(), oesTextureId, tbuf.getType() == VideoFrame.TextureBuffer.Type.OES, tran_matrix, CameraCapturer.this.imageListener);
                            CameraCapturer.this.stored_rotation = frame.getRotation();
                            CameraCapturer.this.stored_timestamp_ns = frame.getTimestampNs();
                            return;
                        }
                    }
                    if (CameraCapturer.this.capturerObserver != null) {
                        CameraCapturer.this.capturerObserver.onFrameCaptured(frame);
                    }
                    return;
                }
                Logging.w(CameraCapturer.TAG, "onFrameCaptured from another session.");
            }
        }
    };
    private final Runnable openCameraTimeoutRunnable = new Runnable() { // from class: org.webrtc.mozi.CameraCapturer.3
        @Override // java.lang.Runnable
        public void run() {
            CameraSessionData sessionData = CameraCapturer.this.currentSession == null ? null : CameraCapturer.this.currentSession.getCameraSessionData();
            CameraCapturer.this.eventsHandler.onCameraError(sessionData, "Camera failed to start within timeout.");
        }
    };
    private final Object stateLock = new Object();
    private SwitchState switchState = SwitchState.IDLE;

    enum SwitchState {
        IDLE,
        PENDING,
        IN_PROGRESS
    }

    protected abstract void createCameraSession(CameraSession.CreateSessionCallback createSessionCallback, CameraSession.Events events, Context context, SurfaceTextureHelper surfaceTextureHelper, String str, int i, int i2, int i3);

    static /* synthetic */ int access$1410(CameraCapturer x0) {
        int i = x0.restartAttemptsRemaining;
        x0.restartAttemptsRemaining = i - 1;
        return i;
    }

    static /* synthetic */ int access$2010(CameraCapturer x0) {
        int i = x0.openAttemptsRemaining;
        x0.openAttemptsRemaining = i - 1;
        return i;
    }

    public CameraCapturer(String cameraName, boolean isFrontFacing, @Nullable CameraVideoCapturer.CameraEventsHandler eventsHandler, CameraEnumerator cameraEnumerator, @Nullable CameraConfig config) {
        this.imageListener = null;
        this.eventsHandler = eventsHandler == null ? new CameraVideoCapturer.CameraEventsHandler() { // from class: org.webrtc.mozi.CameraCapturer.4
            @Override // org.webrtc.mozi.CameraVideoCapturer.CameraEventsHandler
            public void onCameraError(CameraSessionData sessionData, String errorDescription) {
            }

            @Override // org.webrtc.mozi.CameraVideoCapturer.CameraEventsHandler
            public void onCameraDisconnected(CameraSessionData sessionData) {
            }

            @Override // org.webrtc.mozi.CameraVideoCapturer.CameraEventsHandler
            public void onCameraFreezed(String errorDescription) {
            }

            @Override // org.webrtc.mozi.CameraVideoCapturer.CameraEventsHandler
            public void onCameraOpening(String cameraName2) {
            }

            @Override // org.webrtc.mozi.CameraVideoCapturer.CameraEventsHandler
            public void onFirstFrameAvailable(CameraSessionData sessionData) {
            }

            @Override // org.webrtc.mozi.CameraVideoCapturer.CameraEventsHandler
            public void onCameraClosed() {
            }
        } : eventsHandler;
        this.cameraEnumerator = cameraEnumerator;
        this.cameraName = cameraName;
        this.uiThreadHandler = new Handler(Looper.getMainLooper());
        this.isFrontFacing = isFrontFacing;
        if (config != null) {
            this.config = config;
        } else {
            this.config = new CameraConfig();
        }
        if (!config.isFixCameraNumberAnr) {
            String[] deviceNames = cameraEnumerator.getDeviceNames();
            if (deviceNames.length == 0) {
                throw new RuntimeException("No cameras attached.");
            }
            if (!Arrays.asList(deviceNames).contains(this.cameraName)) {
                throw new IllegalArgumentException("Camera name " + this.cameraName + " does not match any known camera device.");
            }
        }
        Logging.i(TAG, "Camera name: " + cameraName);
        this.imageListener = new ImageReaderCore.OnImageReaderCoreListener() { // from class: org.webrtc.mozi.CameraCapturer.5
            @Override // org.webrtc.mozi.ImageReaderCore.OnImageReaderCoreListener
            public void onImageArrive() {
            }

            @Override // org.webrtc.mozi.ImageReaderCore.OnImageReaderCoreListener
            public void onRawData(byte[] data, int width, int height, int color) {
                if (color == 1 || color == 2) {
                    VideoFrame.Buffer frameBuffer = new RGBABuffer(width, height, width, data, new Runnable() { // from class: org.webrtc.mozi.CameraCapturer.5.1
                        @Override // java.lang.Runnable
                        public void run() {
                        }
                    });
                    VideoFrame frame = new VideoFrame(frameBuffer, CameraCapturer.this.stored_rotation, CameraCapturer.this.stored_timestamp_ns);
                    CameraCapturer.this.capturerObserver.onFrameCaptured(frame);
                    frame.release();
                }
            }
        };
    }

    @Override // org.webrtc.mozi.VideoCapturer
    public void initialize(@Nullable SurfaceTextureHelper surfaceTextureHelper, Context applicationContext, CapturerObserver capturerObserver) {
        this.applicationContext = applicationContext;
        this.capturerObserver = capturerObserver;
        this.surfaceHelper = surfaceTextureHelper;
        this.cameraThreadHandler = surfaceTextureHelper == null ? null : surfaceTextureHelper.getHandler();
        if (this.publishResolution != null && capturerObserver != null) {
            Logging.e(TAG, "initialize setOutputFormatRequest to capturerObserver");
            capturerObserver.setOutputFormatRequest(this.publishResolution.width, this.publishResolution.height, this.publishResolution.fps);
        }
    }

    public static void PushTexture2Yuv(boolean on) {
        if (!disable_dummy_render) {
            Logging.w(TAG, "Texture will goto yuv");
            if (texture2yuv != on) {
                needNofityCaptureThreadChange = true;
            }
            texture2yuv = on;
        }
    }

    @Override // org.webrtc.mozi.VideoCapturer
    public void startCapture(int width, int height, int framerate) {
        Logging.e(TAG, "startCapture: " + width + "x" + height + "@" + framerate + "#" + this);
        if (this.applicationContext == null) {
            throw new RuntimeException("CameraCapturer must be initialized before calling startCapture.");
        }
        if (!disable_dummy_render) {
            H264Config config = this.configHelper.getH264Config();
            if (config.forceSWEncoder()) {
                texture2yuv = true;
            }
        }
        synchronized (this.stateLock) {
            this.hasStoped = false;
            if (!this.sessionOpening && this.currentSession == null) {
                this.width = width;
                this.height = height;
                this.framerate = framerate;
                this.sessionOpening = true;
                this.openAttemptsRemaining = 3;
                createSessionInternal(0);
                if (this.publishResolution == null) {
                    Logging.e(TAG, "startCapture, publishResolution null, setOutputFormatRequest");
                    this.capturerObserver.setOutputFormatRequest(width, height, framerate);
                }
                return;
            }
            Logging.w(TAG, "Session already open");
        }
    }

    public void setOutputFormatRequest(int width, int height, int fps) {
        Logging.e(TAG, "setOutputFormatRequest: " + width + "x" + height + "@" + this.framerate);
        VideoResolution videoResolution = this.publishResolution;
        if (videoResolution == null) {
            this.publishResolution = new VideoResolution(width, height, fps);
        } else {
            videoResolution.width = width;
            this.publishResolution.height = height;
            this.publishResolution.fps = fps;
        }
        if (this.capturerObserver != null) {
            Logging.e(TAG, "setOutputFormatRequest to capturerObserver");
            this.capturerObserver.setOutputFormatRequest(width, height, fps);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void createSessionInternal(int delayMs) {
        if (this.cameraThreadHandler == null) {
            Logging.e(TAG, "create camera session failed, cameraThreadHandler is null");
            return;
        }
        Logging.i(TAG, "createSessionInternal " + this.cameraName + ",isFixCameraNumberAnr: " + this.config.isFixCameraNumberAnr + ", isFixSwitchCamera: " + this.config.isFixSwitchCamera);
        this.uiThreadHandler.postDelayed(this.openCameraTimeoutRunnable, (long) (delayMs + 10000));
        this.cameraThreadHandler.postDelayed(new Runnable() { // from class: org.webrtc.mozi.CameraCapturer.6
            /* JADX WARN: Removed duplicated region for block: B:8:0x0023  */
            @Override // java.lang.Runnable
            /*
                Code decompiled incorrectly, please refer to instructions dump.
                To view partially-correct add '--show-bad-code' argument
            */
            public void run() {
                /*
                    Method dump skipped, instruction units count: 317
                    To view this dump add '--comments-level debug' option
                */
                throw new UnsupportedOperationException("Method not decompiled: org.webrtc.mozi.CameraCapturer.AnonymousClass6.run():void");
            }
        }, (long) delayMs);
    }

    @Override // org.webrtc.mozi.VideoCapturer
    public void stopCapture() {
        Logging.d(TAG, "Stop capture");
        synchronized (this.stateLock) {
            if (!this.isFixStopCameraAnr) {
                while (this.sessionOpening) {
                    Logging.d(TAG, "Stop capture: Waiting for session to open");
                    try {
                        this.stateLock.wait();
                    } catch (InterruptedException e) {
                        Logging.w(TAG, "Stop capture interrupted while waiting for the session to open.");
                        Thread.currentThread().interrupt();
                        return;
                    }
                }
            } else {
                Logging.d(TAG, "Stop capture: No waiting for session to open " + this.sessionOpening);
            }
            this.hasStoped = true;
            if (this.currentSession != null) {
                Logging.d(TAG, "Stop capture: Nulling session");
                this.cameraStatistics.release();
                this.cameraStatistics = null;
                final CameraSession oldSession = this.currentSession;
                this.cameraThreadHandler.post(new Runnable() { // from class: org.webrtc.mozi.CameraCapturer.7
                    @Override // java.lang.Runnable
                    public void run() {
                        oldSession.stop();
                    }
                });
                this.currentSession = null;
                if (this.capturerObserver != null) {
                    this.capturerObserver.onCapturerStopped();
                }
            } else {
                Logging.d(TAG, "Stop capture: No session open");
            }
            if (this.dummyRender != null) {
                this.dummyRender.release();
                this.dummyRender = null;
            }
        }
        Logging.d(TAG, "Stop capture done");
    }

    @Override // org.webrtc.mozi.VideoCapturer
    public void changeCaptureFormat(int width, int height, int framerate) {
        Logging.d(TAG, "changeCaptureFormat: " + width + "x" + height + "@" + framerate);
        synchronized (this.stateLock) {
            stopCapture();
            startCapture(width, height, framerate);
        }
    }

    @Override // org.webrtc.mozi.VideoCapturer
    public void dispose() {
        Logging.d(TAG, "dispose");
        stopCapture();
        CameraConfig cameraConfig = this.config;
        if (cameraConfig != null && cameraConfig.isFixCameraDispose) {
            synchronized (this.stateLock) {
                this.capturerObserver = null;
            }
        }
    }

    @Override // org.webrtc.mozi.CameraVideoCapturer
    public void switchCamera(final CameraVideoCapturer.CameraSwitchHandler switchEventsHandler) {
        Logging.d(TAG, "switchCamera");
        this.cameraThreadHandler.post(new Runnable() { // from class: org.webrtc.mozi.CameraCapturer.8
            @Override // java.lang.Runnable
            public void run() {
                CameraCapturer.this.switchCameraInternal(switchEventsHandler);
            }
        });
    }

    @Override // org.webrtc.mozi.VideoCapturer
    public boolean isScreencast() {
        return false;
    }

    public boolean isOpening() {
        boolean z;
        synchronized (this.stateLock) {
            Logging.d(TAG, "CameraSession is opening");
            z = this.sessionOpening;
        }
        return z;
    }

    @Deprecated
    public void setPreviewCallbackWithBuffer(Camera.PreviewCallback cb) {
    }

    public void setFixStopCameraAnr(boolean isFixStopCameraAnr) {
        this.isFixStopCameraAnr = isFixStopCameraAnr;
    }

    public void printStackTrace() {
        Thread cameraThread = null;
        Handler handler = this.cameraThreadHandler;
        if (handler != null) {
            cameraThread = handler.getLooper().getThread();
        }
        if (cameraThread != null) {
            StackTraceElement[] cameraStackTrace = cameraThread.getStackTrace();
            if (cameraStackTrace.length > 0) {
                Logging.d(TAG, "CameraCapturer stack trace:");
                for (StackTraceElement traceElem : cameraStackTrace) {
                    Logging.d(TAG, traceElem.toString());
                }
            }
        }
    }

    private void reportCameraSwitchError(String error, @Nullable CameraVideoCapturer.CameraSwitchHandler switchEventsHandler) {
        Logging.e(TAG, error);
        if (switchEventsHandler != null) {
            switchEventsHandler.onCameraSwitchError(error);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void switchCameraInternal(@Nullable CameraVideoCapturer.CameraSwitchHandler switchEventsHandler) {
        Logging.d(TAG, "switchCamera internal");
        String[] deviceNames = this.cameraEnumerator.getDeviceNames();
        if (deviceNames.length < 2) {
            if (switchEventsHandler != null) {
                switchEventsHandler.onCameraSwitchError("No camera to switch to.");
                return;
            }
            return;
        }
        synchronized (this.stateLock) {
            if (this.switchState != SwitchState.IDLE) {
                reportCameraSwitchError("Camera switch already in progress.", switchEventsHandler);
                return;
            }
            if (!this.sessionOpening && this.currentSession == null) {
                reportCameraSwitchError("switchCamera: camera is not running.", switchEventsHandler);
                return;
            }
            this.switchEventsHandler = switchEventsHandler;
            if (this.sessionOpening) {
                this.switchState = SwitchState.PENDING;
                return;
            }
            this.switchState = SwitchState.IN_PROGRESS;
            Logging.d(TAG, "switchCamera: Stopping session");
            this.cameraStatistics.release();
            this.cameraStatistics = null;
            final CameraSession oldSession = this.currentSession;
            this.cameraThreadHandler.post(new Runnable() { // from class: org.webrtc.mozi.CameraCapturer.9
                @Override // java.lang.Runnable
                public void run() {
                    oldSession.stop();
                }
            });
            this.currentSession = null;
            int cameraNameIndex = Arrays.asList(deviceNames).indexOf(this.cameraName);
            this.cameraName = deviceNames[(cameraNameIndex + 1) % deviceNames.length];
            if (this.config.isFixCameraNumberAnr) {
                this.isFrontFacing = this.cameraEnumerator.isFrontFacing(this.cameraName);
            }
            this.sessionOpening = true;
            this.openAttemptsRemaining = 1;
            createSessionInternal(0);
            Logging.d(TAG, "switchCamera done");
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void checkIsOnCameraThread() {
        if (Thread.currentThread() != this.cameraThreadHandler.getLooper().getThread()) {
            Logging.e(TAG, "Check is on camera thread failed.");
            throw new RuntimeException("Not on camera thread.");
        }
    }

    protected String getCameraName() {
        String str;
        synchronized (this.stateLock) {
            str = this.cameraName;
        }
        return str;
    }

    public boolean getFrontFacing() {
        return this.isFrontFacing;
    }

    protected void onCreateCameraSessionDone(CameraSession session) {
    }

    public void setRestartAttemptsEnable(boolean flag) {
        this.isRestartAttemptsEnable = flag;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean isEmpty(String str) {
        return str == null || "".equals(str);
    }

    public CameraSession getCameraSession() {
        if (this.config.isFixCameraSessionLeak) {
            return this.currentSession;
        }
        return null;
    }

    public void setWindowRotation(int rotation) {
    }

    public void setEnableDoubleCallback(boolean enable) {
    }
}
