package org.webrtc.mozi;

import android.content.Context;
import android.content.Intent;
import android.graphics.Point;
import android.hardware.display.VirtualDisplay;
import android.media.projection.MediaProjection;
import android.media.projection.MediaProjectionManager;
import android.view.Surface;
import javax.annotation.Nullable;

/* JADX INFO: loaded from: classes3.dex */
public class ScreenCapturerAndroid implements VideoCapturer, VideoSink {
    private static final int DISPLAY_FLAGS = 3;
    private static final String TAG = "ScreenCapturerAndroid";
    private static final int VIRTUAL_DISPLAY_DPI = 400;

    @Nullable
    private CapturerObserver capturerObserver;
    private MediaProjection externalMediaProjection;
    private int height;

    @Nullable
    private MediaProjection mediaProjection;
    private MediaProjection.Callback mediaProjectionCallback;

    @Nullable
    private MediaProjectionManager mediaProjectionManager;
    private Intent mediaProjectionPermissionResultData;

    @Nullable
    private MediaProjectionStopInterceptor mediaProjectionStopInterceptor;
    private boolean resizeEnabled;
    private int rotation;

    @Nullable
    private SurfaceTextureHelper surfaceTextureHelper;

    @Nullable
    private VirtualDisplay virtualDisplay;
    private int width;
    private long numCapturedFrames = 0;
    private boolean isDisposed = false;

    public interface MediaProjectionStopInterceptor {
        boolean onMediaProjectionNeedStop(MediaProjection mediaProjection);
    }

    public ScreenCapturerAndroid(Intent mediaProjectionPermissionResultData, MediaProjection.Callback mediaProjectionCallback) {
        this.mediaProjectionPermissionResultData = mediaProjectionPermissionResultData;
        this.mediaProjectionCallback = mediaProjectionCallback;
    }

    public void setMediaProjectionCallback(MediaProjection.Callback mediaProjectionCallback) {
        this.mediaProjectionCallback = mediaProjectionCallback;
    }

    public void setResizeEnabled(boolean enabled) {
        this.resizeEnabled = enabled;
    }

    public void setMediaProjectionPermissionResultData(Intent data) {
        this.mediaProjectionPermissionResultData = data;
    }

    private void checkNotDisposed() {
        if (this.isDisposed) {
            throw new RuntimeException("capturer is disposed.");
        }
    }

    public MediaProjection getMediaProjection() {
        return this.mediaProjection;
    }

    public void setExternalMediaProjection(MediaProjection mediaProjection) {
        this.externalMediaProjection = mediaProjection;
    }

    @Override // org.webrtc.mozi.VideoCapturer
    public synchronized void initialize(SurfaceTextureHelper surfaceTextureHelper, Context applicationContext, CapturerObserver capturerObserver) {
        checkNotDisposed();
        if (capturerObserver == null) {
            throw new RuntimeException("capturerObserver not set.");
        }
        this.capturerObserver = capturerObserver;
        if (surfaceTextureHelper == null) {
            throw new RuntimeException("surfaceTextureHelper not set.");
        }
        this.surfaceTextureHelper = surfaceTextureHelper;
        this.mediaProjectionManager = (MediaProjectionManager) applicationContext.getSystemService("media_projection");
    }

    @Override // org.webrtc.mozi.VideoCapturer
    public synchronized void startCapture(int width, int height, int ignoredFramerate) {
        checkNotDisposed();
        this.width = width;
        this.height = height;
        if (this.externalMediaProjection != null) {
            this.mediaProjection = this.externalMediaProjection;
        } else {
            try {
                this.mediaProjection = this.mediaProjectionManager.getMediaProjection(-1, this.mediaProjectionPermissionResultData);
            } catch (SecurityException e) {
                Logging.d(TAG, "GetMediaProjection Permission Denied, exception: " + e.getMessage());
            }
        }
        if (this.mediaProjection == null) {
            Logging.e(TAG, "MediaProjection is null!");
            return;
        }
        this.mediaProjection.registerCallback(this.mediaProjectionCallback, this.surfaceTextureHelper.getHandler());
        createVirtualDisplay();
        this.capturerObserver.onCapturerStarted(true);
        this.surfaceTextureHelper.startListening(this);
    }

    @Override // org.webrtc.mozi.VideoCapturer
    public synchronized void stopCapture() {
        checkNotDisposed();
        ThreadUtils.invokeAtFrontUninterruptibly(this.surfaceTextureHelper.getHandler(), new Runnable() { // from class: org.webrtc.mozi.ScreenCapturerAndroid.1
            @Override // java.lang.Runnable
            public void run() {
                ScreenCapturerAndroid.this.surfaceTextureHelper.stopListening();
                ScreenCapturerAndroid.this.capturerObserver.onCapturerStopped();
                if (ScreenCapturerAndroid.this.virtualDisplay != null) {
                    ScreenCapturerAndroid.this.virtualDisplay.release();
                    ScreenCapturerAndroid.this.virtualDisplay = null;
                }
                if (ScreenCapturerAndroid.this.mediaProjection != null) {
                    if (ScreenCapturerAndroid.this.mediaProjectionCallback != null) {
                        ScreenCapturerAndroid.this.mediaProjection.unregisterCallback(ScreenCapturerAndroid.this.mediaProjectionCallback);
                    }
                    if ((ScreenCapturerAndroid.this.mediaProjectionStopInterceptor == null || !ScreenCapturerAndroid.this.mediaProjectionStopInterceptor.onMediaProjectionNeedStop(ScreenCapturerAndroid.this.mediaProjection)) && ScreenCapturerAndroid.this.mediaProjection != ScreenCapturerAndroid.this.externalMediaProjection) {
                        ScreenCapturerAndroid.this.mediaProjection.stop();
                    }
                    ScreenCapturerAndroid.this.mediaProjection = null;
                }
            }
        });
    }

    @Override // org.webrtc.mozi.VideoCapturer
    public synchronized void dispose() {
        this.isDisposed = true;
    }

    @Override // org.webrtc.mozi.VideoCapturer
    public synchronized void changeCaptureFormat(final int width, final int height, final int ignoredFramerate) {
        checkNotDisposed();
        int preCaptureSize = this.width * this.height;
        this.width = width;
        this.height = height;
        if (this.virtualDisplay == null) {
            return;
        }
        if (WebrtcGrayConfig.sOptScreenCapturerSizeChange && isCaptureSizeEqual()) {
            return;
        }
        final boolean captureSizeChanged = preCaptureSize != width * height;
        Logging.d(TAG, "changeCaptureFormat: " + width + "x" + height + "*" + this.rotation);
        ThreadUtils.invokeAtFrontUninterruptibly(this.surfaceTextureHelper.getHandler(), new Runnable() { // from class: org.webrtc.mozi.ScreenCapturerAndroid.2
            @Override // java.lang.Runnable
            public void run() {
                try {
                    if (ScreenCapturerAndroid.this.resizeEnabled) {
                        ScreenCapturerAndroid.this.resizeVirtualDisplay(ScreenCapturerAndroid.this.getDisplayWidth(), ScreenCapturerAndroid.this.getDisplayHeight());
                    } else {
                        ScreenCapturerAndroid.this.recreateVirtualDisplay();
                    }
                    if (WebrtcGrayConfig.sOptScreenCapturerSizeChange && captureSizeChanged && ScreenCapturerAndroid.this.capturerObserver != null) {
                        Logging.d(ScreenCapturerAndroid.TAG, "setOutputFormatRequest to capturerObserver: " + width + "x" + height + "*" + ignoredFramerate);
                        ScreenCapturerAndroid.this.capturerObserver.setOutputFormatRequest(width, height, ignoredFramerate);
                    }
                } catch (Throwable e) {
                    Logging.e(ScreenCapturerAndroid.TAG, "resize virtual display failed, resize enabled " + ScreenCapturerAndroid.this.resizeEnabled, e);
                }
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void recreateVirtualDisplay() {
        VirtualDisplay virtualDisplay = this.virtualDisplay;
        if (virtualDisplay != null) {
            virtualDisplay.release();
        }
        createVirtualDisplay();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void resizeVirtualDisplay(int width, int height) {
        SurfaceTextureHelper surfaceTextureHelper;
        if (this.virtualDisplay == null || (surfaceTextureHelper = this.surfaceTextureHelper) == null) {
            return;
        }
        surfaceTextureHelper.recreateSurface();
        this.surfaceTextureHelper.setTextureSize(width, height);
        this.virtualDisplay.resize(width, height, VIRTUAL_DISPLAY_DPI);
        Surface oldSurface = this.virtualDisplay.getSurface();
        this.virtualDisplay.setSurface(new Surface(this.surfaceTextureHelper.getSurfaceTexture()));
        if (oldSurface != null) {
            oldSurface.release();
        }
    }

    public void setRotation(int rotation) {
        this.rotation = rotation;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public int getDisplayWidth() {
        int i = this.rotation;
        return (i == 0 || i == 180) ? this.width : this.height;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public int getDisplayHeight() {
        int i = this.rotation;
        return (i == 0 || i == 180) ? this.height : this.width;
    }

    private boolean isCaptureSizeEqual() {
        VirtualDisplay display = this.virtualDisplay;
        if (display == null || display.getDisplay() == null) {
            return false;
        }
        Point point = new Point();
        display.getDisplay().getSize(point);
        return point.x == getDisplayWidth() && point.y == getDisplayHeight();
    }

    private void createVirtualDisplay() {
        int displayWidth = getDisplayWidth();
        int displayHeight = getDisplayHeight();
        Logging.d(TAG, "createVirtualDisplay: " + displayWidth + "x" + displayHeight);
        this.surfaceTextureHelper.setTextureSize(displayWidth, displayHeight);
        try {
            this.virtualDisplay = this.mediaProjection.createVirtualDisplay("WebRTC_ScreenCapture", displayWidth, displayHeight, VIRTUAL_DISPLAY_DPI, 3, new Surface(this.surfaceTextureHelper.getSurfaceTexture()), null, null);
        } catch (SecurityException e) {
            Logging.d(TAG, "CreateVirtualDisplay Permission Denied, exception: " + e.getMessage());
        }
    }

    @Override // org.webrtc.mozi.VideoSink
    public void onFrame(VideoFrame frame) {
        if (frame == null) {
            return;
        }
        this.numCapturedFrames++;
        this.capturerObserver.onFrameCaptured(frame);
    }

    @Override // org.webrtc.mozi.VideoCapturer
    public boolean isScreencast() {
        return true;
    }

    public long getNumCapturedFrames() {
        return this.numCapturedFrames;
    }

    public void setMediaProjectionStopInterceptor(MediaProjectionStopInterceptor mediaProjectionStopInterceptor) {
        this.mediaProjectionStopInterceptor = mediaProjectionStopInterceptor;
    }
}
