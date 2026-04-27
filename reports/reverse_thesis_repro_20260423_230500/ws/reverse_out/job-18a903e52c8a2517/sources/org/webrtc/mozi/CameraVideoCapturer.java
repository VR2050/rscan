package org.webrtc.mozi;

import android.media.MediaRecorder;
import com.google.android.exoplayer2.trackselection.AdaptiveTrackSelection;

/* JADX INFO: loaded from: classes3.dex */
public abstract class CameraVideoCapturer implements VideoCapturer {

    public interface CameraEventsHandler {
        void onCameraClosed();

        void onCameraDisconnected(CameraSessionData cameraSessionData);

        void onCameraError(CameraSessionData cameraSessionData, String str);

        void onCameraFreezed(String str);

        void onCameraOpening(String str);

        void onFirstFrameAvailable(CameraSessionData cameraSessionData);
    }

    public interface CameraSwitchHandler {
        void onCameraSwitchDone(boolean z);

        void onCameraSwitchError(String str);
    }

    @Deprecated
    public interface MediaRecorderHandler {
        void onMediaRecorderError(String str);

        void onMediaRecorderSuccess();
    }

    abstract void switchCamera(CameraSwitchHandler cameraSwitchHandler);

    @Deprecated
    void addMediaRecorderToCamera(MediaRecorder mediaRecorder, MediaRecorderHandler resultHandler) {
        throw new UnsupportedOperationException("Deprecated and not implemented.");
    }

    @Deprecated
    void removeMediaRecorderFromCamera(MediaRecorderHandler resultHandler) {
        throw new UnsupportedOperationException("Deprecated and not implemented.");
    }

    public static class CameraStatistics {
        private static final int CAMERA_FREEZE_REPORT_TIMOUT_MS = 4000;
        private static final int CAMERA_OBSERVER_PERIOD_MS = 2000;
        private static final String TAG = "CameraStatistics";
        private VideoFrame cameraFrame;
        private final Runnable cameraObserver = new Runnable() { // from class: org.webrtc.mozi.CameraVideoCapturer.CameraStatistics.1
            @Override // java.lang.Runnable
            public void run() {
                int cameraFps = Math.round((CameraStatistics.this.frameCount * 1000.0f) / 2000.0f);
                Logging.d(CameraStatistics.TAG, "Camera fps: " + cameraFps + ".");
                if (CameraStatistics.this.frameCount != 0) {
                    CameraStatistics.this.freezePeriodCount = 0;
                } else {
                    CameraStatistics.access$104(CameraStatistics.this);
                    if (CameraStatistics.this.freezePeriodCount * 2000 >= 4000 && CameraStatistics.this.eventsHandler != null) {
                        Logging.e(CameraStatistics.TAG, "Camera freezed.");
                        if (!CameraStatistics.this.surfaceTextureHelper.isTextureInUse()) {
                            CameraStatistics.this.eventsHandler.onCameraFreezed("Camera failure.");
                            return;
                        }
                        String trace = "";
                        VideoFrame frame = CameraStatistics.this.cameraFrame;
                        if (frame != null) {
                            trace = frame.dump();
                        }
                        CameraStatistics.this.eventsHandler.onCameraFreezed("Camera failure. Client must return video buffers. " + trace);
                        return;
                    }
                }
                CameraStatistics.this.frameCount = 0;
                CameraStatistics.this.surfaceTextureHelper.getHandler().postDelayed(this, AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS);
            }
        };
        private final CameraEventsHandler eventsHandler;
        private int frameCount;
        private int freezePeriodCount;
        private final SurfaceTextureHelper surfaceTextureHelper;

        static /* synthetic */ int access$104(CameraStatistics x0) {
            int i = x0.freezePeriodCount + 1;
            x0.freezePeriodCount = i;
            return i;
        }

        public CameraStatistics(SurfaceTextureHelper surfaceTextureHelper, CameraEventsHandler eventsHandler) {
            if (surfaceTextureHelper == null) {
                throw new IllegalArgumentException("SurfaceTextureHelper is null");
            }
            this.surfaceTextureHelper = surfaceTextureHelper;
            this.eventsHandler = eventsHandler;
            this.frameCount = 0;
            this.freezePeriodCount = 0;
            surfaceTextureHelper.getHandler().postDelayed(this.cameraObserver, AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS);
        }

        private void checkThread() {
            if (Thread.currentThread() != this.surfaceTextureHelper.getHandler().getLooper().getThread()) {
                throw new IllegalStateException("Wrong thread");
            }
        }

        public void addFrame(VideoFrame frame) {
            checkThread();
            this.frameCount++;
            if (WebrtcGrayConfig.sEnableCameraVideoFrameMonitor) {
                this.cameraFrame = frame;
            }
        }

        public void release() {
            this.surfaceTextureHelper.getHandler().removeCallbacks(this.cameraObserver);
        }
    }
}
