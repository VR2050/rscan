package org.webrtc.mozi;

import android.content.Context;
import android.hardware.Camera;
import javax.annotation.Nullable;
import org.webrtc.mozi.CameraSession;
import org.webrtc.mozi.CameraVideoCapturer;

/* JADX INFO: loaded from: classes3.dex */
public class Camera1Capturer extends CameraCapturer {

    @Deprecated
    private Camera1Session camera1Session;
    private final boolean captureToTexture;
    private boolean enableDoubleCallback;
    private final boolean isFixCamera1SessionLeak;
    private CameraConfig mConfig;
    private Camera.PreviewCallback previewCallback;
    private int windowRotation;

    @Override // org.webrtc.mozi.CameraCapturer, org.webrtc.mozi.VideoCapturer
    public /* bridge */ /* synthetic */ void changeCaptureFormat(int i, int i2, int i3) {
        super.changeCaptureFormat(i, i2, i3);
    }

    @Override // org.webrtc.mozi.CameraCapturer, org.webrtc.mozi.VideoCapturer
    public /* bridge */ /* synthetic */ void dispose() {
        super.dispose();
    }

    @Override // org.webrtc.mozi.CameraCapturer
    public /* bridge */ /* synthetic */ boolean getFrontFacing() {
        return super.getFrontFacing();
    }

    @Override // org.webrtc.mozi.CameraCapturer, org.webrtc.mozi.VideoCapturer
    public /* bridge */ /* synthetic */ void initialize(@Nullable SurfaceTextureHelper surfaceTextureHelper, Context context, CapturerObserver capturerObserver) {
        super.initialize(surfaceTextureHelper, context, capturerObserver);
    }

    @Override // org.webrtc.mozi.CameraCapturer
    public /* bridge */ /* synthetic */ boolean isOpening() {
        return super.isOpening();
    }

    @Override // org.webrtc.mozi.CameraCapturer, org.webrtc.mozi.VideoCapturer
    public /* bridge */ /* synthetic */ boolean isScreencast() {
        return super.isScreencast();
    }

    @Override // org.webrtc.mozi.CameraCapturer
    public /* bridge */ /* synthetic */ void printStackTrace() {
        super.printStackTrace();
    }

    @Override // org.webrtc.mozi.CameraCapturer
    public /* bridge */ /* synthetic */ void setFixStopCameraAnr(boolean z) {
        super.setFixStopCameraAnr(z);
    }

    @Override // org.webrtc.mozi.CameraCapturer
    public /* bridge */ /* synthetic */ void setOutputFormatRequest(int i, int i2, int i3) {
        super.setOutputFormatRequest(i, i2, i3);
    }

    @Override // org.webrtc.mozi.CameraCapturer
    public /* bridge */ /* synthetic */ void setRestartAttemptsEnable(boolean z) {
        super.setRestartAttemptsEnable(z);
    }

    @Override // org.webrtc.mozi.CameraCapturer, org.webrtc.mozi.VideoCapturer
    public /* bridge */ /* synthetic */ void startCapture(int i, int i2, int i3) {
        super.startCapture(i, i2, i3);
    }

    @Override // org.webrtc.mozi.CameraCapturer, org.webrtc.mozi.VideoCapturer
    public /* bridge */ /* synthetic */ void stopCapture() {
        super.stopCapture();
    }

    @Override // org.webrtc.mozi.CameraCapturer, org.webrtc.mozi.CameraVideoCapturer
    public /* bridge */ /* synthetic */ void switchCamera(CameraVideoCapturer.CameraSwitchHandler cameraSwitchHandler) {
        super.switchCamera(cameraSwitchHandler);
    }

    public Camera1Capturer(String cameraName, boolean isFrontFacing, CameraVideoCapturer.CameraEventsHandler eventsHandler, boolean captureToTexture, CameraConfig config) {
        super(cameraName, isFrontFacing, eventsHandler, new Camera1Enumerator(captureToTexture), config);
        this.windowRotation = -1;
        boolean z = false;
        this.enableDoubleCallback = false;
        this.captureToTexture = captureToTexture;
        this.mConfig = config;
        if (config != null && config.isFixCameraSessionLeak) {
            z = true;
        }
        this.isFixCamera1SessionLeak = z;
    }

    @Override // org.webrtc.mozi.CameraCapturer
    protected void createCameraSession(CameraSession.CreateSessionCallback createSessionCallback, CameraSession.Events events, Context applicationContext, SurfaceTextureHelper surfaceTextureHelper, String cameraName, int width, int height, int framerate) {
        Camera1Session.create(createSessionCallback, events, this.captureToTexture, applicationContext, surfaceTextureHelper, Camera1Enumerator.getCameraIndex(cameraName), width, height, framerate, this.mConfig);
    }

    @Override // org.webrtc.mozi.CameraCapturer
    protected void onCreateCameraSessionDone(CameraSession session) {
        super.onCreateCameraSessionDone(session);
        if (this.isFixCamera1SessionLeak) {
            if (session instanceof Camera1Session) {
                Camera1Session cameraSession = (Camera1Session) session;
                Camera.PreviewCallback previewCallback = this.previewCallback;
                if (previewCallback != null) {
                    cameraSession.setPreviewCallbackWithBuffer(previewCallback);
                }
                int i = this.windowRotation;
                if (i >= 0) {
                    cameraSession.setWindowRotation(i);
                }
                cameraSession.setEnableDoubleCallback(this.enableDoubleCallback);
                return;
            }
            return;
        }
        if (session instanceof Camera1Session) {
            Camera1Session camera1Session = (Camera1Session) session;
            this.camera1Session = camera1Session;
            Camera.PreviewCallback previewCallback2 = this.previewCallback;
            if (previewCallback2 != null) {
                camera1Session.setPreviewCallbackWithBuffer(previewCallback2);
            }
            int i2 = this.windowRotation;
            if (i2 >= 0) {
                this.camera1Session.setWindowRotation(i2);
            }
            this.camera1Session.setEnableDoubleCallback(this.enableDoubleCallback);
        }
    }

    @Override // org.webrtc.mozi.CameraCapturer
    public void setPreviewCallbackWithBuffer(Camera.PreviewCallback cb) {
        this.previewCallback = cb;
        if (this.isFixCamera1SessionLeak) {
            Camera1Session session = getCamera1Session();
            if (session != null) {
                session.setPreviewCallbackWithBuffer(cb);
                return;
            }
            return;
        }
        Camera1Session camera1Session = this.camera1Session;
        if (camera1Session != null) {
            camera1Session.setPreviewCallbackWithBuffer(cb);
        }
    }

    @Override // org.webrtc.mozi.CameraCapturer
    public CameraSession getCameraSession() {
        if (this.isFixCamera1SessionLeak) {
            return super.getCameraSession();
        }
        return this.camera1Session;
    }

    @Override // org.webrtc.mozi.CameraCapturer
    public void setWindowRotation(int rotation) {
        Camera1Session camera1Session;
        this.windowRotation = rotation;
        if (this.isFixCamera1SessionLeak) {
            Camera1Session session = getCamera1Session();
            int i = this.windowRotation;
            if (i >= 0 && session != null) {
                session.setWindowRotation(i);
                return;
            }
            return;
        }
        if (rotation >= 0 && (camera1Session = this.camera1Session) != null) {
            camera1Session.setWindowRotation(rotation);
        }
    }

    @Override // org.webrtc.mozi.CameraCapturer
    public void setEnableDoubleCallback(boolean enable) {
        this.enableDoubleCallback = enable;
        if (this.isFixCamera1SessionLeak) {
            Camera1Session session = getCamera1Session();
            if (session != null) {
                session.setEnableDoubleCallback(this.enableDoubleCallback);
                return;
            }
            return;
        }
        Camera1Session camera1Session = this.camera1Session;
        if (camera1Session != null) {
            camera1Session.setEnableDoubleCallback(enable);
        }
    }

    @Nullable
    private Camera1Session getCamera1Session() {
        if (getCameraSession() instanceof Camera1Session) {
            return (Camera1Session) getCameraSession();
        }
        return null;
    }
}
