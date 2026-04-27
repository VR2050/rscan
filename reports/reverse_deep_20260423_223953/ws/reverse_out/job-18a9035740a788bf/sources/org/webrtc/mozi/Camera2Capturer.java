package org.webrtc.mozi;

import android.content.Context;
import android.hardware.Camera;
import android.hardware.camera2.CameraManager;
import javax.annotation.Nullable;
import org.webrtc.mozi.CameraSession;
import org.webrtc.mozi.CameraVideoCapturer;

/* JADX INFO: loaded from: classes3.dex */
public class Camera2Capturer extends CameraCapturer {
    private Camera2Session camera2Session;

    @Nullable
    private final CameraManager cameraManager;
    private final Context context;

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
    public /* bridge */ /* synthetic */ void setEnableDoubleCallback(boolean z) {
        super.setEnableDoubleCallback(z);
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
    @Deprecated
    public /* bridge */ /* synthetic */ void setPreviewCallbackWithBuffer(Camera.PreviewCallback previewCallback) {
        super.setPreviewCallbackWithBuffer(previewCallback);
    }

    @Override // org.webrtc.mozi.CameraCapturer
    public /* bridge */ /* synthetic */ void setRestartAttemptsEnable(boolean z) {
        super.setRestartAttemptsEnable(z);
    }

    @Override // org.webrtc.mozi.CameraCapturer
    public /* bridge */ /* synthetic */ void setWindowRotation(int i) {
        super.setWindowRotation(i);
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

    public Camera2Capturer(Context context, String cameraName, CameraVideoCapturer.CameraEventsHandler eventsHandler) {
        super(cameraName, true, eventsHandler, new Camera2Enumerator(context), null);
        this.context = context;
        this.cameraManager = (CameraManager) context.getSystemService("camera");
    }

    @Override // org.webrtc.mozi.CameraCapturer
    protected void createCameraSession(CameraSession.CreateSessionCallback createSessionCallback, CameraSession.Events events, Context applicationContext, SurfaceTextureHelper surfaceTextureHelper, String cameraName, int width, int height, int framerate) {
        Camera2Session.create(createSessionCallback, events, applicationContext, this.cameraManager, surfaceTextureHelper, cameraName, width, height, framerate);
    }

    @Override // org.webrtc.mozi.CameraCapturer
    protected void onCreateCameraSessionDone(CameraSession session) {
        super.onCreateCameraSessionDone(session);
        if (session instanceof Camera2Session) {
            this.camera2Session = (Camera2Session) session;
        }
    }

    @Override // org.webrtc.mozi.CameraCapturer
    public CameraSession getCameraSession() {
        return this.camera2Session;
    }
}
