package org.webrtc.mozi;

import org.webrtc.mozi.VideoFrame;

/* JADX INFO: loaded from: classes3.dex */
class NativeCapturerObserver implements CapturerObserver {
    private final long nativeSource;

    private static native void nativeCapturerStarted(long j, boolean z);

    private static native void nativeCapturerStopped(long j);

    private static native void nativeOnCaptureThreadChanged(long j);

    private static native void nativeOnFrameCaptured(long j, int i, int i2, int i3, int i4, long j2, VideoFrame.Buffer buffer);

    private static native void nativeSetOutputFormatRequest(long j, int i, int i2, int i3);

    public NativeCapturerObserver(long nativeSource) {
        this.nativeSource = nativeSource;
    }

    @Override // org.webrtc.mozi.CapturerObserver
    public void onCapturerStarted(boolean success) {
        nativeCapturerStarted(this.nativeSource, success);
    }

    @Override // org.webrtc.mozi.CapturerObserver
    public void onCapturerStopped() {
        nativeCapturerStopped(this.nativeSource);
    }

    @Override // org.webrtc.mozi.CapturerObserver
    public void onFrameCaptured(VideoFrame frame) {
        nativeOnFrameCaptured(this.nativeSource, frame.getBuffer().getWidth(), frame.getBuffer().getHeight(), frame.getRotation(), frame.getExtraRotation(), frame.getTimestampNs(), frame.getBuffer());
    }

    @Override // org.webrtc.mozi.CapturerObserver
    public void onCaptureThreadChanged() {
        nativeOnCaptureThreadChanged(this.nativeSource);
    }

    @Override // org.webrtc.mozi.CapturerObserver
    public void setOutputFormatRequest(int width, int height, int fps) {
        nativeSetOutputFormatRequest(this.nativeSource, width, height, fps);
    }
}
