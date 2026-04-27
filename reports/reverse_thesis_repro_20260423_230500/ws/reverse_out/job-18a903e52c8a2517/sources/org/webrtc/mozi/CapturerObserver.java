package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
public interface CapturerObserver {
    void onCaptureThreadChanged();

    void onCapturerStarted(boolean z);

    void onCapturerStopped();

    void onFrameCaptured(VideoFrame videoFrame);

    void setOutputFormatRequest(int i, int i2, int i3);
}
