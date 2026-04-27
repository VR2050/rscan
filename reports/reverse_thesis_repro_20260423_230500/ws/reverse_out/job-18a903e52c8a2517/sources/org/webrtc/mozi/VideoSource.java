package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
public class VideoSource extends MediaSource {
    private final NativeCapturerObserver capturerObserver;

    private static native void nativeAdaptOutputFormat(long j, int i, int i2, int i3);

    private static native long nativeGetInternalSource(long j);

    public VideoSource(long nativeSource) {
        super(nativeSource);
        this.capturerObserver = new NativeCapturerObserver(nativeGetInternalSource(nativeSource));
    }

    public void adaptOutputFormat(int width, int height, int fps) {
        nativeAdaptOutputFormat(this.nativeSource, width, height, fps);
    }

    public CapturerObserver getCapturerObserver() {
        return this.capturerObserver;
    }
}
