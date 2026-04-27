package org.webrtc.mozi;

import java.nio.ByteBuffer;
import java.util.List;

/* JADX INFO: loaded from: classes3.dex */
public class RtmpController {
    private final long nativeController;

    public interface Observer {
        void SendAudioData(ByteBuffer byteBuffer, long j);

        void onEncodedImage(EncodedImage encodedImage, long j);
    }

    private native void nativeAddTrack(long j, List<String> list);

    private static native void nativeFreeOwnedController(long j);

    private native void nativeOnBitrateUpdated(long j, byte b, long j2);

    RtmpController(long nativeController) {
        this.nativeController = nativeController;
    }

    public void addTrack(MediaStreamTrack track, List<String> streamIds) {
        if (track == null || streamIds == null) {
            throw new NullPointerException("No MediaStreamTrack specified in addTrack.");
        }
        nativeAddTrack(track.nativeTrack, streamIds);
    }

    public void onBitrateUpdated(long bitrateBps, byte fractionLost, long roundTripTimeMs) {
        nativeOnBitrateUpdated(bitrateBps, fractionLost, roundTripTimeMs);
    }

    public void dispose() {
        nativeFreeOwnedController(this.nativeController);
    }

    long getNativeOwnedController() {
        return this.nativeController;
    }
}
