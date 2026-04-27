package org.webrtc.mozi;

import java.nio.ByteBuffer;
import javax.annotation.Nullable;
import org.webrtc.mozi.VideoEncoder;

/* JADX INFO: loaded from: classes3.dex */
class VideoEncoderWrapper {
    /* JADX INFO: Access modifiers changed from: private */
    public static native void nativeOnEncodeError(long j, int i, int i2);

    /* JADX INFO: Access modifiers changed from: private */
    public static native void nativeOnEncodedFrame(long j, ByteBuffer byteBuffer, int i, int i2, long j2, int i3, int i4, boolean z, Integer num, int i5, boolean z2);

    /* JADX INFO: Access modifiers changed from: private */
    public static native int nativeOnParseFrame(long j, ByteBuffer byteBuffer, int i);

    /* JADX INFO: Access modifiers changed from: private */
    public static native ByteBuffer nativeOnWriteCropInfo(long j, ByteBuffer byteBuffer, int i, int i2, int i3, int i4);

    VideoEncoderWrapper() {
    }

    static boolean getScalingSettingsOn(VideoEncoder.ScalingSettings scalingSettings) {
        return scalingSettings.on;
    }

    @Nullable
    static Integer getScalingSettingsLow(VideoEncoder.ScalingSettings scalingSettings) {
        return scalingSettings.low;
    }

    @Nullable
    static Integer getScalingSettingsHigh(VideoEncoder.ScalingSettings scalingSettings) {
        return scalingSettings.high;
    }

    static VideoEncoder.Callback createEncoderCallback(final long nativeEncoder) {
        return new VideoEncoder.Callback() { // from class: org.webrtc.mozi.VideoEncoderWrapper.1
            @Override // org.webrtc.mozi.VideoEncoder.Callback
            public void onEncodedFrame(EncodedImage frame, VideoEncoder.CodecSpecificInfo info) {
                VideoEncoderWrapper.nativeOnEncodedFrame(nativeEncoder, frame.buffer, frame.encodedWidth, frame.encodedHeight, frame.captureTimeNs, frame.frameType.getNative(), frame.rotation, frame.completeFrame, frame.qp, info.sim_index, info.end_mark);
            }

            @Override // org.webrtc.mozi.VideoEncoder.Callback
            public int onParseFrame(ByteBuffer frame, int index) {
                return VideoEncoderWrapper.nativeOnParseFrame(nativeEncoder, frame, index);
            }

            @Override // org.webrtc.mozi.VideoEncoder.Callback
            public void onEncodeError(int majorCode, int minorCode) {
                VideoEncoderWrapper.nativeOnEncodeError(nativeEncoder, majorCode, minorCode);
            }

            @Override // org.webrtc.mozi.VideoEncoder.Callback
            public ByteBuffer onWriteCropInfo(ByteBuffer csd, int cropLeft, int cropRight, int cropTop, int cropBottom) {
                return VideoEncoderWrapper.nativeOnWriteCropInfo(nativeEncoder, csd, cropLeft, cropRight, cropTop, cropBottom);
            }
        };
    }
}
