package org.webrtc.mozi;

import org.webrtc.mozi.VideoDecoder;

/* JADX INFO: loaded from: classes3.dex */
class VideoDecoderWrapper {
    /* JADX INFO: Access modifiers changed from: private */
    public static native void nativeOnDecodeError(long j, int i, int i2);

    /* JADX INFO: Access modifiers changed from: private */
    public static native void nativeOnDecodedFrame(long j, VideoFrame videoFrame, Integer num, Integer num2);

    /* JADX INFO: Access modifiers changed from: private */
    public static native void nativeOnObligedDropFrame(long j, long j2);

    VideoDecoderWrapper() {
    }

    static VideoDecoder.Callback createDecoderCallback(final long nativeDecoder) {
        return new VideoDecoder.Callback() { // from class: org.webrtc.mozi.VideoDecoderWrapper.1
            @Override // org.webrtc.mozi.VideoDecoder.Callback
            public void onDecodedFrame(VideoFrame frame, Integer decodeTimeMs, Integer qp) {
                VideoDecoderWrapper.nativeOnDecodedFrame(nativeDecoder, frame, decodeTimeMs, qp);
            }

            @Override // org.webrtc.mozi.VideoDecoder.Callback
            public void onObligedDropFrame(long presentationTimeNs) {
                VideoDecoderWrapper.nativeOnObligedDropFrame(nativeDecoder, presentationTimeNs);
            }

            @Override // org.webrtc.mozi.VideoDecoder.Callback
            public void onDecodeError(int majorCode, int minorCode) {
                VideoDecoderWrapper.nativeOnDecodeError(nativeDecoder, majorCode, minorCode);
            }
        };
    }
}
