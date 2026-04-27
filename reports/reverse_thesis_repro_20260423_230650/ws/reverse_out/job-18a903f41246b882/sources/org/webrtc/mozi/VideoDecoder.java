package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
public interface VideoDecoder {

    public interface Callback {
        void onDecodeError(int i, int i2);

        void onDecodedFrame(VideoFrame videoFrame, Integer num, Integer num2);

        void onObligedDropFrame(long j);
    }

    long createNativeVideoDecoder();

    VideoCodecStatus decode(EncodedImage encodedImage, DecodeInfo decodeInfo);

    String getCodecProfiles();

    String getImplementationName();

    String getImplementationName2();

    boolean getPrefersLateDecoding();

    VideoCodecStatus initDecode(Settings settings, Callback callback);

    VideoCodecStatus release();

    public static class Settings {
        public final int height;
        public final int numberOfCores;
        public final int ssrc;
        public final int width;

        public Settings(int numberOfCores, int ssrc, int width, int height) {
            this.numberOfCores = numberOfCores;
            this.ssrc = ssrc;
            this.width = width;
            this.height = height;
        }
    }

    public static class DecodeInfo {
        public final boolean isMissingFrames;
        public final long renderTimeMs;

        public DecodeInfo(boolean isMissingFrames, long renderTimeMs) {
            this.isMissingFrames = isMissingFrames;
            this.renderTimeMs = renderTimeMs;
        }
    }
}
