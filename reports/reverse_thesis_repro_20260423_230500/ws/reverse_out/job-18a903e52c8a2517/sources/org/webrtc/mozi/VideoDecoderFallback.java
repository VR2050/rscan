package org.webrtc.mozi;

import org.webrtc.mozi.VideoDecoder;

/* JADX INFO: loaded from: classes3.dex */
public class VideoDecoderFallback extends WrappedNativeVideoDecoder {
    private int dynamicDecodePixelsThreshold;
    private final VideoDecoder fallback;
    private final McsConfigHelper mcsConfigHelper;
    private final VideoDecoder primary;

    private static native long nativeCreateDecoder(VideoDecoder videoDecoder, VideoDecoder videoDecoder2, int i, long j);

    @Override // org.webrtc.mozi.WrappedNativeVideoDecoder, org.webrtc.mozi.VideoDecoder
    public /* bridge */ /* synthetic */ VideoCodecStatus decode(EncodedImage encodedImage, VideoDecoder.DecodeInfo decodeInfo) {
        return super.decode(encodedImage, decodeInfo);
    }

    @Override // org.webrtc.mozi.WrappedNativeVideoDecoder, org.webrtc.mozi.VideoDecoder
    public /* bridge */ /* synthetic */ String getCodecProfiles() {
        return super.getCodecProfiles();
    }

    @Override // org.webrtc.mozi.WrappedNativeVideoDecoder, org.webrtc.mozi.VideoDecoder
    public /* bridge */ /* synthetic */ String getImplementationName() {
        return super.getImplementationName();
    }

    @Override // org.webrtc.mozi.WrappedNativeVideoDecoder, org.webrtc.mozi.VideoDecoder
    public /* bridge */ /* synthetic */ String getImplementationName2() {
        return super.getImplementationName2();
    }

    @Override // org.webrtc.mozi.WrappedNativeVideoDecoder, org.webrtc.mozi.VideoDecoder
    public /* bridge */ /* synthetic */ boolean getPrefersLateDecoding() {
        return super.getPrefersLateDecoding();
    }

    @Override // org.webrtc.mozi.WrappedNativeVideoDecoder, org.webrtc.mozi.VideoDecoder
    public /* bridge */ /* synthetic */ VideoCodecStatus initDecode(VideoDecoder.Settings settings, VideoDecoder.Callback callback) {
        return super.initDecode(settings, callback);
    }

    @Override // org.webrtc.mozi.WrappedNativeVideoDecoder, org.webrtc.mozi.VideoDecoder
    public /* bridge */ /* synthetic */ VideoCodecStatus release() {
        return super.release();
    }

    public VideoDecoderFallback(VideoDecoder fallback, VideoDecoder primary, int dynamicDecodePixelsThreshold, McsConfigHelper mcsConfigHelper) {
        this.dynamicDecodePixelsThreshold = 0;
        this.fallback = fallback;
        this.primary = primary;
        this.dynamicDecodePixelsThreshold = dynamicDecodePixelsThreshold;
        this.mcsConfigHelper = mcsConfigHelper;
    }

    @Override // org.webrtc.mozi.WrappedNativeVideoDecoder, org.webrtc.mozi.VideoDecoder
    public long createNativeVideoDecoder() {
        return nativeCreateDecoder(this.fallback, this.primary, this.dynamicDecodePixelsThreshold, this.mcsConfigHelper.getNativeOwtFactory());
    }
}
