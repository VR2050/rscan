package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
class SimulcastEncoderAdapter extends WrappedNativeVideoEncoder {
    private final VideoEncoderFactory auxiliaryFactory;
    private final VideoCodecInfo codecInfo;
    private final McsConfigHelper configHelper;
    private final VideoEncoderFactory mainFactory;

    static native long nativeCreateEncoder(VideoEncoderFactory videoEncoderFactory, VideoEncoderFactory videoEncoderFactory2, String str, long j);

    public SimulcastEncoderAdapter(VideoEncoderFactory factory, VideoEncoderFactory auxiliaryFactory, VideoCodecInfo info, McsConfigHelper configHelper) {
        this.mainFactory = factory;
        this.auxiliaryFactory = auxiliaryFactory;
        this.codecInfo = info;
        this.configHelper = configHelper;
    }

    @Override // org.webrtc.mozi.WrappedNativeVideoEncoder, org.webrtc.mozi.VideoEncoder
    public long createNativeVideoEncoder() {
        return nativeCreateEncoder(this.mainFactory, this.auxiliaryFactory, this.codecInfo.name, this.configHelper.getNativeOwtFactory());
    }

    @Override // org.webrtc.mozi.WrappedNativeVideoEncoder, org.webrtc.mozi.VideoEncoder
    public boolean isHardwareEncoder() {
        return this.auxiliaryFactory != null;
    }
}
