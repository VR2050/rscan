package org.webrtc.mozi.video.codecfactory;

import org.webrtc.mozi.EglBase;
import org.webrtc.mozi.HardwareVideoDecoder;
import org.webrtc.mozi.HardwareVideoDecoderFactory;
import org.webrtc.mozi.McsConfigHelper;
import org.webrtc.mozi.VideoCodecInfo;
import org.webrtc.mozi.VideoDecoder;

/* JADX INFO: loaded from: classes3.dex */
public class RTCFallbackHardwareVideoDecoderFactory extends HardwareVideoDecoderFactory {
    private static final int FALLBACK_RESOLUTION_THRESHOLD = 1000;
    private int mSoftVideoSize;

    public RTCFallbackHardwareVideoDecoderFactory(McsConfigHelper mcsConfigHelper, EglBase.Context sharedContext) {
        this(mcsConfigHelper, sharedContext, 1000);
    }

    public RTCFallbackHardwareVideoDecoderFactory(McsConfigHelper mcsConfigHelper, EglBase.Context sharedContext, int softVideoSize) {
        super(mcsConfigHelper, sharedContext);
        this.mSoftVideoSize = softVideoSize;
    }

    @Override // org.webrtc.mozi.HardwareVideoDecoderFactory, org.webrtc.mozi.VideoDecoderFactory
    public VideoDecoder createDecoder(VideoCodecInfo codecType) {
        VideoDecoder decoder = super.createDecoder(codecType);
        if (decoder instanceof HardwareVideoDecoder) {
            ((HardwareVideoDecoder) decoder).setFallbackController(new HardwareVideoDecoder.FallbackController() { // from class: org.webrtc.mozi.video.codecfactory.RTCFallbackHardwareVideoDecoderFactory.1
                @Override // org.webrtc.mozi.HardwareVideoDecoder.FallbackController
                public boolean isFallback(VideoDecoder.Settings settings) {
                    if (settings == null || settings.width > RTCFallbackHardwareVideoDecoderFactory.this.mSoftVideoSize || settings.height > RTCFallbackHardwareVideoDecoderFactory.this.mSoftVideoSize) {
                        return false;
                    }
                    return true;
                }
            });
        }
        return decoder;
    }
}
