package org.webrtc.mozi.video.codecfactory;

import android.os.Build;
import org.webrtc.mozi.EglBase;
import org.webrtc.mozi.HardwareVideoDecoderFactory;
import org.webrtc.mozi.McsConfigHelper;
import org.webrtc.mozi.MediaCodecWrapperFactory;
import org.webrtc.mozi.VideoDecoderFactory;

/* JADX INFO: loaded from: classes3.dex */
public class RTCCompatDecoderFactoryWrapper {
    public static VideoDecoderFactory CreateCompatDecoderFactory(long configHandler, EglBase.Context sharedContext, boolean preferFallbackHardwareDecoder, int forceSoftDecoderVideoSize, int reclaimWidth, int reclaimHeight) {
        McsConfigHelper mcsConfigHelper = new McsConfigHelper(configHandler);
        if (preferFallbackHardwareDecoder) {
            VideoDecoderFactory hardwareDecoderFactory = new RTCFallbackHardwareVideoDecoderFactory(mcsConfigHelper, sharedContext);
            return hardwareDecoderFactory;
        }
        if (forceSoftDecoderVideoSize > 0) {
            VideoDecoderFactory hardwareDecoderFactory2 = new RTCFallbackHardwareVideoDecoderFactory(mcsConfigHelper, sharedContext, forceSoftDecoderVideoSize);
            return hardwareDecoderFactory2;
        }
        MediaCodecWrapperFactory mediaCodecWrapperFactory = null;
        if (Build.VERSION.SDK_INT >= 23 && reclaimWidth > 0 && reclaimHeight > 0) {
            mediaCodecWrapperFactory = new RTCReclaimMediaCodecWrapperFactory(reclaimWidth, reclaimHeight);
        }
        VideoDecoderFactory hardwareDecoderFactory3 = new HardwareVideoDecoderFactory(mcsConfigHelper, sharedContext, mediaCodecWrapperFactory);
        return hardwareDecoderFactory3;
    }
}
