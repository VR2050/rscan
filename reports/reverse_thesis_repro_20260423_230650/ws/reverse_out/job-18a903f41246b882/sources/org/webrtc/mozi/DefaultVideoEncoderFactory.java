package org.webrtc.mozi;

import java.util.Arrays;
import java.util.LinkedHashSet;
import javax.annotation.Nullable;
import org.webrtc.mozi.EglBase;

/* JADX INFO: loaded from: classes3.dex */
public class DefaultVideoEncoderFactory implements VideoEncoderFactory {
    private static final String TAG = "DefaultVideoEncoderFactory";
    private final McsConfigHelper configHelper;
    private final VideoEncoderFactory hardwareVideoEncoderFactory;
    private final VideoEncoderFactory softwareVideoEncoderFactory;

    public DefaultVideoEncoderFactory(long configHandler, EglBase.Context eglContext, boolean enableIntelVp8Encoder, boolean enableH264HighProfile) {
        this(new McsConfigHelper(configHandler), eglContext, enableIntelVp8Encoder, enableH264HighProfile, -1);
    }

    public DefaultVideoEncoderFactory(McsConfigHelper configHelper, EglBase.Context eglContext, boolean enableIntelVp8Encoder, boolean enableH264HighProfile, int forceKeyframeInterval) {
        this.configHelper = configHelper;
        this.hardwareVideoEncoderFactory = new HardwareVideoEncoderFactory(configHelper, eglContext, enableIntelVp8Encoder, enableH264HighProfile, forceKeyframeInterval);
        boolean supportCHP = configHelper != null && configHelper.getH264Config().supportCHP();
        this.softwareVideoEncoderFactory = new SoftwareVideoEncoderFactory(supportCHP);
    }

    public DefaultVideoEncoderFactory(McsConfigHelper configHelper) {
        this.configHelper = configHelper;
        this.hardwareVideoEncoderFactory = null;
        this.softwareVideoEncoderFactory = new SoftwareVideoEncoderFactory();
    }

    DefaultVideoEncoderFactory(McsConfigHelper configHelper, VideoEncoderFactory hardwareVideoEncoderFactory) {
        this.configHelper = configHelper;
        this.hardwareVideoEncoderFactory = hardwareVideoEncoderFactory;
        this.softwareVideoEncoderFactory = new SoftwareVideoEncoderFactory();
    }

    @Override // org.webrtc.mozi.VideoEncoderFactory
    @Nullable
    public VideoEncoder createEncoder(VideoCodecInfo info) {
        VideoEncoder softwareEncoder = this.softwareVideoEncoderFactory.createEncoder(info);
        H264Config config = this.configHelper.getH264Config();
        if (config.forceSWEncoder()) {
            Logging.d(TAG, "createEncoder, force to use SW");
            CodecMonitorHelper.encoderEvent(CodecMonitorHelper.EVENT_INIT, CodecMonitorHelper.FORMAT_SW, "fore to sw");
            return softwareEncoder;
        }
        VideoEncoderFactory videoEncoderFactory = this.hardwareVideoEncoderFactory;
        VideoEncoder hardwareEncoder = videoEncoderFactory != null ? videoEncoderFactory.createEncoder(info) : null;
        if (hardwareEncoder == null || softwareEncoder == null) {
            return hardwareEncoder != null ? hardwareEncoder : softwareEncoder;
        }
        Logging.d(TAG, "createEncoder, new VideoEncoderFallback");
        CodecMonitorHelper.encoderEvent(CodecMonitorHelper.EVENT_INIT, CodecMonitorHelper.FORMAT_HW, "support hw and sw");
        return new VideoEncoderFallback(softwareEncoder, hardwareEncoder, this.configHelper);
    }

    @Override // org.webrtc.mozi.VideoEncoderFactory
    public VideoCodecInfo[] getSupportedCodecs() {
        LinkedHashSet<VideoCodecInfo> supportedCodecInfos = new LinkedHashSet<>();
        supportedCodecInfos.addAll(Arrays.asList(this.softwareVideoEncoderFactory.getSupportedCodecs()));
        VideoEncoderFactory videoEncoderFactory = this.hardwareVideoEncoderFactory;
        if (videoEncoderFactory != null) {
            supportedCodecInfos.addAll(Arrays.asList(videoEncoderFactory.getSupportedCodecs()));
        }
        return (VideoCodecInfo[]) supportedCodecInfos.toArray(new VideoCodecInfo[supportedCodecInfos.size()]);
    }
}
