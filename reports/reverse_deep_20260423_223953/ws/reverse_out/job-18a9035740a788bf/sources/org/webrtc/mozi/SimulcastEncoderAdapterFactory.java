package org.webrtc.mozi;

import java.util.Arrays;
import java.util.LinkedHashSet;
import javax.annotation.Nullable;
import org.webrtc.mozi.EglBase;

/* JADX INFO: loaded from: classes3.dex */
public class SimulcastEncoderAdapterFactory implements VideoEncoderFactory {
    private static final String TAG = "SimulcastEncoderAdapterFactory";
    private final McsConfigHelper configHelper;
    private final VideoEncoderFactory hardwareVideoEncoderFactory;
    private final VideoEncoderFactory softwareVideoEncoderFactory;

    public SimulcastEncoderAdapterFactory(McsConfigHelper configHelper, EglBase.Context eglContext, boolean enableIntelVp8Encoder, boolean enableH264HighProfile, boolean supportCHP) {
        this.configHelper = configHelper;
        this.hardwareVideoEncoderFactory = new DefaultVideoEncoderFactory(configHelper.getNativeMcsConfig(), eglContext, enableIntelVp8Encoder, enableH264HighProfile);
        this.softwareVideoEncoderFactory = new SoftwareVideoEncoderFactory(supportCHP);
    }

    public SimulcastEncoderAdapterFactory(long configHanlde, EglBase.Context eglContext, boolean enableIntelVp8Encoder, boolean enableH264HighProfile, boolean supportCHP) {
        McsConfigHelper mcsConfigHelper = new McsConfigHelper(configHanlde);
        this.configHelper = mcsConfigHelper;
        this.hardwareVideoEncoderFactory = new DefaultVideoEncoderFactory(mcsConfigHelper.getNativeMcsConfig(), eglContext, enableIntelVp8Encoder, enableH264HighProfile);
        this.softwareVideoEncoderFactory = new SoftwareVideoEncoderFactory(supportCHP);
    }

    public SimulcastEncoderAdapterFactory(McsConfigHelper configHelper) {
        this.configHelper = configHelper;
        this.hardwareVideoEncoderFactory = null;
        this.softwareVideoEncoderFactory = new SoftwareVideoEncoderFactory();
    }

    SimulcastEncoderAdapterFactory(McsConfigHelper configHelper, VideoEncoderFactory hardwareVideoEncoderFactory) {
        this.configHelper = configHelper;
        this.hardwareVideoEncoderFactory = hardwareVideoEncoderFactory;
        this.softwareVideoEncoderFactory = new SoftwareVideoEncoderFactory();
    }

    @Override // org.webrtc.mozi.VideoEncoderFactory
    @Nullable
    public VideoEncoder createEncoder(VideoCodecInfo info) {
        if (this.configHelper.getSimulcastConfig().getLowestValidVersion() <= 10) {
            H264Config config = this.configHelper.getH264Config();
            if (config.forceSWEncoder() || this.hardwareVideoEncoderFactory == null) {
                Logging.d(TAG, "createEncoder, force to use sw or hw not available");
                CodecMonitorHelper.encoderEvent(CodecMonitorHelper.EVENT_INIT, CodecMonitorHelper.FORMAT_SW, "fore to sw");
                VideoEncoder encoder = new SimulcastEncoderAdapter(this.softwareVideoEncoderFactory, null, info, this.configHelper);
                return encoder;
            }
            Logging.d(TAG, "createEncoder, use hybrid hw/sw video encoder");
            VideoEncoder encoder2 = new SimulcastEncoderAdapter(this.hardwareVideoEncoderFactory, this.softwareVideoEncoderFactory, info, this.configHelper);
            return encoder2;
        }
        VideoEncoderFactory videoEncoderFactory = this.hardwareVideoEncoderFactory;
        if (videoEncoderFactory != null) {
            return videoEncoderFactory.createEncoder(info);
        }
        return this.softwareVideoEncoderFactory.createEncoder(info);
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
