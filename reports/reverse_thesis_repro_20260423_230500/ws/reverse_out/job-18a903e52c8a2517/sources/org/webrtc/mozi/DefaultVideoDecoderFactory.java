package org.webrtc.mozi;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import javax.annotation.Nullable;
import org.webrtc.mozi.EglBase;

/* JADX INFO: loaded from: classes3.dex */
public class DefaultVideoDecoderFactory implements VideoDecoderFactory {
    private static final String TAG = "DefaultVideoDecoderFactory";
    private final McsConfigHelper configHelper;
    private int dynamicDecodePixelsThreshold;
    private final VideoDecoderFactory hardwareVideoDecoderFactory;
    private final VideoDecoderFactory softwareVideoDecoderFactory;

    public DefaultVideoDecoderFactory(McsConfigHelper configHelper, EglBase.Context eglContext) {
        this.dynamicDecodePixelsThreshold = 0;
        this.hardwareVideoDecoderFactory = new HardwareVideoDecoderFactory(configHelper, eglContext);
        this.softwareVideoDecoderFactory = new SoftwareVideoDecoderFactory();
        this.configHelper = configHelper;
    }

    public DefaultVideoDecoderFactory(McsConfigHelper configHelper) {
        this.dynamicDecodePixelsThreshold = 0;
        this.hardwareVideoDecoderFactory = null;
        this.softwareVideoDecoderFactory = new SoftwareVideoDecoderFactory();
        this.configHelper = configHelper;
    }

    public DefaultVideoDecoderFactory(long configHandler, VideoDecoderFactory hardwareVideoDecoderFactory) {
        this.dynamicDecodePixelsThreshold = 0;
        this.hardwareVideoDecoderFactory = hardwareVideoDecoderFactory;
        this.softwareVideoDecoderFactory = new SoftwareVideoDecoderFactory();
        this.configHelper = new McsConfigHelper(configHandler);
    }

    public DefaultVideoDecoderFactory(long configHandler, VideoDecoderFactory hardwareVideoDecoderFactory, boolean supportCHP) {
        this.dynamicDecodePixelsThreshold = 0;
        this.hardwareVideoDecoderFactory = hardwareVideoDecoderFactory;
        this.softwareVideoDecoderFactory = new SoftwareVideoDecoderFactory(supportCHP);
        this.configHelper = new McsConfigHelper(configHandler);
    }

    @Override // org.webrtc.mozi.VideoDecoderFactory
    @Nullable
    @Deprecated
    public VideoDecoder createDecoder(String codecType) {
        throw new UnsupportedOperationException("Deprecated and not implemented.");
    }

    @Override // org.webrtc.mozi.VideoDecoderFactory
    @Nullable
    public VideoDecoder createDecoder(VideoCodecInfo codecType) {
        VideoDecoder softwareDecoder = this.softwareVideoDecoderFactory.createDecoder(codecType);
        H264Config config = this.configHelper.getH264Config();
        if (config.forceSWDecoder()) {
            Logging.d(TAG, "createDecoder, force to use SW");
            CodecMonitorHelper.decoderEvent(CodecMonitorHelper.EVENT_INIT, CodecMonitorHelper.FORMAT_SW, "fore to sw");
            return softwareDecoder;
        }
        VideoDecoderFactory videoDecoderFactory = this.hardwareVideoDecoderFactory;
        VideoDecoder hardwareDecoder = videoDecoderFactory != null ? videoDecoderFactory.createDecoder(codecType) : null;
        if (hardwareDecoder == null || softwareDecoder == null) {
            return hardwareDecoder != null ? hardwareDecoder : softwareDecoder;
        }
        CodecMonitorHelper.decoderEvent(CodecMonitorHelper.EVENT_INIT, CodecMonitorHelper.FORMAT_HW, "support hw and sw");
        return new VideoDecoderFallback(softwareDecoder, hardwareDecoder, this.dynamicDecodePixelsThreshold, this.configHelper);
    }

    @Override // org.webrtc.mozi.VideoDecoderFactory
    public VideoCodecInfo[] getSupportedCodecs() {
        LinkedHashSet<VideoCodecInfo> supportedCodecInfos = new LinkedHashSet<>();
        SdpConfig sdpConfig = this.configHelper.getSdpConfig();
        if (sdpConfig.useHwDecodeCaps()) {
            H264Config h264Config = this.configHelper.getH264Config();
            boolean supportHardwareDecoder = true;
            if (this.configHelper.getAndroidRoomsConfig().isRooms()) {
                supportHardwareDecoder = McsHWDeviceHelper.getInstance().supportHardwareDecoder();
            }
            if (this.hardwareVideoDecoderFactory != null && supportHardwareDecoder && !h264Config.forceSWDecoder()) {
                supportedCodecInfos.addAll(Arrays.asList(this.hardwareVideoDecoderFactory.getSupportedCodecs()));
                if (supportedCodecInfos.isEmpty()) {
                    Logging.i(TAG, "Hardware decoder codecInfos are invalid; appending software decoder codecInfos.");
                    supportedCodecInfos.addAll(Arrays.asList(this.softwareVideoDecoderFactory.getSupportedCodecs()));
                } else {
                    VideoCodecInfo[] softwareSupportedCodecs = this.softwareVideoDecoderFactory.getSupportedCodecs();
                    ensureHwMissingCodecSupport(supportedCodecInfos, softwareSupportedCodecs, VideoCodecType.H264);
                    AV1Config av1Config = this.configHelper.getAV1Config();
                    if (av1Config.isEnableDecode()) {
                        ensureHwMissingCodecSupport(supportedCodecInfos, softwareSupportedCodecs, VideoCodecType.AV1);
                    }
                }
            } else {
                supportedCodecInfos.addAll(Arrays.asList(this.softwareVideoDecoderFactory.getSupportedCodecs()));
            }
        } else {
            supportedCodecInfos.addAll(Arrays.asList(this.softwareVideoDecoderFactory.getSupportedCodecs()));
            VideoDecoderFactory videoDecoderFactory = this.hardwareVideoDecoderFactory;
            if (videoDecoderFactory != null) {
                supportedCodecInfos.addAll(Arrays.asList(videoDecoderFactory.getSupportedCodecs()));
            }
        }
        return (VideoCodecInfo[]) supportedCodecInfos.toArray(new VideoCodecInfo[supportedCodecInfos.size()]);
    }

    @Override // org.webrtc.mozi.VideoDecoderFactory
    public void setDynamicDecodePixelsThreshold(int pixelsThreshold) {
        this.dynamicDecodePixelsThreshold = pixelsThreshold;
    }

    private static void ensureHwMissingCodecSupport(LinkedHashSet<VideoCodecInfo> supportedCodecs, VideoCodecInfo[] softwareSupportedCodecs, VideoCodecType codecType) {
        boolean hardwareCodecSupported = false;
        Iterator<VideoCodecInfo> it = supportedCodecs.iterator();
        while (true) {
            if (it.hasNext()) {
                if (it.next().getName().equals(codecType.name())) {
                    hardwareCodecSupported = true;
                    break;
                }
            } else {
                break;
            }
        }
        if (!hardwareCodecSupported) {
            List<VideoCodecInfo> filteredSoftwareCodecs = new ArrayList<>();
            for (VideoCodecInfo codec : softwareSupportedCodecs) {
                if (codec.getName().equals(codecType.name())) {
                    filteredSoftwareCodecs.add(codec);
                }
            }
            supportedCodecs.addAll(filteredSoftwareCodecs);
            Logging.i(TAG, codecType.name() + " codec is not supported by hardware; using software codec.");
        }
    }
}
