package org.webrtc.mozi;

import android.media.MediaCodecInfo;
import android.media.MediaCodecList;
import android.os.Build;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.Nullable;
import org.webrtc.mozi.EglBase;

/* JADX INFO: loaded from: classes3.dex */
public class HardwareVideoDecoderFactory implements VideoDecoderFactory {
    private static final String TAG = "HardwareVideoDecoderFactory";
    private final McsConfigHelper configHelper;
    private MediaCodecWrapperFactory mediaCodecWrapperFactory;
    private final EglBase.Context sharedContext;

    @Deprecated
    public HardwareVideoDecoderFactory(McsConfigHelper configHelper) {
        this(configHelper, null);
    }

    public HardwareVideoDecoderFactory(McsConfigHelper configHelper, EglBase.Context sharedContext) {
        this.sharedContext = sharedContext;
        this.configHelper = configHelper;
    }

    public HardwareVideoDecoderFactory(McsConfigHelper configHelper, EglBase.Context sharedContext, MediaCodecWrapperFactory mediaCodecWrapperFactory) {
        this.sharedContext = sharedContext;
        this.mediaCodecWrapperFactory = mediaCodecWrapperFactory;
        this.configHelper = configHelper;
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
        String cause;
        List<Integer> eventRecord = new ArrayList<>();
        VideoCodecType type = VideoCodecType.valueOf(codecType.getName());
        MediaCodecInfo info = findCodecForType(type, eventRecord);
        if (info == null) {
            if (!eventRecord.isEmpty()) {
                cause = String.valueOf(eventRecord.get(0));
            } else {
                cause = String.valueOf(1);
            }
            CodecMonitorHelper.decoderEvent(CodecMonitorHelper.EVENT_INIT, CodecMonitorHelper.FORMAT_SW, "no_codec_" + cause);
            return null;
        }
        try {
            MediaCodecInfo.CodecCapabilities capabilities = info.getCapabilitiesForType(type.mimeType());
            if (capabilities == null) {
                Logging.d(TAG, "createDecoder failed because of no CodecCapabilities");
                CodecMonitorHelper.decoderEvent(CodecMonitorHelper.EVENT_INIT, CodecMonitorHelper.FORMAT_SW, "codec_no_cap");
                return null;
            }
            if (type == VideoCodecType.AV1) {
                return null;
            }
            McsConfigHelper mcsConfigHelper = this.configHelper;
            MediaCodecWrapperFactory mediaCodecWrapperFactoryImpl = this.mediaCodecWrapperFactory;
            if (mediaCodecWrapperFactoryImpl == null) {
                mediaCodecWrapperFactoryImpl = new MediaCodecWrapperFactoryImpl();
            }
            return new HardwareVideoDecoder(mcsConfigHelper, mediaCodecWrapperFactoryImpl, info.getName(), type, MediaCodecUtils.selectColorFormat(MediaCodecUtils.DECODER_COLOR_FORMATS, capabilities).intValue(), this.sharedContext);
        } catch (Throwable e) {
            Logging.e(TAG, "createDecoder failed because of CodecCapabilities exception", e);
            CodecMonitorHelper.decoderEvent(CodecMonitorHelper.EVENT_INIT, CodecMonitorHelper.FORMAT_SW, "codec_cap_error");
            return null;
        }
    }

    @Override // org.webrtc.mozi.VideoDecoderFactory
    public VideoCodecInfo[] getSupportedCodecs() {
        List<VideoCodecInfo> supportedCodecInfos = new ArrayList<>();
        VideoCodecType[] videoCodecTypeArr = {VideoCodecType.VP8, VideoCodecType.VP9, VideoCodecType.H264, VideoCodecType.H265};
        for (int i = 0; i < 4; i++) {
            VideoCodecType type = videoCodecTypeArr[i];
            MediaCodecInfo codec = findCodecForType(type, null);
            if (codec != null) {
                String name = type.name();
                if (type == VideoCodecType.H264 && isH264HighProfileSupported(codec)) {
                    supportedCodecInfos.add(new VideoCodecInfo(name, MediaCodecUtils.getCodecProperties(type, true)));
                }
                supportedCodecInfos.add(new VideoCodecInfo(name, MediaCodecUtils.getCodecProperties(type, false)));
            }
        }
        return (VideoCodecInfo[]) supportedCodecInfos.toArray(new VideoCodecInfo[supportedCodecInfos.size()]);
    }

    @Override // org.webrtc.mozi.VideoDecoderFactory
    public void setDynamicDecodePixelsThreshold(int pixelsThreshold) {
    }

    @Nullable
    private MediaCodecInfo findCodecForType(VideoCodecType type, List<Integer> eventRecord) {
        if (Build.VERSION.SDK_INT < 19) {
            return null;
        }
        List<MediaCodecInfo> codecInfoCache = MediaCodecCache.getCodecInfoCache();
        if (codecInfoCache.size() > 0) {
            for (MediaCodecInfo codecInfo : codecInfoCache) {
                if (codecInfo != null && !codecInfo.isEncoder() && isSupportedCodec(codecInfo, type, eventRecord)) {
                    Logging.d(TAG, "findCodecForType hit cache. type = " + type.name());
                    return codecInfo;
                }
            }
            return null;
        }
        try {
            int numCodecs = MediaCodecList.getCodecCount();
            for (int i = 0; i < numCodecs; i++) {
                MediaCodecInfo info = null;
                try {
                    info = MediaCodecList.getCodecInfoAt(i);
                } catch (IllegalArgumentException e) {
                    Logging.e(TAG, "Cannot retrieve encoder codec info", e);
                }
                if (info != null && !info.isEncoder() && isSupportedCodec(info, type, eventRecord)) {
                    return info;
                }
            }
            return null;
        } catch (RuntimeException e2) {
            Logging.e(TAG, "findCodecForType exception", e2);
            MediaCodecUtils.recordLatestCodecEventCode(eventRecord, 2);
            return null;
        }
    }

    private boolean isSupportedCodec(MediaCodecInfo info, VideoCodecType type, List<Integer> eventRecord) {
        try {
            if (!MediaCodecUtils.codecSupportsType(info, type)) {
                return false;
            }
            if (MediaCodecUtils.selectColorFormat(MediaCodecUtils.DECODER_COLOR_FORMATS, info.getCapabilitiesForType(type.mimeType())) == null) {
                MediaCodecUtils.recordLatestCodecEventCode(eventRecord, 3);
                return false;
            }
            return isHardwareSupported(info, type, eventRecord);
        } catch (Throwable e) {
            Logging.e(TAG, "isSupportedCodec api error", e);
            return false;
        }
    }

    private boolean isHardwareConfigSupported(VideoCodecType type, String name, long version) {
        List<HardwareModel> decoderConfig;
        String codec;
        VideoMediaCodecConfig config = this.configHelper.getVideoMediaCodecConfig();
        if (config == null || type == null || name == null || (decoderConfig = config.getHardwareDecoderSupportList()) == null) {
            return false;
        }
        int i = AnonymousClass1.$SwitchMap$org$webrtc$mozi$VideoCodecType[type.ordinal()];
        if (i == 1) {
            codec = "vp8";
        } else if (i == 2) {
            codec = "vp9";
        } else if (i == 3) {
            codec = "h264";
        } else {
            if (i != 4) {
                return false;
            }
            codec = "h265";
        }
        for (HardwareModel model : decoderConfig) {
            if (codec.equals(model.getCodec()) && name.startsWith(model.getName())) {
                try {
                    if (version >= Long.valueOf(model.getVersion()).longValue()) {
                        return true;
                    }
                } catch (Throwable th) {
                    return false;
                }
            }
        }
        return false;
    }

    /* JADX INFO: renamed from: org.webrtc.mozi.HardwareVideoDecoderFactory$1, reason: invalid class name */
    static /* synthetic */ class AnonymousClass1 {
        static final /* synthetic */ int[] $SwitchMap$org$webrtc$mozi$VideoCodecType;

        static {
            int[] iArr = new int[VideoCodecType.values().length];
            $SwitchMap$org$webrtc$mozi$VideoCodecType = iArr;
            try {
                iArr[VideoCodecType.VP8.ordinal()] = 1;
            } catch (NoSuchFieldError e) {
            }
            try {
                $SwitchMap$org$webrtc$mozi$VideoCodecType[VideoCodecType.VP9.ordinal()] = 2;
            } catch (NoSuchFieldError e2) {
            }
            try {
                $SwitchMap$org$webrtc$mozi$VideoCodecType[VideoCodecType.H264.ordinal()] = 3;
            } catch (NoSuchFieldError e3) {
            }
            try {
                $SwitchMap$org$webrtc$mozi$VideoCodecType[VideoCodecType.H265.ordinal()] = 4;
            } catch (NoSuchFieldError e4) {
            }
        }
    }

    private boolean isHardwareSupported(MediaCodecInfo info, VideoCodecType type, List<Integer> eventRecord) {
        String name = info.getName();
        boolean z = true;
        if (isHardwareConfigSupported(type, name, Build.VERSION.SDK_INT)) {
            return true;
        }
        int i = AnonymousClass1.$SwitchMap$org$webrtc$mozi$VideoCodecType[type.ordinal()];
        if (i == 1) {
            return name.startsWith("OMX.qcom.") || name.startsWith("OMX.Intel.") || name.startsWith("OMX.Exynos.") || name.startsWith("OMX.Nvidia.") || name.startsWith("OMX.hisi.");
        }
        if (i == 2) {
            boolean support = name.startsWith("OMX.qcom.");
            return support || name.startsWith("OMX.Exynos.") || name.startsWith("OMX.hisi.");
        }
        if (i != 3) {
            if (i != 4) {
                return false;
            }
            return name.startsWith("OMX.qcom.") || name.startsWith("OMX.Intel.") || name.startsWith("OMX.Exynos.") || name.startsWith("OMX.hisi.");
        }
        if (this.configHelper.getAndroidRoomsConfig().isRooms()) {
            Logging.d(TAG, "rooms support hw decoder");
            boolean support2 = McsHWDeviceHelper.getInstance().supportHardwareDecoder();
            if (!support2) {
                MediaCodecUtils.recordLatestCodecEventCode(eventRecord, 4);
            }
            return support2;
        }
        boolean support3 = name.startsWith("OMX.qcom.");
        if (!support3 && !name.startsWith("OMX.Intel.") && !name.startsWith("OMX.Exynos.") && !name.startsWith("OMX.IMG.") && !name.startsWith("OMX.ittiam.") && ((!name.startsWith("OMX.hisi.") || Build.VERSION.SDK_INT < 21) && (!name.startsWith("OMX.sprd.") || Build.VERSION.SDK_INT < WebrtcGrayConfig.sEnableHardwareDecoderForUNISOCMinOS))) {
            z = false;
        }
        boolean support4 = z;
        if (!support4) {
            MediaCodecUtils.recordLatestCodecEventCode(eventRecord, 6);
        }
        return support4;
    }

    private boolean isH264HighProfileSupported(MediaCodecInfo info) {
        if (!this.configHelper.getVideoCodecConfig().isEnableGetCodecProfiles()) {
            String name = info.getName();
            if (Build.VERSION.SDK_INT < 21 || !name.startsWith("OMX.qcom.")) {
                return Build.VERSION.SDK_INT >= 23 && name.startsWith("OMX.Exynos.");
            }
            return true;
        }
        int[] profiles = MediaCodecUtils.getCodecProfiles(info, "video/avc");
        if (profiles == null) {
            return false;
        }
        for (int i : profiles) {
            if (i == 8) {
                return true;
            }
        }
        return false;
    }
}
