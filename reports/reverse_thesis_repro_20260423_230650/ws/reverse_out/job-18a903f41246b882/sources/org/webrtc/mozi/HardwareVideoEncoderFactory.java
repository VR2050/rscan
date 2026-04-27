package org.webrtc.mozi;

import android.media.MediaCodecInfo;
import android.media.MediaCodecList;
import android.os.Build;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.annotation.Nullable;
import org.webrtc.mozi.EglBase;
import org.webrtc.mozi.EglBase14;

/* JADX INFO: loaded from: classes3.dex */
public class HardwareVideoEncoderFactory implements VideoEncoderFactory {
    private static final List<String> H264_HW_EXCEPTION_MODELS = Arrays.asList("SAMSUNG-SGH-I337", "Nexus 7", "Nexus 4");
    private static final int QCOM_VP8_KEY_FRAME_INTERVAL_ANDROID_L_MS = 15000;
    private static final int QCOM_VP8_KEY_FRAME_INTERVAL_ANDROID_M_MS = 20000;
    private static final int QCOM_VP8_KEY_FRAME_INTERVAL_ANDROID_N_MS = 15000;
    private static final String TAG = "HardwareVideoEncoderFactory";
    private final McsConfigHelper configHelper;
    private final boolean enableH264HighProfile;
    private final boolean enableIntelVp8Encoder;
    private final int forcedKeyFrameInterval;

    @Nullable
    private final EglBase14.Context sharedContext;

    public HardwareVideoEncoderFactory(McsConfigHelper configHelper, EglBase.Context sharedContext, boolean enableIntelVp8Encoder, boolean enableH264HighProfile) {
        this(configHelper, sharedContext, enableIntelVp8Encoder, enableH264HighProfile, -1);
    }

    public HardwareVideoEncoderFactory(McsConfigHelper configHelper, EglBase.Context sharedContext, boolean enableIntelVp8Encoder, boolean enableH264HighProfile, int forcedKeyFrameInterval) {
        if (sharedContext instanceof EglBase14.Context) {
            this.sharedContext = (EglBase14.Context) sharedContext;
        } else {
            Logging.w(TAG, "No shared EglBase.Context.  Encoders will not use texture mode.");
            this.sharedContext = null;
        }
        this.configHelper = configHelper;
        this.enableIntelVp8Encoder = enableIntelVp8Encoder;
        this.enableH264HighProfile = enableH264HighProfile;
        this.forcedKeyFrameInterval = forcedKeyFrameInterval;
    }

    @Deprecated
    public HardwareVideoEncoderFactory(McsConfigHelper configHelper, boolean enableIntelVp8Encoder, boolean enableH264HighProfile) {
        this(configHelper, null, enableIntelVp8Encoder, enableH264HighProfile);
    }

    @Override // org.webrtc.mozi.VideoEncoderFactory
    @Nullable
    public VideoEncoder createEncoder(VideoCodecInfo input) {
        int[] colorFormats;
        String codecName;
        boolean failed_to_create_h264_high_profile;
        String cause;
        List<Integer> eventRecord = new ArrayList<>();
        VideoCodecType type = VideoCodecType.valueOf(input.name);
        MediaCodecInfo info = findCodecForType(type, eventRecord);
        if (info == null) {
            if (!eventRecord.isEmpty()) {
                cause = String.valueOf(eventRecord.get(0));
            } else {
                cause = String.valueOf(1);
            }
            CodecMonitorHelper.encoderEvent(CodecMonitorHelper.EVENT_INIT, CodecMonitorHelper.FORMAT_SW, "no_codec_" + cause);
            return null;
        }
        String codecName2 = info.getName();
        String mime = type.mimeType();
        Integer surfaceColorFormat = MediaCodecUtils.selectColorFormat(MediaCodecUtils.TEXTURE_COLOR_FORMATS, info.getCapabilitiesForType(mime));
        int[] colorFormats2 = MediaCodecUtils.CompatibleColorSpaces.get(Build.MANUFACTURER);
        if (colorFormats2 != null) {
            colorFormats = colorFormats2;
        } else {
            colorFormats = MediaCodecUtils.ENCODER_COLOR_FORMATS;
        }
        Integer yuvColorFormat = MediaCodecUtils.selectColorFormat(colorFormats, info.getCapabilitiesForType(mime));
        if (yuvColorFormat == null) {
            CodecMonitorHelper.encoderEvent(CodecMonitorHelper.EVENT_INIT, CodecMonitorHelper.FORMAT_SW, "not_support_yuvColor");
            return null;
        }
        if (type == VideoCodecType.H264) {
            boolean hwFallbackCB = this.configHelper.getH264Config().hwFallbackCB();
            boolean failed_to_create_h264_high_profile2 = false;
            boolean isHighProfile = H264Utils.isSameH264Profile(input.params, MediaCodecUtils.getCodecProperties(type, true));
            boolean isBaselineProfile = H264Utils.isSameH264Profile(input.params, MediaCodecUtils.getCodecProperties(type, false));
            if (!isHighProfile && !isBaselineProfile) {
                if (!hwFallbackCB) {
                    CodecMonitorHelper.encoderEvent(CodecMonitorHelper.EVENT_INIT, CodecMonitorHelper.FORMAT_SW, "not_support_hb_profile");
                    return null;
                }
                failed_to_create_h264_high_profile2 = true;
            }
            if (isHighProfile && !isH264HighProfileSupported(info)) {
                if (!hwFallbackCB) {
                    CodecMonitorHelper.encoderEvent(CodecMonitorHelper.EVENT_INIT, CodecMonitorHelper.FORMAT_SW, "not_support_h_profile");
                    return null;
                }
                failed_to_create_h264_high_profile = true;
            } else {
                failed_to_create_h264_high_profile = failed_to_create_h264_high_profile2;
            }
            if (failed_to_create_h264_high_profile) {
                Logging.d(TAG, "Failed to create high/main profile encoder. Creating baseline instead.");
                return new HardwareVideoEncoder(this.configHelper, new MediaCodecWrapperFactoryImpl(), codecName2, type, surfaceColorFormat, yuvColorFormat, MediaCodecUtils.getCodecProperties(type, false), getKeyFrameIntervalSec(type), getForcedKeyFrameIntervalMs(type, codecName2), this, this.sharedContext);
            }
            codecName = codecName2;
        } else {
            codecName = codecName2;
        }
        if (type == VideoCodecType.AV1) {
            return null;
        }
        return new HardwareVideoEncoder(this.configHelper, new MediaCodecWrapperFactoryImpl(), codecName, type, surfaceColorFormat, yuvColorFormat, input.params, getKeyFrameIntervalSec(type), getForcedKeyFrameIntervalMs(type, codecName), this, this.sharedContext);
    }

    @Override // org.webrtc.mozi.VideoEncoderFactory
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

    @Nullable
    private MediaCodecInfo findCodecForType(VideoCodecType type, List<Integer> eventRecord) {
        List<MediaCodecInfo> codecInfoCache = MediaCodecCache.getCodecInfoCache();
        if (codecInfoCache.size() > 0) {
            for (MediaCodecInfo codecInfo : codecInfoCache) {
                if (codecInfo != null && codecInfo.isEncoder() && isSupportedCodec(codecInfo, type, eventRecord)) {
                    Logging.d(TAG, "findCodecForType hit cache. type = " + type.name());
                    return codecInfo;
                }
            }
            return null;
        }
        for (int i = 0; i < MediaCodecList.getCodecCount(); i++) {
            try {
                MediaCodecInfo info = null;
                try {
                    info = MediaCodecList.getCodecInfoAt(i);
                } catch (IllegalArgumentException e) {
                    Logging.e(TAG, "Cannot retrieve encoder codec info", e);
                }
                if (info != null && info.isEncoder() && isSupportedCodec(info, type, eventRecord)) {
                    return info;
                }
            } catch (Throwable e2) {
                Logging.e(TAG, "findCodecForType exception", e2);
                return null;
            }
        }
        return null;
    }

    private boolean isSupportedCodec(MediaCodecInfo info, VideoCodecType type, List<Integer> eventRecord) {
        MediaCodecInfo.CodecCapabilities codecCapabilities;
        if (!MediaCodecUtils.codecSupportsType(info, type)) {
            return false;
        }
        if (Build.VERSION.SDK_INT < 21) {
            try {
                codecCapabilities = info.getCapabilitiesForType(type.mimeType());
            } catch (Throwable th) {
                MediaCodecUtils.recordLatestCodecEventCode(eventRecord, 2);
                return false;
            }
        } else {
            codecCapabilities = info.getCapabilitiesForType(type.mimeType());
        }
        if (MediaCodecUtils.selectColorFormat(MediaCodecUtils.ENCODER_COLOR_FORMATS, codecCapabilities) == null) {
            MediaCodecUtils.recordLatestCodecEventCode(eventRecord, 3);
            return false;
        }
        return isHardwareSupportedInCurrentSdk(info, type, eventRecord);
    }

    /* JADX INFO: renamed from: org.webrtc.mozi.HardwareVideoEncoderFactory$1, reason: invalid class name */
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

    private boolean isHardwareSupportedInCurrentSdk(MediaCodecInfo info, VideoCodecType type, List<Integer> eventRecord) {
        int i = AnonymousClass1.$SwitchMap$org$webrtc$mozi$VideoCodecType[type.ordinal()];
        if (i == 1) {
            return isHardwareSupportedInCurrentSdkVp8(info);
        }
        if (i == 2) {
            return isHardwareSupportedInCurrentSdkVp9(info);
        }
        if (i == 3) {
            return isHardwareSupportedInCurrentSdkH264(info, eventRecord);
        }
        if (i == 4) {
            return isHardwareSupportedInCurrentSdkH265(info);
        }
        return false;
    }

    private boolean isHardwareSupportedInCurrentSdkVp8(MediaCodecInfo info) {
        String name = info.getName();
        if (isHardwareConfigSupported("vp8", name, Build.VERSION.SDK_INT)) {
            return true;
        }
        if (name.startsWith("OMX.qcom.") && Build.VERSION.SDK_INT >= 19) {
            return true;
        }
        if (name.startsWith("OMX.Exynos.") && Build.VERSION.SDK_INT >= 23) {
            return true;
        }
        if (name.startsWith("OMX.Intel.") && Build.VERSION.SDK_INT >= 21 && this.enableIntelVp8Encoder) {
            return true;
        }
        return name.startsWith("OMX.hisi.") && Build.VERSION.SDK_INT >= 19;
    }

    private boolean isHardwareSupportedInCurrentSdkVp9(MediaCodecInfo info) {
        String name = info.getName();
        if (isHardwareConfigSupported("vp9", name, Build.VERSION.SDK_INT)) {
            return true;
        }
        return (name.startsWith("OMX.qcom.") || name.startsWith("OMX.Exynos.") || name.startsWith("OMX.hisi.")) && Build.VERSION.SDK_INT >= 24;
    }

    private boolean isHardwareSupportedInCurrentSdkH264(MediaCodecInfo info, List<Integer> eventRecord) {
        if (this.configHelper.getProjectionConfig().isP2pProjection() || this.configHelper.getProjectionConfig().isMeetingProjection()) {
            boolean forceUseHwEncoder = this.configHelper.getProjectionConfig().androidForceHwEncoder();
            Logging.w(TAG, "projection force use hw encoder:" + forceUseHwEncoder);
            return forceUseHwEncoder;
        }
        if (this.configHelper.getAndroidRoomsConfig().isRooms()) {
            Logging.w(TAG, "rooms force hw encoder");
            boolean support = McsHWDeviceHelper.getInstance().forceHardwareEncoder();
            if (!support) {
                MediaCodecUtils.recordLatestCodecEventCode(eventRecord, 4);
            }
            return support;
        }
        boolean support2 = false;
        if (H264_HW_EXCEPTION_MODELS.contains(Build.MODEL)) {
            MediaCodecUtils.recordLatestCodecEventCode(eventRecord, 5);
            return false;
        }
        String name = info.getName();
        if (isHardwareConfigSupported("h264", name, Build.VERSION.SDK_INT)) {
            return true;
        }
        if ((name.startsWith("OMX.qcom.") && Build.VERSION.SDK_INT >= 19) || ((name.startsWith("OMX.Exynos.") && Build.VERSION.SDK_INT >= 21) || ((name.startsWith("OMX.hisi.") && Build.VERSION.SDK_INT >= 19) || ((name.startsWith("OMX.IMG.") && Build.VERSION.SDK_INT >= 19) || ((name.startsWith("OMX.ittiam.") && Build.VERSION.SDK_INT >= 19) || ((name.startsWith("OMX.MTK.") && Build.VERSION.SDK_INT >= WebrtcGrayConfig.sEnableHardwareEncoderForMTKSocMinOS) || (name.startsWith("OMX.sprd.") && Build.VERSION.SDK_INT >= WebrtcGrayConfig.sEnableHardwareEncoderForUNISOCMinOS))))))) {
            support2 = true;
        }
        if (!support2) {
            MediaCodecUtils.recordLatestCodecEventCode(eventRecord, 6);
        }
        return support2;
    }

    private boolean isHardwareSupportedInCurrentSdkH265(MediaCodecInfo info) {
        return isHardwareSupportedInCurrentSdkH264(info, null);
    }

    private boolean isHardwareConfigSupported(String codec, String name, long version) {
        List<HardwareModel> encoderConfig;
        VideoMediaCodecConfig config = this.configHelper.getVideoMediaCodecConfig();
        if (config == null || codec == null || name == null || (encoderConfig = config.getHardwareEncoderSupportList()) == null) {
            return false;
        }
        for (HardwareModel model : encoderConfig) {
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

    private int getKeyFrameIntervalSec(VideoCodecType type) {
        int i = AnonymousClass1.$SwitchMap$org$webrtc$mozi$VideoCodecType[type.ordinal()];
        if (i == 1 || i == 2) {
            return 100;
        }
        if (i == 3 || i == 4) {
            return 20;
        }
        throw new IllegalArgumentException("Unsupported VideoCodecType " + type);
    }

    private int getForcedKeyFrameIntervalMs(VideoCodecType type, String codecName) {
        int i = this.forcedKeyFrameInterval;
        if (i >= 0) {
            return i;
        }
        if (type == VideoCodecType.VP8 && codecName.startsWith("OMX.qcom.")) {
            if (Build.VERSION.SDK_INT == 21 || Build.VERSION.SDK_INT == 22) {
                return 15000;
            }
            if (Build.VERSION.SDK_INT == 23) {
                return QCOM_VP8_KEY_FRAME_INTERVAL_ANDROID_M_MS;
            }
            return Build.VERSION.SDK_INT > 23 ? 15000 : 0;
        }
        return 0;
    }

    public boolean bingoAdjusterInCpuList(String codecName, ArrayList<String> cpuList) {
        Logging.d(TAG, "test cpu list for adjuster, hardware:" + Build.HARDWARE + ", board:" + Build.BOARD + ", model:" + Build.MODEL);
        if (codecName.startsWith("OMX.hisi.") || codecName.startsWith("OMX.MTK.") || codecName.startsWith("OMX.Exynos.")) {
            if (cpuList.indexOf(Build.HARDWARE) != -1) {
                Logging.d(TAG, "bingo cpu list on Build.HARDWARE");
                return true;
            }
            return false;
        }
        if ((codecName.startsWith("OMX.qcom.") || codecName.startsWith("OMX.IMG.")) && cpuList.indexOf(Build.BOARD) != -1) {
            Logging.d(TAG, "bingo cpu list on Build.BOARD");
            return true;
        }
        return false;
    }

    public BitrateAdjuster createBitrateAdjuster(VideoCodecType type, String codecName) {
        Logging.d(TAG, "createBitrateAdjuster, type:" + type + ", name:" + codecName);
        if (!WebrtcGrayConfig.sVideoEncoderBitrateChipAdjust || (this.configHelper.oneRTCNativeGrayConfigEnabled() && this.configHelper.getMediaCodecGrayConfig().videoEncoderBitrateChipAdjust)) {
            if (codecName.startsWith("OMX.Exynos.")) {
                if (type == VideoCodecType.VP8) {
                    return new DynamicBitrateAdjuster();
                }
                return new FramerateBitrateAdjuster();
            }
        } else if (type == VideoCodecType.VP8) {
            if (codecName.startsWith("OMX.Exynos.")) {
                return new DynamicBitrateAdjuster();
            }
        } else if (type == VideoCodecType.H264) {
            if (this.configHelper.getAndroidRoomsConfig().isRooms() && !McsHWDeviceHelper.getInstance().encoderIsBaseBrAdjuster()) {
                Logging.d(TAG, "rooms createBitrateAdjuster, framerate adjuster");
                return new FramerateBitrateAdjuster();
            }
            ArrayList<String> list4FramerateAdjuster = McsConfig.listCpuOfFramerateAdjuster();
            if (bingoAdjusterInCpuList(codecName, list4FramerateAdjuster)) {
                Logging.d(TAG, "createBitrateAdjuster, framerate adjuster");
                return new FramerateBitrateAdjuster();
            }
            ArrayList<String> list4BaseAdjuster = McsConfig.listCpuOfBaseAdjuster();
            if (bingoAdjusterInCpuList(codecName, list4BaseAdjuster)) {
                Logging.d(TAG, "createBitrateAdjuster, base adjuster");
                return new BaseBitrateAdjuster();
            }
            if (codecName.startsWith("OMX.qcom.") || codecName.startsWith("OMX.MTK.")) {
                Logging.d(TAG, "createBitrateAdjuster, no adjuster");
                return new BaseBitrateAdjuster();
            }
            if (codecName.startsWith("OMX.Exynos.") || codecName.startsWith("OMX.hisi.") || codecName.startsWith("OMX.rk.") || codecName.startsWith("OMX.IMG.")) {
                Logging.d(TAG, "createBitrateAdjuster, framerate adjuster");
                return new FramerateBitrateAdjuster();
            }
        }
        if (this.configHelper.getAndroidRoomsConfig().isRooms()) {
            boolean baseBrA = McsHWDeviceHelper.getInstance().encoderIsBaseBrAdjuster();
            Logging.d(TAG, "rooms encoder is base-br adjuster:" + baseBrA);
            if (baseBrA) {
                return new BaseBitrateAdjuster();
            }
            return new FramerateBitrateAdjuster();
        }
        if (WebrtcGrayConfig.sFallbackFramerateBitrateAdjuster || (this.configHelper.oneRTCNativeGrayConfigEnabled() && this.configHelper.getMediaCodecGrayConfig().fallbackFramerateBitrateAdjuster)) {
            return new FramerateBitrateAdjuster();
        }
        return new BaseBitrateAdjuster();
    }

    private boolean isH264HighProfileSupported(MediaCodecInfo info) {
        int[] profiles;
        if (!this.configHelper.getVideoCodecConfig().isEnableGetCodecProfiles()) {
            return this.enableH264HighProfile && Build.VERSION.SDK_INT > 23 && info.getName().startsWith("OMX.Exynos.");
        }
        if (!this.enableH264HighProfile || (profiles = MediaCodecUtils.getCodecProfiles(info, "video/avc")) == null) {
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
