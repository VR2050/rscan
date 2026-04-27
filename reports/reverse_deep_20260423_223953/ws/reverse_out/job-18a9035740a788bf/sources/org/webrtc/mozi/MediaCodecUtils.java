package org.webrtc.mozi;

import android.media.MediaCodecInfo;
import android.media.MediaCodecList;
import android.os.Build;
import com.google.android.gms.common.Scopes;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;

/* JADX INFO: loaded from: classes3.dex */
class MediaCodecUtils {
    static final String AMLOGIC_PREFIX = "OMX.amlogic.";
    static final int CODEC_NOT_SUPPORT_BY_API_EXCEPTION = 2;
    static final int CODEC_NOT_SUPPORT_BY_COLOR_FORMAT = 3;
    static final int CODEC_NOT_SUPPORT_BY_EXCEPTION_MODELS = 5;
    static final int CODEC_NOT_SUPPORT_BY_HARDWARE = 6;
    static final int CODEC_NOT_SUPPORT_BY_ROOMS = 4;
    static final int CODEC_NOT_SUPPORT_BY_VIDEO_TYPE = 1;
    static final String EXYNOS_PREFIX = "OMX.Exynos.";
    static final String HISI_PREFIX = "OMX.hisi.";
    static final String IMG_PREFIX = "OMX.IMG.";
    static final String INTEL_PREFIX = "OMX.Intel.";
    static final String ITTIAM_PREFIX = "OMX.ittiam.";
    static final String MTK_PREFIX = "OMX.MTK.";
    static final String NVIDIA_PREFIX = "OMX.Nvidia.";
    static final String QCOM_PREFIX = "OMX.qcom.";
    static final String RK_PREFIX = "OMX.rk.";
    private static final String TAG = "MediaCodecUtils";
    static final String UNISOC_PREFIX = "OMX.sprd.";
    static final int COLOR_QCOM_FORMATYVU420PackedSemiPlanar32m4ka = 2141391873;
    static final int COLOR_QCOM_FORMATYVU420PackedSemiPlanar16m4ka = 2141391874;
    static final int COLOR_QCOM_FORMATYVU420PackedSemiPlanar64x32Tile2m8ka = 2141391875;
    static final int COLOR_QCOM_FORMATYUV420PackedSemiPlanar32m = 2141391876;
    static final int[] DECODER_COLOR_FORMATS = {19, 21, 2135033992, 2141391872, COLOR_QCOM_FORMATYVU420PackedSemiPlanar32m4ka, COLOR_QCOM_FORMATYVU420PackedSemiPlanar16m4ka, COLOR_QCOM_FORMATYVU420PackedSemiPlanar64x32Tile2m8ka, COLOR_QCOM_FORMATYUV420PackedSemiPlanar32m};
    static final int[] ENCODER_COLOR_FORMATS = {19, 21, 2141391872, COLOR_QCOM_FORMATYUV420PackedSemiPlanar32m};
    static final HashMap<String, int[]> CompatibleColorSpaces = new HashMap() { // from class: org.webrtc.mozi.MediaCodecUtils.1
        {
            put("HUAWEI", new int[]{21});
        }
    };
    static final int[] TEXTURE_COLOR_FORMATS = {2130708361};

    @Nullable
    static Integer selectColorFormat(int[] supportedColorFormats, MediaCodecInfo.CodecCapabilities capabilities) {
        for (int supportedColorFormat : supportedColorFormats) {
            for (int codecColorFormat : capabilities.colorFormats) {
                if (codecColorFormat == supportedColorFormat) {
                    return Integer.valueOf(codecColorFormat);
                }
            }
        }
        return null;
    }

    static boolean codecSupportsType(MediaCodecInfo info, VideoCodecType type) {
        for (String mimeType : info.getSupportedTypes()) {
            if (type.mimeType().equals(mimeType)) {
                return true;
            }
        }
        return false;
    }

    /* JADX INFO: renamed from: org.webrtc.mozi.MediaCodecUtils$2, reason: invalid class name */
    static /* synthetic */ class AnonymousClass2 {
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
                $SwitchMap$org$webrtc$mozi$VideoCodecType[VideoCodecType.H265.ordinal()] = 3;
            } catch (NoSuchFieldError e3) {
            }
            try {
                $SwitchMap$org$webrtc$mozi$VideoCodecType[VideoCodecType.H264.ordinal()] = 4;
            } catch (NoSuchFieldError e4) {
            }
            try {
                $SwitchMap$org$webrtc$mozi$VideoCodecType[VideoCodecType.AV1.ordinal()] = 5;
            } catch (NoSuchFieldError e5) {
            }
        }
    }

    static Map<String, String> getCodecProperties(VideoCodecType type, boolean highProfile) {
        int i = AnonymousClass2.$SwitchMap$org$webrtc$mozi$VideoCodecType[type.ordinal()];
        if (i == 1 || i == 2 || i == 3) {
            return new HashMap();
        }
        if (i == 4) {
            return H264Utils.getDefaultH264Params(highProfile);
        }
        if (i == 5) {
            HashMap<String, String> av1ProfileParams = new HashMap<>();
            av1ProfileParams.put("level-idx", "8");
            av1ProfileParams.put(Scopes.PROFILE, "0");
            return av1ProfileParams;
        }
        throw new IllegalArgumentException("Unsupported codec: " + type);
    }

    static void recordLatestCodecEventCode(List<Integer> eventRecord, int eventCode) {
        if (eventRecord != null) {
            if (eventRecord.isEmpty()) {
                eventRecord.add(Integer.valueOf(eventCode));
            } else if (eventRecord.get(0).intValue() < eventCode) {
                eventRecord.set(0, Integer.valueOf(eventCode));
            }
        }
    }

    private MediaCodecUtils() {
    }

    public static class CodecExtraProperties {
        public final int maxHeight;
        public final int maxWidth;
        public final int minHeight;
        public final int minWidth;
        public final String profiles;
        public final boolean supportAdaptivePlayback;
        public final boolean supportLowLatency;

        public CodecExtraProperties(int max_width, int max_height, int min_width, int min_height, boolean adaptive_playback, boolean low_latency, String profiles) {
            this.maxWidth = max_width;
            this.maxHeight = max_height;
            this.minWidth = min_width;
            this.minHeight = min_height;
            this.supportAdaptivePlayback = adaptive_playback;
            this.supportLowLatency = low_latency;
            this.profiles = profiles;
        }
    }

    public static CodecExtraProperties getCodecExtraProperties(String codecName, String mime, boolean isEncoder) {
        String name;
        int max_height;
        int min_width;
        int min_height;
        MediaCodecInfo.VideoCapabilities video_caps;
        if (Build.VERSION.SDK_INT < 19) {
            return null;
        }
        Logging.d(TAG, "Trying to get properties for " + codecName);
        List<MediaCodecInfo> codecInfoCache = MediaCodecCache.getCodecInfoCache();
        if (codecInfoCache.isEmpty()) {
            for (int i = 0; i < MediaCodecList.getCodecCount(); i++) {
                MediaCodecInfo info = null;
                try {
                    info = MediaCodecList.getCodecInfoAt(i);
                } catch (IllegalArgumentException e) {
                    Logging.e(TAG, "Cannot retrieve codec info:" + e.getMessage());
                }
                if (info != null) {
                    codecInfoCache.add(info);
                }
            }
        }
        for (MediaCodecInfo info2 : codecInfoCache) {
            if (info2 != null && (!isEncoder || info2.isEncoder())) {
                if (isEncoder || !info2.isEncoder()) {
                    String[] supportedTypes = info2.getSupportedTypes();
                    int length = supportedTypes.length;
                    int i2 = 0;
                    while (true) {
                        if (i2 >= length) {
                            name = null;
                            break;
                        }
                        String mimeType = supportedTypes[i2];
                        if (!mimeType.equals(mime)) {
                            i2++;
                        } else {
                            String name2 = info2.getName();
                            name = name2;
                            break;
                        }
                    }
                    if (name == null) {
                        continue;
                    } else {
                        Logging.d(TAG, "Found candidate codec: " + name);
                        if (name.equals(codecName)) {
                            try {
                                MediaCodecInfo.CodecCapabilities capabilities = info2.getCapabilitiesForType(mime);
                                boolean adaptive_playback = false;
                                boolean low_latency = false;
                                if (!isEncoder) {
                                    adaptive_playback = capabilities.isFeatureSupported("adaptive-playback");
                                    Logging.d(TAG, "is support adaptive playback:" + adaptive_playback);
                                    low_latency = capabilities.isFeatureSupported("low-latency");
                                    Logging.d(TAG, "is support low latency:" + low_latency);
                                }
                                int max_width = 0;
                                if (Build.VERSION.SDK_INT >= 21 && (video_caps = capabilities.getVideoCapabilities()) != null) {
                                    max_width = ((Integer) video_caps.getSupportedWidths().getUpper()).intValue();
                                    int max_height2 = ((Integer) video_caps.getSupportedHeights().getUpper()).intValue();
                                    int min_width2 = ((Integer) video_caps.getSupportedWidths().getLower()).intValue();
                                    int min_height2 = ((Integer) video_caps.getSupportedHeights().getLower()).intValue();
                                    Logging.d(TAG, "Got supported max width:" + max_width + ", max height:" + max_height2 + ", min width:" + min_width2 + ", min height:" + min_height2);
                                    max_height = max_height2;
                                    min_width = min_width2;
                                    min_height = min_height2;
                                } else {
                                    max_height = 0;
                                    min_width = 0;
                                    min_height = 0;
                                }
                                StringBuilder sb = new StringBuilder();
                                for (int i3 = 0; i3 < capabilities.profileLevels.length; i3++) {
                                    sb.append(capabilities.profileLevels[i3].profile);
                                    if (i3 != capabilities.profileLevels.length - 1) {
                                        sb.append(",");
                                    }
                                }
                                Logging.d(TAG, "Got supported profiles:" + sb.toString());
                                return new CodecExtraProperties(max_width, max_height, min_width, min_height, adaptive_playback, low_latency, sb.toString());
                            } catch (IllegalArgumentException e2) {
                                Logging.e(TAG, "Cannot retrieve codec capabilities:" + e2.getMessage());
                            }
                        } else {
                            continue;
                        }
                    }
                }
            }
        }
        return null;
    }

    public static int[] getCodecProfiles(MediaCodecInfo info, String mime) {
        if (info == null) {
            return null;
        }
        try {
            MediaCodecInfo.CodecCapabilities capabilities = info.getCapabilitiesForType(mime);
            int[] profiles = null;
            if (capabilities.profileLevels.length > 0) {
                profiles = new int[capabilities.profileLevels.length];
            }
            for (int i = 0; i < capabilities.profileLevels.length; i++) {
                Logging.d(TAG, "Codec:" + info.getName() + " supported profile:" + capabilities.profileLevels[i].profile);
                profiles[i] = capabilities.profileLevels[i].profile;
            }
            return profiles;
        } catch (IllegalArgumentException e) {
            Logging.e(TAG, "Cannot retrieve codec capabilities:" + e.getMessage());
            return null;
        }
    }
}
