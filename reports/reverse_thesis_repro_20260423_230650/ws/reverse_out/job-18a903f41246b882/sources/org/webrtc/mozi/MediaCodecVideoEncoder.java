package org.webrtc.mozi;

import android.graphics.Matrix;
import android.media.MediaCodec;
import android.media.MediaCodecInfo;
import android.media.MediaCodecList;
import android.media.MediaCrypto;
import android.media.MediaFormat;
import android.opengl.GLES20;
import android.os.Build;
import android.os.Bundle;
import android.view.Surface;
import com.google.android.exoplayer2.DefaultRenderersFactory;
import com.google.android.gms.common.Scopes;
import com.google.firebase.remoteconfig.FirebaseRemoteConfig;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import javax.annotation.Nullable;
import org.webrtc.mozi.EglBase;
import org.webrtc.mozi.EglBase14;
import org.webrtc.mozi.VideoFrame;

/* JADX INFO: loaded from: classes3.dex */
@Deprecated
public class MediaCodecVideoEncoder {
    private static final String AV1_MIME_TYPE = "video/av1";
    private static final int BITRATE_ADJUSTMENT_FPS = 30;
    private static final double BITRATE_CORRECTION_MAX_SCALE = 4.0d;
    private static final double BITRATE_CORRECTION_SEC = 3.0d;
    private static final int BITRATE_CORRECTION_STEPS = 20;
    private static final int COLOR_QCOM_FORMATYUV420PackedSemiPlanar32m = 2141391876;
    private static final int DEQUEUE_TIMEOUT = 0;
    private static final String[] H264_HW_EXCEPTION_MODELS;
    private static final String H264_MIME_TYPE = "video/avc";
    private static final String H265_MIME_TYPE = "video/hevc";
    private static final int MAXIMUM_INITIAL_FPS = 30;
    private static final int MEDIA_CODEC_RELEASE_TIMEOUT_MS = 5000;
    private static final long QCOM_VP8_KEY_FRAME_INTERVAL_ANDROID_L_MS = 15000;
    private static final long QCOM_VP8_KEY_FRAME_INTERVAL_ANDROID_M_MS = 20000;
    private static final long QCOM_VP8_KEY_FRAME_INTERVAL_ANDROID_N_MS = 15000;
    private static final String TAG = "MediaCodecVideoEncoder";
    private static final int VIDEO_AVCLevel3 = 256;
    private static final int VIDEO_AVCProfileHigh = 8;
    private static final int VIDEO_ControlRateConstant = 2;
    private static final String VP8_MIME_TYPE = "video/x-vnd.on2.vp8";
    private static final String VP9_MIME_TYPE = "video/x-vnd.on2.vp9";
    private static final MediaCodecProperties defaultH264HwProperties;
    private static final MediaCodecProperties defaultVp9HwProperties;
    private static final MediaCodecProperties exynosH264HighProfileHwProperties;
    private static final MediaCodecProperties exynosH264HwProperties;
    private static final MediaCodecProperties[] h264HighProfileHwList;
    private static String[] h264HwCodecBlacklist;
    private static String[] h265HwCodecBlacklist;
    private static final MediaCodecProperties[] h265HwList;
    private static final MediaCodecProperties mediatekH264HwProperties;
    private static final MediaCodecProperties qcomH264HwProperties;
    private static final MediaCodecProperties qcomH265HwProperties;

    @Nullable
    private static EglBase staticEglBase;
    private static final int[] supportedColorList;
    private static final int[] supportedSurfaceColorList;
    private static String[] vp9HwCodecBlacklist;
    private static final MediaCodecProperties[] vp9HwList;
    private double bitrateAccumulator;
    private double bitrateAccumulatorMax;
    private int bitrateAdjustmentScaleExp;
    private double bitrateObservationTimeMs;
    private int colorFormat;

    @Nullable
    private GlRectDrawer drawer;

    @Nullable
    private EglBase14 eglBase;
    private long forcedKeyFrameMs;
    private int height;

    @Nullable
    private Surface inputSurface;
    private long lastKeyFrameMs;

    @Nullable
    private MediaCodec mediaCodec;

    @Nullable
    private Thread mediaCodecThread;
    private ByteBuffer[] outputBuffers;
    private int profile;
    private int targetBitrateBps;
    private int targetFps;
    private VideoCodecType type;
    private int width;

    @Nullable
    private static MediaCodecVideoEncoder runningInstance = null;

    @Nullable
    private static MediaCodecVideoEncoderErrorCallback errorCallback = null;
    private static int codecErrors = 0;
    private static Set<String> hwEncoderDisabledTypes = new HashSet();
    private static final MediaCodecProperties qcomVp8HwProperties = new MediaCodecProperties("OMX.qcom.", 19, BitrateAdjustmentType.NO_ADJUSTMENT);
    private static final MediaCodecProperties exynosVp8HwProperties = new MediaCodecProperties("OMX.Exynos.", 23, BitrateAdjustmentType.DYNAMIC_ADJUSTMENT);
    private static final MediaCodecProperties intelVp8HwProperties = new MediaCodecProperties("OMX.Intel.", 21, BitrateAdjustmentType.NO_ADJUSTMENT);
    private static final MediaCodecProperties defaultVp8HwProperties = new MediaCodecProperties("OMX.", 19, BitrateAdjustmentType.NO_ADJUSTMENT);
    private static String[] vp8HwCodecBlacklist = {"OMX.google."};
    private static final MediaCodecProperties qcomVp9HwProperties = new MediaCodecProperties("OMX.qcom.", 24, BitrateAdjustmentType.NO_ADJUSTMENT);
    private static final MediaCodecProperties exynosVp9HwProperties = new MediaCodecProperties("OMX.Exynos.", 24, BitrateAdjustmentType.FRAMERATE_ADJUSTMENT);
    private BitrateAdjustmentType bitrateAdjustmentType = BitrateAdjustmentType.NO_ADJUSTMENT;

    @Nullable
    private ByteBuffer configData = null;

    public enum BitrateAdjustmentType {
        NO_ADJUSTMENT,
        FRAMERATE_ADJUSTMENT,
        DYNAMIC_ADJUSTMENT
    }

    public interface MediaCodecVideoEncoderErrorCallback {
        void onMediaCodecVideoEncoderCriticalError(int i);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static native long nativeCreateEncoder(VideoCodecInfo videoCodecInfo, boolean z);

    private static native void nativeFillInputBuffer(long j, int i, ByteBuffer byteBuffer, int i2, ByteBuffer byteBuffer2, int i3, ByteBuffer byteBuffer3, int i4);

    public static VideoEncoderFactory createFactory() {
        return new DefaultVideoEncoderFactory(new McsConfigHelper(0L), new HwEncoderFactory());
    }

    static class HwEncoderFactory implements VideoEncoderFactory {
        private final VideoCodecInfo[] supportedHardwareCodecs = getSupportedHardwareCodecs();

        HwEncoderFactory() {
        }

        private static boolean isSameCodec(VideoCodecInfo codecA, VideoCodecInfo codecB) {
            if (!codecA.name.equalsIgnoreCase(codecB.name)) {
                return false;
            }
            if (codecA.name.equalsIgnoreCase("H264")) {
                return H264Utils.isSameH264Profile(codecA.params, codecB.params);
            }
            return true;
        }

        private static boolean isCodecSupported(VideoCodecInfo[] supportedCodecs, VideoCodecInfo codec) {
            for (VideoCodecInfo supportedCodec : supportedCodecs) {
                if (isSameCodec(supportedCodec, codec)) {
                    return true;
                }
            }
            return false;
        }

        private static VideoCodecInfo[] getSupportedHardwareCodecs() {
            List<VideoCodecInfo> codecs = new ArrayList<>();
            if (MediaCodecVideoEncoder.isVp8HwSupported()) {
                Logging.d(MediaCodecVideoEncoder.TAG, "VP8 HW Encoder supported.");
                codecs.add(new VideoCodecInfo("VP8", new HashMap()));
            }
            if (MediaCodecVideoEncoder.isVp9HwSupported()) {
                Logging.d(MediaCodecVideoEncoder.TAG, "VP9 HW Encoder supported.");
                codecs.add(new VideoCodecInfo("VP9", new HashMap()));
            }
            if (MediaCodecVideoDecoder.isH264HighProfileHwSupported()) {
                Logging.d(MediaCodecVideoEncoder.TAG, "H.264 High Profile HW Encoder supported.");
                codecs.add(H264Utils.DEFAULT_H264_HIGH_PROFILE_CODEC);
            }
            if (MediaCodecVideoEncoder.isH264HwSupported()) {
                Logging.d(MediaCodecVideoEncoder.TAG, "H.264 HW Encoder supported.");
                codecs.add(H264Utils.DEFAULT_H264_BASELINE_PROFILE_CODEC);
            }
            return (VideoCodecInfo[]) codecs.toArray(new VideoCodecInfo[codecs.size()]);
        }

        @Override // org.webrtc.mozi.VideoEncoderFactory
        public VideoCodecInfo[] getSupportedCodecs() {
            return this.supportedHardwareCodecs;
        }

        @Override // org.webrtc.mozi.VideoEncoderFactory
        @Nullable
        public VideoEncoder createEncoder(final VideoCodecInfo info) {
            if (!isCodecSupported(this.supportedHardwareCodecs, info)) {
                Logging.d(MediaCodecVideoEncoder.TAG, "No HW video encoder for codec " + info.name);
                return null;
            }
            Logging.d(MediaCodecVideoEncoder.TAG, "Create HW video encoder for " + info.name);
            return new WrappedNativeVideoEncoder() { // from class: org.webrtc.mozi.MediaCodecVideoEncoder.HwEncoderFactory.1
                @Override // org.webrtc.mozi.WrappedNativeVideoEncoder, org.webrtc.mozi.VideoEncoder
                public long createNativeVideoEncoder() {
                    return MediaCodecVideoEncoder.nativeCreateEncoder(info, MediaCodecVideoEncoder.staticEglBase instanceof EglBase14);
                }

                @Override // org.webrtc.mozi.WrappedNativeVideoEncoder, org.webrtc.mozi.VideoEncoder
                public boolean isHardwareEncoder() {
                    return true;
                }
            };
        }
    }

    public enum VideoCodecType {
        VIDEO_CODEC_UNKNOWN,
        VIDEO_CODEC_VP8,
        VIDEO_CODEC_VP9,
        VIDEO_CODEC_H264,
        VIDEO_CODEC_H265,
        VIDEO_CODEC_AV1;

        static VideoCodecType fromNativeIndex(int nativeIndex) {
            return values()[nativeIndex];
        }
    }

    static {
        MediaCodecProperties mediaCodecProperties = new MediaCodecProperties("OMX.", 23, BitrateAdjustmentType.NO_ADJUSTMENT);
        defaultVp9HwProperties = mediaCodecProperties;
        vp9HwList = new MediaCodecProperties[]{qcomVp9HwProperties, exynosVp9HwProperties, mediaCodecProperties};
        vp9HwCodecBlacklist = new String[]{"OMX.google."};
        qcomH264HwProperties = new MediaCodecProperties("OMX.qcom.", 19, BitrateAdjustmentType.NO_ADJUSTMENT);
        exynosH264HwProperties = new MediaCodecProperties("OMX.Exynos.", 21, BitrateAdjustmentType.FRAMERATE_ADJUSTMENT);
        mediatekH264HwProperties = new MediaCodecProperties("OMX.MTK.", 27, BitrateAdjustmentType.FRAMERATE_ADJUSTMENT);
        defaultH264HwProperties = new MediaCodecProperties("OMX.", 19, BitrateAdjustmentType.NO_ADJUSTMENT);
        h264HwCodecBlacklist = new String[]{"OMX.google."};
        MediaCodecProperties mediaCodecProperties2 = new MediaCodecProperties("OMX.Exynos.", 23, BitrateAdjustmentType.FRAMERATE_ADJUSTMENT);
        exynosH264HighProfileHwProperties = mediaCodecProperties2;
        h264HighProfileHwList = new MediaCodecProperties[]{mediaCodecProperties2, defaultH264HwProperties};
        MediaCodecProperties mediaCodecProperties3 = new MediaCodecProperties("OMX.qcom.", 19, BitrateAdjustmentType.NO_ADJUSTMENT);
        qcomH265HwProperties = mediaCodecProperties3;
        h265HwList = new MediaCodecProperties[]{mediaCodecProperties3};
        h265HwCodecBlacklist = new String[]{"OMX.google."};
        H264_HW_EXCEPTION_MODELS = new String[]{"SAMSUNG-SGH-I337", "Nexus 7", "Nexus 4"};
        supportedColorList = new int[]{19, 21, 2141391872, COLOR_QCOM_FORMATYUV420PackedSemiPlanar32m};
        supportedSurfaceColorList = new int[]{2130708361};
    }

    public enum H264Profile {
        CONSTRAINED_BASELINE(0),
        BASELINE(1),
        MAIN(2),
        CONSTRAINED_HIGH(3),
        HIGH(4);

        private final int value;

        H264Profile(int value) {
            this.value = value;
        }

        public int getValue() {
            return this.value;
        }
    }

    private static class MediaCodecProperties {
        public final BitrateAdjustmentType bitrateAdjustmentType;
        public final String codecPrefix;
        public final int minSdk;

        MediaCodecProperties(String codecPrefix, int minSdk, BitrateAdjustmentType bitrateAdjustmentType) {
            this.codecPrefix = codecPrefix;
            this.minSdk = minSdk;
            this.bitrateAdjustmentType = bitrateAdjustmentType;
        }
    }

    public static void setEglContext(EglBase.Context eglContext) {
        if (staticEglBase != null) {
            Logging.w(TAG, "Egl context already set.");
            staticEglBase.release();
        }
        staticEglBase = EglBase.create(eglContext);
    }

    public static void disposeEglContext() {
        EglBase eglBase = staticEglBase;
        if (eglBase != null) {
            eglBase.release();
            staticEglBase = null;
        }
    }

    @Nullable
    static EglBase.Context getEglContext() {
        EglBase eglBase = staticEglBase;
        if (eglBase == null) {
            return null;
        }
        return eglBase.getEglBaseContext();
    }

    private static MediaCodecProperties[] vp8HwList() {
        ArrayList<MediaCodecProperties> supported_codecs = new ArrayList<>();
        supported_codecs.add(qcomVp8HwProperties);
        supported_codecs.add(exynosVp8HwProperties);
        if (PeerConnectionFactory.fieldTrialsFindFullName("WebRTC-IntelVP8").equals(PeerConnectionFactory.TRIAL_ENABLED)) {
            supported_codecs.add(intelVp8HwProperties);
        }
        supported_codecs.add(defaultVp8HwProperties);
        return (MediaCodecProperties[]) supported_codecs.toArray(new MediaCodecProperties[supported_codecs.size()]);
    }

    private static final MediaCodecProperties[] h264HwList() {
        ArrayList<MediaCodecProperties> supported_codecs = new ArrayList<>();
        supported_codecs.add(qcomH264HwProperties);
        supported_codecs.add(exynosH264HwProperties);
        if (PeerConnectionFactory.fieldTrialsFindFullName("WebRTC-MediaTekH264").equals(PeerConnectionFactory.TRIAL_ENABLED)) {
            supported_codecs.add(mediatekH264HwProperties);
        }
        supported_codecs.add(defaultH264HwProperties);
        return (MediaCodecProperties[]) supported_codecs.toArray(new MediaCodecProperties[supported_codecs.size()]);
    }

    public static void setErrorCallback(MediaCodecVideoEncoderErrorCallback errorCallback2) {
        Logging.d(TAG, "Set error callback");
        errorCallback = errorCallback2;
    }

    public static void disableVp8HwCodec() {
        Logging.w(TAG, "VP8 encoding is disabled by application.");
        hwEncoderDisabledTypes.add("video/x-vnd.on2.vp8");
    }

    public static void disableVp9HwCodec() {
        Logging.w(TAG, "VP9 encoding is disabled by application.");
        hwEncoderDisabledTypes.add("video/x-vnd.on2.vp9");
    }

    public static void disableH264HwCodec() {
        Logging.w(TAG, "H.264 encoding is disabled by application.");
        hwEncoderDisabledTypes.add("video/avc");
    }

    public static boolean isVp8HwSupported() {
        return (hwEncoderDisabledTypes.contains("video/x-vnd.on2.vp8") || findHwEncoder("video/x-vnd.on2.vp8", vp8HwList(), supportedColorList) == null) ? false : true;
    }

    @Nullable
    public static EncoderProperties vp8HwEncoderProperties() {
        if (hwEncoderDisabledTypes.contains("video/x-vnd.on2.vp8")) {
            return null;
        }
        return findHwEncoder("video/x-vnd.on2.vp8", vp8HwList(), supportedColorList);
    }

    public static boolean isVp9HwSupported() {
        return (hwEncoderDisabledTypes.contains("video/x-vnd.on2.vp9") || findHwEncoder("video/x-vnd.on2.vp9", vp9HwList, supportedColorList) == null) ? false : true;
    }

    public static boolean isH264HwSupported() {
        return (hwEncoderDisabledTypes.contains("video/avc") || findHwEncoder("video/avc", h264HwList(), supportedColorList) == null) ? false : true;
    }

    public static boolean isH264HighProfileHwSupported() {
        return (hwEncoderDisabledTypes.contains("video/avc") || findHwEncoder("video/avc", h264HighProfileHwList, supportedColorList) == null) ? false : true;
    }

    public static boolean isVp8HwSupportedUsingTextures() {
        return (hwEncoderDisabledTypes.contains("video/x-vnd.on2.vp8") || findHwEncoder("video/x-vnd.on2.vp8", vp8HwList(), supportedSurfaceColorList) == null) ? false : true;
    }

    public static boolean isVp9HwSupportedUsingTextures() {
        return (hwEncoderDisabledTypes.contains("video/x-vnd.on2.vp9") || findHwEncoder("video/x-vnd.on2.vp9", vp9HwList, supportedSurfaceColorList) == null) ? false : true;
    }

    public static boolean isH264HwSupportedUsingTextures() {
        return (hwEncoderDisabledTypes.contains("video/avc") || findHwEncoder("video/avc", h264HwList(), supportedSurfaceColorList) == null) ? false : true;
    }

    public static class EncoderProperties {
        public final BitrateAdjustmentType bitrateAdjustmentType;
        public final String codecName;
        public final int colorFormat;

        public EncoderProperties(String codecName, int colorFormat, BitrateAdjustmentType bitrateAdjustmentType) {
            this.codecName = codecName;
            this.colorFormat = colorFormat;
            this.bitrateAdjustmentType = bitrateAdjustmentType;
        }
    }

    private static boolean isBlacklisted(String codecName, String mime) {
        String[] blacklist;
        if (mime.equals("video/x-vnd.on2.vp8")) {
            blacklist = vp8HwCodecBlacklist;
        } else if (mime.equals("video/x-vnd.on2.vp9")) {
            blacklist = vp9HwCodecBlacklist;
        } else if (mime.equals("video/avc")) {
            blacklist = h264HwCodecBlacklist;
        } else {
            if (!mime.equals("video/hevc")) {
                return false;
            }
            blacklist = h265HwCodecBlacklist;
        }
        for (String blacklistedCodec : blacklist) {
            if (codecName.startsWith(blacklistedCodec)) {
                return true;
            }
        }
        return false;
    }

    private static EncoderProperties findHwEncoder(String mime, MediaCodecProperties[] supportedHwCodecProperties, int[] colorList) {
        String name;
        BitrateAdjustmentType bitrateAdjustmentType;
        boolean supportedCodec;
        if (Build.VERSION.SDK_INT < 19) {
            return null;
        }
        if (mime.equals("video/avc")) {
            List<String> exceptionModels = Arrays.asList(H264_HW_EXCEPTION_MODELS);
            if (exceptionModels.contains(Build.MODEL)) {
                Logging.w(TAG, "Model: " + Build.MODEL + " has black listed H.264 encoder.");
                return null;
            }
        }
        for (int i = 0; i < MediaCodecList.getCodecCount(); i++) {
            MediaCodecInfo info = null;
            try {
                info = MediaCodecList.getCodecInfoAt(i);
            } catch (IllegalArgumentException e) {
                Logging.e(TAG, "Cannot retrieve encoder codec info", e);
            }
            if (info != null && info.isEncoder()) {
                String[] supportedTypes = info.getSupportedTypes();
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
                        String name2 = info.getName();
                        Logging.d(TAG, "Found codec name: " + name2);
                        name = name2;
                        break;
                    }
                }
                if (name != null && !isBlacklisted(name, mime)) {
                    Logging.v(TAG, "Found candidate encoder " + name);
                    BitrateAdjustmentType bitrateAdjustmentType2 = BitrateAdjustmentType.NO_ADJUSTMENT;
                    int length2 = supportedHwCodecProperties.length;
                    int i3 = 0;
                    while (true) {
                        if (i3 >= length2) {
                            bitrateAdjustmentType = bitrateAdjustmentType2;
                            supportedCodec = false;
                            break;
                        }
                        MediaCodecProperties codecProperties = supportedHwCodecProperties[i3];
                        if (name.startsWith(codecProperties.codecPrefix)) {
                            if (Build.VERSION.SDK_INT < codecProperties.minSdk) {
                                Logging.w(TAG, "Codec " + name + " is disabled due to SDK version " + Build.VERSION.SDK_INT);
                            } else {
                                if (codecProperties.bitrateAdjustmentType != BitrateAdjustmentType.NO_ADJUSTMENT) {
                                    bitrateAdjustmentType2 = codecProperties.bitrateAdjustmentType;
                                    Logging.w(TAG, "Codec " + name + " requires bitrate adjustment: " + bitrateAdjustmentType2);
                                }
                                bitrateAdjustmentType = bitrateAdjustmentType2;
                                supportedCodec = true;
                            }
                        }
                        i3++;
                    }
                    if (supportedCodec) {
                        try {
                            MediaCodecInfo.CodecCapabilities capabilities = info.getCapabilitiesForType(mime);
                            for (int colorFormat : capabilities.colorFormats) {
                                Logging.v(TAG, "   Color: 0x" + Integer.toHexString(colorFormat));
                            }
                            for (int supportedColorFormat : colorList) {
                                int[] iArr = capabilities.colorFormats;
                                int length3 = iArr.length;
                                int i4 = 0;
                                while (i4 < length3) {
                                    MediaCodecInfo.CodecCapabilities capabilities2 = capabilities;
                                    int codecColorFormat = iArr[i4];
                                    if (codecColorFormat != supportedColorFormat) {
                                        i4++;
                                        capabilities = capabilities2;
                                    } else {
                                        Logging.d(TAG, "Found target encoder for mime " + mime + " : " + name + ". Color: 0x" + Integer.toHexString(codecColorFormat) + ". Bitrate adjustment: " + bitrateAdjustmentType);
                                        return new EncoderProperties(name, codecColorFormat, bitrateAdjustmentType);
                                    }
                                }
                            }
                        } catch (IllegalArgumentException e2) {
                            Logging.e(TAG, "Cannot retrieve encoder capabilities", e2);
                        }
                    } else {
                        continue;
                    }
                }
            }
        }
        return null;
    }

    MediaCodecVideoEncoder() {
    }

    private void checkOnMediaCodecThread() {
        if (this.mediaCodecThread.getId() != Thread.currentThread().getId()) {
            throw new RuntimeException("MediaCodecVideoEncoder previously operated on " + this.mediaCodecThread + " but is now called on " + Thread.currentThread());
        }
    }

    public static void printStackTrace() {
        Thread thread;
        MediaCodecVideoEncoder mediaCodecVideoEncoder = runningInstance;
        if (mediaCodecVideoEncoder != null && (thread = mediaCodecVideoEncoder.mediaCodecThread) != null) {
            StackTraceElement[] mediaCodecStackTraces = thread.getStackTrace();
            if (mediaCodecStackTraces.length > 0) {
                Logging.d(TAG, "MediaCodecVideoEncoder stacks trace:");
                for (StackTraceElement stackTrace : mediaCodecStackTraces) {
                    Logging.d(TAG, stackTrace.toString());
                }
            }
        }
    }

    @Nullable
    static MediaCodec createByCodecName(String codecName) {
        try {
            return MediaCodec.createByCodecName(codecName);
        } catch (Exception e) {
            return null;
        }
    }

    boolean initEncode(VideoCodecType type, int profile, int width, int height, int kbps, int fps, boolean useSurface) {
        String mime;
        EncoderProperties properties;
        int keyFrameIntervalSec;
        int fps2;
        Logging.d(TAG, "Java initEncode: " + type + ". Profile: " + profile + " : " + width + " x " + height + ". @ " + kbps + " kbps. Fps: " + fps + ". Encode from texture : " + useSurface);
        this.profile = profile;
        this.width = width;
        this.height = height;
        if (this.mediaCodecThread != null) {
            throw new RuntimeException("Forgot to release()?");
        }
        boolean configureH264HighProfile = false;
        if (type == VideoCodecType.VIDEO_CODEC_VP8) {
            mime = "video/x-vnd.on2.vp8";
            properties = findHwEncoder("video/x-vnd.on2.vp8", vp8HwList(), useSurface ? supportedSurfaceColorList : supportedColorList);
            keyFrameIntervalSec = 100;
        } else if (type == VideoCodecType.VIDEO_CODEC_VP9) {
            mime = "video/x-vnd.on2.vp9";
            properties = findHwEncoder("video/x-vnd.on2.vp9", vp9HwList, useSurface ? supportedSurfaceColorList : supportedColorList);
            keyFrameIntervalSec = 100;
        } else if (type == VideoCodecType.VIDEO_CODEC_H264) {
            mime = "video/avc";
            properties = findHwEncoder("video/avc", h264HwList(), useSurface ? supportedSurfaceColorList : supportedColorList);
            if (profile == H264Profile.CONSTRAINED_HIGH.getValue()) {
                EncoderProperties h264HighProfileProperties = findHwEncoder("video/avc", h264HighProfileHwList, useSurface ? supportedSurfaceColorList : supportedColorList);
                if (h264HighProfileProperties != null) {
                    Logging.d(TAG, "High profile H.264 encoder supported.");
                    configureH264HighProfile = true;
                } else {
                    Logging.d(TAG, "High profile H.264 encoder requested, but not supported. Use baseline.");
                }
            }
            keyFrameIntervalSec = 20;
        } else if (type == VideoCodecType.VIDEO_CODEC_H265) {
            mime = "video/hevc";
            properties = findHwEncoder("video/hevc", h265HwList, useSurface ? supportedSurfaceColorList : supportedColorList);
            keyFrameIntervalSec = 20;
        } else {
            throw new RuntimeException("initEncode: Non-supported codec " + type);
        }
        if (properties == null) {
            throw new RuntimeException("Can not find HW encoder for " + type);
        }
        runningInstance = this;
        this.colorFormat = properties.colorFormat;
        BitrateAdjustmentType bitrateAdjustmentType = properties.bitrateAdjustmentType;
        this.bitrateAdjustmentType = bitrateAdjustmentType;
        if (bitrateAdjustmentType == BitrateAdjustmentType.FRAMERATE_ADJUSTMENT) {
            fps2 = 30;
        } else {
            fps2 = Math.min(fps, 30);
        }
        this.forcedKeyFrameMs = 0L;
        this.lastKeyFrameMs = -1L;
        if (type == VideoCodecType.VIDEO_CODEC_VP8 && properties.codecName.startsWith(qcomVp8HwProperties.codecPrefix)) {
            if (Build.VERSION.SDK_INT == 21 || Build.VERSION.SDK_INT == 22) {
                this.forcedKeyFrameMs = 15000L;
            } else if (Build.VERSION.SDK_INT == 23) {
                this.forcedKeyFrameMs = QCOM_VP8_KEY_FRAME_INTERVAL_ANDROID_M_MS;
            } else if (Build.VERSION.SDK_INT > 23) {
                this.forcedKeyFrameMs = 15000L;
            }
        }
        Logging.d(TAG, "Color format: " + this.colorFormat + ". Bitrate adjustment: " + this.bitrateAdjustmentType + ". Key frame interval: " + this.forcedKeyFrameMs + " . Initial fps: " + fps2);
        int i = kbps * 1000;
        this.targetBitrateBps = i;
        this.targetFps = fps2;
        this.bitrateAccumulatorMax = ((double) i) / 8.0d;
        this.bitrateAccumulator = FirebaseRemoteConfig.DEFAULT_VALUE_FOR_DOUBLE;
        this.bitrateObservationTimeMs = FirebaseRemoteConfig.DEFAULT_VALUE_FOR_DOUBLE;
        this.bitrateAdjustmentScaleExp = 0;
        this.mediaCodecThread = Thread.currentThread();
        try {
            MediaFormat format = MediaFormat.createVideoFormat(mime, width, height);
            format.setInteger("bitrate", this.targetBitrateBps);
            format.setInteger("bitrate-mode", 2);
            format.setInteger("color-format", properties.colorFormat);
            format.setInteger("frame-rate", this.targetFps);
            format.setInteger("i-frame-interval", keyFrameIntervalSec);
            if (configureH264HighProfile) {
                format.setInteger(Scopes.PROFILE, 8);
                format.setInteger("level", 256);
            }
            Logging.d(TAG, "  Format: " + format);
            MediaCodec mediaCodecCreateByCodecName = createByCodecName(properties.codecName);
            this.mediaCodec = mediaCodecCreateByCodecName;
            try {
                this.type = type;
                if (mediaCodecCreateByCodecName == null) {
                    Logging.e(TAG, "Can not create media encoder");
                    release();
                    return false;
                }
                mediaCodecCreateByCodecName.configure(format, (Surface) null, (MediaCrypto) null, 1);
                if (useSurface) {
                    this.eglBase = new EglBase14((EglBase14.Context) getEglContext(), EglBase.CONFIG_RECORDABLE);
                    Surface surfaceCreateInputSurface = this.mediaCodec.createInputSurface();
                    this.inputSurface = surfaceCreateInputSurface;
                    this.eglBase.createSurface(surfaceCreateInputSurface);
                    this.drawer = new GlRectDrawer();
                }
                this.mediaCodec.start();
                this.outputBuffers = this.mediaCodec.getOutputBuffers();
                Logging.d(TAG, "Output buffers: " + this.outputBuffers.length);
                return true;
            } catch (IllegalStateException e) {
                e = e;
                Logging.e(TAG, "initEncode failed", e);
                release();
                return false;
            }
        } catch (IllegalStateException e2) {
            e = e2;
        }
    }

    ByteBuffer[] getInputBuffers() {
        ByteBuffer[] inputBuffers = this.mediaCodec.getInputBuffers();
        Logging.d(TAG, "Input buffers: " + inputBuffers.length);
        return inputBuffers;
    }

    void checkKeyFrameRequired(boolean requestedKeyFrame, long presentationTimestampUs) {
        long presentationTimestampMs = (500 + presentationTimestampUs) / 1000;
        if (this.lastKeyFrameMs < 0) {
            this.lastKeyFrameMs = presentationTimestampMs;
        }
        boolean forcedKeyFrame = false;
        if (!requestedKeyFrame) {
            long j = this.forcedKeyFrameMs;
            if (j > 0 && presentationTimestampMs > this.lastKeyFrameMs + j) {
                forcedKeyFrame = true;
            }
        }
        if (requestedKeyFrame || forcedKeyFrame) {
            if (requestedKeyFrame) {
                Logging.d(TAG, "Sync frame request");
            } else {
                Logging.d(TAG, "Sync frame forced");
            }
            Bundle b = new Bundle();
            b.putInt("request-sync", 0);
            this.mediaCodec.setParameters(b);
            this.lastKeyFrameMs = presentationTimestampMs;
        }
    }

    boolean encodeBuffer(boolean isKeyframe, int inputBuffer, int size, long presentationTimestampUs) {
        checkOnMediaCodecThread();
        try {
            checkKeyFrameRequired(isKeyframe, presentationTimestampUs);
            this.mediaCodec.queueInputBuffer(inputBuffer, 0, size, presentationTimestampUs, 0);
            return true;
        } catch (IllegalStateException e) {
            Logging.e(TAG, "encodeBuffer failed", e);
            return false;
        }
    }

    boolean encodeFrame(long nativeEncoder, boolean isKeyframe, VideoFrame frame, int bufferIndex, long presentationTimestampUs) {
        checkOnMediaCodecThread();
        try {
            checkKeyFrameRequired(isKeyframe, presentationTimestampUs);
            VideoFrame.Buffer buffer = frame.getBuffer();
            if (buffer instanceof VideoFrame.TextureBuffer) {
                VideoFrame.TextureBuffer textureBuffer = (VideoFrame.TextureBuffer) buffer;
                this.eglBase.makeCurrent();
                GLES20.glClear(16384);
                VideoFrameDrawer.drawTexture(this.drawer, textureBuffer, new Matrix(), this.width, this.height, 0, 0, this.width, this.height);
                this.eglBase.swapBuffers(TimeUnit.MICROSECONDS.toNanos(presentationTimestampUs));
            } else {
                VideoFrame.I420Buffer i420Buffer = buffer.toI420();
                int chromaHeight = (this.height + 1) / 2;
                ByteBuffer dataY = i420Buffer.getDataY();
                ByteBuffer dataU = i420Buffer.getDataU();
                ByteBuffer dataV = i420Buffer.getDataV();
                int strideY = i420Buffer.getStrideY();
                int strideU = i420Buffer.getStrideU();
                int strideV = i420Buffer.getStrideV();
                if (dataY.capacity() < this.height * strideY) {
                    throw new RuntimeException("Y-plane buffer size too small.");
                }
                if (dataU.capacity() < strideU * chromaHeight) {
                    throw new RuntimeException("U-plane buffer size too small.");
                }
                if (dataV.capacity() < strideV * chromaHeight) {
                    throw new RuntimeException("V-plane buffer size too small.");
                }
                nativeFillInputBuffer(nativeEncoder, bufferIndex, dataY, strideY, dataU, strideU, dataV, strideV);
                i420Buffer.release();
                int yuvSize = ((this.width * this.height) * 3) / 2;
                this.mediaCodec.queueInputBuffer(bufferIndex, 0, yuvSize, presentationTimestampUs, 0);
            }
            return true;
        } catch (RuntimeException e) {
            Logging.e(TAG, "encodeFrame failed", e);
            return false;
        }
    }

    void release() {
        Logging.d(TAG, "Java releaseEncoder");
        checkOnMediaCodecThread();
        final C1CaughtException caughtException = new C1CaughtException();
        boolean stopHung = false;
        if (this.mediaCodec != null) {
            final CountDownLatch releaseDone = new CountDownLatch(1);
            Runnable runMediaCodecRelease = new Runnable() { // from class: org.webrtc.mozi.MediaCodecVideoEncoder.1
                @Override // java.lang.Runnable
                public void run() {
                    Logging.d(MediaCodecVideoEncoder.TAG, "Java releaseEncoder on release thread");
                    try {
                        MediaCodecVideoEncoder.this.mediaCodec.stop();
                    } catch (Exception e) {
                        Logging.e(MediaCodecVideoEncoder.TAG, "Media encoder stop failed", e);
                    }
                    try {
                        MediaCodecVideoEncoder.this.mediaCodec.release();
                    } catch (Exception e2) {
                        Logging.e(MediaCodecVideoEncoder.TAG, "Media encoder release failed", e2);
                        caughtException.e = e2;
                    }
                    Logging.d(MediaCodecVideoEncoder.TAG, "Java releaseEncoder on release thread done");
                    releaseDone.countDown();
                }
            };
            new Thread(runMediaCodecRelease).start();
            if (!ThreadUtils.awaitUninterruptibly(releaseDone, DefaultRenderersFactory.DEFAULT_ALLOWED_VIDEO_JOINING_TIME_MS)) {
                Logging.e(TAG, "Media encoder release timeout");
                stopHung = true;
            }
            this.mediaCodec = null;
        }
        this.mediaCodecThread = null;
        GlRectDrawer glRectDrawer = this.drawer;
        if (glRectDrawer != null) {
            glRectDrawer.release();
            this.drawer = null;
        }
        EglBase14 eglBase14 = this.eglBase;
        if (eglBase14 != null) {
            eglBase14.release();
            this.eglBase = null;
        }
        Surface surface = this.inputSurface;
        if (surface != null) {
            surface.release();
            this.inputSurface = null;
        }
        runningInstance = null;
        if (stopHung) {
            codecErrors++;
            if (errorCallback != null) {
                Logging.e(TAG, "Invoke codec error callback. Errors: " + codecErrors);
                errorCallback.onMediaCodecVideoEncoderCriticalError(codecErrors);
            }
            throw new RuntimeException("Media encoder release timeout.");
        }
        if (caughtException.e == null) {
            Logging.d(TAG, "Java releaseEncoder done");
        } else {
            RuntimeException runtimeException = new RuntimeException(caughtException.e);
            runtimeException.setStackTrace(ThreadUtils.concatStackTraces(caughtException.e.getStackTrace(), runtimeException.getStackTrace()));
            throw runtimeException;
        }
    }

    /* JADX INFO: renamed from: org.webrtc.mozi.MediaCodecVideoEncoder$1CaughtException, reason: invalid class name */
    class C1CaughtException {
        Exception e;

        C1CaughtException() {
        }
    }

    private boolean setRates(int kbps, int frameRate) {
        int i;
        checkOnMediaCodecThread();
        int codecBitrateBps = kbps * 1000;
        if (this.bitrateAdjustmentType == BitrateAdjustmentType.DYNAMIC_ADJUSTMENT) {
            this.bitrateAccumulatorMax = ((double) codecBitrateBps) / 8.0d;
            int i2 = this.targetBitrateBps;
            if (i2 > 0 && codecBitrateBps < i2) {
                this.bitrateAccumulator = (this.bitrateAccumulator * ((double) codecBitrateBps)) / ((double) i2);
            }
        }
        this.targetBitrateBps = codecBitrateBps;
        this.targetFps = frameRate;
        if (this.bitrateAdjustmentType == BitrateAdjustmentType.FRAMERATE_ADJUSTMENT && (i = this.targetFps) > 0) {
            codecBitrateBps = (this.targetBitrateBps * 30) / i;
            Logging.v(TAG, "setRates: " + kbps + " -> " + (codecBitrateBps / 1000) + " kbps. Fps: " + this.targetFps);
        } else if (this.bitrateAdjustmentType == BitrateAdjustmentType.DYNAMIC_ADJUSTMENT) {
            Logging.v(TAG, "setRates: " + kbps + " kbps. Fps: " + this.targetFps + ". ExpScale: " + this.bitrateAdjustmentScaleExp);
            int i3 = this.bitrateAdjustmentScaleExp;
            if (i3 != 0) {
                codecBitrateBps = (int) (((double) codecBitrateBps) * getBitrateScale(i3));
            }
        } else {
            Logging.v(TAG, "setRates: " + kbps + " kbps. Fps: " + this.targetFps);
        }
        try {
            Bundle params = new Bundle();
            params.putInt("video-bitrate", codecBitrateBps);
            this.mediaCodec.setParameters(params);
            return true;
        } catch (IllegalStateException e) {
            Logging.e(TAG, "setRates failed", e);
            return false;
        }
    }

    int dequeueInputBuffer() {
        checkOnMediaCodecThread();
        try {
            return this.mediaCodec.dequeueInputBuffer(0L);
        } catch (IllegalStateException e) {
            Logging.e(TAG, "dequeueIntputBuffer failed", e);
            return -2;
        }
    }

    static class OutputBufferInfo {
        public final ByteBuffer buffer;
        public final int index;
        public final boolean isKeyFrame;
        public final long presentationTimestampUs;

        public OutputBufferInfo(int index, ByteBuffer buffer, boolean isKeyFrame, long presentationTimestampUs) {
            this.index = index;
            this.buffer = buffer;
            this.isKeyFrame = isKeyFrame;
            this.presentationTimestampUs = presentationTimestampUs;
        }

        int getIndex() {
            return this.index;
        }

        ByteBuffer getBuffer() {
            return this.buffer;
        }

        boolean isKeyFrame() {
            return this.isKeyFrame;
        }

        long getPresentationTimestampUs() {
            return this.presentationTimestampUs;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:17:0x00a9  */
    @javax.annotation.Nullable
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    org.webrtc.mozi.MediaCodecVideoEncoder.OutputBufferInfo dequeueOutputBuffer() {
        /*
            Method dump skipped, instruction units count: 401
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: org.webrtc.mozi.MediaCodecVideoEncoder.dequeueOutputBuffer():org.webrtc.mozi.MediaCodecVideoEncoder$OutputBufferInfo");
    }

    private double getBitrateScale(int bitrateAdjustmentScaleExp) {
        return Math.pow(BITRATE_CORRECTION_MAX_SCALE, ((double) bitrateAdjustmentScaleExp) / 20.0d);
    }

    private void reportEncodedFrame(int size) {
        if (this.targetFps != 0 && this.bitrateAdjustmentType == BitrateAdjustmentType.DYNAMIC_ADJUSTMENT) {
            double d = this.targetBitrateBps;
            int i = this.targetFps;
            double expectedBytesPerFrame = d / (((double) i) * 8.0d);
            double d2 = this.bitrateAccumulator + (((double) size) - expectedBytesPerFrame);
            this.bitrateAccumulator = d2;
            this.bitrateObservationTimeMs += 1000.0d / ((double) i);
            double bitrateAccumulatorCap = this.bitrateAccumulatorMax * BITRATE_CORRECTION_SEC;
            double dMin = Math.min(d2, bitrateAccumulatorCap);
            this.bitrateAccumulator = dMin;
            this.bitrateAccumulator = Math.max(dMin, -bitrateAccumulatorCap);
            if (this.bitrateObservationTimeMs > 3000.0d) {
                Logging.d(TAG, "Acc: " + ((int) this.bitrateAccumulator) + ". Max: " + ((int) this.bitrateAccumulatorMax) + ". ExpScale: " + this.bitrateAdjustmentScaleExp);
                boolean bitrateAdjustmentScaleChanged = false;
                double d3 = this.bitrateAccumulator;
                double d4 = this.bitrateAccumulatorMax;
                if (d3 > d4) {
                    int bitrateAdjustmentInc = (int) ((d3 / d4) + 0.5d);
                    this.bitrateAdjustmentScaleExp -= bitrateAdjustmentInc;
                    this.bitrateAccumulator = d4;
                    bitrateAdjustmentScaleChanged = true;
                } else if (d3 < (-d4)) {
                    int bitrateAdjustmentInc2 = (int) (((-d3) / d4) + 0.5d);
                    this.bitrateAdjustmentScaleExp += bitrateAdjustmentInc2;
                    this.bitrateAccumulator = -d4;
                    bitrateAdjustmentScaleChanged = true;
                }
                if (bitrateAdjustmentScaleChanged) {
                    int iMin = Math.min(this.bitrateAdjustmentScaleExp, 20);
                    this.bitrateAdjustmentScaleExp = iMin;
                    this.bitrateAdjustmentScaleExp = Math.max(iMin, -20);
                    Logging.d(TAG, "Adjusting bitrate scale to " + this.bitrateAdjustmentScaleExp + ". Value: " + getBitrateScale(this.bitrateAdjustmentScaleExp));
                    setRates(this.targetBitrateBps / 1000, this.targetFps);
                }
                this.bitrateObservationTimeMs = FirebaseRemoteConfig.DEFAULT_VALUE_FOR_DOUBLE;
            }
        }
    }

    boolean releaseOutputBuffer(int index) {
        checkOnMediaCodecThread();
        try {
            this.mediaCodec.releaseOutputBuffer(index, false);
            return true;
        } catch (IllegalStateException e) {
            Logging.e(TAG, "releaseOutputBuffer failed", e);
            return false;
        }
    }

    int getColorFormat() {
        return this.colorFormat;
    }

    static boolean isTextureBuffer(VideoFrame.Buffer buffer) {
        return buffer instanceof VideoFrame.TextureBuffer;
    }
}
