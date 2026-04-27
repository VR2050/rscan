package org.webrtc.mozi;

import android.media.MediaCodec;
import android.media.MediaCodecInfo;
import android.media.MediaCodecList;
import android.media.MediaCrypto;
import android.media.MediaFormat;
import android.os.Build;
import android.os.SystemClock;
import android.view.Surface;
import com.google.android.exoplayer2.DefaultRenderersFactory;
import java.nio.ByteBuffer;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import javax.annotation.Nullable;
import org.webrtc.mozi.EglBase;
import org.webrtc.mozi.VideoFrame;

/* JADX INFO: loaded from: classes3.dex */
@Deprecated
public class MediaCodecVideoDecoder {
    private static final String AV1_MIME_TYPE = "video/av1";
    private static final int DEQUEUE_INPUT_TIMEOUT = 500000;
    private static final String FORMAT_KEY_CROP_BOTTOM = "crop-bottom";
    private static final String FORMAT_KEY_CROP_LEFT = "crop-left";
    private static final String FORMAT_KEY_CROP_RIGHT = "crop-right";
    private static final String FORMAT_KEY_CROP_TOP = "crop-top";
    private static final String FORMAT_KEY_SLICE_HEIGHT = "slice-height";
    private static final String FORMAT_KEY_STRIDE = "stride";
    private static final String H264_MIME_TYPE = "video/avc";
    private static final String H265_MIME_TYPE = "video/hevc";
    private static final long MAX_DECODE_TIME_MS = 200;
    private static final int MAX_QUEUED_OUTPUTBUFFERS = 3;
    private static final int MEDIA_CODEC_RELEASE_TIMEOUT_MS = 5000;
    private static final String TAG = "MediaCodecVideoDecoder";
    private static final String VP8_MIME_TYPE = "video/x-vnd.on2.vp8";
    private static final String VP9_MIME_TYPE = "video/x-vnd.on2.vp9";

    @Nullable
    private static EglBase eglBase = null;
    private static final String supportedMediaTekH264HighProfileHwCodecPrefix = "OMX.MTK.";
    private int colorFormat;
    private int droppedFrames;
    private boolean hasDecodedFirstFrame;
    private int height;
    private ByteBuffer[] inputBuffers;

    @Nullable
    private MediaCodec mediaCodec;

    @Nullable
    private Thread mediaCodecThread;
    private ByteBuffer[] outputBuffers;
    private int sliceHeight;
    private int stride;

    @Nullable
    private TextureListener textureListener;
    private int width;

    @Nullable
    private static MediaCodecVideoDecoder runningInstance = null;

    @Nullable
    private static MediaCodecVideoDecoderErrorCallback errorCallback = null;
    private static int codecErrors = 0;
    private static Set<String> hwDecoderDisabledTypes = new HashSet();
    private static String[] vp8HwCodecBlacklist = {"OMX.google."};
    private static final String supportedQcomH264HighProfileHwCodecPrefix = "OMX.qcom.";
    private static final String supportedExynosH264HighProfileHwCodecPrefix = "OMX.Exynos.";
    private static final String[] supportedVp9HwCodecPrefixes = {supportedQcomH264HighProfileHwCodecPrefix, supportedExynosH264HighProfileHwCodecPrefix, "OMX."};
    private static String[] vp9HwCodecBlacklist = {"OMX.google."};
    private static String[] h264HwCodecBlacklist = {"OMX.google."};
    private static final String[] supportedH265HwCodecPrefixes = {"OMX."};
    private static String[] h265HwCodecBlacklist = {"OMX.google."};
    private static final int COLOR_QCOM_FORMATYVU420PackedSemiPlanar32m4ka = 2141391873;
    private static final int COLOR_QCOM_FORMATYVU420PackedSemiPlanar16m4ka = 2141391874;
    private static final int COLOR_QCOM_FORMATYVU420PackedSemiPlanar64x32Tile2m8ka = 2141391875;
    private static final int COLOR_QCOM_FORMATYUV420PackedSemiPlanar32m = 2141391876;
    private static final List<Integer> supportedColorList = Arrays.asList(19, 21, 2141391872, Integer.valueOf(COLOR_QCOM_FORMATYVU420PackedSemiPlanar32m4ka), Integer.valueOf(COLOR_QCOM_FORMATYVU420PackedSemiPlanar16m4ka), Integer.valueOf(COLOR_QCOM_FORMATYVU420PackedSemiPlanar64x32Tile2m8ka), Integer.valueOf(COLOR_QCOM_FORMATYUV420PackedSemiPlanar32m));
    private final Queue<TimeStamps> decodeStartTimeMs = new ArrayDeque();

    @Nullable
    private Surface surface = null;
    private final Queue<DecodedOutputBuffer> dequeuedSurfaceOutputBuffers = new ArrayDeque();

    public interface MediaCodecVideoDecoderErrorCallback {
        void onMediaCodecVideoDecoderCriticalError(int i);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static native long nativeCreateDecoder(String str, boolean z);

    public static VideoDecoderFactory createFactory() {
        return new DefaultVideoDecoderFactory(0L, new HwDecoderFactory());
    }

    static class HwDecoderFactory implements VideoDecoderFactory {
        private final VideoCodecInfo[] supportedHardwareCodecs = getSupportedHardwareCodecs();

        HwDecoderFactory() {
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
            if (MediaCodecVideoDecoder.isVp8HwSupported()) {
                Logging.d(MediaCodecVideoDecoder.TAG, "VP8 HW Decoder supported.");
                codecs.add(new VideoCodecInfo("VP8", new HashMap()));
            }
            if (MediaCodecVideoDecoder.isVp9HwSupported()) {
                Logging.d(MediaCodecVideoDecoder.TAG, "VP9 HW Decoder supported.");
                codecs.add(new VideoCodecInfo("VP9", new HashMap()));
            }
            if (MediaCodecVideoDecoder.isH264HighProfileHwSupported()) {
                Logging.d(MediaCodecVideoDecoder.TAG, "H.264 High Profile HW Decoder supported.");
                codecs.add(H264Utils.DEFAULT_H264_HIGH_PROFILE_CODEC);
            }
            if (MediaCodecVideoDecoder.isH264HwSupported()) {
                Logging.d(MediaCodecVideoDecoder.TAG, "H.264 HW Decoder supported.");
                codecs.add(H264Utils.DEFAULT_H264_BASELINE_PROFILE_CODEC);
            }
            return (VideoCodecInfo[]) codecs.toArray(new VideoCodecInfo[codecs.size()]);
        }

        @Override // org.webrtc.mozi.VideoDecoderFactory
        public VideoCodecInfo[] getSupportedCodecs() {
            return this.supportedHardwareCodecs;
        }

        @Override // org.webrtc.mozi.VideoDecoderFactory
        @Nullable
        @Deprecated
        public VideoDecoder createDecoder(String codecType) {
            throw new UnsupportedOperationException("Deprecated and not implemented.");
        }

        @Override // org.webrtc.mozi.VideoDecoderFactory
        @Nullable
        public VideoDecoder createDecoder(final VideoCodecInfo codec) {
            if (!isCodecSupported(this.supportedHardwareCodecs, codec)) {
                Logging.d(MediaCodecVideoDecoder.TAG, "No HW video decoder for codec " + codec.name);
                return null;
            }
            Logging.d(MediaCodecVideoDecoder.TAG, "Create HW video decoder for " + codec.name);
            return new WrappedNativeVideoDecoder() { // from class: org.webrtc.mozi.MediaCodecVideoDecoder.HwDecoderFactory.1
                @Override // org.webrtc.mozi.WrappedNativeVideoDecoder, org.webrtc.mozi.VideoDecoder
                public long createNativeVideoDecoder() {
                    return MediaCodecVideoDecoder.nativeCreateDecoder(codec.name, MediaCodecVideoDecoder.useSurface());
                }
            };
        }

        @Override // org.webrtc.mozi.VideoDecoderFactory
        public void setDynamicDecodePixelsThreshold(int pixelsThreshold) {
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

    private static final String[] supportedVp8HwCodecPrefixes() {
        ArrayList<String> supportedPrefixes = new ArrayList<>();
        supportedPrefixes.add(supportedQcomH264HighProfileHwCodecPrefix);
        supportedPrefixes.add("OMX.Nvidia.");
        supportedPrefixes.add(supportedExynosH264HighProfileHwCodecPrefix);
        supportedPrefixes.add("OMX.Intel.");
        if (PeerConnectionFactory.fieldTrialsFindFullName("WebRTC-MediaTekVP8").equals(PeerConnectionFactory.TRIAL_ENABLED) && Build.VERSION.SDK_INT >= 24) {
            supportedPrefixes.add(supportedMediaTekH264HighProfileHwCodecPrefix);
        }
        supportedPrefixes.add("OMX.");
        return (String[]) supportedPrefixes.toArray(new String[supportedPrefixes.size()]);
    }

    private static final String[] supportedH264HwCodecPrefixes() {
        ArrayList<String> supportedPrefixes = new ArrayList<>();
        supportedPrefixes.add(supportedQcomH264HighProfileHwCodecPrefix);
        supportedPrefixes.add("OMX.Intel.");
        supportedPrefixes.add(supportedExynosH264HighProfileHwCodecPrefix);
        if (PeerConnectionFactory.fieldTrialsFindFullName("WebRTC-MediaTekH264").equals(PeerConnectionFactory.TRIAL_ENABLED) && Build.VERSION.SDK_INT >= 27) {
            supportedPrefixes.add(supportedMediaTekH264HighProfileHwCodecPrefix);
        }
        supportedPrefixes.add("OMX.");
        return (String[]) supportedPrefixes.toArray(new String[supportedPrefixes.size()]);
    }

    public static void setEglContext(EglBase.Context eglContext) {
        if (eglBase != null) {
            Logging.w(TAG, "Egl context already set.");
            eglBase.release();
        }
        eglBase = EglBase.create(eglContext);
    }

    public static void disposeEglContext() {
        EglBase eglBase2 = eglBase;
        if (eglBase2 != null) {
            eglBase2.release();
            eglBase = null;
        }
    }

    static boolean useSurface() {
        return eglBase != null;
    }

    public static void setErrorCallback(MediaCodecVideoDecoderErrorCallback errorCallback2) {
        Logging.d(TAG, "Set error callback");
        errorCallback = errorCallback2;
    }

    public static void disableVp8HwCodec() {
        Logging.w(TAG, "VP8 decoding is disabled by application.");
        hwDecoderDisabledTypes.add("video/x-vnd.on2.vp8");
    }

    public static void disableVp9HwCodec() {
        Logging.w(TAG, "VP9 decoding is disabled by application.");
        hwDecoderDisabledTypes.add("video/x-vnd.on2.vp9");
    }

    public static void disableH264HwCodec() {
        Logging.w(TAG, "H.264 decoding is disabled by application.");
        hwDecoderDisabledTypes.add("video/avc");
    }

    public static void disableH265HwCodec() {
        Logging.w(TAG, "H.265 decoding is disabled by application.");
        hwDecoderDisabledTypes.add("video/hevc");
    }

    public static boolean isVp8HwSupported() {
        return (hwDecoderDisabledTypes.contains("video/x-vnd.on2.vp8") || findDecoder("video/x-vnd.on2.vp8", supportedVp8HwCodecPrefixes()) == null) ? false : true;
    }

    public static boolean isVp9HwSupported() {
        return (hwDecoderDisabledTypes.contains("video/x-vnd.on2.vp9") || findDecoder("video/x-vnd.on2.vp9", supportedVp9HwCodecPrefixes) == null) ? false : true;
    }

    public static boolean isH264HwSupported() {
        return (hwDecoderDisabledTypes.contains("video/avc") || findDecoder("video/avc", supportedH264HwCodecPrefixes()) == null) ? false : true;
    }

    public static boolean isH264HighProfileHwSupported() {
        if (hwDecoderDisabledTypes.contains("video/avc")) {
            return false;
        }
        if (Build.VERSION.SDK_INT >= 21 && findDecoder("video/avc", new String[]{supportedQcomH264HighProfileHwCodecPrefix}) != null) {
            return true;
        }
        if (Build.VERSION.SDK_INT < 23 || findDecoder("video/avc", new String[]{supportedExynosH264HighProfileHwCodecPrefix}) == null) {
            return PeerConnectionFactory.fieldTrialsFindFullName("WebRTC-MediaTekH264").equals(PeerConnectionFactory.TRIAL_ENABLED) && Build.VERSION.SDK_INT >= 27 && findDecoder("video/avc", new String[]{supportedMediaTekH264HighProfileHwCodecPrefix}) != null;
        }
        return true;
    }

    public static void printStackTrace() {
        Thread thread;
        MediaCodecVideoDecoder mediaCodecVideoDecoder = runningInstance;
        if (mediaCodecVideoDecoder != null && (thread = mediaCodecVideoDecoder.mediaCodecThread) != null) {
            StackTraceElement[] mediaCodecStackTraces = thread.getStackTrace();
            if (mediaCodecStackTraces.length > 0) {
                Logging.d(TAG, "MediaCodecVideoDecoder stacks trace:");
                for (StackTraceElement stackTrace : mediaCodecStackTraces) {
                    Logging.d(TAG, stackTrace.toString());
                }
            }
        }
    }

    private static class DecoderProperties {
        public final String codecName;
        public final int colorFormat;

        public DecoderProperties(String codecName, int colorFormat) {
            this.codecName = codecName;
            this.colorFormat = colorFormat;
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

    @Nullable
    private static DecoderProperties findDecoder(String mime, String[] supportedCodecPrefixes) {
        if (Build.VERSION.SDK_INT < 19) {
            return null;
        }
        Logging.d(TAG, "Trying to find HW decoder for mime " + mime);
        for (int i = 0; i < MediaCodecList.getCodecCount(); i++) {
            MediaCodecInfo info = null;
            try {
                info = MediaCodecList.getCodecInfoAt(i);
            } catch (IllegalArgumentException e) {
                Logging.e(TAG, "Cannot retrieve decoder codec info", e);
            }
            if (info != null && !info.isEncoder()) {
                String name = null;
                String[] supportedTypes = info.getSupportedTypes();
                int length = supportedTypes.length;
                int i2 = 0;
                while (true) {
                    if (i2 >= length) {
                        break;
                    }
                    String mimeType = supportedTypes[i2];
                    if (!mimeType.equals(mime)) {
                        i2++;
                    } else {
                        name = info.getName();
                        break;
                    }
                }
                if (name != null && !isBlacklisted(name, mime)) {
                    Logging.d(TAG, "Found candidate decoder " + name);
                    boolean supportedCodec = false;
                    int length2 = supportedCodecPrefixes.length;
                    int i3 = 0;
                    while (true) {
                        if (i3 >= length2) {
                            break;
                        }
                        String codecPrefix = supportedCodecPrefixes[i3];
                        if (!name.startsWith(codecPrefix)) {
                            i3++;
                        } else {
                            supportedCodec = true;
                            break;
                        }
                    }
                    if (supportedCodec) {
                        try {
                            MediaCodecInfo.CodecCapabilities capabilities = info.getCapabilitiesForType(mime);
                            for (int colorFormat : capabilities.colorFormats) {
                                Logging.v(TAG, "   Color: 0x" + Integer.toHexString(colorFormat));
                            }
                            Iterator<Integer> it = supportedColorList.iterator();
                            while (it.hasNext()) {
                                int supportedColorFormat = it.next().intValue();
                                for (int codecColorFormat : capabilities.colorFormats) {
                                    if (codecColorFormat == supportedColorFormat) {
                                        Logging.d(TAG, "Found target decoder " + name + ". Color: 0x" + Integer.toHexString(codecColorFormat));
                                        return new DecoderProperties(name, codecColorFormat);
                                    }
                                }
                            }
                        } catch (IllegalArgumentException e2) {
                            Logging.e(TAG, "Cannot retrieve decoder capabilities", e2);
                        }
                    } else {
                        continue;
                    }
                }
            }
        }
        Logging.d(TAG, "No HW decoder found for mime " + mime);
        return null;
    }

    MediaCodecVideoDecoder() {
    }

    private void checkOnMediaCodecThread() throws IllegalStateException {
        if (this.mediaCodecThread.getId() != Thread.currentThread().getId()) {
            throw new IllegalStateException("MediaCodecVideoDecoder previously operated on " + this.mediaCodecThread + " but is now called on " + Thread.currentThread());
        }
    }

    private boolean initDecode(VideoCodecType type, int width, int height) {
        String mime;
        String[] supportedCodecPrefixes;
        SurfaceTextureHelper surfaceTextureHelper;
        if (this.mediaCodecThread != null) {
            throw new RuntimeException("initDecode: Forgot to release()?");
        }
        if (type == VideoCodecType.VIDEO_CODEC_VP8) {
            mime = "video/x-vnd.on2.vp8";
            supportedCodecPrefixes = supportedVp8HwCodecPrefixes();
        } else if (type == VideoCodecType.VIDEO_CODEC_VP9) {
            mime = "video/x-vnd.on2.vp9";
            supportedCodecPrefixes = supportedVp9HwCodecPrefixes;
        } else if (type == VideoCodecType.VIDEO_CODEC_H264) {
            mime = "video/avc";
            supportedCodecPrefixes = supportedH264HwCodecPrefixes();
        } else if (type == VideoCodecType.VIDEO_CODEC_H265) {
            mime = "video/hevc";
            supportedCodecPrefixes = supportedH265HwCodecPrefixes;
        } else {
            throw new RuntimeException("initDecode: Non-supported codec " + type);
        }
        DecoderProperties properties = findDecoder(mime, supportedCodecPrefixes);
        if (properties == null) {
            throw new RuntimeException("Cannot find HW decoder for " + type);
        }
        Logging.d(TAG, "Java initDecode: " + type + " : " + width + " x " + height + ". Color: 0x" + Integer.toHexString(properties.colorFormat) + ". Use Surface: " + useSurface());
        runningInstance = this;
        this.mediaCodecThread = Thread.currentThread();
        try {
            this.width = width;
            this.height = height;
            this.stride = width;
            this.sliceHeight = height;
            if (useSurface() && (surfaceTextureHelper = SurfaceTextureHelper.create("Decoder SurfaceTextureHelper", eglBase.getEglBaseContext(), 0L)) != null) {
                TextureListener textureListener = new TextureListener(surfaceTextureHelper);
                this.textureListener = textureListener;
                textureListener.setSize(width, height);
                this.surface = new Surface(surfaceTextureHelper.getSurfaceTexture());
            }
            MediaFormat format = MediaFormat.createVideoFormat(mime, width, height);
            if (!useSurface()) {
                format.setInteger("color-format", properties.colorFormat);
            }
            Logging.d(TAG, "  Format: " + format);
            MediaCodec mediaCodecCreateByCodecName = MediaCodecVideoEncoder.createByCodecName(properties.codecName);
            this.mediaCodec = mediaCodecCreateByCodecName;
            if (mediaCodecCreateByCodecName == null) {
                Logging.e(TAG, "Can not create media decoder");
                return false;
            }
            mediaCodecCreateByCodecName.configure(format, this.surface, (MediaCrypto) null, 0);
            this.mediaCodec.start();
            this.colorFormat = properties.colorFormat;
            this.outputBuffers = this.mediaCodec.getOutputBuffers();
            this.inputBuffers = this.mediaCodec.getInputBuffers();
            this.decodeStartTimeMs.clear();
            this.hasDecodedFirstFrame = false;
            this.dequeuedSurfaceOutputBuffers.clear();
            this.droppedFrames = 0;
            Logging.d(TAG, "Input buffers: " + this.inputBuffers.length + ". Output buffers: " + this.outputBuffers.length);
            return true;
        } catch (IllegalStateException e) {
            Logging.e(TAG, "initDecode failed", e);
            return false;
        }
    }

    private void reset(int width, int height) {
        if (this.mediaCodecThread == null || this.mediaCodec == null) {
            throw new RuntimeException("Incorrect reset call for non-initialized decoder.");
        }
        Logging.d(TAG, "Java reset: " + width + " x " + height);
        this.mediaCodec.flush();
        this.width = width;
        this.height = height;
        TextureListener textureListener = this.textureListener;
        if (textureListener != null) {
            textureListener.setSize(width, height);
        }
        this.decodeStartTimeMs.clear();
        this.dequeuedSurfaceOutputBuffers.clear();
        this.hasDecodedFirstFrame = false;
        this.droppedFrames = 0;
    }

    private void release() {
        Logging.d(TAG, "Java releaseDecoder. Total number of dropped frames: " + this.droppedFrames);
        checkOnMediaCodecThread();
        final CountDownLatch releaseDone = new CountDownLatch(1);
        Runnable runMediaCodecRelease = new Runnable() { // from class: org.webrtc.mozi.MediaCodecVideoDecoder.1
            @Override // java.lang.Runnable
            public void run() {
                try {
                    Logging.d(MediaCodecVideoDecoder.TAG, "Java releaseDecoder on release thread");
                    MediaCodecVideoDecoder.this.mediaCodec.stop();
                    MediaCodecVideoDecoder.this.mediaCodec.release();
                    Logging.d(MediaCodecVideoDecoder.TAG, "Java releaseDecoder on release thread done");
                } catch (Exception e) {
                    Logging.e(MediaCodecVideoDecoder.TAG, "Media decoder release failed", e);
                }
                releaseDone.countDown();
            }
        };
        new Thread(runMediaCodecRelease).start();
        if (!ThreadUtils.awaitUninterruptibly(releaseDone, DefaultRenderersFactory.DEFAULT_ALLOWED_VIDEO_JOINING_TIME_MS)) {
            Logging.e(TAG, "Media decoder release timeout");
            codecErrors++;
            if (errorCallback != null) {
                Logging.e(TAG, "Invoke codec error callback. Errors: " + codecErrors);
                errorCallback.onMediaCodecVideoDecoderCriticalError(codecErrors);
            }
        }
        this.mediaCodec = null;
        this.mediaCodecThread = null;
        runningInstance = null;
        if (useSurface()) {
            this.surface.release();
            this.surface = null;
            this.textureListener.release();
        }
        Logging.d(TAG, "Java releaseDecoder done");
    }

    private int dequeueInputBuffer() {
        checkOnMediaCodecThread();
        try {
            return this.mediaCodec.dequeueInputBuffer(500000L);
        } catch (IllegalStateException e) {
            Logging.e(TAG, "dequeueIntputBuffer failed", e);
            return -2;
        }
    }

    private boolean queueInputBuffer(int inputBufferIndex, int size, long presentationTimeStamUs, long timeStampMs, long ntpTimeStamp) {
        checkOnMediaCodecThread();
        try {
            this.inputBuffers[inputBufferIndex].position(0);
            try {
                this.inputBuffers[inputBufferIndex].limit(size);
                this.decodeStartTimeMs.add(new TimeStamps(SystemClock.elapsedRealtime(), timeStampMs, ntpTimeStamp));
                this.mediaCodec.queueInputBuffer(inputBufferIndex, 0, size, presentationTimeStamUs, 0);
                return true;
            } catch (IllegalStateException e) {
                e = e;
                Logging.e(TAG, "decode failed", e);
                return false;
            }
        } catch (IllegalStateException e2) {
            e = e2;
        }
    }

    private static class TimeStamps {
        private final long decodeStartTimeMs;
        private final long ntpTimeStampMs;
        private final long timeStampMs;

        public TimeStamps(long decodeStartTimeMs, long timeStampMs, long ntpTimeStampMs) {
            this.decodeStartTimeMs = decodeStartTimeMs;
            this.timeStampMs = timeStampMs;
            this.ntpTimeStampMs = ntpTimeStampMs;
        }
    }

    private static class DecodedOutputBuffer {
        private final long decodeTimeMs;
        private final long endDecodeTimeMs;
        private final int index;
        private final long ntpTimeStampMs;
        private final int offset;
        private final long presentationTimeStampMs;
        private final int size;
        private final long timeStampMs;

        public DecodedOutputBuffer(int index, int offset, int size, long presentationTimeStampMs, long timeStampMs, long ntpTimeStampMs, long decodeTime, long endDecodeTime) {
            this.index = index;
            this.offset = offset;
            this.size = size;
            this.presentationTimeStampMs = presentationTimeStampMs;
            this.timeStampMs = timeStampMs;
            this.ntpTimeStampMs = ntpTimeStampMs;
            this.decodeTimeMs = decodeTime;
            this.endDecodeTimeMs = endDecodeTime;
        }

        int getIndex() {
            return this.index;
        }

        int getOffset() {
            return this.offset;
        }

        int getSize() {
            return this.size;
        }

        long getPresentationTimestampMs() {
            return this.presentationTimeStampMs;
        }

        long getTimestampMs() {
            return this.timeStampMs;
        }

        long getNtpTimestampMs() {
            return this.ntpTimeStampMs;
        }

        long getDecodeTimeMs() {
            return this.decodeTimeMs;
        }
    }

    private static class DecodedTextureBuffer {
        private final long decodeTimeMs;
        private final long frameDelayMs;
        private final long ntpTimeStampMs;
        private final long presentationTimeStampMs;
        private final long timeStampMs;
        private final VideoFrame.Buffer videoFrameBuffer;

        public DecodedTextureBuffer(VideoFrame.Buffer videoFrameBuffer, long presentationTimeStampMs, long timeStampMs, long ntpTimeStampMs, long decodeTimeMs, long frameDelay) {
            this.videoFrameBuffer = videoFrameBuffer;
            this.presentationTimeStampMs = presentationTimeStampMs;
            this.timeStampMs = timeStampMs;
            this.ntpTimeStampMs = ntpTimeStampMs;
            this.decodeTimeMs = decodeTimeMs;
            this.frameDelayMs = frameDelay;
        }

        VideoFrame.Buffer getVideoFrameBuffer() {
            return this.videoFrameBuffer;
        }

        long getPresentationTimestampMs() {
            return this.presentationTimeStampMs;
        }

        long getTimeStampMs() {
            return this.timeStampMs;
        }

        long getNtpTimestampMs() {
            return this.ntpTimeStampMs;
        }

        long getDecodeTimeMs() {
            return this.decodeTimeMs;
        }

        long getFrameDelayMs() {
            return this.frameDelayMs;
        }
    }

    private class TextureListener implements VideoSink {

        @Nullable
        private DecodedOutputBuffer bufferToRender;
        private final Object newFrameLock = new Object();

        @Nullable
        private DecodedTextureBuffer renderedBuffer;
        private final SurfaceTextureHelper surfaceTextureHelper;

        public TextureListener(SurfaceTextureHelper surfaceTextureHelper) {
            this.surfaceTextureHelper = surfaceTextureHelper;
            surfaceTextureHelper.startListening(this);
        }

        public void addBufferToRender(DecodedOutputBuffer buffer) {
            if (this.bufferToRender != null) {
                Logging.e(MediaCodecVideoDecoder.TAG, "Unexpected addBufferToRender() called while waiting for a texture.");
                throw new IllegalStateException("Waiting for a texture.");
            }
            this.bufferToRender = buffer;
        }

        public boolean isWaitingForTexture() {
            boolean z;
            synchronized (this.newFrameLock) {
                z = this.bufferToRender != null;
            }
            return z;
        }

        public void setSize(int width, int height) {
            this.surfaceTextureHelper.setTextureSize(width, height);
        }

        @Override // org.webrtc.mozi.VideoSink
        public void onFrame(VideoFrame frame) {
            synchronized (this.newFrameLock) {
                if (this.renderedBuffer != null) {
                    Logging.e(MediaCodecVideoDecoder.TAG, "Unexpected onFrame() called while already holding a texture.");
                    throw new IllegalStateException("Already holding a texture.");
                }
                VideoFrame.Buffer buffer = frame.getBuffer();
                buffer.retain();
                this.renderedBuffer = new DecodedTextureBuffer(buffer, this.bufferToRender.presentationTimeStampMs, this.bufferToRender.timeStampMs, this.bufferToRender.ntpTimeStampMs, this.bufferToRender.decodeTimeMs, SystemClock.elapsedRealtime() - this.bufferToRender.endDecodeTimeMs);
                this.bufferToRender = null;
                this.newFrameLock.notifyAll();
            }
        }

        @Nullable
        public DecodedTextureBuffer dequeueTextureBuffer(int timeoutMs) {
            DecodedTextureBuffer returnedBuffer;
            synchronized (this.newFrameLock) {
                if (this.renderedBuffer == null && timeoutMs > 0 && isWaitingForTexture()) {
                    try {
                        this.newFrameLock.wait(timeoutMs);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                    returnedBuffer = this.renderedBuffer;
                    this.renderedBuffer = null;
                } else {
                    returnedBuffer = this.renderedBuffer;
                    this.renderedBuffer = null;
                }
            }
            return returnedBuffer;
        }

        public void release() {
            this.surfaceTextureHelper.stopListening();
            synchronized (this.newFrameLock) {
                if (this.renderedBuffer != null) {
                    this.renderedBuffer.getVideoFrameBuffer().release();
                    this.renderedBuffer = null;
                }
            }
            this.surfaceTextureHelper.dispose();
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:37:0x013a, code lost:
    
        throw new java.lang.RuntimeException("Unexpected size change. Configured " + r23.width + "*" + r23.height + ". New " + r9 + "*" + r5);
     */
    @javax.annotation.Nullable
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private org.webrtc.mozi.MediaCodecVideoDecoder.DecodedOutputBuffer dequeueOutputBuffer(int r24) {
        /*
            Method dump skipped, instruction units count: 538
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: org.webrtc.mozi.MediaCodecVideoDecoder.dequeueOutputBuffer(int):org.webrtc.mozi.MediaCodecVideoDecoder$DecodedOutputBuffer");
    }

    @Nullable
    private DecodedTextureBuffer dequeueTextureBuffer(int dequeueTimeoutMs) {
        checkOnMediaCodecThread();
        if (!useSurface()) {
            throw new IllegalStateException("dequeueTexture() called for byte buffer decoding.");
        }
        DecodedOutputBuffer outputBuffer = dequeueOutputBuffer(dequeueTimeoutMs);
        if (outputBuffer != null) {
            this.dequeuedSurfaceOutputBuffers.add(outputBuffer);
        }
        MaybeRenderDecodedTextureBuffer();
        DecodedTextureBuffer renderedBuffer = this.textureListener.dequeueTextureBuffer(dequeueTimeoutMs);
        if (renderedBuffer != null) {
            MaybeRenderDecodedTextureBuffer();
            return renderedBuffer;
        }
        if (this.dequeuedSurfaceOutputBuffers.size() >= Math.min(3, this.outputBuffers.length) || (dequeueTimeoutMs > 0 && !this.dequeuedSurfaceOutputBuffers.isEmpty())) {
            this.droppedFrames++;
            DecodedOutputBuffer droppedFrame = this.dequeuedSurfaceOutputBuffers.remove();
            if (dequeueTimeoutMs > 0) {
                Logging.w(TAG, "Draining decoder. Dropping frame with TS: " + droppedFrame.presentationTimeStampMs + ". Total number of dropped frames: " + this.droppedFrames);
            } else {
                Logging.w(TAG, "Too many output buffers " + this.dequeuedSurfaceOutputBuffers.size() + ". Dropping frame with TS: " + droppedFrame.presentationTimeStampMs + ". Total number of dropped frames: " + this.droppedFrames);
            }
            this.mediaCodec.releaseOutputBuffer(droppedFrame.index, false);
            return new DecodedTextureBuffer(null, droppedFrame.presentationTimeStampMs, droppedFrame.timeStampMs, droppedFrame.ntpTimeStampMs, droppedFrame.decodeTimeMs, SystemClock.elapsedRealtime() - droppedFrame.endDecodeTimeMs);
        }
        return null;
    }

    private void MaybeRenderDecodedTextureBuffer() {
        if (this.dequeuedSurfaceOutputBuffers.isEmpty() || this.textureListener.isWaitingForTexture()) {
            return;
        }
        DecodedOutputBuffer buffer = this.dequeuedSurfaceOutputBuffers.remove();
        this.textureListener.addBufferToRender(buffer);
        this.mediaCodec.releaseOutputBuffer(buffer.index, true);
    }

    private void returnDecodedOutputBuffer(int index) throws IllegalStateException {
        checkOnMediaCodecThread();
        if (useSurface()) {
            throw new IllegalStateException("returnDecodedOutputBuffer() called for surface decoding.");
        }
        this.mediaCodec.releaseOutputBuffer(index, false);
    }

    ByteBuffer[] getInputBuffers() {
        return this.inputBuffers;
    }

    ByteBuffer[] getOutputBuffers() {
        return this.outputBuffers;
    }

    int getColorFormat() {
        return this.colorFormat;
    }

    int getWidth() {
        return this.width;
    }

    int getHeight() {
        return this.height;
    }

    int getStride() {
        return this.stride;
    }

    int getSliceHeight() {
        return this.sliceHeight;
    }
}
