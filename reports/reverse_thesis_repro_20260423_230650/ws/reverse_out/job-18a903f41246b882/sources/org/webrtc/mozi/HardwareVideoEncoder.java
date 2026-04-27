package org.webrtc.mozi;

import android.media.MediaCodec;
import android.media.MediaCodecInfo;
import android.media.MediaCodecList;
import android.opengl.GLES20;
import android.os.Build;
import android.os.Bundle;
import android.os.SystemClock;
import android.text.TextUtils;
import android.view.Surface;
import com.google.android.exoplayer2.DefaultRenderersFactory;
import com.zhy.http.okhttp.OkHttpUtils;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.BlockingDeque;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantLock;
import javax.annotation.Nullable;
import org.webrtc.mozi.EglBase14;
import org.webrtc.mozi.EncodedImage;
import org.webrtc.mozi.MediaCodecUtils;
import org.webrtc.mozi.ThreadUtils;
import org.webrtc.mozi.VideoEncoder;
import org.webrtc.mozi.VideoFrame;
import org.webrtc.mozi.video.grayconfig.MediaCodecGrayConfig;

/* JADX INFO: loaded from: classes3.dex */
class HardwareVideoEncoder implements VideoEncoder {
    private static final int DEQUEUE_OUTPUT_BUFFER_TIMEOUT_US = 100000;
    private static final String KEY_BITRATE_MODE = "bitrate-mode";
    private static final int MAX_ENCODER_Q_SIZE = 2;
    private static final int MAX_ENCODER_Q_SIZE_ENLARGE = 5;
    private static final int MAX_VIDEO_FRAMERATE = 30;
    private static final int MEDIA_CODEC_RELEASE_TIMEOUT_MS = 5000;
    private static final String TAG = "codec HardwareVideoEncoder";
    private static final int VIDEO_AVC_LEVEL_3 = 256;
    private static final int VIDEO_AVC_LEVEL_41 = 4096;
    private static final int VIDEO_AVC_PROFILE_BASELINE = 1;
    private static final int VIDEO_AVC_PROFILE_CONSTRAINED_BASELINE = 65536;
    private static final int VIDEO_AVC_PROFILE_CONSTRAINED_HIGH = 524288;
    private static final int VIDEO_AVC_PROFILE_HIGH = 8;
    private static final int VIDEO_AVC_PROFILE_UNKNOWN = -1;
    private static final int VIDEO_ControlRateConstant = 2;
    private static final int WAIT_TIME_WHILE_IDLE_MS = 50;
    private int alignment;
    private TextureAlignmentDrawer alignmentDrawer;
    private boolean automaticResizeOn;
    private VideoEncoder.Callback callback;
    private final String codecName;
    private final VideoCodecType codecType;
    private final McsConfigHelper configHelper;
    private String defaultH264Level;
    private ArrayList<EncoderEssential> encoderEssentials;
    private int encoderMaxQueueSize;
    private final long forcedKeyFrameNs;
    private ArrayList<FpsKeeper> fpsKeepers;
    private final int keyFrameIntervalSec;
    private MediaCodecGrayConfig mcGrayConfig;
    private final MediaCodecWrapperFactory mediaCodecWrapperFactory;
    private int mode;
    HardwareVideoEncoderFactory myFactory;

    @Nullable
    private Thread outputThread;
    private Thread outputThreadLabel;
    private final Map<String, String> params;
    private final EglBase14.Context sharedContext;
    private final Integer surfaceColorFormat;
    private final Integer yuvColorFormat;
    private final YuvFormat yuvFormat;
    private final GlRectDrawer textureDrawer = new GlRectDrawer();
    private final VideoFrameDrawer videoFrameDrawer = new VideoFrameDrawer();
    private final ThreadUtils.ThreadChecker encodeThreadChecker = new ThreadUtils.ThreadChecker();
    private final ThreadUtils.ThreadChecker outputThreadChecker = new ThreadUtils.ThreadChecker();
    private final Object callbackLock = new Object();
    private boolean new_fashion_simulcast_control = false;
    private boolean bFrameForceSoftware = false;
    private boolean bFrameForceBaseline = false;
    private final int B_SLICE_TYPE_1 = 1;
    private final int B_SLICE_TYPE_6 = 6;
    private final int LEFT_DEQUES = 2;
    private MediaCodecUtils.CodecExtraProperties encoderProperties = null;
    private volatile boolean running = false;

    @Nullable
    private volatile Exception shutdownException = null;

    private class EncoderEssential {
        private BitrateAdjuster bitrateAdjuster;

        @Nullable
        private MediaCodecWrapper codec;
        private HardwareVideoEncoder encoder_obj;
        private int height;
        private int index;
        private int origWidth;

        @Nullable
        private EglBase14 textureEglBase;

        @Nullable
        private Surface textureInputSurface;
        private int width;
        private boolean sending = false;
        private int left_deque = 2;
        private int maxFramerate = 0;
        private int minFramerate = 0;
        private int profile = -1;
        private boolean useSurfaceMode = false;
        private int adjustedBitrate = 0;
        private int originTargetBitrate = 0;

        @Nullable
        private ByteBuffer configBuffer = null;
        private final BlockingDeque<EncodedImage.Builder> outputBuilders = new LinkedBlockingDeque();
        private long lastKeyFrameNs = -1;
        private int dequeueFailCount = 0;
        private boolean dequeueFail = false;
        private boolean pendingKeyFrameReq = false;
        private boolean selfGenerateKeyFrame = false;
        private final ReentrantLock lock = new ReentrantLock(true);
        private final int STATS_INTERVAL_MS = 10000;
        private AtomicLong framesReceived = new AtomicLong(0);
        private AtomicLong framesQueued = new AtomicLong(0);
        private AtomicLong framesDropped = new AtomicLong(0);
        private volatile long lastFramesDropped = -1;
        private int currentBytes = 0;
        private long framesEncoded = 0;
        private int currentFramesEncoded = 0;
        private long statsStartTimeMs = 0;

        static /* synthetic */ int access$2510(EncoderEssential x0) {
            int i = x0.left_deque;
            x0.left_deque = i - 1;
            return i;
        }

        static /* synthetic */ long access$3204(EncoderEssential x0) {
            long j = x0.framesEncoded + 1;
            x0.framesEncoded = j;
            return j;
        }

        static /* synthetic */ int access$3304(EncoderEssential x0) {
            int i = x0.currentFramesEncoded + 1;
            x0.currentFramesEncoded = i;
            return i;
        }

        static /* synthetic */ int access$3408(EncoderEssential x0) {
            int i = x0.dequeueFailCount;
            x0.dequeueFailCount = i + 1;
            return i;
        }

        public EncoderEssential(int width, int height, int origWidth, int index, HardwareVideoEncoder obj) {
            this.index = 0;
            this.width = 0;
            this.height = 0;
            this.origWidth = 0;
            this.width = width;
            this.height = height;
            this.origWidth = origWidth;
            this.index = index;
            this.encoder_obj = obj;
        }

        public boolean seems(VideoEncoder.LayerSetting layer) {
            return this.width == layer.width && this.height == layer.height;
        }

        public void resetVariables() {
            this.statsStartTimeMs = SystemClock.elapsedRealtime();
            this.framesReceived.set(0L);
            this.framesQueued.set(0L);
            this.framesDropped.set(0L);
            this.lastFramesDropped = -1L;
            this.currentBytes = 0;
            this.framesEncoded = 0L;
            this.currentFramesEncoded = 0;
        }

        public void logStats(boolean logImmediately) {
            long interval_ms = SystemClock.elapsedRealtime() - this.statsStartTimeMs;
            if (interval_ms > OkHttpUtils.DEFAULT_MILLISECONDS || logImmediately) {
                int encodedFps = interval_ms > 0 ? (int) (((long) (this.currentFramesEncoded * 1000)) / interval_ms) : 0;
                int kbps = interval_ms > 0 ? (int) (((long) (this.currentBytes * 8)) / interval_ms) : 0;
                Logging.d(HardwareVideoEncoder.TAG, "stats, frames received:" + this.framesReceived.get() + ", dropped:" + this.framesDropped.get() + ", queued:" + this.framesQueued.get() + ", encoded:" + this.framesEncoded + ", bitrate:" + kbps + "kbps, fps:" + encodedFps + " for last " + interval_ms + "ms, esse index:" + this.index + ", esse:" + this + ", HardwareVideoEncoder:" + this.encoder_obj);
                this.statsStartTimeMs = SystemClock.elapsedRealtime();
                this.currentFramesEncoded = 0;
                this.currentBytes = 0;
                long dropped = this.framesDropped.get();
                if (this.lastFramesDropped >= 0 && dropped - this.lastFramesDropped > 0) {
                    HardwareVideoEncoder.this.reportError(VideoCodecStatus.MC_ENC_ENCODE_STUCK, 0);
                }
                this.lastFramesDropped = dropped;
            }
        }
    }

    public HardwareVideoEncoder(McsConfigHelper configHelper, MediaCodecWrapperFactory mediaCodecWrapperFactory, String codecName, VideoCodecType codecType, Integer surfaceColorFormat, Integer yuvColorFormat, Map<String, String> params, int keyFrameIntervalSec, int forceKeyFrameIntervalMs, HardwareVideoEncoderFactory myFactory, EglBase14.Context sharedContext) {
        MediaCodecGrayConfig mediaCodecGrayConfig;
        this.alignmentDrawer = null;
        int i = 2;
        this.mcGrayConfig = null;
        this.alignment = 0;
        this.defaultH264Level = "1f";
        Logging.d(TAG, "HardwareVideoEncoder. codecName:" + codecName + " codecType:" + codecType + " surfaceColorFormat:" + surfaceColorFormat + " yuvColorFormat:" + yuvColorFormat + " keyFrameIntervalSec:" + keyFrameIntervalSec + " forceKeyFrameIntervalMs:" + forceKeyFrameIntervalMs + " sharedContext:" + sharedContext + ", this:" + this);
        this.configHelper = configHelper;
        this.mediaCodecWrapperFactory = mediaCodecWrapperFactory;
        this.codecName = codecName;
        this.codecType = codecType;
        this.surfaceColorFormat = surfaceColorFormat;
        this.yuvColorFormat = yuvColorFormat;
        this.yuvFormat = YuvFormat.valueOf(yuvColorFormat.intValue());
        this.params = params;
        this.keyFrameIntervalSec = keyFrameIntervalSec;
        this.forcedKeyFrameNs = TimeUnit.MILLISECONDS.toNanos((long) forceKeyFrameIntervalMs);
        this.sharedContext = sharedContext;
        this.myFactory = myFactory;
        if (configHelper.oneRTCNativeGrayConfigEnabled()) {
            this.mcGrayConfig = configHelper.getMediaCodecGrayConfig();
        }
        this.encoderEssentials = new ArrayList<>();
        this.fpsKeepers = new ArrayList<>();
        if (WebrtcGrayConfig.sEnlargeEncoderMaxQueueSize || ((mediaCodecGrayConfig = this.mcGrayConfig) != null && mediaCodecGrayConfig.enlargeEncoderMaxQueueSize)) {
            i = 5;
        }
        this.encoderMaxQueueSize = i;
        int encoderAlignment = configHelper.getVideoCodecConfig().getEncoderAlignment();
        this.alignment = encoderAlignment;
        if (encoderAlignment > 0) {
            TextureAlignmentDrawer textureAlignmentDrawer = new TextureAlignmentDrawer();
            this.alignmentDrawer = textureAlignmentDrawer;
            textureAlignmentDrawer.setConfigHelper(configHelper);
        }
        MediaCodecLevelConfig levelConfig = configHelper.getMediaCodecLevelConfig();
        if (levelConfig.enable()) {
            this.defaultH264Level = VideoCodecInfo.H264_LEVEL_4_1;
        }
        Logging.d(TAG, "encoder max queue size:" + this.encoderMaxQueueSize + ", alignment:" + this.alignment + ", defaultH264Level:" + this.defaultH264Level);
        this.encodeThreadChecker.detachThread();
    }

    @Override // org.webrtc.mozi.VideoEncoder
    public long createNativeVideoEncoder() {
        return 0L;
    }

    @Override // org.webrtc.mozi.VideoEncoder
    public boolean isHardwareEncoder() {
        return true;
    }

    @Override // org.webrtc.mozi.VideoEncoder
    public VideoCodecStatus initEncode(VideoEncoder.Settings settings, VideoEncoder.Callback callback) {
        this.encodeThreadChecker.checkIsOnValidThread();
        CodecMonitorHelper.encoderEvent(CodecMonitorHelper.EVENT_RUNTIME, CodecMonitorHelper.FORMAT_HW, CodecMonitorHelper.EVENT_INIT);
        this.callback = callback;
        this.automaticResizeOn = settings.automaticResizeOn;
        this.mode = settings.mode;
        this.fpsKeepers.clear();
        this.encoderEssentials.clear();
        for (int i = 0; i < settings.layers.length; i++) {
            VideoEncoder.LayerSetting layer = settings.layers[i];
            Logging.d(TAG, "initEncode, layer:" + layer.width + "x" + layer.height + ", br:" + layer.targetBitrate + ", fps:" + layer.maxFramerate + ", active:" + layer.active + ", this:" + this);
            int origWidth = layer.width;
            if (this.alignment > 0 && layer.width % this.alignment != 0) {
                int i2 = layer.width;
                int i3 = this.alignment;
                layer.width = (i2 + (i3 - 1)) & (~(i3 - 1));
                Logging.d(TAG, "initEncode, layer width has aligned to " + layer.width);
            }
            EncoderEssential esse = new EncoderEssential(layer.width, layer.height, origWidth, i, this);
            esse.bitrateAdjuster = this.myFactory.createBitrateAdjuster(this.codecType, this.codecName);
            esse.bitrateAdjuster.setTargets(layer.targetBitrate * 1000, layer.maxFramerate);
            esse.adjustedBitrate = esse.bitrateAdjuster.getAdjustedBitrateBps();
            esse.originTargetBitrate = layer.targetBitrate * 1000;
            esse.maxFramerate = layer.maxFramerate;
            esse.minFramerate = layer.minFramerate;
            esse.useSurfaceMode = canUseSurface();
            esse.lastKeyFrameNs = -1L;
            this.encoderEssentials.add(esse);
            FpsKeeper keeper = new FpsKeeper();
            keeper.SetTargetFps(layer.maxFramerate);
            this.fpsKeepers.add(keeper);
        }
        if (WebrtcGrayConfig.sHWCodecImprove) {
            this.encoderProperties = MediaCodecUtils.getCodecExtraProperties(this.codecName, this.codecType.mimeType(), true);
        }
        VideoCodecStatus result = initEncodeInternal();
        if (result == VideoCodecStatus.FALLBACK_SOFTWARE) {
            CodecMonitorHelper.encoderEvent(CodecMonitorHelper.EVENT_RUNTIME, CodecMonitorHelper.FORMAT_HW, "fallback");
        }
        return result;
    }

    @Nullable
    private MediaCodecInfo findCodecForType(String mime) {
        for (int i = 0; i < MediaCodecList.getCodecCount(); i++) {
            try {
                MediaCodecInfo info = null;
                try {
                    info = MediaCodecList.getCodecInfoAt(i);
                } catch (IllegalArgumentException e) {
                    Logging.e(TAG, "Cannot retrieve encoder codec info", e);
                }
                if (info != null && info.isEncoder()) {
                    String[] types = info.getSupportedTypes();
                    for (String str : types) {
                        if (str.equalsIgnoreCase(mime)) {
                            return info;
                        }
                    }
                }
            } catch (Throwable e2) {
                Logging.e(TAG, "findCodecForType exception", e2);
                return null;
            }
        }
        return null;
    }

    @Override // org.webrtc.mozi.VideoEncoder
    public String getProfileLevel() {
        String profileLevel = getSupportedHighProfileId();
        if (TextUtils.isEmpty(profileLevel)) {
            return VideoCodecInfo.H264_PROFILE_BASELINE + this.defaultH264Level;
        }
        return profileLevel;
    }

    private String getSupportedHighProfileId() {
        if (this.configHelper.getAndroidRoomsConfig().isRooms() && !McsHWDeviceHelper.getInstance().encoderSupportHighlineProfile()) {
            Logging.w(TAG, "high profile is not supported on rooms");
            return null;
        }
        MediaCodecInfo info = findCodecForType("video/avc");
        if (info != null) {
            MediaCodecInfo.CodecCapabilities caps = info.getCapabilitiesForType("video/avc");
            for (int i = 0; i < caps.profileLevels.length; i++) {
                Logging.d(TAG, "AVC encoder supported profile:" + caps.profileLevels[i].profile);
                if (caps.profileLevels[i].profile == 8) {
                    return VideoCodecInfo.H264_PROFILE_HIGH + this.defaultH264Level;
                }
                if (caps.profileLevels[i].profile == 524288) {
                    return "640c" + this.defaultH264Level;
                }
            }
        }
        Logging.w(TAG, "High profile is not supported on this device");
        return null;
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    /* JADX WARN: Removed duplicated region for block: B:57:0x01e6  */
    /* JADX WARN: Removed duplicated region for block: B:83:0x0251  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private org.webrtc.mozi.VideoCodecStatus setupEncoderInternal(org.webrtc.mozi.HardwareVideoEncoder.EncoderEssential r18) {
        /*
            Method dump skipped, instruction units count: 1090
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: org.webrtc.mozi.HardwareVideoEncoder.setupEncoderInternal(org.webrtc.mozi.HardwareVideoEncoder$EncoderEssential):org.webrtc.mozi.VideoCodecStatus");
    }

    private VideoCodecStatus initEncodeInternal() {
        this.encodeThreadChecker.checkIsOnValidThread();
        Logging.d(TAG, "initEncodeInternal start, this:" + this);
        VideoCodecStatus returnValue = VideoCodecStatus.OK;
        for (EncoderEssential esse : this.encoderEssentials) {
            returnValue = setupEncoderInternal(esse);
            if (returnValue.getNumber() < VideoCodecStatus.OK.getNumber()) {
                Logging.e(TAG, "initEncodeInternal error " + returnValue + ", this:" + this);
                return returnValue;
            }
        }
        this.running = true;
        this.outputThreadChecker.detachThread();
        Thread threadCreateOutputThread = createOutputThread();
        this.outputThread = threadCreateOutputThread;
        this.outputThreadLabel = threadCreateOutputThread;
        threadCreateOutputThread.start();
        Logging.d(TAG, "initEncodeInternal done, this:" + this);
        return returnValue;
    }

    private void releaseEgl(EncoderEssential esse) {
        Logging.d(TAG, "releaseEgl start, esse index:" + esse.index + ", this:" + this);
        if (esse.textureEglBase != null) {
            esse.textureEglBase.release();
            esse.textureEglBase = null;
        }
        if (esse.textureInputSurface != null) {
            esse.textureInputSurface.release();
            esse.textureInputSurface = null;
        }
        Logging.d(TAG, "releaseEgl end, esse index:" + esse.index + ", this:" + this);
    }

    private void releaseInternal(EncoderEssential esse) {
        Logging.d(TAG, "releaseInternal start, esse index:" + esse.index + ", this:" + this);
        esse.logStats(true);
        if (!WebrtcGrayConfig.sFixEglLeak) {
            if (esse.textureEglBase != null) {
                esse.textureEglBase.release();
                esse.textureEglBase = null;
            }
            if (esse.textureInputSurface != null) {
                esse.textureInputSurface.release();
                esse.textureInputSurface = null;
            }
        }
        esse.outputBuilders.clear();
        if (esse.codec != null) {
            esse.codec.release();
            if (!this.configHelper.getVideoCodecConfig().isFixMCCrashEnabled()) {
                esse.codec = null;
            }
            LeakMonitor.deallocate(LeakMonitorConstants.TYPE_CODEC, LeakMonitorConstants.ALLOCATION_ENCODE);
        }
        esse.configBuffer = null;
        Logging.d(TAG, "releaseInternal done, esse index:" + esse.index + ", this:" + this);
    }

    @Override // org.webrtc.mozi.VideoEncoder
    public VideoCodecStatus release() {
        VideoCodecStatus returnValue;
        this.encodeThreadChecker.checkIsOnValidThread();
        Logging.d(TAG, "release finally, this:" + this);
        if (this.outputThread == null) {
            Logging.d(TAG, "output thread is null, this:" + this);
            returnValue = VideoCodecStatus.OK;
        } else {
            this.running = false;
            this.outputThreadLabel = null;
            if (!ThreadUtils.joinUninterruptibly(this.outputThread, DefaultRenderersFactory.DEFAULT_ALLOWED_VIDEO_JOINING_TIME_MS)) {
                Logging.e(TAG, "Media encoder release timeout, this:" + this);
                VideoCodecStatus returnValue2 = VideoCodecStatus.TIMEOUT;
                reportError(VideoCodecStatus.MC_ENC_RELEASE_TIMEOUT, 0);
                returnValue = returnValue2;
            } else if (this.shutdownException != null) {
                Logging.e(TAG, "Media encoder release exception, this:" + this, this.shutdownException);
                returnValue = VideoCodecStatus.ERROR;
            } else {
                returnValue = VideoCodecStatus.OK;
            }
        }
        this.textureDrawer.release();
        this.videoFrameDrawer.release();
        TextureAlignmentDrawer textureAlignmentDrawer = this.alignmentDrawer;
        if (textureAlignmentDrawer != null) {
            textureAlignmentDrawer.release();
        }
        if (WebrtcGrayConfig.sFixEglLeak) {
            for (EncoderEssential esse : this.encoderEssentials) {
                releaseEgl(esse);
            }
            this.encoderEssentials.clear();
        }
        synchronized (this.callbackLock) {
            this.callback = null;
        }
        this.outputThread = null;
        this.encodeThreadChecker.detachThread();
        Logging.d(TAG, "release done, ret:" + returnValue.getNumber() + ", this:" + this);
        return returnValue;
    }

    @Override // org.webrtc.mozi.VideoEncoder
    public VideoCodecStatus encode(VideoFrame inputFrame, VideoEncoder.EncodeInfo encodeInfo) {
        VideoFrame videoFrame;
        VideoCodecStatus returnValue;
        int inputWidth;
        VideoCodecStatus returnValue2 = VideoCodecStatus.OK;
        boolean needReleaseFrame = false;
        int inputWidth2 = inputFrame.getBuffer().getWidth();
        int i = this.alignment;
        if (i > 0 && inputWidth2 % i != 0) {
            if (inputFrame.getBuffer() instanceof VideoFrame.TextureBuffer) {
                TextureBufferImpl buffer = (TextureBufferImpl) inputFrame.getBuffer();
                if (!this.configHelper.getVideoCodecConfig().isFixAlignDrawer()) {
                    buffer.setAlignmentDrawer(this.alignmentDrawer);
                }
                buffer.setConfigHelper(this.configHelper);
                VideoFrame.Buffer alignedBuffer = buffer.alignWidth(this.alignment);
                videoFrame = new VideoFrame(alignedBuffer, inputFrame.getRotation(), inputFrame.getExtraRotation(), inputFrame.getTimestampNs(), false, 0L, inputFrame.getColorspace(), inputFrame.isMirror());
            } else {
                VideoFrame.I420Buffer i420 = inputFrame.getBuffer().toI420();
                VideoFrame.Buffer alignedBuffer2 = i420.alignWidth(this.alignment);
                videoFrame = new VideoFrame(alignedBuffer2, inputFrame.getRotation(), inputFrame.getExtraRotation(), inputFrame.getTimestampNs(), false, 0L, inputFrame.getColorspace(), inputFrame.isMirror());
                i420.release();
            }
            needReleaseFrame = true;
        } else {
            videoFrame = inputFrame;
        }
        int frameWidth = videoFrame.getBuffer().getWidth();
        int frameHeight = videoFrame.getBuffer().getHeight();
        int i2 = this.encoderEssentials.size() - 1;
        while (true) {
            if (i2 < 0) {
                break;
            }
            EncoderEssential esse = this.encoderEssentials.get(i2);
            esse.framesReceived.incrementAndGet();
            if (!esse.sending) {
                returnValue = returnValue2;
                inputWidth = inputWidth2;
            } else if (esse.width > frameWidth || esse.height > frameHeight) {
                returnValue = returnValue2;
                inputWidth = inputWidth2;
                Logging.w(TAG, "encoder resolution " + esse.width + "x" + esse.height + " is smaller than input " + frameWidth + "x" + frameHeight + ", this:" + this);
            } else {
                boolean requestedKeyFrame = false;
                if (esse.selfGenerateKeyFrame) {
                    Logging.d(TAG, "will generate key frame(by state) for layer " + i2 + ", this:" + this);
                    esse.selfGenerateKeyFrame = false;
                    requestedKeyFrame = true;
                }
                if (!requestedKeyFrame && encodeInfo.frameTypes[i2] == EncodedImage.FrameType.VideoFrameKey) {
                    Logging.d(TAG, "will generate key frame(by request) for layer " + i2 + ", this:" + this);
                    requestedKeyFrame = true;
                }
                if (!requestedKeyFrame && !this.fpsKeepers.get(i2).KeepIt(videoFrame.getTimestampNs())) {
                    returnValue = returnValue2;
                    inputWidth = inputWidth2;
                } else {
                    int cropWidth = frameWidth;
                    int cropHeight = frameHeight;
                    if (esse.height * frameWidth > frameHeight * esse.width) {
                        cropWidth = (esse.width * frameHeight) / esse.height;
                    } else if (esse.height * frameWidth < esse.width * frameHeight) {
                        cropHeight = (esse.height * frameWidth) / esse.width;
                    }
                    int cropX = (frameWidth - cropWidth) / 2;
                    int cropY = (frameHeight - cropHeight) / 2;
                    VideoFrame.Buffer processed_buffer = videoFrame.getBuffer().cropAndScale(cropX, cropY, cropWidth, cropHeight, esse.width, esse.height);
                    VideoFrame processed_frame = new VideoFrame(processed_buffer, videoFrame.getRotation(), videoFrame.getExtraRotation(), videoFrame.getTimestampNs(), false, 0L, inputFrame.getColorspace());
                    inputWidth = inputWidth2;
                    VideoCodecStatus returnValue3 = encodeInternal(esse, processed_frame, requestedKeyFrame);
                    processed_frame.releaseBy("codec HardwareVideoEncoder#encode");
                    if (returnValue3.getNumber() >= VideoCodecStatus.OK.getNumber()) {
                        returnValue2 = returnValue3;
                        i2--;
                        inputWidth2 = inputWidth;
                    } else {
                        Logging.e(TAG, "encodeInternal error, " + returnValue3 + ", index:" + i2 + ", this:" + this);
                        returnValue2 = returnValue3;
                        break;
                    }
                }
            }
            returnValue2 = returnValue;
            i2--;
            inputWidth2 = inputWidth;
        }
        if (needReleaseFrame) {
            videoFrame.releaseBy("codec HardwareVideoEncoderencode");
        }
        return returnValue2;
    }

    /* JADX WARN: Removed duplicated region for block: B:64:0x01dc  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private org.webrtc.mozi.VideoCodecStatus encodeInternal(org.webrtc.mozi.HardwareVideoEncoder.EncoderEssential r17, org.webrtc.mozi.VideoFrame r18, boolean r19) {
        /*
            Method dump skipped, instruction units count: 674
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: org.webrtc.mozi.HardwareVideoEncoder.encodeInternal(org.webrtc.mozi.HardwareVideoEncoder$EncoderEssential, org.webrtc.mozi.VideoFrame, boolean):org.webrtc.mozi.VideoCodecStatus");
    }

    private VideoCodecStatus encodeTextureBuffer(EncoderEssential esse, VideoFrame videoFrame) {
        this.encodeThreadChecker.checkIsOnValidThread();
        try {
            GLES20.glClear(16384);
            VideoFrame derotatedFrame = new VideoFrame(videoFrame.getBuffer(), 0, videoFrame.getTimestampNs());
            this.videoFrameDrawer.drawFrame(derotatedFrame, this.textureDrawer, null);
            esse.textureEglBase.swapBuffers(videoFrame.getTimestampNs());
            return VideoCodecStatus.OK;
        } catch (RuntimeException e) {
            Logging.e(TAG, "encodeTexture failed, this:" + this, e);
            reportError(VideoCodecStatus.MC_ENC_ENCODE_TEXTURE_FAILED, 0);
            return VideoCodecStatus.ERROR;
        }
    }

    private VideoCodecStatus encodeByteBuffer(EncoderEssential esse, VideoFrame videoFrame, VideoFrame.Buffer videoFrameBuffer, int bufferSize) {
        this.encodeThreadChecker.checkIsOnValidThread();
        long presentationTimestampUs = (videoFrame.getTimestampNs() + 500) / 1000;
        try {
            int index = esse.codec.dequeueInputBuffer(0L);
            if (index != -1) {
                try {
                    ByteBuffer buffer = ((WebrtcGrayConfig.sUseNewMethodForGetBufferFromCodec || (this.mcGrayConfig != null && this.mcGrayConfig.useNewMethodForGetBufferFromCodec)) && Build.VERSION.SDK_INT >= 21) ? esse.codec.getInputBuffer(index) : esse.codec.getInputBuffers()[index];
                    fillInputBuffer(buffer, videoFrameBuffer);
                    try {
                        esse.codec.queueInputBuffer(index, 0, bufferSize, presentationTimestampUs, 0);
                        return VideoCodecStatus.OK;
                    } catch (IllegalStateException e) {
                        Logging.e(TAG, "queueInputBuffer failed:" + e.getMessage() + ", this:" + this, e);
                        reportError(VideoCodecStatus.MC_ENC_ENCODE_QUEUE_INPUT_BUFFER_FAILED, 0);
                        return VideoCodecStatus.ERROR;
                    }
                } catch (IllegalStateException e2) {
                    Logging.e(TAG, "getInputBuffers failed, this:" + this, e2);
                    reportError(VideoCodecStatus.MC_ENC_ENCODE_GET_INPUT_BUFFER_FAILED, 0);
                    return VideoCodecStatus.ERROR;
                }
            }
            Logging.d(TAG, "Dropped frame, no input buffers available, this:" + this);
            reportError(VideoCodecStatus.MC_ENC_ENCODE_DEQUEUE_INPUT_BUFFER_FAILED, 2);
            esse.framesDropped.incrementAndGet();
            return VideoCodecStatus.NO_OUTPUT;
        } catch (IllegalStateException e3) {
            Logging.e(TAG, "dequeueInputBuffer failed, this:" + this, e3);
            reportError(VideoCodecStatus.MC_ENC_ENCODE_DEQUEUE_INPUT_BUFFER_FAILED, 1);
            return VideoCodecStatus.ERROR;
        }
    }

    @Override // org.webrtc.mozi.VideoEncoder
    public VideoCodecStatus setChannelParameters(short packetLoss, long roundTripTimeMs) {
        this.encodeThreadChecker.checkIsOnValidThread();
        return VideoCodecStatus.OK;
    }

    @Override // org.webrtc.mozi.VideoEncoder
    public VideoCodecStatus setRateAllocation(VideoEncoder.BitrateAllocation bitrateAllocation, int framerate) {
        this.encodeThreadChecker.checkIsOnValidThread();
        if (!this.running) {
            return VideoCodecStatus.OK;
        }
        Logging.d(TAG, "setRateAllocation. bitrateAllocation: " + bitrateAllocation.getSum() + ". framerate: " + framerate + ", this:" + this);
        if (framerate > 30) {
            framerate = 30;
        }
        for (int i = 0; i < this.encoderEssentials.size(); i++) {
            FpsKeeper keeper = this.fpsKeepers.get(i);
            keeper.SetInputFps(framerate);
            EncoderEssential esse = this.encoderEssentials.get(i);
            int layer_bitrate = bitrateAllocation.getLayerSum(i);
            esse.originTargetBitrate = layer_bitrate;
            if (layer_bitrate == 0) {
                if (esse.sending) {
                    esse.left_deque = 2;
                }
                esse.sending = false;
                Logging.d(TAG, "setRateAllocation, " + i + " off sending, this:" + this);
            } else {
                if (!esse.sending) {
                    esse.sending = true;
                    esse.selfGenerateKeyFrame = true;
                }
                if (esse.bitrateAdjuster != null) {
                    esse.bitrateAdjuster.setTargets(layer_bitrate, keeper.GetOutputFps());
                }
                Logging.d(TAG, "setRateAllocation, " + i + " at br:" + layer_bitrate + ", this:" + this);
            }
        }
        return VideoCodecStatus.OK;
    }

    @Override // org.webrtc.mozi.VideoEncoder
    public int setAdaptedFramerateRatio(int index, int denominator, int numerator) {
        this.encodeThreadChecker.checkIsOnValidThread();
        if (index < this.fpsKeepers.size()) {
            FpsKeeper keeper = this.fpsKeepers.get(index);
            int current_fps = keeper.GetOutputFps();
            EncoderEssential esse = this.encoderEssentials.get(index);
            int new_fps = denominator == 0 ? esse.maxFramerate : (current_fps * numerator) / denominator;
            Logging.d(TAG, "setAdaptedFramerateRatio, index:" + index + ", new fps:" + new_fps + ", current fps:" + current_fps + ", valid:" + esse.minFramerate + "~" + esse.maxFramerate + ", this:" + this);
            if (new_fps >= esse.minFramerate && new_fps <= esse.maxFramerate) {
                keeper.SetTargetFps(new_fps);
                if (esse.bitrateAdjuster != null) {
                    esse.bitrateAdjuster.setTargets(esse.originTargetBitrate, keeper.GetOutputFps());
                    Logging.d(TAG, "setAdaptedFramerateRatio, ok to set real fps:" + keeper.GetOutputFps() + ", this:" + this);
                }
                return new_fps;
            }
            return -1;
        }
        return -1;
    }

    @Override // org.webrtc.mozi.VideoEncoder
    public VideoCodecStatus updateSimulcastConfig(VideoEncoder.LayerSetting[] layers) {
        this.encodeThreadChecker.checkIsOnValidThread();
        if (layers.length > this.encoderEssentials.size()) {
            Logging.e(TAG, "wrong layers length: " + layers.length + ", " + this.encoderEssentials.size() + ", this:" + this);
            return VideoCodecStatus.ERR_PARAMETER;
        }
        for (int i = 0; i < layers.length; i++) {
            EncoderEssential esse = this.encoderEssentials.get(i);
            if (!esse.seems(layers[i])) {
                esse.lock.lock();
                try {
                    try {
                        Logging.d(TAG, "updateSimulcastConfig for index:" + i + ", " + layers[i].width + "x" + layers[i].height + ", this:" + this);
                        if (WebrtcGrayConfig.sFixEglLeak) {
                            releaseEgl(esse);
                        }
                        releaseInternal(esse);
                        esse.origWidth = layers[i].width;
                        if (this.alignment > 0 && layers[i].width % this.alignment != 0) {
                            layers[i].width = (layers[i].width + (this.alignment - 1)) & (~(this.alignment - 1));
                            Logging.d(TAG, "updateSimulcastConfig, layer width has aligned to " + layers[i].width);
                        }
                        esse.width = layers[i].width;
                        esse.height = layers[i].height;
                        VideoCodecStatus returnValue = setupEncoderInternal(esse);
                        if (returnValue.getNumber() < VideoCodecStatus.OK.getNumber()) {
                            Logging.e(TAG, "updateSimulcastConfig error " + returnValue + ", this:" + this);
                            return returnValue;
                        }
                    } catch (Exception e) {
                        Logging.e(TAG, "updateSimulcastConfig releaseInternal failed, this:" + this, e);
                        reportError(VideoCodecStatus.MC_ENC_RELEASE_ENCODER_RELEASE_FAILED, 0);
                    }
                } finally {
                    esse.lock.unlock();
                }
            } else if (esse.sending != layers[i].active) {
                Logging.d(TAG, "updateSimulcastConfig, active diff, this:" + this);
                if (layers[i].active) {
                    turnOnLayerWithEssential(esse);
                } else {
                    turnOffLayerWithEssential(esse);
                }
            }
        }
        return VideoCodecStatus.OK;
    }

    @Override // org.webrtc.mozi.VideoEncoder
    public void turnOffLayer(int layer) {
        this.encodeThreadChecker.checkIsOnValidThread();
        if (layer < this.encoderEssentials.size()) {
            EncoderEssential esse = this.encoderEssentials.get(layer);
            turnOffLayerWithEssential(esse);
        }
    }

    private void turnOffLayerWithEssential(EncoderEssential esse) {
        if (esse.sending) {
            Logging.d(TAG, "turnOffLayerWithEssential, sending:" + esse.sending + ", this:" + this);
            esse.sending = false;
        }
    }

    @Override // org.webrtc.mozi.VideoEncoder
    public void turnOnLayer(int layer) {
        this.encodeThreadChecker.checkIsOnValidThread();
        if (layer < this.encoderEssentials.size()) {
            EncoderEssential esse = this.encoderEssentials.get(layer);
            turnOnLayerWithEssential(esse);
        }
    }

    private void turnOnLayerWithEssential(EncoderEssential esse) {
        if (!esse.sending) {
            Logging.d(TAG, "turnOnLayerWithEssential, sending:" + esse.sending + ", this:" + this);
            esse.sending = true;
            esse.selfGenerateKeyFrame = true;
        }
    }

    @Override // org.webrtc.mozi.VideoEncoder
    public VideoEncoder.ScalingSettings getScalingSettings() {
        this.encodeThreadChecker.checkIsOnValidThread();
        Logging.d(TAG, "getScalingSettings. automaticResizeOn: " + this.automaticResizeOn + ", this:" + this);
        if (this.automaticResizeOn) {
            if (this.codecType == VideoCodecType.VP8) {
                return new VideoEncoder.ScalingSettings(29, 95);
            }
            if (this.codecType == VideoCodecType.H264) {
                return new VideoEncoder.ScalingSettings(24, 37);
            }
        }
        return VideoEncoder.ScalingSettings.OFF;
    }

    @Override // org.webrtc.mozi.VideoEncoder
    public String getImplementationName() {
        return "HWEncoder";
    }

    @Override // org.webrtc.mozi.VideoEncoder
    public String getImplementationName2() {
        String str = this.codecName;
        return str == null ? "mediacodec" : str;
    }

    @Override // org.webrtc.mozi.VideoEncoder
    public void decideToFallback() {
        CameraCapturer.PushTexture2Yuv(true);
    }

    private boolean shouldForceKeyFrame(EncoderEssential esse, long presentationTimestampNs) {
        this.encodeThreadChecker.checkIsOnValidThread();
        return this.forcedKeyFrameNs > 0 && presentationTimestampNs > esse.lastKeyFrameNs + this.forcedKeyFrameNs;
    }

    private void requestKeyFrame(EncoderEssential esse, long presentationTimestampNs) {
        Logging.d(TAG, "requestKeyFrame. presentationTimestampNs:" + presentationTimestampNs + ", this:" + this);
        this.encodeThreadChecker.checkIsOnValidThread();
        if (esse.codec == null) {
            return;
        }
        try {
            Bundle b = new Bundle();
            b.putInt("request-sync", 0);
            esse.codec.setParameters(b);
            esse.lastKeyFrameNs = presentationTimestampNs;
        } catch (IllegalStateException e) {
            Logging.e(TAG, "requestKeyFrame failed, this:" + this, e);
            reportError(VideoCodecStatus.MC_ENC_ENCODE_REQUEST_KEY_FRAME_FAILED, 0);
        }
    }

    private Thread createOutputThread() {
        return new Thread("HwEncOut") { // from class: org.webrtc.mozi.HardwareVideoEncoder.1
            @Override // java.lang.Thread, java.lang.Runnable
            public void run() {
                while (HardwareVideoEncoder.this.running) {
                    int dequeue_output_timeout_us = 100000;
                    if (HardwareVideoEncoder.this.encoderEssentials.size() > 1) {
                        dequeue_output_timeout_us = 10000;
                    }
                    boolean ever_sending = false;
                    boolean need_break = false;
                    for (EncoderEssential esse : HardwareVideoEncoder.this.encoderEssentials) {
                        esse.lock.lock();
                        try {
                            if (!esse.sending) {
                                if (esse.left_deque > 0) {
                                    EncoderEssential.access$2510(esse);
                                    HardwareVideoEncoder.this.deliverEncodedImage(esse, dequeue_output_timeout_us);
                                }
                            } else {
                                HardwareVideoEncoder.this.deliverEncodedImage(esse, dequeue_output_timeout_us);
                                ever_sending = true;
                            }
                            esse.logStats(false);
                            if (esse.dequeueFail) {
                                Logging.e(HardwareVideoEncoder.TAG, "break out of encoding loop, HardwareVideoEncoder:" + esse.encoder_obj);
                                need_break = true;
                            }
                            esse.lock.unlock();
                        } catch (Throwable th) {
                            esse.logStats(false);
                            if (esse.dequeueFail) {
                                Logging.e(HardwareVideoEncoder.TAG, "break out of encoding loop, HardwareVideoEncoder:" + esse.encoder_obj);
                            }
                            esse.lock.unlock();
                            throw th;
                        }
                    }
                    if (need_break) {
                        break;
                    } else if (!ever_sending) {
                        try {
                            Thread.sleep(50L);
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                        }
                    }
                }
                Iterator it = HardwareVideoEncoder.this.encoderEssentials.iterator();
                while (it.hasNext()) {
                    HardwareVideoEncoder.this.releaseCodecOnOutputThread((EncoderEssential) it.next());
                }
                if (!WebrtcGrayConfig.sFixEglLeak) {
                    HardwareVideoEncoder.this.encoderEssentials.clear();
                }
            }
        };
    }

    protected void deliverEncodedImage(EncoderEssential esse, int dequeue_output_timeout_us) {
        ByteBuffer codecOutputBuffer;
        ByteBuffer frameBuffer;
        int frametype;
        ByteBuffer rewriteBuffer;
        this.outputThreadChecker.checkIsOnValidThread();
        try {
            if (esse.codec == null) {
                return;
            }
            MediaCodec.BufferInfo info = new MediaCodec.BufferInfo();
            try {
                int index = esse.codec.dequeueOutputBuffer(info, dequeue_output_timeout_us);
                if (index < 0) {
                    return;
                }
                if (!this.running) {
                    Logging.d(TAG, "encoder released before dequeueOutputBuffer, this:" + this);
                    return;
                }
                long anchorMs = SystemClock.elapsedRealtime();
                boolean useNewApi = false;
                if ((WebrtcGrayConfig.sUseNewMethodForGetBufferFromCodec || (this.mcGrayConfig != null && this.mcGrayConfig.useNewMethodForGetBufferFromCodec)) && Build.VERSION.SDK_INT >= 21) {
                    codecOutputBuffer = esse.codec.getOutputBuffer(index);
                    useNewApi = true;
                } else {
                    codecOutputBuffer = esse.codec.getOutputBuffers()[index];
                }
                if (SystemClock.elapsedRealtime() - anchorMs > 1000) {
                    Logging.w(TAG, "get output buffer took time:" + (SystemClock.elapsedRealtime() - anchorMs) + "ms, use new api:" + useNewApi + ", this:" + this);
                }
                codecOutputBuffer.position(info.offset);
                codecOutputBuffer.limit(info.offset + info.size);
                if ((info.flags & 2) == 0) {
                    esse.bitrateAdjuster.reportEncodedFrame(info.size);
                    if (esse.adjustedBitrate != esse.bitrateAdjuster.getAdjustedBitrateBps()) {
                        updateBitrate(esse);
                    }
                    boolean isKeyFrame = (info.flags & 1) != 0;
                    if (isKeyFrame) {
                        Logging.d(TAG, "Sync frame generated, size:" + info.size + ", index:" + esse.index + ", this:" + this);
                    }
                    if (isKeyFrame && this.codecType == VideoCodecType.H264) {
                        Logging.d(TAG, "Prepending config frame of size " + esse.configBuffer.capacity() + " to output buffer with offset " + info.offset + ", size " + info.size + ", this:" + this);
                        frameBuffer = ByteBuffer.allocateDirect(info.size + esse.configBuffer.capacity());
                        esse.configBuffer.rewind();
                        frameBuffer.put(esse.configBuffer);
                        frameBuffer.put(codecOutputBuffer);
                        frameBuffer.rewind();
                    } else {
                        frameBuffer = codecOutputBuffer.slice();
                    }
                    esse.currentBytes += frameBuffer.remaining();
                    EncoderEssential.access$3204(esse);
                    EncoderEssential.access$3304(esse);
                    if (esse.profile == 8 && !McsConfig.allowUnexpectedBFrameInHWEncoder() && ((frametype = this.callback.onParseFrame(frameBuffer, esse.index)) == 1 || frametype == 6)) {
                        if (McsConfig.getUnexpectedBFrameAction() == 2) {
                            Logging.w(TAG, "drop unexpected B frame, and fallback software, this:" + this);
                            this.bFrameForceSoftware = true;
                            return;
                        }
                        if (McsConfig.getUnexpectedBFrameAction() == 1) {
                            Logging.w(TAG, "drop unexpected B frame, and fallback baseline, this:" + this);
                            this.bFrameForceBaseline = true;
                            return;
                        }
                        return;
                    }
                    EncodedImage.FrameType frameType = isKeyFrame ? EncodedImage.FrameType.VideoFrameKey : EncodedImage.FrameType.VideoFrameDelta;
                    EncodedImage.Builder builder = (EncodedImage.Builder) esse.outputBuilders.poll();
                    builder.setBuffer(frameBuffer).setFrameType(frameType);
                    if (this.outputThreadLabel == Thread.currentThread()) {
                        VideoEncoder.CodecSpecificInfo codecSpec = new VideoEncoder.CodecSpecificInfo();
                        codecSpec.sim_index = esse.index;
                        codecSpec.end_mark = PossibleLastLayer(esse.index);
                        this.callback.onEncodedFrame(builder.createEncodedImage(), codecSpec);
                    }
                } else {
                    Logging.d(TAG, "Config frame generated. Offset: " + info.offset + ". Size: " + info.size + ", index:" + esse.index + ", this:" + this);
                    esse.configBuffer = ByteBuffer.allocateDirect(info.size);
                    esse.configBuffer.put(codecOutputBuffer);
                    if (this.alignment > 0 && esse.origWidth != esse.width && (rewriteBuffer = this.callback.onWriteCropInfo(esse.configBuffer, 0, esse.width - esse.origWidth, 0, 0)) != null) {
                        esse.configBuffer = rewriteBuffer;
                    }
                }
                esse.codec.releaseOutputBuffer(index, false);
                esse.dequeueFailCount = 0;
                return;
            } catch (IllegalStateException e) {
                e = e;
            }
        } catch (IllegalStateException e2) {
            e = e2;
        }
        if (EncoderEssential.access$3408(esse) > 10) {
            Logging.e(TAG, "deliverEncodedImage failed, mark it, this:" + this);
            esse.dequeueFail = true;
        }
        Logging.e(TAG, "deliverOutput failed:" + e.getMessage() + ", this:" + this, e);
    }

    private boolean PossibleLastLayer(int index) {
        if (index == this.encoderEssentials.size() - 1) {
            return true;
        }
        if (this.encoderEssentials.get(index + 1).sending) {
            return false;
        }
        return PossibleLastLayer(index + 1);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void releaseCodecOnOutputThread(EncoderEssential esse) {
        this.outputThreadChecker.checkIsOnValidThread();
        esse.logStats(true);
        Logging.d(TAG, "start to stop codec, this:" + this);
        if (esse.codec != null) {
            try {
                esse.codec.stop();
            } catch (Exception e) {
                Logging.e(TAG, "Media encoder stop failed, this:" + this, e);
                reportError(VideoCodecStatus.MC_ENC_RELEASE_ENCODER_STOP_FAILED, 0);
            }
            Logging.d(TAG, "start to release codec, this:" + this);
            try {
                releaseInternal(esse);
            } catch (Exception e2) {
                Logging.e(TAG, "Media encoder release failed, this:" + this, e2);
                reportError(VideoCodecStatus.MC_ENC_RELEASE_ENCODER_RELEASE_FAILED, 0);
                this.shutdownException = e2;
            }
            Logging.d(TAG, "EncoderEssential released on output thread, index:" + esse.index + ", this:" + this);
        }
    }

    private VideoCodecStatus updateBitrate(EncoderEssential esse) {
        this.outputThreadChecker.checkIsOnValidThread();
        esse.adjustedBitrate = esse.bitrateAdjuster.getAdjustedBitrateBps();
        Logging.d(TAG, "updateBitrate start, this:" + this);
        try {
            Bundle params = new Bundle();
            params.putInt("video-bitrate", esse.adjustedBitrate);
            esse.codec.setParameters(params);
            Logging.d(TAG, "updateBitrate " + esse.adjustedBitrate + " for encoder " + esse.width + "x" + esse.height + ", this:" + this);
            return VideoCodecStatus.OK;
        } catch (IllegalStateException e) {
            Logging.e(TAG, "updateBitrate failed, this:" + this, e);
            reportError(VideoCodecStatus.MC_ENC_ENCODER_UPDATE_BITRATE_FAILED, 0);
            return VideoCodecStatus.ERROR;
        }
    }

    private boolean canUseSurface() {
        return (this.sharedContext == null || this.surfaceColorFormat == null) ? false : true;
    }

    protected void fillInputBuffer(ByteBuffer buffer, VideoFrame.Buffer videoFrameBuffer) {
        this.yuvFormat.fillBuffer(buffer, videoFrameBuffer);
    }

    private enum YuvFormat {
        I420 { // from class: org.webrtc.mozi.HardwareVideoEncoder.YuvFormat.1
            @Override // org.webrtc.mozi.HardwareVideoEncoder.YuvFormat
            void fillBuffer(ByteBuffer dstBuffer, VideoFrame.Buffer srcBuffer) {
                VideoFrame.I420Buffer i420 = srcBuffer.toI420();
                YuvHelper.I420Copy(i420.getDataY(), i420.getStrideY(), i420.getDataU(), i420.getStrideU(), i420.getDataV(), i420.getStrideV(), dstBuffer, i420.getWidth(), i420.getHeight());
                i420.release();
            }
        },
        NV12 { // from class: org.webrtc.mozi.HardwareVideoEncoder.YuvFormat.2
            @Override // org.webrtc.mozi.HardwareVideoEncoder.YuvFormat
            void fillBuffer(ByteBuffer dstBuffer, VideoFrame.Buffer srcBuffer) {
                VideoFrame.I420Buffer i420 = srcBuffer.toI420();
                YuvHelper.I420ToNV12(i420.getDataY(), i420.getStrideY(), i420.getDataU(), i420.getStrideU(), i420.getDataV(), i420.getStrideV(), dstBuffer, i420.getWidth(), i420.getHeight());
                i420.release();
            }
        };

        abstract void fillBuffer(ByteBuffer byteBuffer, VideoFrame.Buffer buffer);

        static YuvFormat valueOf(int colorFormat) {
            if (colorFormat == 19) {
                return I420;
            }
            if (colorFormat == 21 || colorFormat == 2141391872 || colorFormat == 2141391876) {
                return NV12;
            }
            throw new IllegalArgumentException("Unsupported colorFormat: " + colorFormat);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void reportError(VideoCodecStatus majorError, int minorError) {
        MediaCodecGrayConfig mediaCodecGrayConfig;
        if (!WebrtcGrayConfig.sReportVideoCodecErrorCodes && ((mediaCodecGrayConfig = this.mcGrayConfig) == null || !mediaCodecGrayConfig.reportVideoCodecErrorCodes)) {
            return;
        }
        synchronized (this.callbackLock) {
            if (this.callback != null) {
                Logging.e(TAG, "reportError majorError:" + majorError.getNumber() + ", minorError:" + minorError + ", this:" + this);
                this.callback.onEncodeError(majorError.getNumber(), minorError);
            }
        }
    }
}
