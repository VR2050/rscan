package org.webrtc.mozi;

import android.media.MediaCodec;
import android.media.MediaFormat;
import android.os.Build;
import android.os.SystemClock;
import android.view.Surface;
import com.google.android.exoplayer2.DefaultRenderersFactory;
import com.zhy.http.okhttp.OkHttpUtils;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayDeque;
import java.util.Queue;
import java.util.concurrent.BlockingDeque;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import javax.annotation.Nullable;
import org.webrtc.mozi.EglBase;
import org.webrtc.mozi.McsHWDeviceHelper;
import org.webrtc.mozi.MediaCodecUtils;
import org.webrtc.mozi.ThreadUtils;
import org.webrtc.mozi.VideoDecoder;
import org.webrtc.mozi.VideoFrame;
import org.webrtc.mozi.video.grayconfig.MediaCodecGrayConfig;

/* JADX INFO: loaded from: classes3.dex */
public class HardwareVideoDecoder implements VideoDecoder, VideoSink {
    private static final int DEQUEUE_INPUT_TIMEOUT_US = 500000;
    private static final int DEQUEUE_OUTPUT_BUFFER_TIMEOUT_US = 10000;
    private static final int MEDIA_CODEC_RELEASE_TIMEOUT_MS = 5000;
    private static final String MEDIA_FORMAT_KEY_CROP_BOTTOM = "crop-bottom";
    private static final String MEDIA_FORMAT_KEY_CROP_LEFT = "crop-left";
    private static final String MEDIA_FORMAT_KEY_CROP_RIGHT = "crop-right";
    private static final String MEDIA_FORMAT_KEY_CROP_TOP = "crop-top";
    private static final String MEDIA_FORMAT_KEY_SLICE_HEIGHT = "slice-height";
    private static final String MEDIA_FORMAT_KEY_STRIDE = "stride";
    private static final String TAG = "codec HardwareVideoDecoder";
    public static boolean sReleaseAfterFallback = true;

    @Nullable
    private VideoDecoder.Callback callback;
    private final String codecName;
    private final VideoCodecType codecType;
    private int colorFormat;
    private final McsConfigHelper configHelper;
    private ThreadUtils.ThreadChecker decoderThreadChecker;
    private final BlockingDeque<FrameInfo> frameInfos;
    private boolean hasDecodedFirstFrame;
    private int height;
    private boolean keyFrameRequired;

    @Nullable
    private FallbackController mFallbackController;
    private MediaCodecGrayConfig mcGrayConfig;
    private final MediaCodecWrapperFactory mediaCodecWrapperFactory;

    @Nullable
    private Thread outputThread;
    private ThreadUtils.ThreadChecker outputThreadChecker;

    @Nullable
    private DecodedTextureMetadata renderedTextureMetadata;
    private final EglBase.Context sharedContext;
    private int sliceHeight;
    private int stride;

    @Nullable
    private SurfaceTextureHelper surfaceTextureHelper;
    private int width;
    private volatile boolean running = false;

    @Nullable
    private volatile Exception shutdownException = null;
    private final Object dimensionLock = new Object();
    private boolean hasInputFirstFrame = false;

    @Nullable
    private Surface surface = null;
    private final int MAX_CONTINUOUS_DEQUEUE_ERROR_COUNT = 10;
    private final int MAX_ADDED_DEQUEUE_ERROR_COUNT = 30;
    private int dequeueContinuousFailCount = 0;
    private int dequeueAddedFailCount = 0;
    private boolean dequeueFail = false;
    private final int MAX_PENDING_FRAMES_COUNT = 10;
    private final int MAX_CONTINUOUS_DEQUEUE_TEXTURE_ERROR_COUNT = 3;
    private final int STATS_INTERVAL_MS = 10000;
    private final int REPORT_STUCK_INTERVAL_MS = 30000;
    private final int REPORT_STUCK_FRAMES = 30;
    private AtomicInteger dequeueTextureErrorCount = new AtomicInteger(0);
    private AtomicLong framesReceived = new AtomicLong(0);
    private AtomicLong framesQueued = new AtomicLong(0);
    private AtomicLong framesBeforeQueued = new AtomicLong(0);
    private AtomicInteger currentBytes = new AtomicInteger(0);
    private volatile long framesDecoded = 0;
    private volatile long textureFramesDelivered = 0;
    private AtomicLong textureFramesDecoded = new AtomicLong(0);
    private AtomicLong textureFramesRendered = new AtomicLong(0);
    private AtomicLong yuvFramesDelivered = new AtomicLong(0);
    private int currentFramesDecoded = 0;
    private long statsStartTimeMs = 0;
    private long reportStuckStartTimeMs = 0;
    private long lastFramesBeforeQueued = 0;
    private long lastTextureFramesDecoded = 0;
    private volatile boolean isFirstTextureDeliverFail = false;
    private int codecAlignWidth = 0;
    private int codecAlignHeight = 0;
    private Queue<DecodedTextureMetadata> decodedTextureMetaQueue = new ArrayDeque();
    private final int DECODED_TEXTURE_META_QUEUE_CAPACITY = 2;
    private MediaCodecUtils.CodecExtraProperties decoderProperties = null;
    private final Object renderedTextureMetadataLock = new Object();
    private boolean renderedTextureMetadataReleased = false;
    private final Object callbackLock = new Object();

    @Nullable
    private MediaCodecWrapper codec = null;

    public interface FallbackController {
        boolean isFallback(VideoDecoder.Settings settings);
    }

    private static class FrameInfo {
        final long decodeStartTimeMs;
        final int rotation;

        FrameInfo(long decodeStartTimeMs, int rotation) {
            this.decodeStartTimeMs = decodeStartTimeMs;
            this.rotation = rotation;
        }
    }

    private static class DecodedTextureMetadata {
        final Integer decodeTimeMs;
        int index;
        final long presentationTimestampUs;

        DecodedTextureMetadata(long presentationTimestampUs, Integer decodeTimeMs) {
            this.presentationTimestampUs = presentationTimestampUs;
            this.decodeTimeMs = decodeTimeMs;
        }

        void setIndex(int index) {
            this.index = index;
        }
    }

    HardwareVideoDecoder(McsConfigHelper configHelper, MediaCodecWrapperFactory mediaCodecWrapperFactory, String codecName, VideoCodecType codecType, int colorFormat, EglBase.Context sharedContext) {
        this.mcGrayConfig = null;
        Logging.d(TAG, "HardwareVideoDecoder. codecName:" + codecName + " codecType:" + codecType + " colorFormat:" + colorFormat + " sharedContext:" + sharedContext + ", " + this);
        if (!isSupportedColorFormat(colorFormat)) {
            throw new IllegalArgumentException("Unsupported color format: " + colorFormat);
        }
        this.configHelper = configHelper;
        this.mediaCodecWrapperFactory = mediaCodecWrapperFactory;
        this.codecName = codecName;
        this.codecType = codecType;
        this.colorFormat = colorFormat;
        this.sharedContext = sharedContext;
        this.frameInfos = new LinkedBlockingDeque();
        if (configHelper.oneRTCNativeGrayConfigEnabled()) {
            this.mcGrayConfig = configHelper.getMediaCodecGrayConfig();
        }
    }

    public void setFallbackController(FallbackController controller) {
        this.mFallbackController = controller;
    }

    @Override // org.webrtc.mozi.VideoDecoder
    public VideoCodecStatus initDecode(VideoDecoder.Settings settings, VideoDecoder.Callback callback) {
        this.decoderThreadChecker = new ThreadUtils.ThreadChecker();
        CodecMonitorHelper.decoderEvent(CodecMonitorHelper.EVENT_RUNTIME, CodecMonitorHelper.FORMAT_HW, CodecMonitorHelper.EVENT_INIT);
        Logging.d(TAG, "start to init decoder, ssrc:" + (((long) settings.ssrc) & 4294967295L) + ", this:" + this);
        this.callback = callback;
        FallbackController fallbackController = this.mFallbackController;
        if (fallbackController != null && fallbackController.isFallback(settings)) {
            Logging.e(TAG, "initDecode fallback by FallbackController");
            return VideoCodecStatus.FALLBACK_SOFTWARE;
        }
        if (McsHWDeviceHelper.getInstance().getHwDecoderFallbackController() != null && McsHWDeviceHelper.getInstance().getHwDecoderFallbackController().isFallback(settings.width, settings.height)) {
            Logging.e(TAG, "initDecode fallback by FallbackController from McsHWDeviceHelper");
            return VideoCodecStatus.FALLBACK_SOFTWARE;
        }
        if (this.sharedContext != null) {
            this.surfaceTextureHelper = createSurfaceTextureHelper();
            Logging.d(TAG, "create surfaceTextureHelper:" + this.surfaceTextureHelper + ", this:" + this);
            if (this.surfaceTextureHelper != null) {
                this.surface = new Surface(this.surfaceTextureHelper.getSurfaceTexture());
                this.surfaceTextureHelper.startListening(this);
            }
        } else {
            Logging.d(TAG, "use buffer mode, this:" + this);
        }
        this.decoderProperties = MediaCodecUtils.getCodecExtraProperties(this.codecName, this.codecType.mimeType(), false);
        VideoCodecStatus result = initDecodeInternal(settings.width, settings.height);
        if (result == VideoCodecStatus.FALLBACK_SOFTWARE) {
            CodecMonitorHelper.decoderEvent(CodecMonitorHelper.EVENT_RUNTIME, CodecMonitorHelper.FORMAT_HW, "fallback");
        }
        return result;
    }

    @Override // org.webrtc.mozi.VideoDecoder
    public long createNativeVideoDecoder() {
        return 0L;
    }

    private VideoCodecStatus initDecodeInternal(int width, int height) {
        MediaCodecGrayConfig mediaCodecGrayConfig;
        MediaCodecUtils.CodecExtraProperties codecExtraProperties;
        this.decoderThreadChecker.checkIsOnValidThread();
        Logging.d(TAG, "initDecodeInternal. w:" + width + " h:" + height + ", this:" + this);
        if ((Build.VERSION.SDK_INT == 26 || Build.VERSION.SDK_INT == 27) && ((width == 100 && height == 176) || (width == 176 && height == 100))) {
            Logging.e(TAG, "initDecodeInternal failed bacause of invalid resolution: " + width + ", " + height);
            reportError(VideoCodecStatus.MC_DEC_INIT_INVALID_PARAMETER, 0);
            return VideoCodecStatus.FALLBACK_SOFTWARE;
        }
        McsConfigHelper mcsConfigHelper = this.configHelper;
        if (mcsConfigHelper != null && mcsConfigHelper.getVideoCodecConfig().isEnableDecodeMaxResCheck() && (codecExtraProperties = this.decoderProperties) != null && (codecExtraProperties.maxWidth < width || this.decoderProperties.maxHeight < height)) {
            Logging.e(TAG, "initDecodeInternal failed resolution is too large than hardware capability, max_width: " + this.decoderProperties.maxWidth + " max_height: " + this.decoderProperties.maxHeight);
            reportError(VideoCodecStatus.MC_DEC_INIT_INVALID_PARAMETER, 0);
            return VideoCodecStatus.FALLBACK_SOFTWARE;
        }
        if (!McsHWDeviceHelper.getInstance().isDisableMCAdaptivePlayback() && (WebrtcGrayConfig.sHWDecoderAdaptivePlayback || ((mediaCodecGrayConfig = this.mcGrayConfig) != null && mediaCodecGrayConfig.HWDecoderAdaptivePlayback))) {
            if (this.running) {
                Logging.e(TAG, "initDecodeInternal called while the codec is already running");
                reportError(VideoCodecStatus.MC_DEC_INIT_ALREADY_RUNNING, 0);
                return VideoCodecStatus.FALLBACK_SOFTWARE;
            }
        } else if (this.outputThread != null) {
            Logging.e(TAG, "initDecodeInternal called while the outputThread is already running");
            reportError(VideoCodecStatus.MC_DEC_INIT_ALREADY_RUNNING, 0);
            return VideoCodecStatus.FALLBACK_SOFTWARE;
        }
        if (this.sharedContext != null) {
            if (this.surfaceTextureHelper == null) {
                Logging.e(TAG, "initDecodeInternal failed without surfaceTextureHelper");
                reportError(VideoCodecStatus.MC_DEC_INIT_NO_SURFACETEXTUREHELPER, 0);
                return VideoCodecStatus.FALLBACK_SOFTWARE;
            }
            if (this.surface == null) {
                Logging.e(TAG, "initDecodeInternal failed without surface");
                reportError(VideoCodecStatus.MC_DEC_INIT_NO_SURFACE, 0);
                return VideoCodecStatus.FALLBACK_SOFTWARE;
            }
        }
        resetVariables();
        this.width = width;
        this.height = height;
        this.codecAlignWidth = 0;
        this.codecAlignHeight = 0;
        this.stride = width;
        this.sliceHeight = height;
        this.hasDecodedFirstFrame = false;
        this.keyFrameRequired = true;
        try {
            this.codec = this.mediaCodecWrapperFactory.createByCodecName(this.codecName, width, height);
            LeakMonitor.allocate(LeakMonitorConstants.TYPE_CODEC, LeakMonitorConstants.ALLOCATION_DECODE);
            try {
                MediaFormat format = MediaFormat.createVideoFormat(this.codecType.mimeType(), width, height);
                if (this.sharedContext == null) {
                    format.setInteger("color-format", this.colorFormat);
                }
                if (this.configHelper.getAndroidRoomsConfig().isRooms()) {
                    boolean lowLatency = McsHWDeviceHelper.getInstance().lowLatencyDecode();
                    Logging.d(TAG, "rooms, low latency decode:" + lowLatency);
                    if (lowLatency) {
                        format.setInteger("vendor.low-latency.enable", 1);
                    }
                }
                if (this.configHelper.getAndroidRoomsConfig().isRooms()) {
                    boolean isP2pProjection = this.configHelper.getProjectionConfig().isP2pProjection();
                    Logging.d(TAG, "rooms, projectionConfig isP2pProjection:" + isP2pProjection);
                    if (isP2pProjection && McsHWDeviceHelper.getInstance().decPictureOrderF2()) {
                        format.setInteger("vendor.qti-ext-dec-picture-order.enable", 1);
                    }
                    if (McsHWDeviceHelper.getInstance().getDecoderMediaFormatHandler() != null) {
                        Logging.d(TAG, "rooms before Handle Format: " + format);
                        McsHWDeviceHelper.getInstance().getDecoderMediaFormatHandler().onHandle(format, -1);
                    }
                }
                boolean setLowLatency = false;
                if (WebrtcGrayConfig.sEnableLowLatencyDecode && this.decoderProperties != null && this.decoderProperties.supportLowLatency) {
                    format.setInteger("low-latency", 1);
                    Logging.d(TAG, "enable low-latency officially");
                    setLowLatency = true;
                }
                if (!setLowLatency) {
                    if (this.codecName.startsWith("OMX.hisi.") && Build.VERSION.SDK_INT >= 29 && WebrtcGrayConfig.sEnableLowLatencyDecodeForHisi) {
                        format.setInteger("vendor.hisi-ext-low-latency-video-dec.video-scene-for-low-latency-req", 1);
                        format.setInteger("vendor.hisi-ext-low-latency-video-dec.video-scene-for-low-latency-rdy", -1);
                        Logging.d(TAG, "enable low-latency for hisi");
                    } else if (this.codecName.startsWith("OMX.qcom.") && Build.VERSION.SDK_INT >= 26 && WebrtcGrayConfig.sEnableLowLatencyDecodeForQcom) {
                        format.setInteger("vendor.qti-ext-dec-picture-order.enable", 1);
                        Logging.d(TAG, "enable low-latency for qcom");
                    } else if (this.codecName.startsWith("OMX.Exynos.") && Build.VERSION.SDK_INT >= 26 && WebrtcGrayConfig.sEnableLowLatencyDecodeForExynos) {
                        format.setInteger("vendor.rtc-ext-dec-low-latency.enable", 1);
                        Logging.d(TAG, "enable low-latency for exynos");
                    } else if (this.codecName.startsWith("OMX.amlogic.") && Build.VERSION.SDK_INT >= 26 && WebrtcGrayConfig.sEnableLowLatencyDecodeForAmlogic) {
                        format.setInteger("vendor.low-latency.enable", 1);
                        Logging.d(TAG, "enable low-latency for amlogic");
                    }
                }
                Logging.d(TAG, "Format: " + format);
                if (this.configHelper.getAndroidRoomsConfig().isRooms() && McsHWDeviceHelper.getInstance().getCodecDelegate() != null) {
                    McsHWDeviceHelper.CodecDelegate delegate = McsHWDeviceHelper.getInstance().getCodecDelegate();
                    if (this.surface != null) {
                        this.codec.configure(delegate.mediaFormat(format), delegate.surface(this.surface), delegate.crypto(null), delegate.flag(0));
                    } else {
                        this.codec.configure(delegate.mediaFormat(format), null, delegate.crypto(null), delegate.flag(0));
                    }
                } else {
                    this.codec.configure(format, this.surface, null, 0);
                }
                this.codec.start();
                this.running = true;
                if (WebrtcGrayConfig.sFixHWDecoderDeadlock) {
                    synchronized (this.renderedTextureMetadataLock) {
                        this.renderedTextureMetadataReleased = false;
                        this.decodedTextureMetaQueue.clear();
                        this.renderedTextureMetadata = null;
                        Logging.d(TAG, "init, clear meta queue");
                    }
                }
                Thread threadCreateOutputThread = createOutputThread();
                this.outputThread = threadCreateOutputThread;
                threadCreateOutputThread.start();
                this.hasInputFirstFrame = false;
                Logging.d(TAG, "initDecodeInternal done, " + this);
                return VideoCodecStatus.OK;
            } catch (IllegalArgumentException | IllegalStateException e) {
                Logging.e(TAG, "initDecode failed", e);
                release();
                reportError(VideoCodecStatus.MC_DEC_INIT_START_DECODER_FAILED, 0);
                return VideoCodecStatus.FALLBACK_SOFTWARE;
            }
        } catch (IOException | IllegalArgumentException | IllegalStateException e2) {
            Logging.e(TAG, "Cannot create media decoder " + this.codecName);
            if (sReleaseAfterFallback) {
                release();
            }
            reportError(VideoCodecStatus.MC_DEC_INIT_CREATE_DECODER_FAILED, 0);
            return VideoCodecStatus.FALLBACK_SOFTWARE;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:90:0x0136 A[Catch: IllegalStateException -> 0x01f7, TRY_ENTER, TRY_LEAVE, TryCatch #3 {IllegalStateException -> 0x01f7, blocks: (B:81:0x0122, B:95:0x0144, B:90:0x0136), top: B:154:0x0122 }] */
    /* JADX WARN: Removed duplicated region for block: B:95:0x0144 A[Catch: IllegalStateException -> 0x01f7, TRY_ENTER, TRY_LEAVE, TryCatch #3 {IllegalStateException -> 0x01f7, blocks: (B:81:0x0122, B:95:0x0144, B:90:0x0136), top: B:154:0x0122 }] */
    @Override // org.webrtc.mozi.VideoDecoder
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public org.webrtc.mozi.VideoCodecStatus decode(org.webrtc.mozi.EncodedImage r18, org.webrtc.mozi.VideoDecoder.DecodeInfo r19) {
        /*
            Method dump skipped, instruction units count: 601
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: org.webrtc.mozi.HardwareVideoDecoder.decode(org.webrtc.mozi.EncodedImage, org.webrtc.mozi.VideoDecoder$DecodeInfo):org.webrtc.mozi.VideoCodecStatus");
    }

    @Override // org.webrtc.mozi.VideoDecoder
    public boolean getPrefersLateDecoding() {
        return true;
    }

    @Override // org.webrtc.mozi.VideoDecoder
    public String getImplementationName() {
        return "HWDecoder";
    }

    @Override // org.webrtc.mozi.VideoDecoder
    public String getImplementationName2() {
        String str = this.codecName;
        return str == null ? "mediacodec" : str;
    }

    @Override // org.webrtc.mozi.VideoDecoder
    public String getCodecProfiles() {
        MediaCodecUtils.CodecExtraProperties codecExtraProperties = this.decoderProperties;
        return codecExtraProperties == null ? "" : codecExtraProperties.profiles;
    }

    @Override // org.webrtc.mozi.VideoDecoder
    public VideoCodecStatus release() {
        Logging.d(TAG, "release, this:" + this);
        synchronized (this.renderedTextureMetadataLock) {
            this.decodedTextureMetaQueue.clear();
            this.renderedTextureMetadataReleased = true;
            this.renderedTextureMetadata = null;
            Logging.d(TAG, "release, clear meta queue");
        }
        VideoCodecStatus status = releaseInternal();
        Logging.d(TAG, "release, decoder stopped");
        if (this.surface != null) {
            releaseSurface();
            this.surface = null;
            if (this.surfaceTextureHelper != null) {
                Logging.d(TAG, "release surfaceTextureHelper:" + this.surfaceTextureHelper + ", textureDelivered:" + this.surfaceTextureHelper.getTextureDelivered() + ", textureReturned:" + this.surfaceTextureHelper.getTextureReturned() + ", this:" + this);
                this.surfaceTextureHelper.stopListening();
                this.surfaceTextureHelper.dispose();
                this.surfaceTextureHelper = null;
            }
            Logging.d(TAG, "release, surface texture helper disposed");
        }
        synchronized (this.callbackLock) {
            this.callback = null;
        }
        this.frameInfos.clear();
        this.dequeueFail = false;
        Logging.d(TAG, "release done, ret:" + status.getNumber() + ", this:" + this);
        return status;
    }

    /* JADX WARN: Multi-variable type inference failed */
    private VideoCodecStatus releaseInternal() {
        VideoCodecStatus videoCodecStatus;
        if (!this.running) {
            Logging.d(TAG, "release: Decoder is not running.");
            return VideoCodecStatus.OK;
        }
        try {
            this.running = false;
            if (!ThreadUtils.joinUninterruptibly(this.outputThread, DefaultRenderersFactory.DEFAULT_ALLOWED_VIDEO_JOINING_TIME_MS)) {
                Logging.e(TAG, "Media decoder release timeout", new RuntimeException());
                reportError(VideoCodecStatus.MC_DEC_RELEASE_TIMEOUT, 0);
                videoCodecStatus = VideoCodecStatus.TIMEOUT;
            } else if (this.shutdownException != null) {
                Logging.e(TAG, "Media decoder release error", new RuntimeException(this.shutdownException));
                this.shutdownException = null;
                videoCodecStatus = VideoCodecStatus.ERROR;
            } else {
                this.codec = null;
                this.outputThread = null;
                logStats(true);
                return VideoCodecStatus.OK;
            }
            return videoCodecStatus;
        } finally {
            this.codec = null;
            this.outputThread = null;
            logStats(true);
        }
    }

    private VideoCodecStatus reinitDecode(int newWidth, int newHeight) {
        this.decoderThreadChecker.checkIsOnValidThread();
        Logging.d(TAG, "reinitDecode. w=" + newWidth + " h=" + newHeight + ", this:" + this);
        synchronized (this.renderedTextureMetadataLock) {
            this.decodedTextureMetaQueue.clear();
            this.renderedTextureMetadataReleased = true;
            this.renderedTextureMetadata = null;
            Logging.d(TAG, "reinitDecode, clear meta queue");
        }
        VideoCodecStatus status = releaseInternal();
        if (status != VideoCodecStatus.OK) {
            return status;
        }
        Logging.d(TAG, "reinitDecode, encoder stopped");
        this.frameInfos.clear();
        return initDecodeInternal(newWidth, newHeight);
    }

    private Thread createOutputThread() {
        return new Thread("HardwareVideoDecoder.outputThread") { // from class: org.webrtc.mozi.HardwareVideoDecoder.1
            @Override // java.lang.Thread, java.lang.Runnable
            public void run() {
                HardwareVideoDecoder.this.outputThreadChecker = new ThreadUtils.ThreadChecker();
                while (true) {
                    if (!HardwareVideoDecoder.this.running) {
                        break;
                    }
                    HardwareVideoDecoder.this.deliverDecodedFrame();
                    HardwareVideoDecoder.this.logStats(false);
                    if (HardwareVideoDecoder.this.dequeueFail) {
                        Logging.w(HardwareVideoDecoder.TAG, "deliverDecodedFrame failed, need to break!");
                        break;
                    }
                }
                HardwareVideoDecoder.this.releaseCodecOnOutputThread();
            }
        };
    }

    protected void deliverDecodedFrame() {
        this.outputThreadChecker.checkIsOnValidThread();
        try {
            synchronized (this.renderedTextureMetadataLock) {
                if (this.surfaceTextureHelper != null) {
                    tryToConsumeMetaQueue();
                }
            }
            MediaCodec.BufferInfo info = new MediaCodec.BufferInfo();
            int result = this.codec.dequeueOutputBuffer(info, OkHttpUtils.DEFAULT_MILLISECONDS);
            if (result == -2) {
                reformat(this.codec.getOutputFormat());
                return;
            }
            if (result < 0) {
                Logging.v(TAG, "dequeueOutputBuffer returned " + result);
                return;
            }
            this.framesDecoded++;
            this.currentFramesDecoded++;
            FrameInfo frameInfo = this.frameInfos.poll();
            Integer decodeTimeMs = null;
            int rotation = 0;
            if (frameInfo != null) {
                decodeTimeMs = Integer.valueOf((int) (SystemClock.elapsedRealtime() - frameInfo.decodeStartTimeMs));
                rotation = frameInfo.rotation;
            }
            if (!this.hasDecodedFirstFrame) {
                Logging.w(TAG, "dequeueOutputBuffer, hasDecodedFirstFrame");
            }
            this.hasDecodedFirstFrame = true;
            if (this.surfaceTextureHelper != null) {
                if (deliverTextureFrame(result, info, rotation, decodeTimeMs)) {
                    this.textureFramesDelivered++;
                }
            } else {
                deliverByteFrame(result, info, rotation, decodeTimeMs);
            }
            if (this.dequeueContinuousFailCount > 0) {
                Logging.w(TAG, "deliverDecodedFrame, recover from previous error, " + this.dequeueContinuousFailCount);
            }
            this.dequeueContinuousFailCount = 0;
        } catch (Throwable e) {
            int i = this.dequeueAddedFailCount;
            this.dequeueAddedFailCount = i + 1;
            if (i > 30) {
                Logging.e(TAG, "deliverDecodedFrame failed, mark it(added), " + this.dequeueAddedFailCount);
                this.dequeueFail = true;
            } else {
                int i2 = this.dequeueContinuousFailCount;
                this.dequeueContinuousFailCount = i2 + 1;
                if (i2 > 10) {
                    Logging.e(TAG, "deliverDecodedFrame failed, mark it(continuous), " + this.dequeueContinuousFailCount);
                    this.dequeueFail = true;
                }
            }
            Logging.e(TAG, "deliverDecodedFrame failed", e);
        }
    }

    private int tryToConsumeMetaQueue() {
        if (this.renderedTextureMetadata == null && this.running && this.decodedTextureMetaQueue.size() > 0) {
            DecodedTextureMetadata decodedTextureMetadataRemove = this.decodedTextureMetaQueue.remove();
            this.renderedTextureMetadata = decodedTextureMetadataRemove;
            this.codec.releaseOutputBuffer(decodedTextureMetadataRemove.index, true);
            this.textureFramesRendered.incrementAndGet();
            return 1;
        }
        return 0;
    }

    private boolean deliverTextureFrame(int index, MediaCodec.BufferInfo info, int rotation, Integer decodeTimeMs) throws Throwable {
        int width;
        int height;
        synchronized (this.dimensionLock) {
            try {
                try {
                    if (this.codecAlignWidth * this.codecAlignHeight != 0) {
                        width = this.codecAlignWidth;
                        height = this.codecAlignHeight;
                    } else {
                        width = this.width;
                        height = this.height;
                    }
                    try {
                        synchronized (this.renderedTextureMetadataLock) {
                            if (this.codec == null) {
                                Logging.e(TAG, "deliverTextureFrame failed, null codec, this:" + this);
                                return false;
                            }
                            if (this.renderedTextureMetadata == null && this.decodedTextureMetaQueue.size() <= 0) {
                                if (width > 0 && height > 0) {
                                    this.surfaceTextureHelper.setTextureSize(width, height);
                                    this.surfaceTextureHelper.setFrameRotation(rotation);
                                    this.renderedTextureMetadata = new DecodedTextureMetadata(info.presentationTimeUs, decodeTimeMs);
                                    this.codec.releaseOutputBuffer(index, true);
                                    this.textureFramesRendered.incrementAndGet();
                                    return true;
                                }
                                Logging.e(TAG, "deliverTextureFrame failed, decoder dimension: " + width + ", x " + height + ", this:" + this);
                                this.codec.releaseOutputBuffer(index, false);
                                if ((WebrtcGrayConfig.sFixHWDecoderDropFrame || (this.mcGrayConfig != null && this.mcGrayConfig.fixHWDecoderDropFrame)) && this.callback != null) {
                                    this.callback.onObligedDropFrame(info.presentationTimeUs * 1000);
                                }
                                reportError(VideoCodecStatus.MC_DEC_DECODE_INVALID_TEXTURE_SIZE, 0);
                                return false;
                            }
                            if (this.decodedTextureMetaQueue.size() > 2) {
                                this.codec.releaseOutputBuffer(index, false);
                                this.callback.onObligedDropFrame(info.presentationTimeUs * 1000);
                                return false;
                            }
                            DecodedTextureMetadata meta = new DecodedTextureMetadata(info.presentationTimeUs, decodeTimeMs);
                            meta.setIndex(index);
                            this.decodedTextureMetaQueue.add(meta);
                            return false;
                        }
                    } catch (Throwable th) {
                        th = th;
                        while (true) {
                            try {
                                throw th;
                            } catch (Throwable th2) {
                                th = th2;
                            }
                        }
                    }
                } catch (Throwable th3) {
                    th = th3;
                }
            } catch (Throwable th4) {
                th = th4;
            }
        }
    }

    @Override // org.webrtc.mozi.VideoSink
    public void onFrame(VideoFrame frame) throws Throwable {
        synchronized (this.renderedTextureMetadataLock) {
            try {
                try {
                    if ((!WebrtcGrayConfig.sFixHWEncoderDecoderLogic && (this.mcGrayConfig == null || !this.mcGrayConfig.fixHWEncoderDecoderLogic)) || frame != null) {
                        this.dequeueTextureErrorCount.set(0);
                        if (WebrtcGrayConfig.sHWCodecImprove && this.renderedTextureMetadataReleased) {
                            return;
                        }
                        if (this.renderedTextureMetadata != null && this.renderedTextureMetadata.decodeTimeMs != null) {
                            long timestampNs = this.renderedTextureMetadata.presentationTimestampUs * 1000;
                            try {
                                int decodeTimeMs = this.renderedTextureMetadata.decodeTimeMs.intValue();
                                this.renderedTextureMetadata = null;
                                this.textureFramesDecoded.incrementAndGet();
                                VideoFrame frameWithModifiedTimeStamp = new VideoFrame(frame.getBuffer(), frame.getRotation(), timestampNs);
                                this.callback.onDecodedFrame(frameWithModifiedTimeStamp, Integer.valueOf(decodeTimeMs), null);
                                return;
                            } catch (Throwable th) {
                                th = th;
                                throw th;
                            }
                        }
                        Logging.e(TAG, "Rendered texture metadata was null in onTextureFrameAvailable, metadata:" + this.renderedTextureMetadata + ", this:" + this);
                        this.renderedTextureMetadata = null;
                        reportError(VideoCodecStatus.MC_DEC_DECODE_INVALID_TEXTURE_METADATA, this.renderedTextureMetadata == null ? 1 : 2);
                        return;
                    }
                    this.renderedTextureMetadata = null;
                    this.dequeueTextureErrorCount.incrementAndGet();
                } catch (Throwable th2) {
                    th = th2;
                }
            } catch (Throwable th3) {
                th = th3;
            }
        }
    }

    private void deliverByteFrame(int result, MediaCodec.BufferInfo info, int rotation, Integer decodeTimeMs) throws Throwable {
        int stride;
        ByteBuffer buffer;
        VideoFrame.Buffer frameBuffer;
        MediaCodecGrayConfig mediaCodecGrayConfig;
        synchronized (this.dimensionLock) {
            try {
                int width = this.width;
                try {
                    int height = this.height;
                    try {
                        int stride2 = this.stride;
                        try {
                            int sliceHeight = this.sliceHeight;
                            try {
                                if (info.size < ((width * height) * 3) / 2) {
                                    Logging.e(TAG, "Insufficient output buffer size: " + info.size);
                                    return;
                                }
                                if (info.size < ((stride2 * height) * 3) / 2 && sliceHeight == height && stride2 > width) {
                                    stride = (info.size * 2) / (height * 3);
                                } else {
                                    stride = stride2;
                                }
                                if ((WebrtcGrayConfig.sUseNewMethodForGetBufferFromCodec || ((mediaCodecGrayConfig = this.mcGrayConfig) != null && mediaCodecGrayConfig.useNewMethodForGetBufferFromCodec)) && Build.VERSION.SDK_INT >= 21) {
                                    buffer = this.codec.getOutputBuffer(result);
                                } else {
                                    buffer = this.codec.getOutputBuffers()[result];
                                }
                                buffer.position(info.offset);
                                buffer.limit(info.offset + info.size);
                                ByteBuffer buffer2 = buffer.slice();
                                if (this.colorFormat == 19) {
                                    frameBuffer = copyI420Buffer(buffer2, stride, sliceHeight, width, height);
                                } else {
                                    frameBuffer = copyNV12ToI420Buffer(buffer2, stride, sliceHeight, width, height);
                                }
                                this.codec.releaseOutputBuffer(result, false);
                                long presentationTimeNs = info.presentationTimeUs * 1000;
                                VideoFrame frame = new VideoFrame(frameBuffer, rotation, presentationTimeNs);
                                this.yuvFramesDelivered.incrementAndGet();
                                this.callback.onDecodedFrame(frame, decodeTimeMs, null);
                                frame.release();
                            } catch (Throwable th) {
                                th = th;
                                while (true) {
                                    try {
                                        throw th;
                                    } catch (Throwable th2) {
                                        th = th2;
                                    }
                                }
                            }
                        } catch (Throwable th3) {
                            th = th3;
                        }
                    } catch (Throwable th4) {
                        th = th4;
                        while (true) {
                            throw th;
                        }
                    }
                } catch (Throwable th5) {
                    th = th5;
                }
            } catch (Throwable th6) {
                th = th6;
            }
        }
    }

    private VideoFrame.Buffer copyNV12ToI420Buffer(ByteBuffer buffer, int stride, int sliceHeight, int width, int height) {
        return new NV12Buffer(width, height, stride, sliceHeight, buffer, null).toI420();
    }

    private VideoFrame.Buffer copyI420Buffer(ByteBuffer buffer, int stride, int sliceHeight, int width, int height) {
        if (stride % 2 != 0) {
            reportError(VideoCodecStatus.MC_DEC_DECODE_INVALID_STRIDE, 0);
            throw new AssertionError("Stride is not divisible by two: " + stride);
        }
        int chromaWidth = (width + 1) / 2;
        int chromaHeight = sliceHeight % 2 == 0 ? (height + 1) / 2 : height / 2;
        int uvStride = stride / 2;
        int yEnd = (stride * height) + 0;
        int uPos = (stride * sliceHeight) + 0;
        int uEnd = uPos + (uvStride * chromaHeight);
        int vPos = uPos + ((uvStride * sliceHeight) / 2);
        int vEnd = vPos + (uvStride * chromaHeight);
        VideoFrame.I420Buffer frameBuffer = allocateI420Buffer(width, height);
        buffer.limit(yEnd);
        buffer.position(0);
        ByteBuffer byteBufferSlice = buffer.slice();
        ByteBuffer dataY = frameBuffer.getDataY();
        int yEnd2 = frameBuffer.getStrideY();
        copyPlane(byteBufferSlice, stride, dataY, yEnd2, width, height);
        buffer.limit(uEnd);
        buffer.position(uPos);
        copyPlane(buffer.slice(), uvStride, frameBuffer.getDataU(), frameBuffer.getStrideU(), chromaWidth, chromaHeight);
        if (sliceHeight % 2 == 1) {
            buffer.position(uPos + ((chromaHeight - 1) * uvStride));
            ByteBuffer dataU = frameBuffer.getDataU();
            dataU.position(frameBuffer.getStrideU() * chromaHeight);
            dataU.put(buffer);
        }
        buffer.limit(vEnd);
        buffer.position(vPos);
        copyPlane(buffer.slice(), uvStride, frameBuffer.getDataV(), frameBuffer.getStrideV(), chromaWidth, chromaHeight);
        if (sliceHeight % 2 == 1) {
            buffer.position(vPos + ((chromaHeight - 1) * uvStride));
            ByteBuffer dataV = frameBuffer.getDataV();
            dataV.position(frameBuffer.getStrideV() * chromaHeight);
            dataV.put(buffer);
        }
        return frameBuffer;
    }

    private void reformat(MediaFormat format) {
        int newWidth;
        int newHeight;
        float scaleX;
        float scaleY;
        this.outputThreadChecker.checkIsOnValidThread();
        Logging.d(TAG, "Decoder format changed: " + format.toString());
        if (format.containsKey(MEDIA_FORMAT_KEY_CROP_LEFT) && format.containsKey(MEDIA_FORMAT_KEY_CROP_RIGHT) && format.containsKey(MEDIA_FORMAT_KEY_CROP_BOTTOM) && format.containsKey(MEDIA_FORMAT_KEY_CROP_TOP)) {
            newWidth = (format.getInteger(MEDIA_FORMAT_KEY_CROP_RIGHT) + 1) - format.getInteger(MEDIA_FORMAT_KEY_CROP_LEFT);
            newHeight = (format.getInteger(MEDIA_FORMAT_KEY_CROP_BOTTOM) + 1) - format.getInteger(MEDIA_FORMAT_KEY_CROP_TOP);
        } else {
            newWidth = format.getInteger("width");
            newHeight = format.getInteger("height");
        }
        synchronized (this.dimensionLock) {
            if ((McsHWDeviceHelper.getInstance().isDisableMCAdaptivePlayback() || (!WebrtcGrayConfig.sHWDecoderAdaptivePlayback && (this.mcGrayConfig == null || !this.mcGrayConfig.HWDecoderAdaptivePlayback))) && this.hasDecodedFirstFrame && (this.width != newWidth || this.height != newHeight)) {
                stopOnOutputThread(new RuntimeException("Unexpected size change. Configured " + this.width + "*" + this.height + ". New " + newWidth + "*" + newHeight));
                return;
            }
            if ((this.width != newWidth || this.height != newHeight) && this.configHelper.getAndroidRoomsConfig().isRooms() && McsHWDeviceHelper.getInstance().isAlignHardwareDecoderResolution()) {
                float rawRatio = this.width / this.height;
                float newRatio = newWidth / newHeight;
                if (newRatio > rawRatio) {
                    scaleX = rawRatio / newRatio;
                    scaleY = 1.0f;
                } else {
                    scaleX = 1.0f;
                    scaleY = newRatio / rawRatio;
                }
                this.codecAlignWidth = (int) (newWidth * scaleX);
                this.codecAlignHeight = (int) (newHeight * scaleY);
                Logging.d(TAG, "align decoder crop size: " + newWidth + "x" + newHeight + ", to: " + this.codecAlignWidth + "x" + this.codecAlignHeight);
            } else {
                this.width = newWidth;
                this.height = newHeight;
            }
            if (this.surfaceTextureHelper == null && format.containsKey("color-format")) {
                this.colorFormat = format.getInteger("color-format");
                Logging.d(TAG, "Color: 0x" + Integer.toHexString(this.colorFormat));
                if (!isSupportedColorFormat(this.colorFormat)) {
                    reportError(VideoCodecStatus.MC_DEC_DECODE_COLOR_FORMAT_NOT_SUPPORTED, 0);
                    stopOnOutputThread(new IllegalStateException("Unsupported color format: " + this.colorFormat));
                    return;
                }
            }
            synchronized (this.dimensionLock) {
                if (format.containsKey(MEDIA_FORMAT_KEY_STRIDE)) {
                    this.stride = format.getInteger(MEDIA_FORMAT_KEY_STRIDE);
                }
                if (format.containsKey(MEDIA_FORMAT_KEY_SLICE_HEIGHT)) {
                    this.sliceHeight = format.getInteger(MEDIA_FORMAT_KEY_SLICE_HEIGHT);
                }
                Logging.d(TAG, "Frame stride and slice height: " + this.stride + " x " + this.sliceHeight);
                this.stride = Math.max(this.width, this.stride);
                this.sliceHeight = Math.max(this.height, this.sliceHeight);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void releaseCodecOnOutputThread() {
        this.outputThreadChecker.checkIsOnValidThread();
        Logging.d(TAG, "Start to release media decoder, " + this);
        MediaCodecWrapper mediaCodecWrapper = this.codec;
        if (mediaCodecWrapper == null || mediaCodecWrapper.isReleased()) {
            Logging.d(TAG, "Release on output thread done skipped, " + this);
            return;
        }
        try {
            this.codec.stop();
        } catch (Exception e) {
            reportError(VideoCodecStatus.MC_DEC_RELEASE_DECODER_STOP_FAILED, 0);
            Logging.e(TAG, "Media decoder stop failed", e);
        }
        try {
            this.codec.release();
            LeakMonitor.deallocate(LeakMonitorConstants.TYPE_CODEC, LeakMonitorConstants.ALLOCATION_DECODE);
        } catch (Exception e2) {
            Logging.e(TAG, "Media decoder release failed", e2);
            reportError(VideoCodecStatus.MC_DEC_RELEASE_DECODER_RELEASE_FAILED, 0);
            this.shutdownException = e2;
        }
        Logging.d(TAG, "Release on output thread done, " + this);
    }

    private void stopOnOutputThread(Exception e) {
        this.outputThreadChecker.checkIsOnValidThread();
        this.running = false;
        this.shutdownException = e;
    }

    private boolean isSupportedColorFormat(int colorFormat) {
        for (int supported : MediaCodecUtils.DECODER_COLOR_FORMATS) {
            if (supported == colorFormat) {
                return true;
            }
        }
        return false;
    }

    protected SurfaceTextureHelper createSurfaceTextureHelper() {
        return SurfaceTextureHelper.create("decoder-texture-thread", this.sharedContext, 0L);
    }

    protected void releaseSurface() {
        this.surface.release();
    }

    protected VideoFrame.I420Buffer allocateI420Buffer(int width, int height) {
        return JavaI420Buffer.allocate(width, height);
    }

    protected void copyPlane(ByteBuffer src, int srcStride, ByteBuffer dst, int dstStride, int width, int height) {
        YuvHelper.copyPlane(src, srcStride, dst, dstStride, width, height);
    }

    private void resetVariables() {
        this.statsStartTimeMs = SystemClock.elapsedRealtime();
        this.reportStuckStartTimeMs = SystemClock.elapsedRealtime();
        this.framesReceived.set(0L);
        this.framesQueued.set(0L);
        this.framesBeforeQueued.set(0L);
        this.currentBytes.set(0);
        this.framesDecoded = 0L;
        this.textureFramesDecoded.set(0L);
        this.textureFramesDelivered = 0L;
        this.textureFramesRendered.set(0L);
        this.yuvFramesDelivered.set(0L);
        this.currentFramesDecoded = 0;
        this.dequeueTextureErrorCount.set(0);
        this.isFirstTextureDeliverFail = false;
        this.lastFramesBeforeQueued = 0L;
        this.lastTextureFramesDecoded = 0L;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void logStats(boolean logImmediately) {
        long interval_ms;
        long surfaceDelivered;
        MediaCodecGrayConfig mediaCodecGrayConfig;
        long interval_ms2 = SystemClock.elapsedRealtime() - this.statsStartTimeMs;
        if (interval_ms2 > OkHttpUtils.DEFAULT_MILLISECONDS || logImmediately) {
            SurfaceTextureHelper stHelper = this.surfaceTextureHelper;
            int decodedFps = interval_ms2 > 0 ? (int) (((long) (this.currentFramesDecoded * 1000)) / interval_ms2) : 0;
            int kbps = interval_ms2 > 0 ? (int) (((long) (this.currentBytes.get() * 8)) / interval_ms2) : 0;
            long surfaceDelivered2 = stHelper != null ? stHelper.getTextureDelivered() : -1L;
            long surfaceReturned = stHelper != null ? stHelper.getTextureReturned() : -1L;
            StringBuilder sb = new StringBuilder();
            if (this.surfaceTextureHelper == null) {
                interval_ms = interval_ms2;
                sb.append("stats, frames received:");
                surfaceDelivered = surfaceDelivered2;
                sb.append(this.framesReceived.get());
                sb.append(", queued:");
                sb.append(this.framesQueued.get());
                sb.append(", decoded:");
                sb.append(this.framesDecoded);
                sb.append(", yuv delivered:");
                sb.append(this.yuvFramesDelivered.get());
                sb.append(", bitrate:");
                sb.append(kbps);
                sb.append("kbps, fps:");
                sb.append(decodedFps);
                sb.append(" for last ");
                sb.append(interval_ms);
                sb.append("ms");
                sb.append(", this:");
                sb.append(this);
            } else {
                sb.append("stats, frames received:");
                sb.append(this.framesReceived.get());
                sb.append(", queued:");
                sb.append(this.framesQueued.get());
                sb.append(", decoded:");
                sb.append(this.framesDecoded);
                sb.append(", texture decoded:");
                sb.append(this.textureFramesDecoded.get());
                sb.append(", texture delivered:");
                sb.append(this.textureFramesDelivered);
                sb.append(", texture rendered:");
                sb.append(this.textureFramesRendered.get());
                sb.append(", surfaceDelivered: ");
                sb.append(surfaceDelivered2);
                sb.append(", surfaceReturned: ");
                sb.append(surfaceReturned);
                sb.append(", bitrate:");
                sb.append(kbps);
                sb.append("kbps, fps:");
                sb.append(decodedFps);
                sb.append(" for last ");
                sb.append(interval_ms2);
                sb.append("ms");
                sb.append(", this:");
                sb.append(this);
                sb.append(", surfaceTexture:");
                sb.append(this.surfaceTextureHelper);
                surfaceDelivered = surfaceDelivered2;
                interval_ms = interval_ms2;
            }
            Logging.d(TAG, sb.toString());
            this.statsStartTimeMs = SystemClock.elapsedRealtime();
            this.currentFramesDecoded = 0;
            this.currentBytes.set(0);
            if (this.surfaceTextureHelper != null && ((WebrtcGrayConfig.sReportHWDecoderTextureDeliverFailed || ((mediaCodecGrayConfig = this.mcGrayConfig) != null && mediaCodecGrayConfig.reportHWDecoderTextureDeliverFailed)) && !this.isFirstTextureDeliverFail && !logImmediately && this.textureFramesRendered.get() > 0 && surfaceDelivered <= 0)) {
                this.isFirstTextureDeliverFail = true;
                reportError(VideoCodecStatus.MC_DEC_DECODE_TEXTURE_DELIVER_FAILED, 0);
                CodecMonitorHelper.decoderEvent(CodecMonitorHelper.EVENT_RUNTIME, CodecMonitorHelper.FORMAT_HW, "texture_deliver_failed");
            }
        } else {
            interval_ms = interval_ms2;
        }
        if (this.surfaceTextureHelper != null && SystemClock.elapsedRealtime() - this.reportStuckStartTimeMs > 30000) {
            this.reportStuckStartTimeMs = SystemClock.elapsedRealtime();
            if (this.lastTextureFramesDecoded == this.textureFramesDecoded.get() && this.framesBeforeQueued.get() - this.lastFramesBeforeQueued >= 30) {
                reportError(VideoCodecStatus.MC_DEC_DECODE_TEXTURE_DECODE_STUCK, 0);
            }
            this.lastFramesBeforeQueued = this.framesBeforeQueued.get();
            this.lastTextureFramesDecoded = this.textureFramesDecoded.get();
        }
    }

    private void reportError(VideoCodecStatus majorError, int minorError) {
        MediaCodecGrayConfig mediaCodecGrayConfig;
        if (!WebrtcGrayConfig.sReportVideoCodecErrorCodes && ((mediaCodecGrayConfig = this.mcGrayConfig) == null || !mediaCodecGrayConfig.reportVideoCodecErrorCodes)) {
            return;
        }
        synchronized (this.callbackLock) {
            if (this.callback != null) {
                Logging.e(TAG, "reportError majorError:" + majorError.getNumber() + ", minorError:" + minorError + ", this:" + this);
                this.callback.onDecodeError(majorError.getNumber(), minorError);
            }
        }
    }
}
