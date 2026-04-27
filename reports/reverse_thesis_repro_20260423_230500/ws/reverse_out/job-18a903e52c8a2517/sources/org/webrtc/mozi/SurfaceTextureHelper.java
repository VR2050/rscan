package org.webrtc.mozi;

import android.graphics.SurfaceTexture;
import android.opengl.GLES20;
import android.os.Build;
import android.os.Handler;
import android.os.HandlerThread;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicLong;
import javax.annotation.Nullable;
import org.webrtc.mozi.EglBase;
import org.webrtc.mozi.VideoFrame;
import org.webrtc.mozi.cache.Cache;
import org.webrtc.mozi.cache.CacheHelper;
import org.webrtc.mozi.video.grayconfig.MediaCodecGrayConfig;

/* JADX INFO: loaded from: classes3.dex */
public class SurfaceTextureHelper implements Cache.Entry {
    private static final String TAG = "SurfaceTextureHelper";
    public static Monitor sMonitor;
    private final TextureAlignmentDrawer alignmentDrawer;
    private McsConfigHelper configHelper;
    private final EglBase eglBase;
    private FpsKeeper fpsKeeper;
    private int frameRotation;
    private final Handler handler;
    private boolean hasPendingTexture;
    private boolean isQuitting;
    private boolean isRecyclable;
    private boolean isRecycled;
    private volatile boolean isTextureInUse;

    @Nullable
    private VideoSink listener;
    private TextureFilter mFilter;
    private String mName;
    private WebRTCStatistics mStatistics;
    private TextureInfo mTextureInfo;
    private MediaCodecGrayConfig mcGrayConfig;
    private int oesTextureId;

    @Nullable
    private VideoSink pendingListener;
    final Runnable setListenerRunnable;
    private SurfaceTexture surfaceTexture;
    private AtomicLong textureDelivered;
    private int textureHeight;
    private AtomicLong textureReturned;
    private final Object textureSizeLock;
    private int textureWidth;
    private final YuvConverter yuvConverter;

    public interface Monitor {
        void onCreate(String str);

        void onDispose(String str);

        void onRelease(String str);
    }

    public interface TextureFilter {
        void filter(EglBase eglBase, TextureInfo textureInfo);

        boolean isWorking();

        void release();
    }

    public static class TextureInfo {
        public boolean dropFrame;
        public Map<String, Integer> filterMs;
        public int height;
        public int id;
        public int textureRotation;
        public float[] transformMatrix;
        public VideoFrame.TextureBuffer.Type type;
        public int width;
    }

    public static SurfaceTextureHelper create(final String threadName, final EglBase.Context sharedContext, final long configPtr) {
        if (CacheHelper.cacheable(SurfaceTextureHelper.class)) {
            SurfaceTextureHelper t = (SurfaceTextureHelper) CacheHelper.poll(SurfaceTextureHelper.class, TAG);
            if (t == null) {
                Logging.e(TAG, "cache missed, create one");
            } else {
                return t;
            }
        }
        HandlerThread thread = new HandlerThread(threadName);
        thread.start();
        final Handler handler = new Handler(thread.getLooper());
        return (SurfaceTextureHelper) ThreadUtils.invokeAtFrontUninterruptibly(handler, new Callable<SurfaceTextureHelper>() { // from class: org.webrtc.mozi.SurfaceTextureHelper.1
            @Override // java.util.concurrent.Callable
            @Nullable
            public SurfaceTextureHelper call() {
                try {
                    return new SurfaceTextureHelper(sharedContext, handler, threadName, configPtr);
                } catch (RuntimeException e) {
                    Logging.e(SurfaceTextureHelper.TAG, threadName + " create failure", e);
                    return null;
                }
            }
        });
    }

    private SurfaceTextureHelper(EglBase.Context sharedContext, Handler handler, String name, long configPtr) {
        this.configHelper = null;
        this.mStatistics = null;
        this.mcGrayConfig = null;
        this.yuvConverter = new YuvConverter();
        this.alignmentDrawer = new TextureAlignmentDrawer();
        this.textureDelivered = new AtomicLong(0L);
        this.textureReturned = new AtomicLong(0L);
        this.textureSizeLock = new Object();
        this.hasPendingTexture = false;
        this.isTextureInUse = false;
        this.isQuitting = false;
        this.isRecyclable = true;
        this.isRecycled = false;
        this.setListenerRunnable = new Runnable() { // from class: org.webrtc.mozi.SurfaceTextureHelper.2
            @Override // java.lang.Runnable
            public void run() {
                SurfaceTextureHelper.this.logD("Setting listener to " + SurfaceTextureHelper.this.pendingListener);
                SurfaceTextureHelper surfaceTextureHelper = SurfaceTextureHelper.this;
                surfaceTextureHelper.listener = surfaceTextureHelper.pendingListener;
                SurfaceTextureHelper.this.pendingListener = null;
                if (SurfaceTextureHelper.this.hasPendingTexture) {
                    SurfaceTextureHelper.this.updateTexImage();
                    SurfaceTextureHelper.this.hasPendingTexture = false;
                }
            }
        };
        this.mTextureInfo = new TextureInfo();
        if (handler.getLooper().getThread() != Thread.currentThread()) {
            throw new IllegalStateException("SurfaceTextureHelper must be created on the handler thread");
        }
        McsConfigHelper mcsConfigHelper = new McsConfigHelper(configPtr);
        this.configHelper = mcsConfigHelper;
        this.mStatistics = new WebRTCStatistics(mcsConfigHelper.getNativeMcsConfig());
        if (this.configHelper.oneRTCNativeGrayConfigEnabled()) {
            this.mcGrayConfig = this.configHelper.getMediaCodecGrayConfig();
        }
        this.alignmentDrawer.setConfigHelper(this.configHelper);
        this.handler = handler;
        this.mName = name;
        Monitor monitor = sMonitor;
        if (monitor != null) {
            monitor.onCreate(name);
        }
        logD("create one");
        Logging.i(TAG, "create one : " + this.configHelper);
        EglBase eglBaseCreate = EglBase.create(sharedContext, EglBase.CONFIG_PIXEL_BUFFER);
        this.eglBase = eglBaseCreate;
        eglBaseCreate.setTraceId(name);
        try {
            this.eglBase.createDummyPbufferSurface();
            this.eglBase.makeCurrent();
            this.oesTextureId = GlUtil.generateTexture(36197);
            SurfaceTexture surfaceTexture = new SurfaceTexture(this.oesTextureId);
            this.surfaceTexture = surfaceTexture;
            setOnFrameAvailableListener(surfaceTexture, SurfaceTextureHelper$$Lambda$1.lambdaFactory$(this), handler);
        } catch (RuntimeException e) {
            this.eglBase.release();
            handler.getLooper().quit();
            throw e;
        }
    }

    public synchronized void deliverTextureFrame() {
        if (this.isRecycled) {
            logD("updateTexImage when deliverTextureFrame but recycle");
            updateTexImage();
        } else {
            this.hasPendingTexture = true;
            this.textureDelivered.incrementAndGet();
            tryDeliverTextureFrame();
        }
    }

    private static void setOnFrameAvailableListener(SurfaceTexture surfaceTexture, SurfaceTexture.OnFrameAvailableListener listener, Handler handler) {
        if (Build.VERSION.SDK_INT >= 21) {
            surfaceTexture.setOnFrameAvailableListener(listener, handler);
        } else {
            surfaceTexture.setOnFrameAvailableListener(listener);
        }
    }

    public void startListening(VideoSink listener) {
        if (this.listener != null || this.pendingListener != null) {
            throw new IllegalStateException("SurfaceTextureHelper listener has already been set.");
        }
        logD("startListening: " + listener);
        this.pendingListener = listener;
        this.handler.post(this.setListenerRunnable);
    }

    public void stopListening() {
        logD("stopListening: " + this.listener);
        this.handler.removeCallbacks(this.setListenerRunnable);
        ThreadUtils.invokeAtFrontUninterruptibly(this.handler, SurfaceTextureHelper$$Lambda$2.lambdaFactory$(this));
    }

    static /* synthetic */ void lambda$stopListening$9(SurfaceTextureHelper surfaceTextureHelper) {
        surfaceTextureHelper.listener = null;
        surfaceTextureHelper.pendingListener = null;
    }

    public void setTextureSize(int textureWidth, int textureHeight) {
        MediaCodecGrayConfig mediaCodecGrayConfig;
        if (textureWidth <= 0) {
            throw new IllegalArgumentException("Texture width must be positive, but was " + textureWidth);
        }
        if (textureHeight <= 0) {
            throw new IllegalArgumentException("Texture height must be positive, but was " + textureHeight);
        }
        this.surfaceTexture.setDefaultBufferSize(textureWidth, textureHeight);
        if (!WebrtcGrayConfig.sHWDecoderSetTextureSizeSynchronously && ((mediaCodecGrayConfig = this.mcGrayConfig) == null || !mediaCodecGrayConfig.HWDecoderSetTextureSizeSynchronously)) {
            this.handler.post(SurfaceTextureHelper$$Lambda$3.lambdaFactory$(this, textureWidth, textureHeight));
            return;
        }
        synchronized (this.textureSizeLock) {
            this.textureWidth = textureWidth;
            this.textureHeight = textureHeight;
        }
    }

    static /* synthetic */ void lambda$setTextureSize$10(SurfaceTextureHelper surfaceTextureHelper, int i, int i2) {
        surfaceTextureHelper.textureWidth = i;
        surfaceTextureHelper.textureHeight = i2;
    }

    public void recreateSurface() {
        ThreadUtils.invokeAtFrontUninterruptibly(this.handler, SurfaceTextureHelper$$Lambda$4.lambdaFactory$(this));
    }

    static /* synthetic */ void lambda$recreateSurface$12(SurfaceTextureHelper surfaceTextureHelper) {
        if (surfaceTextureHelper.eglBase == null) {
            return;
        }
        surfaceTextureHelper.logD("recreateSurface");
        surfaceTextureHelper.textureReturned.set(0L);
        surfaceTextureHelper.textureDelivered.set(0L);
        surfaceTextureHelper.eglBase.releaseSurface();
        surfaceTextureHelper.eglBase.createDummyPbufferSurface();
        surfaceTextureHelper.eglBase.makeCurrent();
        int i = surfaceTextureHelper.oesTextureId;
        if (i > 0) {
            GLES20.glDeleteTextures(1, new int[]{i}, 0);
        }
        SurfaceTexture surfaceTexture = surfaceTextureHelper.surfaceTexture;
        if (surfaceTexture != null) {
            surfaceTexture.release();
        }
        surfaceTextureHelper.oesTextureId = GlUtil.generateTexture(36197);
        SurfaceTexture surfaceTexture2 = new SurfaceTexture(surfaceTextureHelper.oesTextureId);
        surfaceTextureHelper.surfaceTexture = surfaceTexture2;
        setOnFrameAvailableListener(surfaceTexture2, SurfaceTextureHelper$$Lambda$10.lambdaFactory$(surfaceTextureHelper), surfaceTextureHelper.handler);
    }

    public void setFrameRotation(int rotation) {
        this.handler.post(SurfaceTextureHelper$$Lambda$5.lambdaFactory$(this, rotation));
    }

    public SurfaceTexture getSurfaceTexture() {
        return this.surfaceTexture;
    }

    public Handler getHandler() {
        return this.handler;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void returnTextureFrame() {
        this.textureReturned.incrementAndGet();
        this.handler.post(SurfaceTextureHelper$$Lambda$6.lambdaFactory$(this));
    }

    static /* synthetic */ void lambda$returnTextureFrame$14(SurfaceTextureHelper surfaceTextureHelper) {
        surfaceTextureHelper.isTextureInUse = false;
        if (surfaceTextureHelper.isQuitting) {
            surfaceTextureHelper.release();
        } else {
            surfaceTextureHelper.tryDeliverTextureFrame();
        }
    }

    public boolean isTextureInUse() {
        return this.isTextureInUse;
    }

    public EglBase.Context getEglContext() {
        EglBase eglBase = this.eglBase;
        if (eglBase == null) {
            return null;
        }
        return eglBase.getEglBaseContext();
    }

    public void dispose() {
        dispose(false);
    }

    public void dispose(boolean isDisposeNoWait) {
        disposeInner(true, isDisposeNoWait);
    }

    private void disposeInner(final boolean recyclable, boolean isDisposeNoWait) {
        logD("dispose(): " + recyclable + ", " + isDisposeNoWait);
        Monitor monitor = sMonitor;
        if (monitor != null) {
            monitor.onDispose(this.mName);
        }
        Runnable runner = new Runnable() { // from class: org.webrtc.mozi.SurfaceTextureHelper.3
            @Override // java.lang.Runnable
            public void run() {
                SurfaceTextureHelper.this.isQuitting = true;
                SurfaceTextureHelper.this.isRecyclable = recyclable;
                if (!SurfaceTextureHelper.this.isTextureInUse) {
                    SurfaceTextureHelper.this.release();
                }
            }
        };
        if (!isDisposeNoWait) {
            ThreadUtils.invokeAtFrontUninterruptibly(this.handler, runner);
        } else {
            this.handler.post(runner);
        }
    }

    @Deprecated
    public VideoFrame.I420Buffer textureToYuv(VideoFrame.TextureBuffer textureBuffer) {
        return textureBuffer.toI420();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean updateTexImage() {
        synchronized (EglBase.lock) {
            try {
                this.surfaceTexture.updateTexImage();
            } catch (Throwable e) {
                logE("surfaceTexture updateTexImage failed", e);
                return false;
            }
        }
        return true;
    }

    private void tryDeliverTextureFrame() {
        int tex_w;
        int tex_h;
        int tex_w2;
        int tex_w3;
        MediaCodecGrayConfig mediaCodecGrayConfig;
        MediaCodecGrayConfig mediaCodecGrayConfig2;
        MediaCodecGrayConfig mediaCodecGrayConfig3;
        if (this.handler.getLooper().getThread() != Thread.currentThread()) {
            throw new IllegalStateException("Wrong thread.");
        }
        if (this.isQuitting || !this.hasPendingTexture || this.isTextureInUse || this.listener == null) {
            return;
        }
        if (WebrtcGrayConfig.sHWDecoderSetTextureSizeSynchronously || ((mediaCodecGrayConfig3 = this.mcGrayConfig) != null && mediaCodecGrayConfig3.HWDecoderSetTextureSizeSynchronously)) {
            synchronized (this.textureSizeLock) {
                tex_w = this.textureWidth;
                tex_h = this.textureHeight;
            }
            tex_w2 = tex_w;
            tex_w3 = tex_h;
        } else {
            tex_w2 = this.textureWidth;
            tex_w3 = this.textureHeight;
        }
        if (tex_w2 == 0 || tex_w3 == 0) {
            logE("Texture size has not been set.", null);
            updateTexImage();
            this.isTextureInUse = false;
            if (WebrtcGrayConfig.sFixHWEncoderDecoderLogic || ((mediaCodecGrayConfig = this.mcGrayConfig) != null && mediaCodecGrayConfig.fixHWEncoderDecoderLogic)) {
                this.listener.onFrame(null);
                return;
            }
            return;
        }
        this.isTextureInUse = true;
        this.hasPendingTexture = false;
        if (!updateTexImage()) {
            this.isTextureInUse = false;
            if (WebrtcGrayConfig.sFixHWEncoderDecoderLogic || ((mediaCodecGrayConfig2 = this.mcGrayConfig) != null && mediaCodecGrayConfig2.fixHWEncoderDecoderLogic)) {
                this.listener.onFrame(null);
                return;
            }
            return;
        }
        long timestampNs = this.surfaceTexture.getTimestamp();
        FpsKeeper fpsKeeper = this.fpsKeeper;
        if (fpsKeeper == null || timestampNs <= 0 || fpsKeeper.KeepIt(timestampNs)) {
            this.mTextureInfo.id = this.oesTextureId;
            this.mTextureInfo.type = VideoFrame.TextureBuffer.Type.OES;
            this.mTextureInfo.width = tex_w2;
            this.mTextureInfo.height = tex_w3;
            float[] transformMatrix = new float[16];
            this.surfaceTexture.getTransformMatrix(transformMatrix);
            this.mTextureInfo.textureRotation = 0;
            this.mTextureInfo.transformMatrix = transformMatrix;
            this.mTextureInfo.dropFrame = false;
            TextureFilter textureFilter = this.mFilter;
            if (textureFilter != null && textureFilter.isWorking()) {
                ThreadUtils.invokeAtFrontUninterruptibly(this.handler, new Runnable() { // from class: org.webrtc.mozi.SurfaceTextureHelper.4
                    @Override // java.lang.Runnable
                    public void run() {
                        if (SurfaceTextureHelper.this.mFilter != null && SurfaceTextureHelper.this.mFilter.isWorking()) {
                            if (SurfaceTextureHelper.this.mTextureInfo.filterMs == null) {
                                SurfaceTextureHelper.this.mTextureInfo.filterMs = new HashMap();
                            } else {
                                SurfaceTextureHelper.this.mTextureInfo.filterMs.clear();
                            }
                            SurfaceTextureHelper.this.mFilter.filter(SurfaceTextureHelper.this.eglBase, SurfaceTextureHelper.this.mTextureInfo);
                            if (SurfaceTextureHelper.this.mTextureInfo.filterMs != null) {
                                Integer totalMs = 0;
                                for (Map.Entry<String, Integer> entry : SurfaceTextureHelper.this.mTextureInfo.filterMs.entrySet()) {
                                    String key = entry.getKey();
                                    Integer value = entry.getValue();
                                    if (value.intValue() > 0) {
                                        totalMs = Integer.valueOf(totalMs.intValue() + value.intValue());
                                        SurfaceTextureHelper.this.mStatistics.addVideoProcessDetail(key, value.intValue());
                                    }
                                }
                                SurfaceTextureHelper.this.mStatistics.addVideoProcessTime(totalMs.intValue());
                            }
                        }
                    }
                });
            }
            if (this.mTextureInfo.dropFrame) {
                this.isTextureInUse = false;
                return;
            }
            VideoFrame.Buffer buffer = new TextureBufferImpl(this.mTextureInfo.width, this.mTextureInfo.height, this.mTextureInfo.type, this.mTextureInfo.id, RendererCommon.convertMatrixToAndroidGraphicsMatrix(this.mTextureInfo.transformMatrix), this.mTextureInfo.textureRotation, this.handler, this.yuvConverter, this.alignmentDrawer, SurfaceTextureHelper$$Lambda$7.lambdaFactory$(this));
            VideoFrame frame = new VideoFrame(buffer, this.frameRotation, timestampNs);
            this.listener.onFrame(frame);
            frame.release();
            return;
        }
        this.isTextureInUse = false;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void release() {
        logD("start to release SurfaceTextureHelper");
        if (this.handler.getLooper().getThread() != Thread.currentThread()) {
            throw new IllegalStateException("Wrong thread.");
        }
        if (this.isTextureInUse || !this.isQuitting) {
            throw new IllegalStateException("Unexpected release.");
        }
        if (this.isRecyclable && CacheHelper.cacheable(SurfaceTextureHelper.class)) {
            CacheHelper.offer(SurfaceTextureHelper.class, TAG, this);
            logD("cache SurfaceTextureHelper");
            return;
        }
        this.yuvConverter.release();
        this.alignmentDrawer.release();
        GLES20.glDeleteTextures(1, new int[]{this.oesTextureId}, 0);
        this.surfaceTexture.release();
        TextureFilter textureFilter = this.mFilter;
        if (textureFilter != null) {
            textureFilter.release();
            this.mFilter = null;
        }
        this.eglBase.release();
        Monitor monitor = sMonitor;
        if (monitor != null) {
            monitor.onRelease(this.mName);
        }
        this.handler.getLooper().quit();
        logD("release SurfaceTextureHelper done");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void logD(String msg) {
        Logging.d(TAG, msg + ", this:" + this);
    }

    private void logE(String msg, Throwable e) {
        if (e != null) {
            Logging.e(TAG, msg + ", this:" + this, e);
            return;
        }
        Logging.e(TAG, msg + ", this:" + this);
    }

    @Override // org.webrtc.mozi.cache.Cache.Entry
    public void reuse() {
        ThreadUtils.invokeAtFrontUninterruptibly(this.handler, SurfaceTextureHelper$$Lambda$8.lambdaFactory$(this));
    }

    static /* synthetic */ void lambda$reuse$15(SurfaceTextureHelper surfaceTextureHelper) {
        surfaceTextureHelper.logD("reuse");
        surfaceTextureHelper.isRecycled = false;
    }

    @Override // org.webrtc.mozi.cache.Cache.Entry
    public void recycle() {
        ThreadUtils.invokeAtFrontUninterruptibly(this.handler, SurfaceTextureHelper$$Lambda$9.lambdaFactory$(this));
    }

    static /* synthetic */ void lambda$recycle$16(SurfaceTextureHelper surfaceTextureHelper) {
        surfaceTextureHelper.logD("recycle");
        if (surfaceTextureHelper.hasPendingTexture) {
            surfaceTextureHelper.logD("updateTexImage when recycle");
            surfaceTextureHelper.updateTexImage();
        }
        TextureFilter textureFilter = surfaceTextureHelper.mFilter;
        if (textureFilter != null) {
            textureFilter.release();
            surfaceTextureHelper.mFilter = null;
        }
        surfaceTextureHelper.textureWidth = 0;
        surfaceTextureHelper.textureHeight = 0;
        surfaceTextureHelper.frameRotation = 0;
        surfaceTextureHelper.isTextureInUse = false;
        surfaceTextureHelper.hasPendingTexture = false;
        surfaceTextureHelper.isQuitting = false;
        surfaceTextureHelper.isRecycled = true;
        surfaceTextureHelper.textureDelivered.set(0L);
        surfaceTextureHelper.textureReturned.set(0L);
    }

    @Override // org.webrtc.mozi.cache.Cache.Entry
    public void cleanup() {
        logD("cleanup");
        disposeInner(false, false);
    }

    public long getTextureDelivered() {
        return this.textureDelivered.get();
    }

    public long getTextureReturned() {
        return this.textureReturned.get();
    }

    public void setTextureFilter(TextureFilter filter) {
        this.mFilter = filter;
    }

    public void setFpsKeeper(FpsKeeper fpsKeeper) {
        this.fpsKeeper = fpsKeeper;
    }
}
