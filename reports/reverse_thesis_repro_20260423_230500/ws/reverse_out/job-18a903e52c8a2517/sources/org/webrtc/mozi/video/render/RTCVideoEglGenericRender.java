package org.webrtc.mozi.video.render;

import android.graphics.Color;
import android.graphics.Matrix;
import android.graphics.Point;
import android.graphics.RectF;
import android.graphics.SurfaceTexture;
import android.opengl.GLES20;
import android.os.Build;
import android.os.Handler;
import android.view.Surface;
import java.text.DecimalFormat;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.webrtc.mozi.EglBase;
import org.webrtc.mozi.GlTextureFrameBuffer;
import org.webrtc.mozi.Logging;
import org.webrtc.mozi.RTCVideoEglDrawer;
import org.webrtc.mozi.RendererCommon;
import org.webrtc.mozi.ThreadUtils;
import org.webrtc.mozi.VideoFrame;
import org.webrtc.mozi.VideoFrameDrawer;
import org.webrtc.mozi.video.render.IRTCVideoRender;
import org.webrtc.mozi.video.render.egl.RTCEglController;
import org.webrtc.mozi.video.render.egl.RTCEglPool;
import org.webrtc.mozi.video.render.egl.RTCEglPoolStandard;

/* JADX INFO: loaded from: classes3.dex */
public class RTCVideoEglGenericRender implements IRTCVideoRender {
    private static final int EVENT_RECEIVE_FRAME = 1;
    private static final int EVENT_RENDER_FRAME = 2;
    private static final long LOG_INTERVAL_SEC = 4;
    private static final String TAG = "MoziVideoEglGenericRender";
    private boolean autoFitViewport;
    private RendererCommon.GlDrawer drawer;
    private RTCEglController eglBase;
    private final VideoFrameDrawer frameDrawer;
    private IRTCVideoRender.FrameRenderInterceptor frameRenderInterceptor;
    private int frameRotation;
    private int framesDropped;
    private int framesReceived;
    private int framesRendered;
    private int heightMeasureSpec;
    private boolean isFirstFrameRendered;
    private int layoutHeight;
    private int layoutWidth;
    protected final String name;
    private VideoFrame pendingFrame;
    private long renderSwapBufferTimeNs;
    private Handler renderThreadHandler;
    private long renderTimeNs;
    private IRTCVideoRender.FrameRenderListener rendererEvents;
    private boolean rotateByOrientation;
    private int rotatedFrameHeight;
    private int rotatedFrameWidth;
    private long statisticsStartTimeNs;
    private int surfaceHeight;
    private int surfaceWidth;
    private int widthMeasureSpec;
    private final Object handlerLock = new Object();
    private RTCEglPool RTCEglPool = RTCEglPoolStandard.getInstance();
    private final Matrix drawMatrix = new Matrix();
    private final Object frameLock = new Object();
    private float layoutAspectRatio = 0.0f;
    private boolean mirror = false;
    private final Object statisticsLock = new Object();
    private final GlTextureFrameBuffer bitmapTextureFramebuffer = new GlTextureFrameBuffer(6408);
    private final RendererCommon.VideoLayoutMeasure videoLayoutMeasure = new RendererCommon.VideoLayoutMeasure();
    private final Object layoutLock = new Object();
    private RTCVideoRenderOptions renderOptions = RTCVideoRenderOptions.EMPTY;
    private final float[] backgroundColorArray = new float[4];
    private final Matrix transformMatrix = new Matrix();
    private final RectF renderSrcRect = new RectF();
    private final RectF renderDistRect = new RectF();
    private final RectF viewportSrcRect = new RectF();
    private final RectF viewportDistRect = new RectF();
    private final Matrix tempMatrix = new Matrix();
    private final float[] tempValues = new float[9];
    private final int[] transformValues = new int[4];
    private RendererCommon.ScalingType scalingType = RendererCommon.ScalingType.SCALE_ASPECT_BALANCED;
    private final Runnable logStatisticsRunnable = new Runnable() { // from class: org.webrtc.mozi.video.render.RTCVideoEglGenericRender.1
        @Override // java.lang.Runnable
        public void run() {
            RTCVideoEglGenericRender.this.logStatistics();
            synchronized (RTCVideoEglGenericRender.this.handlerLock) {
                if (RTCVideoEglGenericRender.this.renderThreadHandler != null) {
                    RTCVideoEglGenericRender.this.renderThreadHandler.removeCallbacks(RTCVideoEglGenericRender.this.logStatisticsRunnable);
                    RTCVideoEglGenericRender.this.renderThreadHandler.postDelayed(RTCVideoEglGenericRender.this.logStatisticsRunnable, TimeUnit.SECONDS.toMillis(RTCVideoEglGenericRender.LOG_INTERVAL_SEC));
                }
            }
        }
    };
    private final EglSurfaceCreation eglSurfaceCreationRunnable = new EglSurfaceCreation();
    private final Runnable redrawRunnable = new Runnable() { // from class: org.webrtc.mozi.video.render.RTCVideoEglGenericRender.5
        @Override // java.lang.Runnable
        public void run() throws Throwable {
            int viewportWidth;
            int viewportHeight;
            int viewportX;
            int viewportY;
            int viewportY2;
            int viewportWidth2;
            int viewportX2;
            int viewportHeight2;
            float h;
            float w;
            float scaleX;
            float coordX;
            if (RTCVideoEglGenericRender.this.eglBase == null || !RTCVideoEglGenericRender.this.eglBase.hasSurface() || RTCVideoEglGenericRender.this.eglSurfaceCreationRunnable.surface == null) {
                RTCVideoEglGenericRender.this.logD("skip renderLastFrame - No surface");
                return;
            }
            RTCVideoEglGenericRender rTCVideoEglGenericRender = RTCVideoEglGenericRender.this;
            if (!rTCVideoEglGenericRender.makeCurrentSafely(rTCVideoEglGenericRender.eglBase)) {
                return;
            }
            RTCVideoEglDrawer eglDrawer = (RTCVideoEglDrawer) RTCVideoEglGenericRender.this.frameDrawer;
            if (!eglDrawer.canRedraw()) {
                RTCVideoEglGenericRender.this.logD("skip renderLastFrame - can't redraw");
                return;
            }
            RTCVideoEglGenericRender.this.logD("renderLastFrame");
            synchronized (RTCVideoEglGenericRender.this.layoutLock) {
                try {
                    int surfaceW = RTCVideoEglGenericRender.this.surfaceWidth;
                    int surfaceH = RTCVideoEglGenericRender.this.surfaceHeight;
                    if (RTCVideoEglGenericRender.this.renderOptions.enableRenderOpenGLMatrixScale) {
                        if (surfaceW == 0) {
                            try {
                                surfaceW = RTCVideoEglGenericRender.this.eglBase.surfaceWidth();
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
                        }
                        if (surfaceH == 0) {
                            surfaceH = RTCVideoEglGenericRender.this.eglBase.surfaceHeight();
                        }
                    }
                    if (RTCVideoEglGenericRender.this.autoFitViewport) {
                        viewportWidth = RTCVideoEglGenericRender.this.layoutWidth;
                        try {
                            viewportHeight = RTCVideoEglGenericRender.this.layoutHeight;
                            try {
                                viewportX = (surfaceW - viewportWidth) / 2;
                            } catch (Throwable th3) {
                                th = th3;
                            }
                        } catch (Throwable th4) {
                            th = th4;
                        }
                        try {
                            viewportY = (surfaceH - viewportHeight) / 2;
                        } catch (Throwable th5) {
                            th = th5;
                            while (true) {
                                throw th;
                            }
                        }
                    } else {
                        viewportWidth = surfaceW;
                        viewportHeight = surfaceH;
                        viewportX = 0;
                        viewportY = 0;
                    }
                    try {
                        int[] transformValues = RTCVideoEglGenericRender.this.transformViewportRect();
                        if (transformValues != null) {
                            try {
                                int viewportX3 = transformValues[0] + viewportX;
                                try {
                                    int viewportX4 = transformValues[1];
                                    int viewportY3 = viewportX4 + viewportY;
                                    try {
                                        int viewportY4 = transformValues[2];
                                        viewportWidth = viewportY4;
                                        int viewportHeight3 = transformValues[3];
                                        viewportY2 = viewportX3;
                                        viewportWidth2 = viewportWidth;
                                        viewportX2 = viewportHeight3;
                                        viewportHeight2 = viewportY3;
                                    } catch (Throwable th6) {
                                        th = th6;
                                        while (true) {
                                            throw th;
                                        }
                                    }
                                } catch (Throwable th7) {
                                    th = th7;
                                }
                            } catch (Throwable th8) {
                                th = th8;
                            }
                        } else {
                            viewportWidth2 = viewportWidth;
                            int i = viewportX;
                            viewportX2 = viewportHeight;
                            viewportHeight2 = viewportY;
                            viewportY2 = i;
                        }
                        try {
                            float frameWidth = RTCVideoEglGenericRender.this.rotatedFrameWidth;
                            float frameHeight = RTCVideoEglGenericRender.this.rotatedFrameHeight;
                            float scaleX2 = RTCVideoEglGenericRender.this.layoutWidth / frameWidth;
                            float scaleY = RTCVideoEglGenericRender.this.layoutHeight / frameHeight;
                            if (RTCVideoEglGenericRender.this.scalingType == RendererCommon.ScalingType.SCALE_ASPECT_FILL) {
                                float scaleX3 = Math.max(scaleX2, scaleY);
                                w = frameWidth * scaleX3;
                                float h2 = frameHeight * scaleX3;
                                float coordX2 = w / RTCVideoEglGenericRender.this.layoutWidth;
                                float coordY = h2 / RTCVideoEglGenericRender.this.layoutHeight;
                                h = h2;
                                scaleX = coordX2;
                                coordX = coordY;
                            } else if (RTCVideoEglGenericRender.this.scalingType == RendererCommon.ScalingType.SCALE_ASPECT_FIT) {
                                float scaleX4 = Math.min(scaleX2, scaleY);
                                w = frameWidth * scaleX4;
                                float h3 = frameHeight * scaleX4;
                                float coordX3 = w / RTCVideoEglGenericRender.this.layoutWidth;
                                float coordY2 = h3 / RTCVideoEglGenericRender.this.layoutHeight;
                                h = h3;
                                scaleX = coordX3;
                                coordX = coordY2;
                            } else {
                                h = 0.0f;
                                w = 0.0f;
                                scaleX = 1.0f;
                                coordX = 1.0f;
                            }
                            float w2 = -scaleX;
                            float[] verticesCoord = {-scaleX, -coordX, scaleX, -coordX, w2, coordX, scaleX, coordX};
                            int i2 = 0;
                            while (i2 < 1) {
                                float coordY3 = coordX;
                                float frameWidth2 = frameWidth;
                                int viewportY5 = viewportHeight2;
                                GLES20.glClearColor(RTCVideoEglGenericRender.this.backgroundColorArray[0], RTCVideoEglGenericRender.this.backgroundColorArray[1], RTCVideoEglGenericRender.this.backgroundColorArray[2], RTCVideoEglGenericRender.this.backgroundColorArray[3]);
                                GLES20.glClear(16384);
                                int error = GLES20.glGetError();
                                if (error != 0) {
                                    RTCVideoEglGenericRender.this.logD("before redrawFrame err:" + error);
                                }
                                RTCVideoEglDrawer rTCVideoEglDrawer = eglDrawer;
                                int error2 = viewportY2;
                                int viewportHeight4 = viewportX2;
                                RTCVideoEglDrawer eglDrawer2 = eglDrawer;
                                int viewportX5 = viewportY2;
                                int viewportX6 = viewportWidth2;
                                rTCVideoEglDrawer.redrawFrame(RTCVideoEglGenericRender.this.drawer, verticesCoord, RTCVideoEglGenericRender.this.mirror, error2, viewportY5, viewportX6, viewportHeight4);
                                RTCVideoEglGenericRender rTCVideoEglGenericRender2 = RTCVideoEglGenericRender.this;
                                rTCVideoEglGenericRender2.swapBufferSafely(rTCVideoEglGenericRender2.eglBase);
                                i2++;
                                viewportY2 = viewportX5;
                                viewportWidth2 = viewportWidth2;
                                coordX = coordY3;
                                frameWidth = frameWidth2;
                                viewportHeight2 = viewportY5;
                                viewportX2 = viewportHeight4;
                                eglDrawer = eglDrawer2;
                                h = h;
                            }
                            int viewportY6 = viewportHeight2;
                            int viewportHeight5 = viewportX2;
                            int viewportX7 = viewportY2;
                            RTCVideoEglGenericRender.this.logD("redraw frame," + viewportX7 + "," + viewportY6 + "," + viewportWidth2 + "," + viewportHeight5);
                        } catch (Throwable th9) {
                            th = th9;
                            while (true) {
                                throw th;
                            }
                        }
                    } catch (Throwable th10) {
                        th = th10;
                    }
                } catch (Throwable th11) {
                    th = th11;
                }
            }
        }
    };

    private static class EglSurfaceCreation implements Runnable {
        private RTCEglController eglBase;
        private VideoFrameDrawer frameDrawer;
        private String name;
        private volatile Object surface;
        private float[] surfaceColorArray;

        private EglSurfaceCreation() {
        }

        public synchronized void setSurface(Object surface) {
            this.surface = surface;
            Logging.d(RTCVideoEglGenericRender.TAG, "setSurface " + surface);
        }

        public synchronized boolean isSurfaceValid() {
            if (this.surface instanceof Surface) {
                return ((Surface) this.surface).isValid();
            }
            if (this.surface instanceof SurfaceTexture) {
                if (Build.VERSION.SDK_INT < 26) {
                    return true;
                }
                return !((SurfaceTexture) this.surface).isReleased();
            }
            return false;
        }

        public synchronized void setEglController(RTCEglController eglBase) {
            this.eglBase = eglBase;
        }

        public synchronized void setSurfaceColor(float[] surfaceColorArray) {
            this.surfaceColorArray = surfaceColorArray;
        }

        public synchronized void setDrawer(VideoFrameDrawer frameDrawer) {
            this.frameDrawer = frameDrawer;
        }

        public synchronized void setName(String name) {
            this.name = name;
        }

        @Override // java.lang.Runnable
        public synchronized void run() {
            Logging.d(RTCVideoEglGenericRender.TAG, "EglSurfaceCreation " + this.name);
            if (this.surface != null && this.eglBase != null && !this.eglBase.hasSurface()) {
                if (this.surface instanceof Surface) {
                    this.eglBase.createSurface((Surface) this.surface);
                } else if (this.surface instanceof SurfaceTexture) {
                    this.eglBase.createSurface((SurfaceTexture) this.surface);
                } else {
                    throw new IllegalStateException("Invalid surface: " + this.surface + ", " + this.name);
                }
                this.eglBase.makeCurrent();
                GLES20.glPixelStorei(3317, 1);
                if (this.frameDrawer != null) {
                    RTCVideoEglDrawer eglDrawer = (RTCVideoEglDrawer) this.frameDrawer;
                    if (eglDrawer.canRedraw()) {
                        Logging.d(RTCVideoEglGenericRender.TAG, "can redraw not clear background " + this.name);
                        return;
                    }
                }
                Logging.d(RTCVideoEglGenericRender.TAG, "EglSurfaceCreation success " + this.name);
            } else {
                Logging.d(RTCVideoEglGenericRender.TAG, "EglSurfaceCreation fail as surface:" + this.surface + ", eglBase:" + this.eglBase + ", hasSurface:" + this.eglBase.hasSurface() + " " + this.name);
            }
        }
    }

    public RTCVideoEglGenericRender(String name, boolean useVideoEglDrawer) {
        this.name = name;
        this.frameDrawer = useVideoEglDrawer ? new RTCVideoEglDrawer() : new VideoFrameDrawer();
    }

    @Override // org.webrtc.mozi.video.render.IRTCVideoRender
    public void init(EglBase.Context sharedContext, IRTCVideoRender.FrameRenderListener events, int[] configAttributes, RendererCommon.GlDrawer drawer) {
        this.rendererEvents = events;
        synchronized (this.layoutLock) {
            this.isFirstFrameRendered = false;
            this.rotatedFrameWidth = 0;
            this.rotatedFrameHeight = 0;
            this.frameRotation = 0;
        }
        synchronized (this.handlerLock) {
            if (this.renderThreadHandler != null) {
                logD(this.name + "Already initialized, return");
                return;
            }
            logD("initializing.");
            this.drawer = drawer;
            RTCEglController rTCEglControllerCreate = this.RTCEglPool.create(sharedContext, configAttributes);
            this.eglBase = rTCEglControllerCreate;
            rTCEglControllerCreate.setTraceId(this.name);
            this.renderThreadHandler = this.eglBase.getRenderHandler(TAG);
            this.eglSurfaceCreationRunnable.setEglController(this.eglBase);
            this.eglSurfaceCreationRunnable.setDrawer(this.frameDrawer);
            this.eglSurfaceCreationRunnable.setName(this.name);
            postToRenderThread(this.eglSurfaceCreationRunnable, true, false);
            resetStatistics(System.nanoTime());
            this.renderThreadHandler.postDelayed(this.logStatisticsRunnable, TimeUnit.SECONDS.toMillis(LOG_INTERVAL_SEC));
        }
    }

    @Override // org.webrtc.mozi.video.render.IRTCVideoRender
    public void createSurface(Surface surface, boolean autoFitViewport, int surfaceColor) {
        if (surface != null) {
            logD("createSurface.");
            if (surfaceColor != 0) {
                this.backgroundColorArray[0] = Color.red(surfaceColor) / 255.0f;
                this.backgroundColorArray[1] = Color.green(surfaceColor) / 255.0f;
                this.backgroundColorArray[2] = Color.blue(surfaceColor) / 255.0f;
                this.backgroundColorArray[3] = Color.alpha(surfaceColor) / 255.0f;
            }
            this.autoFitViewport = autoFitViewport;
            this.eglSurfaceCreationRunnable.setSurface(surface);
            this.eglSurfaceCreationRunnable.setSurfaceColor(this.backgroundColorArray);
            this.eglSurfaceCreationRunnable.setDrawer(this.frameDrawer);
            postToRenderThread(this.eglSurfaceCreationRunnable, true, false);
            logD("try redraw");
            if (this.frameDrawer instanceof RTCVideoEglDrawer) {
                postToRenderThread(this.redrawRunnable, false, false);
                return;
            }
            return;
        }
        throw new IllegalStateException("Input must be either a Surface or SurfaceTexture");
    }

    @Override // org.webrtc.mozi.video.render.IRTCVideoRender
    public void setSurfaceSize(int width, int height) {
        boolean isSurfaceSizeChange = false;
        synchronized (this.layoutLock) {
            if (this.surfaceWidth != width || this.surfaceHeight != height) {
                this.surfaceWidth = width;
                this.surfaceHeight = height;
                isSurfaceSizeChange = true;
            }
        }
        if (isSurfaceSizeChange) {
            logD("setSurfaceSize. " + width + " x " + height);
            if (this.isFirstFrameRendered && this.renderOptions.redrawLastFrameWhenSurfaceSizeChange) {
                renderLastFrame();
            }
        }
    }

    @Override // org.webrtc.mozi.video.render.IRTCVideoRender
    public void setRotateByOrientation(boolean rotateByOrientation) {
        this.rotateByOrientation = rotateByOrientation;
    }

    @Override // org.webrtc.mozi.video.render.IRTCVideoRender
    public void destroySurface() {
        logD("destroySurface.");
        final CountDownLatch completionLatch = new CountDownLatch(1);
        releaseEglSurface(new Runnable() { // from class: org.webrtc.mozi.video.render.RTCVideoEglGenericRender.2
            @Override // java.lang.Runnable
            public void run() {
                completionLatch.countDown();
            }
        });
        ThreadUtils.awaitUninterruptibly(completionLatch);
        logD("destroySurface done.");
    }

    @Override // org.webrtc.mozi.video.render.IRTCVideoRender
    public void release() {
        logD("release.");
        final CountDownLatch eglCleanupBarrier = new CountDownLatch(1);
        synchronized (this.handlerLock) {
            if (this.renderThreadHandler == null) {
                logD("already released");
                return;
            }
            this.eglSurfaceCreationRunnable.setEglController(null);
            this.renderThreadHandler.removeCallbacks(this.eglSurfaceCreationRunnable);
            this.renderThreadHandler.removeCallbacks(this.logStatisticsRunnable);
            this.renderThreadHandler.removeCallbacks(this.redrawRunnable);
            this.renderThreadHandler.postAtFrontOfQueue(new Runnable() { // from class: org.webrtc.mozi.video.render.RTCVideoEglGenericRender.3
                private void releaseEglBase(RTCEglController eglBase) {
                    if (eglBase != null) {
                        RTCVideoEglGenericRender.this.logD("eglBase detach and release.");
                        eglBase.detachCurrent();
                        eglBase.release();
                    }
                }

                @Override // java.lang.Runnable
                public void run() {
                    if (RTCVideoEglGenericRender.this.drawer != null) {
                        RTCVideoEglGenericRender.this.drawer.release();
                        RTCVideoEglGenericRender.this.drawer = null;
                    }
                    RTCVideoEglGenericRender.this.logD("release frameDrawer");
                    RTCVideoEglGenericRender.this.frameDrawer.release();
                    RTCVideoEglGenericRender.this.bitmapTextureFramebuffer.release();
                    RTCEglController egl = RTCVideoEglGenericRender.this.eglBase;
                    RTCVideoEglGenericRender.this.eglBase = null;
                    RTCVideoEglGenericRender.this.rendererEvents = null;
                    eglCleanupBarrier.countDown();
                    releaseEglBase(egl);
                }
            });
            this.renderThreadHandler = null;
            ThreadUtils.awaitUninterruptibly(eglCleanupBarrier);
            synchronized (this.frameLock) {
                if (this.pendingFrame != null) {
                    this.pendingFrame.release();
                    this.pendingFrame = null;
                }
            }
            logD("releasing done.");
        }
    }

    @Override // org.webrtc.mozi.video.render.IRTCVideoRender
    public void setEglPool(RTCEglPool RTCEglPool) {
        if (RTCEglPool != null) {
            this.RTCEglPool = RTCEglPool;
        }
    }

    @Override // org.webrtc.mozi.video.render.IRTCVideoRender
    public void setRenderOptions(RTCVideoRenderOptions renderOptions) {
        if (renderOptions != null) {
            this.renderOptions = renderOptions;
        }
    }

    @Override // org.webrtc.mozi.video.render.IRTCVideoRender
    public void setRenderInterceptor(IRTCVideoRender.FrameRenderInterceptor interceptor) {
        this.frameRenderInterceptor = interceptor;
    }

    @Override // org.webrtc.mozi.video.render.IRTCVideoRender
    public void setSurfaceMeasureSpec(int widthSpec, int heightSpec) {
        logD("setSurfaceMeasureSpec. " + widthSpec + "x" + heightSpec);
        this.widthMeasureSpec = widthSpec;
        this.heightMeasureSpec = heightSpec;
        updateLayoutAspectRatio();
    }

    @Override // org.webrtc.mozi.video.render.IRTCVideoRender
    public void setTransformMatrix(Matrix matrix) {
        if (!this.renderOptions.enableRenderOpenGLMatrixScale) {
            return;
        }
        logD("setTransformMatrix : " + matrix);
        synchronized (this.layoutLock) {
            this.transformMatrix.set(matrix);
        }
        if (this.renderOptions.redrawLastFrameWhenSurfaceSizeChange && !this.renderSrcRect.isEmpty()) {
            renderLastFrame();
        }
    }

    @Override // org.webrtc.mozi.video.render.IRTCVideoRender
    public void setScalingType(RendererCommon.ScalingType hMatchScaleType, RendererCommon.ScalingType hMismatchScaleType, RendererCommon.ScalingType vMatchScaleType, RendererCommon.ScalingType vMismatchScaleType) {
        this.scalingType = hMatchScaleType;
        this.videoLayoutMeasure.setScalingType(hMatchScaleType, hMismatchScaleType, vMatchScaleType, vMismatchScaleType);
        updateLayoutAspectRatio();
    }

    @Override // org.webrtc.mozi.video.render.IRTCVideoRender
    public void setMirror(boolean mirror) {
        logD("setMirror: " + mirror);
        synchronized (this.layoutLock) {
            this.mirror = mirror;
        }
    }

    @Override // org.webrtc.mozi.video.render.IRTCVideoRender
    public void renderFrame(VideoFrame videoFrame) {
        boolean z;
        notifyCallbacks(videoFrame, 1);
        updateFrameDimensionsAndReportEvents(videoFrame);
        if (this.rotateByOrientation && !this.renderOptions.redrawLastFrameWhenSurfaceSizeChange && isRenderOrientationChanged()) {
            clearImage(1);
            return;
        }
        synchronized (this.statisticsLock) {
            this.framesReceived++;
        }
        synchronized (this.handlerLock) {
            if (this.renderThreadHandler == null) {
                logD("dropping frame - Not initialized or already released.");
                return;
            }
            synchronized (this.frameLock) {
                z = this.pendingFrame != null;
                if (z) {
                    this.pendingFrame.release();
                }
                this.pendingFrame = videoFrame;
                videoFrame.retain();
                final RTCEglController rTCEglController = this.eglBase;
                postToRenderThread(new Runnable() { // from class: org.webrtc.mozi.video.render.RTCVideoEglGenericRender.4
                    @Override // java.lang.Runnable
                    public void run() throws Throwable {
                        RTCVideoEglGenericRender.this.renderFrameOnRenderThread(rTCEglController);
                    }
                }, false, false);
            }
            if (z) {
                synchronized (this.statisticsLock) {
                    this.framesDropped++;
                }
            }
        }
    }

    private void renderLastFrame() {
        if (this.frameDrawer instanceof RTCVideoEglDrawer) {
            postToRenderThread(this.redrawRunnable, true, false);
        }
    }

    private void clearImage(final int count) {
        logD("clearImage " + count);
        postToRenderThread(new Runnable() { // from class: org.webrtc.mozi.video.render.RTCVideoEglGenericRender.6
            @Override // java.lang.Runnable
            public void run() {
                RTCVideoEglGenericRender.this.clearImageOnRenderThread(count);
            }
        }, true, false);
    }

    private void resetRenderState() {
        if (this.renderOptions.optEglRenderResetLocker) {
            synchronized (this.layoutLock) {
                resetRenderStateInner();
            }
        } else {
            synchronized (this.handlerLock) {
                resetRenderStateInner();
            }
        }
    }

    private void resetRenderStateInner() {
        this.isFirstFrameRendered = false;
        this.rotatedFrameWidth = 0;
        this.rotatedFrameHeight = 0;
        this.frameRotation = 0;
        this.transformMatrix.reset();
        this.renderSrcRect.setEmpty();
        VideoFrameDrawer videoFrameDrawer = this.frameDrawer;
        if (videoFrameDrawer instanceof RTCVideoEglDrawer) {
            ((RTCVideoEglDrawer) videoFrameDrawer).clearRedraw();
        }
    }

    private void releaseEglSurface(final Runnable completionCallback) {
        this.eglSurfaceCreationRunnable.setSurface(null);
        synchronized (this.handlerLock) {
            if (this.renderThreadHandler != null) {
                this.renderThreadHandler.removeCallbacks(this.eglSurfaceCreationRunnable);
                this.renderThreadHandler.removeCallbacks(this.redrawRunnable);
                logD("releaseEglSurface");
                postToRenderThread(new Runnable() { // from class: org.webrtc.mozi.video.render.RTCVideoEglGenericRender.7
                    @Override // java.lang.Runnable
                    public void run() {
                        RTCVideoEglGenericRender.this.logD("releaseEglSurface run");
                        if (RTCVideoEglGenericRender.this.eglBase != null) {
                            RTCVideoEglGenericRender.this.logD("eglBase detach and release surface.");
                            RTCVideoEglGenericRender.this.eglBase.detachCurrent();
                            RTCVideoEglGenericRender.this.eglBase.releaseSurface();
                        }
                        completionCallback.run();
                        RTCVideoEglGenericRender.this.logD("releaseEglSurface done");
                    }
                }, true, false);
                logD("releaseEglSurface return");
                return;
            }
            completionCallback.run();
            logD("releaseEglSurface renderThreadHandler is null");
        }
    }

    private void postToRenderThread(Runnable runnable, boolean atFront, boolean replaceRunnable) {
        synchronized (this.handlerLock) {
            if (this.renderThreadHandler != null) {
                if (replaceRunnable) {
                    this.renderThreadHandler.removeCallbacks(runnable);
                }
                if (atFront) {
                    this.renderThreadHandler.postAtFrontOfQueue(runnable);
                } else {
                    this.renderThreadHandler.post(runnable);
                }
            }
        }
    }

    private void resetStatistics(long currentTimeNs) {
        synchronized (this.statisticsLock) {
            this.statisticsStartTimeNs = currentTimeNs;
            this.framesReceived = 0;
            this.framesDropped = 0;
            this.framesRendered = 0;
            this.renderTimeNs = 0L;
            this.renderSwapBufferTimeNs = 0L;
        }
    }

    private void updateLayoutAspectRatio() {
        if (this.widthMeasureSpec != 0 && this.heightMeasureSpec != 0 && this.rotatedFrameWidth != 0 && this.rotatedFrameHeight != 0) {
            int preLayoutWidth = this.layoutWidth;
            int preLayoutHeight = this.layoutHeight;
            synchronized (this.layoutLock) {
                Point size = this.videoLayoutMeasure.measure(this.widthMeasureSpec, this.heightMeasureSpec);
                this.layoutWidth = size.x;
                this.layoutHeight = size.y;
                this.layoutAspectRatio = size.x / size.y;
                int left = (this.widthMeasureSpec - this.layoutWidth) / 2;
                int top = (this.heightMeasureSpec - this.layoutHeight) / 2;
                this.renderSrcRect.set(left, top, this.layoutWidth + left, this.layoutHeight + top);
                logD("setLayoutAspectRatio: " + this.layoutWidth + "x" + this.layoutHeight + ", ratio: " + this.layoutAspectRatio);
            }
            if (this.rendererEvents != null) {
                if (preLayoutWidth != this.layoutWidth || preLayoutHeight != this.layoutHeight) {
                    this.rendererEvents.onRenderRegionChange(this.layoutWidth, this.layoutHeight);
                }
            }
        }
    }

    private boolean isRenderOrientationChanged() {
        int i;
        int i2;
        boolean isRenderOrientationChange = false;
        RTCEglController eglBase = this.eglBase;
        if (eglBase != null) {
            int surfaceWidth = eglBase.surfaceWidth();
            int surfaceHeight = eglBase.surfaceHeight();
            if (surfaceWidth > 0 && surfaceHeight > 0 && (i = this.rotatedFrameWidth) > 0 && (i2 = this.rotatedFrameHeight) > 0) {
                float frameRatio = i / i2;
                float surfaceRatio = eglBase.surfaceWidth() / eglBase.surfaceHeight();
                int frameOrientation = frameRatio > 1.0f ? 2 : 1;
                int surfaceOrientation = surfaceRatio <= 1.0f ? 1 : 2;
                if (surfaceOrientation != frameOrientation) {
                    isRenderOrientationChange = true;
                }
                if (isRenderOrientationChange) {
                    logD("frameOrientation: " + frameOrientation + ", surfaceOrientation: " + surfaceOrientation);
                }
            }
        }
        return isRenderOrientationChange;
    }

    private boolean dropFrameIfSurfaceInvalid(VideoFrame frame) {
        if (this.eglSurfaceCreationRunnable.surface == null) {
            logD("Dropping frame - render destroyed");
            frame.release();
            return true;
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void renderFrameOnRenderThread(RTCEglController renderEglBase) throws Throwable {
        int surfaceWidth;
        int surfaceHeight;
        int viewportWidth;
        int viewportHeight;
        int viewportX;
        int viewportY;
        int viewportWidth2;
        int viewportHeight2;
        int viewportX2;
        int viewportY2;
        float scaleX;
        float h;
        float coordY;
        synchronized (this.frameLock) {
            try {
                if (this.pendingFrame == null) {
                    return;
                }
                VideoFrame frame = this.pendingFrame;
                try {
                    this.pendingFrame = null;
                    RTCEglController rTCEglController = this.eglBase;
                    if (rTCEglController == null || !rTCEglController.hasSurface()) {
                        logD("Dropping frame - No surface");
                        frame.release();
                        return;
                    }
                    if (renderEglBase != null && renderEglBase != this.eglBase) {
                        logD("Dropping frame - Egl group changed");
                        frame.release();
                        return;
                    }
                    if (!dropFrameIfSurfaceInvalid(frame)) {
                        if (!makeCurrentSafely(this.eglBase)) {
                            logD("Dropping frame - surface invalid");
                            frame.release();
                            return;
                        }
                        boolean shouldRenderFrame = !onInterceptFrame(this.eglBase.getEglBase());
                        if (!shouldRenderFrame) {
                            logD("Dropping frame - render intercept.");
                        }
                        long startTimeNs = System.nanoTime();
                        synchronized (this.layoutLock) {
                            try {
                                int surfaceWidth2 = this.surfaceWidth;
                                try {
                                    int surfaceHeight2 = this.surfaceHeight;
                                    try {
                                        int layoutWidth = this.layoutWidth;
                                        try {
                                            int layoutHeight = this.layoutHeight;
                                            try {
                                                float f = this.layoutAspectRatio;
                                                try {
                                                    int[] transformValues = transformViewportRect();
                                                    try {
                                                        this.drawMatrix.reset();
                                                        this.drawMatrix.preTranslate(0.5f, 0.5f);
                                                        if (this.mirror) {
                                                            if (frame.getExtraRotation() == 90 || frame.getExtraRotation() == 270) {
                                                                this.drawMatrix.preRotate(frame.getRotation());
                                                                this.drawMatrix.preScale(-1.0f, 1.0f);
                                                            } else {
                                                                this.drawMatrix.preScale(-1.0f, 1.0f);
                                                                this.drawMatrix.preRotate(frame.getRotation());
                                                            }
                                                        } else {
                                                            this.drawMatrix.preRotate(frame.getRotation());
                                                        }
                                                        this.drawMatrix.preTranslate(-0.5f, -0.5f);
                                                        if (shouldRenderFrame) {
                                                            if (surfaceWidth2 != 0) {
                                                                surfaceWidth = surfaceWidth2;
                                                            } else {
                                                                surfaceWidth = this.eglBase.surfaceWidth();
                                                            }
                                                            if (surfaceHeight2 != 0) {
                                                                surfaceHeight = surfaceHeight2;
                                                            } else {
                                                                surfaceHeight = this.eglBase.surfaceHeight();
                                                            }
                                                            if (this.autoFitViewport) {
                                                                viewportWidth = layoutWidth;
                                                                viewportHeight = layoutHeight;
                                                                viewportX = (surfaceWidth - viewportWidth) / 2;
                                                                viewportY = (surfaceHeight - viewportHeight) / 2;
                                                            } else {
                                                                viewportWidth = surfaceWidth;
                                                                viewportHeight = surfaceHeight;
                                                                viewportX = 0;
                                                                viewportY = 0;
                                                            }
                                                            if (transformValues == null) {
                                                                viewportWidth2 = viewportWidth;
                                                                viewportHeight2 = viewportHeight;
                                                                viewportX2 = viewportX;
                                                                viewportY2 = viewportY;
                                                            } else {
                                                                int viewportX3 = viewportX + transformValues[0];
                                                                int viewportY3 = viewportY + transformValues[1];
                                                                int viewportWidth3 = transformValues[2];
                                                                int viewportHeight3 = transformValues[3];
                                                                viewportWidth2 = viewportWidth3;
                                                                viewportHeight2 = viewportHeight3;
                                                                viewportX2 = viewportX3;
                                                                viewportY2 = viewportY3;
                                                            }
                                                            if (dropFrameIfSurfaceInvalid(frame)) {
                                                                return;
                                                            }
                                                            float frameWidth = frame.getRotatedWidth();
                                                            float frameHeight = frame.getRotatedHeight();
                                                            float scaleX2 = layoutWidth / frameWidth;
                                                            float scaleY = layoutHeight / frameHeight;
                                                            if (this.scalingType == RendererCommon.ScalingType.SCALE_ASPECT_FILL) {
                                                                float scaleX3 = Math.max(scaleX2, scaleY);
                                                                float w = frameWidth * scaleX3;
                                                                float h2 = frameHeight * scaleX3;
                                                                float coordX = w / layoutWidth;
                                                                float coordY2 = h2 / layoutHeight;
                                                                scaleX = scaleX3;
                                                                h = coordY2;
                                                                coordY = coordX;
                                                            } else if (this.scalingType != RendererCommon.ScalingType.SCALE_ASPECT_FIT) {
                                                                scaleX = scaleX2;
                                                                h = 1.0f;
                                                                coordY = 1.0f;
                                                            } else {
                                                                float scaleX4 = Math.min(scaleX2, scaleY);
                                                                float w2 = frameWidth * scaleX4;
                                                                float h3 = frameHeight * scaleX4;
                                                                float coordX2 = w2 / layoutWidth;
                                                                float coordY3 = h3 / layoutHeight;
                                                                scaleX = scaleX4;
                                                                h = coordY3;
                                                                coordY = coordX2;
                                                            }
                                                            float[] verticesCoord = {-coordY, -h, coordY, -h, -coordY, h, coordY, h};
                                                            float[] fArr = this.backgroundColorArray;
                                                            GLES20.glClearColor(fArr[0], fArr[1], fArr[2], fArr[3]);
                                                            GLES20.glClear(16384);
                                                            int error = GLES20.glGetError();
                                                            if (error != 0) {
                                                                logD("before drawFrame err:" + error);
                                                            }
                                                            this.frameDrawer.drawFrame(frame, this.drawer, verticesCoord, this.drawMatrix, viewportX2, viewportY2, viewportWidth2, viewportHeight2);
                                                            long swapBuffersStartTimeNs = System.nanoTime();
                                                            swapBufferSafely(this.eglBase);
                                                            long currentTimeNs = System.nanoTime();
                                                            synchronized (this.statisticsLock) {
                                                                this.framesRendered++;
                                                                this.renderTimeNs += currentTimeNs - startTimeNs;
                                                                this.renderSwapBufferTimeNs += currentTimeNs - swapBuffersStartTimeNs;
                                                            }
                                                        }
                                                        if (shouldRenderFrame) {
                                                            notifyCallbacks(frame, 2);
                                                        }
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
                                            }
                                        } catch (Throwable th5) {
                                            th = th5;
                                        }
                                    } catch (Throwable th6) {
                                        th = th6;
                                    }
                                } catch (Throwable th7) {
                                    th = th7;
                                }
                            } catch (Throwable th8) {
                                th = th8;
                            }
                        }
                    }
                } catch (Throwable th9) {
                    th = th9;
                    while (true) {
                        try {
                            throw th;
                        } catch (Throwable th10) {
                            th = th10;
                        }
                    }
                }
            } catch (Throwable th11) {
                th = th11;
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public int[] transformViewportRect() {
        if (!this.renderOptions.enableRenderOpenGLMatrixScale || this.renderSrcRect.isEmpty() || this.transformMatrix.isIdentity()) {
            return null;
        }
        this.transformMatrix.mapRect(this.renderDistRect, this.renderSrcRect);
        float renderCenterDx = this.renderSrcRect.centerX() - this.renderDistRect.centerX();
        float renderCenterDy = this.renderSrcRect.centerY() - this.renderDistRect.centerY();
        this.viewportSrcRect.set(0.0f, 0.0f, this.layoutWidth, this.layoutHeight);
        this.transformMatrix.getValues(this.tempValues);
        this.tempMatrix.reset();
        Matrix matrix = this.tempMatrix;
        float[] fArr = this.tempValues;
        matrix.postScale(fArr[0], fArr[4], this.viewportSrcRect.left, this.viewportSrcRect.bottom);
        this.tempMatrix.mapRect(this.viewportDistRect, this.viewportSrcRect);
        float viewportCenterDx = this.viewportSrcRect.centerX() - this.viewportDistRect.centerX();
        float viewportCenterDy = this.viewportSrcRect.centerY() - this.viewportDistRect.centerY();
        float viewportX = viewportCenterDx - renderCenterDx;
        float viewportY = viewportCenterDy - renderCenterDy;
        int[] iArr = this.transformValues;
        iArr[0] = (int) viewportX;
        iArr[1] = (int) (-viewportY);
        iArr[2] = (int) this.renderDistRect.width();
        this.transformValues[3] = (int) this.renderDistRect.height();
        return this.transformValues;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void clearImageOnRenderThread(int count) {
        RTCEglController rTCEglController;
        if (this.eglSurfaceCreationRunnable.surface != null && (rTCEglController = this.eglBase) != null && rTCEglController.hasSurface()) {
            logD("clearSurface");
            if (!makeCurrentSafely(this.eglBase)) {
                return;
            }
            for (int i = 0; i < count; i++) {
                float[] fArr = this.backgroundColorArray;
                GLES20.glClearColor(fArr[0], fArr[1], fArr[2], fArr[3]);
                GLES20.glClear(16384);
                swapBufferSafely(this.eglBase);
            }
        }
    }

    private void notifyCallbacks(VideoFrame frame, int eventType) {
        IRTCVideoRender.VideoFrameType frameType;
        IRTCVideoRender.FrameRenderListener rendererEvents = this.rendererEvents;
        if (rendererEvents != null) {
            if (frame.getBuffer() instanceof VideoFrame.TextureBuffer) {
                frameType = IRTCVideoRender.VideoFrameType.TEXTURE;
            } else if (frame.getBuffer() instanceof VideoFrame.I420Buffer) {
                frameType = IRTCVideoRender.VideoFrameType.I420;
            } else {
                frameType = IRTCVideoRender.VideoFrameType.OTHER;
            }
            if (eventType == 1) {
                rendererEvents.onReceiveFrame(frameType);
            } else if (eventType == 2) {
                rendererEvents.onRenderFrame(frameType);
            }
        }
    }

    private boolean onInterceptFrame(EglBase eglBase) {
        IRTCVideoRender.FrameRenderInterceptor frameRenderInterceptor = this.frameRenderInterceptor;
        return frameRenderInterceptor != null && frameRenderInterceptor.onInterceptFrame(eglBase);
    }

    private String averageTimeAsString(long sumTimeNs, int count) {
        if (count <= 0) {
            return "NA";
        }
        return TimeUnit.NANOSECONDS.toMicros(sumTimeNs / ((long) count)) + " μs";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean makeCurrentSafely(RTCEglController eglBase) {
        try {
            eglBase.makeCurrent();
            return true;
        } catch (Throwable ex) {
            String msg = "video egl make failed: " + ex.getMessage();
            logD(msg);
            if (!this.eglSurfaceCreationRunnable.isSurfaceValid()) {
                logD("surface is invalid!");
                return false;
            }
            throw ex;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void swapBufferSafely(RTCEglController eglBase) {
        try {
            eglBase.swapBuffers();
        } catch (Throwable ex) {
            String msg = "video egl swap failed: " + ex.getMessage();
            logD(msg);
            if (!this.eglSurfaceCreationRunnable.isSurfaceValid()) {
                logD("surface is invalid!");
                return;
            }
            throw ex;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void logStatistics() {
        DecimalFormat fpsFormat = new DecimalFormat("#.0");
        long currentTimeNs = System.nanoTime();
        synchronized (this.statisticsLock) {
            long elapsedTimeNs = currentTimeNs - this.statisticsStartTimeNs;
            if (elapsedTimeNs <= 0) {
                return;
            }
            float renderFps = (((long) this.framesRendered) * TimeUnit.SECONDS.toNanos(1L)) / elapsedTimeNs;
            logD("Duration: " + TimeUnit.NANOSECONDS.toMillis(elapsedTimeNs) + " ms. Frames received: " + this.framesReceived + ". Dropped: " + this.framesDropped + ". Rendered: " + this.framesRendered + ". Render fps: " + fpsFormat.format(renderFps) + ". Average render time: " + averageTimeAsString(this.renderTimeNs, this.framesRendered) + ". Average swapBuffer time: " + averageTimeAsString(this.renderSwapBufferTimeNs, this.framesRendered) + ".");
            resetStatistics(currentTimeNs);
        }
    }

    private void updateFrameDimensionsAndReportEvents(VideoFrame frame) {
        IRTCVideoRender.FrameRenderListener rendererEvents = this.rendererEvents;
        synchronized (this.layoutLock) {
            boolean frameRotationChange = true;
            if (!this.isFirstFrameRendered) {
                this.isFirstFrameRendered = true;
                logD("Reporting first rendered frame.");
                if (rendererEvents != null) {
                    rendererEvents.onFirstFrameRendered();
                    rendererEvents.onFirstFrameRenderedWithResolution(frame.getRotatedWidth(), frame.getRotatedHeight());
                }
            }
            if (rendererEvents != null) {
                rendererEvents.onFrameRenderedWithResolution(frame.getRotatedWidth(), frame.getRotatedHeight());
            }
            boolean frameWidthChange = this.rotatedFrameWidth != frame.getRotatedWidth();
            boolean frameHeightChange = this.rotatedFrameHeight != frame.getRotatedHeight();
            if (this.frameRotation == frame.getRotation()) {
                frameRotationChange = false;
            }
            if (frameWidthChange || frameHeightChange || frameRotationChange) {
                logD("Reporting frame resolution changed to " + frame.getBuffer().getWidth() + "x" + frame.getBuffer().getHeight() + " with rotation " + frame.getRotation() + ", " + frame.getRotatedWidth() + "x" + frame.getRotatedHeight());
                this.rotatedFrameWidth = frame.getRotatedWidth();
                this.rotatedFrameHeight = frame.getRotatedHeight();
                this.frameRotation = frame.getRotation();
                if (frameWidthChange || frameHeightChange) {
                    updateLayoutAspectRatio();
                }
                if (rendererEvents != null) {
                    rendererEvents.onFrameResolutionChanged(frame.getBuffer().getWidth(), frame.getBuffer().getHeight(), frame.getRotation());
                }
            }
        }
    }

    public String toString() {
        return this.name + "@" + Integer.toHexString(hashCode());
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void logD(String string) {
        Logging.d(TAG, string + " egl: " + this);
    }
}
