package im.uwrkaxlmjj.ui.components.paint;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.Matrix;
import android.graphics.RectF;
import android.graphics.SurfaceTexture;
import android.opengl.GLES20;
import android.opengl.GLUtils;
import android.os.Looper;
import android.view.MotionEvent;
import android.view.TextureView;
import im.uwrkaxlmjj.messenger.BuildVars;
import im.uwrkaxlmjj.messenger.DispatchQueue;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.ui.components.Size;
import im.uwrkaxlmjj.ui.components.paint.Painting;
import java.util.concurrent.CountDownLatch;
import javax.microedition.khronos.egl.EGL10;
import javax.microedition.khronos.egl.EGLConfig;
import javax.microedition.khronos.egl.EGLContext;
import javax.microedition.khronos.egl.EGLDisplay;
import javax.microedition.khronos.egl.EGLSurface;

/* JADX INFO: loaded from: classes5.dex */
public class RenderView extends TextureView {
    private Bitmap bitmap;
    private Brush brush;
    private int color;
    private RenderViewDelegate delegate;
    private Input input;
    private CanvasInternal internal;
    private int orientation;
    private Painting painting;
    private DispatchQueue queue;
    private boolean shuttingDown;
    private boolean transformedBitmap;
    private UndoStore undoStore;
    private float weight;

    public interface RenderViewDelegate {
        void onBeganDrawing();

        void onFinishedDrawing(boolean z);

        boolean shouldDraw();
    }

    public RenderView(Context context, Painting paint, Bitmap b, int rotation) {
        super(context);
        this.bitmap = b;
        this.orientation = rotation;
        this.painting = paint;
        paint.setRenderView(this);
        setSurfaceTextureListener(new TextureView.SurfaceTextureListener() { // from class: im.uwrkaxlmjj.ui.components.paint.RenderView.1
            @Override // android.view.TextureView.SurfaceTextureListener
            public void onSurfaceTextureAvailable(SurfaceTexture surface, int width, int height) {
                if (surface == null || RenderView.this.internal != null) {
                    return;
                }
                RenderView.this.internal = RenderView.this.new CanvasInternal(surface);
                RenderView.this.internal.setBufferSize(width, height);
                RenderView.this.updateTransform();
                RenderView.this.internal.requestRender();
                if (RenderView.this.painting.isPaused()) {
                    RenderView.this.painting.onResume();
                }
            }

            @Override // android.view.TextureView.SurfaceTextureListener
            public void onSurfaceTextureSizeChanged(SurfaceTexture surface, int width, int height) {
                if (RenderView.this.internal != null) {
                    RenderView.this.internal.setBufferSize(width, height);
                    RenderView.this.updateTransform();
                    RenderView.this.internal.requestRender();
                    RenderView.this.internal.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.paint.RenderView.1.1
                        @Override // java.lang.Runnable
                        public void run() {
                            if (RenderView.this.internal != null) {
                                RenderView.this.internal.requestRender();
                            }
                        }
                    });
                }
            }

            @Override // android.view.TextureView.SurfaceTextureListener
            public boolean onSurfaceTextureDestroyed(SurfaceTexture surface) {
                if (RenderView.this.internal != null && !RenderView.this.shuttingDown) {
                    RenderView.this.painting.onPause(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.paint.RenderView.1.2
                        @Override // java.lang.Runnable
                        public void run() {
                            RenderView.this.internal.shutdown();
                            RenderView.this.internal = null;
                        }
                    });
                }
                return true;
            }

            @Override // android.view.TextureView.SurfaceTextureListener
            public void onSurfaceTextureUpdated(SurfaceTexture surface) {
            }
        });
        this.input = new Input(this);
        this.painting.setDelegate(new Painting.PaintingDelegate() { // from class: im.uwrkaxlmjj.ui.components.paint.RenderView.2
            @Override // im.uwrkaxlmjj.ui.components.paint.Painting.PaintingDelegate
            public void contentChanged(RectF rect) {
                if (RenderView.this.internal != null) {
                    RenderView.this.internal.scheduleRedraw();
                }
            }

            @Override // im.uwrkaxlmjj.ui.components.paint.Painting.PaintingDelegate
            public void strokeCommited() {
            }

            @Override // im.uwrkaxlmjj.ui.components.paint.Painting.PaintingDelegate
            public UndoStore requestUndoStore() {
                return RenderView.this.undoStore;
            }

            @Override // im.uwrkaxlmjj.ui.components.paint.Painting.PaintingDelegate
            public DispatchQueue requestDispatchQueue() {
                return RenderView.this.queue;
            }
        });
    }

    @Override // android.view.View
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        super.onMeasure(widthMeasureSpec, heightMeasureSpec);
    }

    @Override // android.view.View
    public boolean onTouchEvent(MotionEvent event) {
        if (event.getPointerCount() > 1) {
            return false;
        }
        CanvasInternal canvasInternal = this.internal;
        if (canvasInternal == null || !canvasInternal.initialized || !this.internal.ready) {
            return true;
        }
        this.input.process(event);
        return true;
    }

    public void setUndoStore(UndoStore store) {
        this.undoStore = store;
    }

    public void setQueue(DispatchQueue dispatchQueue) {
        this.queue = dispatchQueue;
    }

    public void setDelegate(RenderViewDelegate renderViewDelegate) {
        this.delegate = renderViewDelegate;
    }

    public Painting getPainting() {
        return this.painting;
    }

    private float brushWeightForSize(float size) {
        float paintingWidth = this.painting.getSize().width;
        return (0.00390625f * paintingWidth) + (0.043945312f * paintingWidth * size);
    }

    public int getCurrentColor() {
        return this.color;
    }

    public void setColor(int value) {
        this.color = value;
    }

    public float getCurrentWeight() {
        return this.weight;
    }

    public void setBrushSize(float size) {
        this.weight = brushWeightForSize(size);
    }

    public Brush getCurrentBrush() {
        return this.brush;
    }

    public void setBrush(Brush value) {
        Painting painting = this.painting;
        this.brush = value;
        painting.setBrush(value);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateTransform() {
        Matrix matrix = new Matrix();
        float scale = this.painting != null ? getWidth() / this.painting.getSize().width : 1.0f;
        if (scale <= 0.0f) {
            scale = 1.0f;
        }
        Size paintingSize = getPainting().getSize();
        matrix.preTranslate(getWidth() / 2.0f, getHeight() / 2.0f);
        matrix.preScale(scale, -scale);
        matrix.preTranslate((-paintingSize.width) / 2.0f, (-paintingSize.height) / 2.0f);
        this.input.setMatrix(matrix);
        float[] proj = GLMatrix.LoadOrtho(0.0f, this.internal.bufferWidth, 0.0f, this.internal.bufferHeight, -1.0f, 1.0f);
        float[] effectiveProjection = GLMatrix.LoadGraphicsMatrix(matrix);
        float[] finalProjection = GLMatrix.MultiplyMat4f(proj, effectiveProjection);
        this.painting.setRenderProjection(finalProjection);
    }

    public boolean shouldDraw() {
        RenderViewDelegate renderViewDelegate = this.delegate;
        return renderViewDelegate == null || renderViewDelegate.shouldDraw();
    }

    public void onBeganDrawing() {
        RenderViewDelegate renderViewDelegate = this.delegate;
        if (renderViewDelegate != null) {
            renderViewDelegate.onBeganDrawing();
        }
    }

    public void onFinishedDrawing(boolean moved) {
        RenderViewDelegate renderViewDelegate = this.delegate;
        if (renderViewDelegate != null) {
            renderViewDelegate.onFinishedDrawing(moved);
        }
    }

    public void shutdown() {
        this.shuttingDown = true;
        if (this.internal != null) {
            performInContext(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.paint.RenderView.3
                @Override // java.lang.Runnable
                public void run() {
                    RenderView.this.painting.cleanResources(RenderView.this.transformedBitmap);
                    RenderView.this.internal.shutdown();
                    RenderView.this.internal = null;
                }
            });
        }
        setVisibility(8);
    }

    private class CanvasInternal extends DispatchQueue {
        private final int EGL_CONTEXT_CLIENT_VERSION;
        private final int EGL_OPENGL_ES2_BIT;
        private int bufferHeight;
        private int bufferWidth;
        private Runnable drawRunnable;
        private EGL10 egl10;
        private EGLConfig eglConfig;
        private EGLContext eglContext;
        private EGLDisplay eglDisplay;
        private EGLSurface eglSurface;
        private boolean initialized;
        private long lastRenderCallTime;
        private boolean ready;
        private Runnable scheduledRunnable;
        private SurfaceTexture surfaceTexture;

        public CanvasInternal(SurfaceTexture surface) {
            super("CanvasInternal");
            this.EGL_CONTEXT_CLIENT_VERSION = 12440;
            this.EGL_OPENGL_ES2_BIT = 4;
            this.drawRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.components.paint.RenderView.CanvasInternal.1
                @Override // java.lang.Runnable
                public void run() {
                    if (CanvasInternal.this.initialized && !RenderView.this.shuttingDown) {
                        CanvasInternal.this.setCurrentContext();
                        GLES20.glBindFramebuffer(36160, 0);
                        GLES20.glViewport(0, 0, CanvasInternal.this.bufferWidth, CanvasInternal.this.bufferHeight);
                        GLES20.glClearColor(0.0f, 0.0f, 0.0f, 1.0f);
                        GLES20.glClear(16384);
                        RenderView.this.painting.render();
                        GLES20.glBlendFunc(1, 771);
                        CanvasInternal.this.egl10.eglSwapBuffers(CanvasInternal.this.eglDisplay, CanvasInternal.this.eglSurface);
                        if (!CanvasInternal.this.ready) {
                            RenderView.this.queue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.paint.RenderView.CanvasInternal.1.1
                                @Override // java.lang.Runnable
                                public void run() {
                                    CanvasInternal.this.ready = true;
                                }
                            }, 200L);
                        }
                    }
                }
            };
            this.surfaceTexture = surface;
        }

        @Override // im.uwrkaxlmjj.messenger.DispatchQueue, java.lang.Thread, java.lang.Runnable
        public void run() {
            if (RenderView.this.bitmap == null || RenderView.this.bitmap.isRecycled()) {
                return;
            }
            this.initialized = initGL();
            super.run();
        }

        private boolean initGL() {
            EGL10 egl10 = (EGL10) EGLContext.getEGL();
            this.egl10 = egl10;
            EGLDisplay eGLDisplayEglGetDisplay = egl10.eglGetDisplay(EGL10.EGL_DEFAULT_DISPLAY);
            this.eglDisplay = eGLDisplayEglGetDisplay;
            if (eGLDisplayEglGetDisplay == EGL10.EGL_NO_DISPLAY) {
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.e("eglGetDisplay failed " + GLUtils.getEGLErrorString(this.egl10.eglGetError()));
                }
                finish();
                return false;
            }
            int[] version = new int[2];
            if (!this.egl10.eglInitialize(this.eglDisplay, version)) {
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.e("eglInitialize failed " + GLUtils.getEGLErrorString(this.egl10.eglGetError()));
                }
                finish();
                return false;
            }
            int[] configsCount = new int[1];
            EGLConfig[] configs = new EGLConfig[1];
            int[] configSpec = {12352, 4, 12324, 8, 12323, 8, 12322, 8, 12321, 8, 12325, 0, 12326, 0, 12344};
            if (!this.egl10.eglChooseConfig(this.eglDisplay, configSpec, configs, 1, configsCount)) {
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.e("eglChooseConfig failed " + GLUtils.getEGLErrorString(this.egl10.eglGetError()));
                }
                finish();
                return false;
            }
            if (configsCount[0] > 0) {
                EGLConfig eGLConfig = configs[0];
                this.eglConfig = eGLConfig;
                int[] attrib_list = {12440, 2, 12344};
                EGLContext eGLContextEglCreateContext = this.egl10.eglCreateContext(this.eglDisplay, eGLConfig, EGL10.EGL_NO_CONTEXT, attrib_list);
                this.eglContext = eGLContextEglCreateContext;
                if (eGLContextEglCreateContext == null) {
                    if (BuildVars.LOGS_ENABLED) {
                        FileLog.e("eglCreateContext failed " + GLUtils.getEGLErrorString(this.egl10.eglGetError()));
                    }
                    finish();
                    return false;
                }
                SurfaceTexture surfaceTexture = this.surfaceTexture;
                if (surfaceTexture instanceof SurfaceTexture) {
                    EGLSurface eGLSurfaceEglCreateWindowSurface = this.egl10.eglCreateWindowSurface(this.eglDisplay, this.eglConfig, surfaceTexture, null);
                    this.eglSurface = eGLSurfaceEglCreateWindowSurface;
                    if (eGLSurfaceEglCreateWindowSurface == null || eGLSurfaceEglCreateWindowSurface == EGL10.EGL_NO_SURFACE) {
                        if (BuildVars.LOGS_ENABLED) {
                            FileLog.e("createWindowSurface failed " + GLUtils.getEGLErrorString(this.egl10.eglGetError()));
                        }
                        finish();
                        return false;
                    }
                    EGL10 egl102 = this.egl10;
                    EGLDisplay eGLDisplay = this.eglDisplay;
                    EGLSurface eGLSurface = this.eglSurface;
                    if (!egl102.eglMakeCurrent(eGLDisplay, eGLSurface, eGLSurface, this.eglContext)) {
                        if (BuildVars.LOGS_ENABLED) {
                            FileLog.e("eglMakeCurrent failed " + GLUtils.getEGLErrorString(this.egl10.eglGetError()));
                        }
                        finish();
                        return false;
                    }
                    GLES20.glEnable(3042);
                    GLES20.glDisable(3024);
                    GLES20.glDisable(2960);
                    GLES20.glDisable(2929);
                    RenderView.this.painting.setupShaders();
                    checkBitmap();
                    RenderView.this.painting.setBitmap(RenderView.this.bitmap);
                    Utils.HasGLError();
                    return true;
                }
                finish();
                return false;
            }
            if (BuildVars.LOGS_ENABLED) {
                FileLog.e("eglConfig not initialized");
            }
            finish();
            return false;
        }

        private Bitmap createBitmap(Bitmap bitmap, float scale) {
            Matrix matrix = new Matrix();
            matrix.setScale(scale, scale);
            matrix.postRotate(RenderView.this.orientation);
            return Bitmap.createBitmap(bitmap, 0, 0, bitmap.getWidth(), bitmap.getHeight(), matrix, true);
        }

        private void checkBitmap() {
            Size paintingSize = RenderView.this.painting.getSize();
            if (RenderView.this.bitmap.getWidth() != paintingSize.width || RenderView.this.bitmap.getHeight() != paintingSize.height || RenderView.this.orientation != 0) {
                float bitmapWidth = RenderView.this.bitmap.getWidth();
                if (RenderView.this.orientation % 360 == 90 || RenderView.this.orientation % 360 == 270) {
                    bitmapWidth = RenderView.this.bitmap.getHeight();
                }
                float scale = paintingSize.width / bitmapWidth;
                RenderView renderView = RenderView.this;
                renderView.bitmap = createBitmap(renderView.bitmap, scale);
                RenderView.this.orientation = 0;
                RenderView.this.transformedBitmap = true;
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        public boolean setCurrentContext() {
            if (!this.initialized) {
                return false;
            }
            if (!this.eglContext.equals(this.egl10.eglGetCurrentContext()) || !this.eglSurface.equals(this.egl10.eglGetCurrentSurface(12377))) {
                EGL10 egl10 = this.egl10;
                EGLDisplay eGLDisplay = this.eglDisplay;
                EGLSurface eGLSurface = this.eglSurface;
                return egl10.eglMakeCurrent(eGLDisplay, eGLSurface, eGLSurface, this.eglContext);
            }
            return true;
        }

        public void setBufferSize(int width, int height) {
            this.bufferWidth = width;
            this.bufferHeight = height;
        }

        public void requestRender() {
            postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.paint.RenderView.CanvasInternal.2
                @Override // java.lang.Runnable
                public void run() {
                    CanvasInternal.this.drawRunnable.run();
                }
            });
        }

        public void scheduleRedraw() {
            Runnable runnable = this.scheduledRunnable;
            if (runnable != null) {
                cancelRunnable(runnable);
                this.scheduledRunnable = null;
            }
            Runnable runnable2 = new Runnable() { // from class: im.uwrkaxlmjj.ui.components.paint.RenderView.CanvasInternal.3
                @Override // java.lang.Runnable
                public void run() {
                    CanvasInternal.this.scheduledRunnable = null;
                    CanvasInternal.this.drawRunnable.run();
                }
            };
            this.scheduledRunnable = runnable2;
            postRunnable(runnable2, 1L);
        }

        public void finish() {
            if (this.eglSurface != null) {
                this.egl10.eglMakeCurrent(this.eglDisplay, EGL10.EGL_NO_SURFACE, EGL10.EGL_NO_SURFACE, EGL10.EGL_NO_CONTEXT);
                this.egl10.eglDestroySurface(this.eglDisplay, this.eglSurface);
                this.eglSurface = null;
            }
            EGLContext eGLContext = this.eglContext;
            if (eGLContext != null) {
                this.egl10.eglDestroyContext(this.eglDisplay, eGLContext);
                this.eglContext = null;
            }
            EGLDisplay eGLDisplay = this.eglDisplay;
            if (eGLDisplay != null) {
                this.egl10.eglTerminate(eGLDisplay);
                this.eglDisplay = null;
            }
        }

        public void shutdown() {
            postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.paint.RenderView.CanvasInternal.4
                @Override // java.lang.Runnable
                public void run() {
                    CanvasInternal.this.finish();
                    Looper looper = Looper.myLooper();
                    if (looper != null) {
                        looper.quit();
                    }
                }
            });
        }

        public Bitmap getTexture() {
            if (!this.initialized) {
                return null;
            }
            final CountDownLatch countDownLatch = new CountDownLatch(1);
            final Bitmap[] object = new Bitmap[1];
            try {
                postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.paint.RenderView.CanvasInternal.5
                    @Override // java.lang.Runnable
                    public void run() {
                        Painting.PaintingData data = RenderView.this.painting.getPaintingData(new RectF(0.0f, 0.0f, RenderView.this.painting.getSize().width, RenderView.this.painting.getSize().height), false);
                        object[0] = data.bitmap;
                        countDownLatch.countDown();
                    }
                });
                countDownLatch.await();
            } catch (Exception e) {
                FileLog.e(e);
            }
            return object[0];
        }
    }

    public Bitmap getResultBitmap() {
        CanvasInternal canvasInternal = this.internal;
        if (canvasInternal != null) {
            return canvasInternal.getTexture();
        }
        return null;
    }

    public void performInContext(final Runnable action) {
        CanvasInternal canvasInternal = this.internal;
        if (canvasInternal == null) {
            return;
        }
        canvasInternal.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.paint.RenderView.4
            @Override // java.lang.Runnable
            public void run() {
                if (RenderView.this.internal != null && RenderView.this.internal.initialized) {
                    RenderView.this.internal.setCurrentContext();
                    action.run();
                }
            }
        });
    }
}
