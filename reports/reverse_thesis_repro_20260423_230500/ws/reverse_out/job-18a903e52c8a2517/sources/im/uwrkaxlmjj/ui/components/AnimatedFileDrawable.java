package im.uwrkaxlmjj.ui.components;

import android.graphics.Bitmap;
import android.graphics.BitmapShader;
import android.graphics.Canvas;
import android.graphics.Matrix;
import android.graphics.Paint;
import android.graphics.RectF;
import android.graphics.Shader;
import android.graphics.drawable.Animatable;
import android.graphics.drawable.BitmapDrawable;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.AnimatedFileDrawableStream;
import im.uwrkaxlmjj.messenger.DispatchQueue;
import im.uwrkaxlmjj.messenger.FileLoader;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.tgnet.TLRPC;
import java.io.File;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/* JADX INFO: loaded from: classes5.dex */
public class AnimatedFileDrawable extends BitmapDrawable implements Animatable {
    public static final int PARAM_NUM_AUDIO_FRAME_SIZE = 5;
    public static final int PARAM_NUM_BITRATE = 3;
    public static final int PARAM_NUM_COUNT = 9;
    public static final int PARAM_NUM_DURATION = 4;
    public static final int PARAM_NUM_FRAMERATE = 7;
    public static final int PARAM_NUM_HEIGHT = 2;
    public static final int PARAM_NUM_IS_AVC = 0;
    public static final int PARAM_NUM_ROTATION = 8;
    public static final int PARAM_NUM_VIDEO_FRAME_SIZE = 6;
    public static final int PARAM_NUM_WIDTH = 1;
    private boolean applyTransformation;
    private Bitmap backgroundBitmap;
    private int backgroundBitmapTime;
    private BitmapShader backgroundShader;
    private int currentAccount;
    private DispatchQueue decodeQueue;
    private boolean decodeSingleFrame;
    private boolean decoderCreated;
    private boolean destroyWhenDone;
    private volatile boolean isRecycled;
    private volatile boolean isRunning;
    private long lastFrameDecodeTime;
    private long lastFrameTime;
    private int lastTimeStamp;
    private Runnable loadFrameTask;
    public volatile long nativePtr;
    private Bitmap nextRenderingBitmap;
    private int nextRenderingBitmapTime;
    private BitmapShader nextRenderingShader;
    private View parentView;
    private File path;
    private boolean pendingRemoveLoading;
    private int pendingRemoveLoadingFramesReset;
    private boolean recycleWithSecond;
    private Bitmap renderingBitmap;
    private int renderingBitmapTime;
    private BitmapShader renderingShader;
    private int roundRadius;
    private View secondParentView;
    private boolean singleFrameDecoded;
    private AnimatedFileDrawableStream stream;
    private long streamFileSize;
    private boolean useSharedQueue;
    private static final Handler uiHandler = new Handler(Looper.getMainLooper());
    private static ScheduledThreadPoolExecutor executor = new ScheduledThreadPoolExecutor(2, new ThreadPoolExecutor.DiscardPolicy());
    private int invalidateAfter = 50;
    private final int[] metaData = new int[5];
    private volatile long pendingSeekTo = -1;
    private volatile long pendingSeekToUI = -1;
    private final Object sync = new Object();
    private RectF actualDrawRect = new RectF();
    private Matrix shaderMatrix = new Matrix();
    private float scaleX = 1.0f;
    private float scaleY = 1.0f;
    private final android.graphics.Rect dstRect = new android.graphics.Rect();
    protected final Runnable mInvalidateTask = new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AnimatedFileDrawable$qvqhSXItsr9CeoTGt4L4cC7SN_M
        @Override // java.lang.Runnable
        public final void run() {
            this.f$0.lambda$new$0$AnimatedFileDrawable();
        }
    };
    private Runnable uiRunnableNoFrame = new Runnable() { // from class: im.uwrkaxlmjj.ui.components.AnimatedFileDrawable.1
        @Override // java.lang.Runnable
        public void run() {
            if (AnimatedFileDrawable.this.destroyWhenDone && AnimatedFileDrawable.this.nativePtr != 0) {
                AnimatedFileDrawable.destroyDecoder(AnimatedFileDrawable.this.nativePtr);
                AnimatedFileDrawable.this.nativePtr = 0L;
            }
            if (AnimatedFileDrawable.this.nativePtr == 0) {
                if (AnimatedFileDrawable.this.renderingBitmap != null) {
                    AnimatedFileDrawable.this.renderingBitmap.recycle();
                    AnimatedFileDrawable.this.renderingBitmap = null;
                }
                if (AnimatedFileDrawable.this.backgroundBitmap != null) {
                    AnimatedFileDrawable.this.backgroundBitmap.recycle();
                    AnimatedFileDrawable.this.backgroundBitmap = null;
                }
                if (AnimatedFileDrawable.this.decodeQueue != null) {
                    AnimatedFileDrawable.this.decodeQueue.recycle();
                    AnimatedFileDrawable.this.decodeQueue = null;
                    return;
                }
                return;
            }
            AnimatedFileDrawable.this.loadFrameTask = null;
            AnimatedFileDrawable.this.scheduleNextGetFrame();
        }
    };
    private Runnable uiRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.components.AnimatedFileDrawable.2
        @Override // java.lang.Runnable
        public void run() {
            if (AnimatedFileDrawable.this.destroyWhenDone && AnimatedFileDrawable.this.nativePtr != 0) {
                AnimatedFileDrawable.destroyDecoder(AnimatedFileDrawable.this.nativePtr);
                AnimatedFileDrawable.this.nativePtr = 0L;
            }
            if (AnimatedFileDrawable.this.nativePtr == 0) {
                if (AnimatedFileDrawable.this.renderingBitmap != null) {
                    AnimatedFileDrawable.this.renderingBitmap.recycle();
                    AnimatedFileDrawable.this.renderingBitmap = null;
                }
                if (AnimatedFileDrawable.this.backgroundBitmap != null) {
                    AnimatedFileDrawable.this.backgroundBitmap.recycle();
                    AnimatedFileDrawable.this.backgroundBitmap = null;
                }
                if (AnimatedFileDrawable.this.decodeQueue != null) {
                    AnimatedFileDrawable.this.decodeQueue.recycle();
                    AnimatedFileDrawable.this.decodeQueue = null;
                    return;
                }
                return;
            }
            if (AnimatedFileDrawable.this.stream != null && AnimatedFileDrawable.this.pendingRemoveLoading) {
                FileLoader.getInstance(AnimatedFileDrawable.this.currentAccount).removeLoadingVideo(AnimatedFileDrawable.this.stream.getDocument(), false, false);
            }
            if (AnimatedFileDrawable.this.pendingRemoveLoadingFramesReset <= 0) {
                AnimatedFileDrawable.this.pendingRemoveLoading = true;
            } else {
                AnimatedFileDrawable.access$1010(AnimatedFileDrawable.this);
            }
            AnimatedFileDrawable.this.singleFrameDecoded = true;
            AnimatedFileDrawable.this.loadFrameTask = null;
            AnimatedFileDrawable animatedFileDrawable = AnimatedFileDrawable.this;
            animatedFileDrawable.nextRenderingBitmap = animatedFileDrawable.backgroundBitmap;
            AnimatedFileDrawable animatedFileDrawable2 = AnimatedFileDrawable.this;
            animatedFileDrawable2.nextRenderingBitmapTime = animatedFileDrawable2.backgroundBitmapTime;
            AnimatedFileDrawable animatedFileDrawable3 = AnimatedFileDrawable.this;
            animatedFileDrawable3.nextRenderingShader = animatedFileDrawable3.backgroundShader;
            if (AnimatedFileDrawable.this.metaData[3] < AnimatedFileDrawable.this.lastTimeStamp) {
                AnimatedFileDrawable.this.lastTimeStamp = 0;
            }
            if (AnimatedFileDrawable.this.metaData[3] - AnimatedFileDrawable.this.lastTimeStamp != 0) {
                AnimatedFileDrawable animatedFileDrawable4 = AnimatedFileDrawable.this;
                animatedFileDrawable4.invalidateAfter = animatedFileDrawable4.metaData[3] - AnimatedFileDrawable.this.lastTimeStamp;
            }
            if (AnimatedFileDrawable.this.pendingSeekToUI >= 0 && AnimatedFileDrawable.this.pendingSeekTo == -1) {
                AnimatedFileDrawable.this.pendingSeekToUI = -1L;
                AnimatedFileDrawable.this.invalidateAfter = 0;
            }
            AnimatedFileDrawable animatedFileDrawable5 = AnimatedFileDrawable.this;
            animatedFileDrawable5.lastTimeStamp = animatedFileDrawable5.metaData[3];
            if (AnimatedFileDrawable.this.secondParentView != null) {
                AnimatedFileDrawable.this.secondParentView.invalidate();
            } else if (AnimatedFileDrawable.this.parentView != null) {
                AnimatedFileDrawable.this.parentView.invalidate();
            }
            AnimatedFileDrawable.this.scheduleNextGetFrame();
        }
    };
    private Runnable loadFrameRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.components.AnimatedFileDrawable.3
        @Override // java.lang.Runnable
        public void run() {
            if (!AnimatedFileDrawable.this.isRecycled) {
                if (!AnimatedFileDrawable.this.decoderCreated && AnimatedFileDrawable.this.nativePtr == 0) {
                    AnimatedFileDrawable animatedFileDrawable = AnimatedFileDrawable.this;
                    animatedFileDrawable.nativePtr = AnimatedFileDrawable.createDecoder(animatedFileDrawable.path.getAbsolutePath(), AnimatedFileDrawable.this.metaData, AnimatedFileDrawable.this.currentAccount, AnimatedFileDrawable.this.streamFileSize, AnimatedFileDrawable.this.stream, false);
                    AnimatedFileDrawable.this.decoderCreated = true;
                }
                try {
                    if (AnimatedFileDrawable.this.nativePtr == 0 && AnimatedFileDrawable.this.metaData[0] != 0 && AnimatedFileDrawable.this.metaData[1] != 0) {
                        AndroidUtilities.runOnUIThread(AnimatedFileDrawable.this.uiRunnableNoFrame);
                        return;
                    }
                    if (AnimatedFileDrawable.this.backgroundBitmap == null && AnimatedFileDrawable.this.metaData[0] > 0 && AnimatedFileDrawable.this.metaData[1] > 0) {
                        try {
                            AnimatedFileDrawable.this.backgroundBitmap = Bitmap.createBitmap(AnimatedFileDrawable.this.metaData[0], AnimatedFileDrawable.this.metaData[1], Bitmap.Config.ARGB_8888);
                        } catch (Throwable e) {
                            FileLog.e(e);
                        }
                        if (AnimatedFileDrawable.this.backgroundShader == null && AnimatedFileDrawable.this.backgroundBitmap != null && AnimatedFileDrawable.this.roundRadius != 0) {
                            AnimatedFileDrawable.this.backgroundShader = new BitmapShader(AnimatedFileDrawable.this.backgroundBitmap, Shader.TileMode.CLAMP, Shader.TileMode.CLAMP);
                        }
                    }
                    boolean seekWas = false;
                    if (AnimatedFileDrawable.this.pendingSeekTo >= 0) {
                        AnimatedFileDrawable.this.metaData[3] = (int) AnimatedFileDrawable.this.pendingSeekTo;
                        long seekTo = AnimatedFileDrawable.this.pendingSeekTo;
                        synchronized (AnimatedFileDrawable.this.sync) {
                            AnimatedFileDrawable.this.pendingSeekTo = -1L;
                        }
                        seekWas = true;
                        if (AnimatedFileDrawable.this.stream != null) {
                            AnimatedFileDrawable.this.stream.reset();
                        }
                        AnimatedFileDrawable.seekToMs(AnimatedFileDrawable.this.nativePtr, seekTo, true);
                    }
                    if (AnimatedFileDrawable.this.backgroundBitmap != null) {
                        AnimatedFileDrawable.this.lastFrameDecodeTime = System.currentTimeMillis();
                        if (AnimatedFileDrawable.getVideoFrame(AnimatedFileDrawable.this.nativePtr, AnimatedFileDrawable.this.backgroundBitmap, AnimatedFileDrawable.this.metaData, AnimatedFileDrawable.this.backgroundBitmap.getRowBytes(), false) == 0) {
                            AndroidUtilities.runOnUIThread(AnimatedFileDrawable.this.uiRunnableNoFrame);
                            return;
                        }
                        if (seekWas) {
                            AnimatedFileDrawable.this.lastTimeStamp = AnimatedFileDrawable.this.metaData[3];
                        }
                        AnimatedFileDrawable.this.backgroundBitmapTime = AnimatedFileDrawable.this.metaData[3];
                    }
                } catch (Throwable e2) {
                    FileLog.e(e2);
                }
            }
            AndroidUtilities.runOnUIThread(AnimatedFileDrawable.this.uiRunnable);
        }
    };
    private final Runnable mStartTask = new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AnimatedFileDrawable$Szlh8B4VU-7CtQ4odDlsY7GhqA0
        @Override // java.lang.Runnable
        public final void run() {
            this.f$0.lambda$new$1$AnimatedFileDrawable();
        }
    };

    /* JADX INFO: Access modifiers changed from: private */
    public static native long createDecoder(String str, int[] iArr, int i, long j, Object obj, boolean z);

    /* JADX INFO: Access modifiers changed from: private */
    public static native void destroyDecoder(long j);

    /* JADX INFO: Access modifiers changed from: private */
    public static native int getVideoFrame(long j, Bitmap bitmap, int[] iArr, int i, boolean z);

    public static native void getVideoInfo(String str, int[] iArr);

    private static native void prepareToSeek(long j);

    /* JADX INFO: Access modifiers changed from: private */
    public static native void seekToMs(long j, long j2, boolean z);

    private static native void stopDecoder(long j);

    static /* synthetic */ int access$1010(AnimatedFileDrawable x0) {
        int i = x0.pendingRemoveLoadingFramesReset;
        x0.pendingRemoveLoadingFramesReset = i - 1;
        return i;
    }

    public /* synthetic */ void lambda$new$0$AnimatedFileDrawable() {
        View view = this.secondParentView;
        if (view != null) {
            view.invalidate();
            return;
        }
        View view2 = this.parentView;
        if (view2 != null) {
            view2.invalidate();
        }
    }

    public /* synthetic */ void lambda$new$1$AnimatedFileDrawable() {
        View view = this.secondParentView;
        if (view != null) {
            view.invalidate();
            return;
        }
        View view2 = this.parentView;
        if (view2 != null) {
            view2.invalidate();
        }
    }

    public AnimatedFileDrawable(File file, boolean createDecoder, long streamSize, TLRPC.Document document, Object parentObject, int account, boolean preview) {
        this.path = file;
        this.streamFileSize = streamSize;
        this.currentAccount = account;
        getPaint().setFlags(2);
        if (streamSize != 0 && document != null) {
            this.stream = new AnimatedFileDrawableStream(document, parentObject, account, preview);
        }
        if (createDecoder) {
            this.nativePtr = createDecoder(file.getAbsolutePath(), this.metaData, this.currentAccount, this.streamFileSize, this.stream, preview);
            this.decoderCreated = true;
        }
    }

    public Bitmap getFrameAtTime(long ms) {
        if (!this.decoderCreated || this.nativePtr == 0) {
            return null;
        }
        AnimatedFileDrawableStream animatedFileDrawableStream = this.stream;
        if (animatedFileDrawableStream != null) {
            animatedFileDrawableStream.cancel(false);
            this.stream.reset();
        }
        seekToMs(this.nativePtr, ms, false);
        if (this.backgroundBitmap == null) {
            int[] iArr = this.metaData;
            this.backgroundBitmap = Bitmap.createBitmap(iArr[0], iArr[1], Bitmap.Config.ARGB_8888);
        }
        long j = this.nativePtr;
        Bitmap bitmap = this.backgroundBitmap;
        int result = getVideoFrame(j, bitmap, this.metaData, bitmap.getRowBytes(), true);
        if (result != 0) {
            return this.backgroundBitmap;
        }
        return null;
    }

    public void setParentView(View view) {
        if (this.parentView != null) {
            return;
        }
        this.parentView = view;
    }

    public void setSecondParentView(View view) {
        this.secondParentView = view;
        if (view == null && this.recycleWithSecond) {
            recycle();
        }
    }

    public void setAllowDecodeSingleFrame(boolean value) {
        this.decodeSingleFrame = value;
        if (value) {
            scheduleNextGetFrame();
        }
    }

    public void seekTo(long ms, boolean removeLoading) {
        synchronized (this.sync) {
            this.pendingSeekTo = ms;
            this.pendingSeekToUI = ms;
            prepareToSeek(this.nativePtr);
            if (this.decoderCreated && this.stream != null) {
                this.stream.cancel(removeLoading);
                this.pendingRemoveLoading = removeLoading;
                this.pendingRemoveLoadingFramesReset = removeLoading ? 0 : 10;
            }
        }
    }

    public void recycle() {
        if (this.secondParentView != null) {
            this.recycleWithSecond = true;
            return;
        }
        this.isRunning = false;
        this.isRecycled = true;
        if (this.loadFrameTask == null) {
            if (this.nativePtr != 0) {
                destroyDecoder(this.nativePtr);
                this.nativePtr = 0L;
            }
            Bitmap bitmap = this.renderingBitmap;
            if (bitmap != null) {
                bitmap.recycle();
                this.renderingBitmap = null;
            }
            Bitmap bitmap2 = this.nextRenderingBitmap;
            if (bitmap2 != null) {
                bitmap2.recycle();
                this.nextRenderingBitmap = null;
            }
            DispatchQueue dispatchQueue = this.decodeQueue;
            if (dispatchQueue != null) {
                dispatchQueue.recycle();
                this.decodeQueue = null;
            }
        } else {
            this.destroyWhenDone = true;
        }
        AnimatedFileDrawableStream animatedFileDrawableStream = this.stream;
        if (animatedFileDrawableStream != null) {
            animatedFileDrawableStream.cancel(true);
        }
    }

    public void resetStream(boolean stop) {
        AnimatedFileDrawableStream animatedFileDrawableStream = this.stream;
        if (animatedFileDrawableStream != null) {
            animatedFileDrawableStream.cancel(true);
        }
        if (this.nativePtr != 0) {
            if (stop) {
                stopDecoder(this.nativePtr);
            } else {
                prepareToSeek(this.nativePtr);
            }
        }
    }

    protected static void runOnUiThread(Runnable task) {
        if (Looper.myLooper() == uiHandler.getLooper()) {
            task.run();
        } else {
            uiHandler.post(task);
        }
    }

    public void setUseSharedQueue(boolean value) {
        this.useSharedQueue = value;
    }

    protected void finalize() throws Throwable {
        try {
            recycle();
        } finally {
            super.finalize();
        }
    }

    @Override // android.graphics.drawable.BitmapDrawable, android.graphics.drawable.Drawable
    public int getOpacity() {
        return -2;
    }

    @Override // android.graphics.drawable.Animatable
    public void start() {
        if (this.isRunning) {
            return;
        }
        this.isRunning = true;
        scheduleNextGetFrame();
        runOnUiThread(this.mStartTask);
    }

    public float getCurrentProgress() {
        if (this.metaData[4] == 0) {
            return 0.0f;
        }
        if (this.pendingSeekToUI >= 0) {
            return this.pendingSeekToUI / this.metaData[4];
        }
        int[] iArr = this.metaData;
        return iArr[3] / iArr[4];
    }

    public int getCurrentProgressMs() {
        if (this.pendingSeekToUI >= 0) {
            return (int) this.pendingSeekToUI;
        }
        int i = this.nextRenderingBitmapTime;
        return i != 0 ? i : this.renderingBitmapTime;
    }

    public int getDurationMs() {
        return this.metaData[4];
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void scheduleNextGetFrame() {
        if (this.loadFrameTask == null) {
            if ((this.nativePtr == 0 && this.decoderCreated) || this.destroyWhenDone) {
                return;
            }
            if (!this.isRunning) {
                boolean z = this.decodeSingleFrame;
                if (!z) {
                    return;
                }
                if (z && this.singleFrameDecoded) {
                    return;
                }
            }
            long ms = 0;
            if (this.lastFrameDecodeTime != 0) {
                int i = this.invalidateAfter;
                ms = Math.min(i, Math.max(0L, ((long) i) - (System.currentTimeMillis() - this.lastFrameDecodeTime)));
            }
            if (this.useSharedQueue) {
                ScheduledThreadPoolExecutor scheduledThreadPoolExecutor = executor;
                Runnable runnable = this.loadFrameRunnable;
                this.loadFrameTask = runnable;
                scheduledThreadPoolExecutor.schedule(runnable, ms, TimeUnit.MILLISECONDS);
                return;
            }
            if (this.decodeQueue == null) {
                this.decodeQueue = new DispatchQueue("decodeQueue" + this);
            }
            DispatchQueue dispatchQueue = this.decodeQueue;
            Runnable runnable2 = this.loadFrameRunnable;
            this.loadFrameTask = runnable2;
            dispatchQueue.postRunnable(runnable2, ms);
        }
    }

    public boolean isLoadingStream() {
        AnimatedFileDrawableStream animatedFileDrawableStream = this.stream;
        return animatedFileDrawableStream != null && animatedFileDrawableStream.isWaitingForLoad();
    }

    @Override // android.graphics.drawable.Animatable
    public void stop() {
        this.isRunning = false;
    }

    @Override // android.graphics.drawable.Animatable
    public boolean isRunning() {
        return this.isRunning;
    }

    @Override // android.graphics.drawable.BitmapDrawable, android.graphics.drawable.Drawable
    public int getIntrinsicHeight() {
        int i = 0;
        if (this.decoderCreated) {
            int[] iArr = this.metaData;
            i = (iArr[2] == 90 || iArr[2] == 270) ? this.metaData[0] : iArr[1];
        }
        int height = i;
        if (height == 0) {
            return AndroidUtilities.dp(100.0f);
        }
        return height;
    }

    @Override // android.graphics.drawable.BitmapDrawable, android.graphics.drawable.Drawable
    public int getIntrinsicWidth() {
        int i = 0;
        if (this.decoderCreated) {
            int[] iArr = this.metaData;
            i = (iArr[2] == 90 || iArr[2] == 270) ? this.metaData[1] : iArr[0];
        }
        int width = i;
        if (width == 0) {
            return AndroidUtilities.dp(100.0f);
        }
        return width;
    }

    @Override // android.graphics.drawable.BitmapDrawable, android.graphics.drawable.Drawable
    protected void onBoundsChange(android.graphics.Rect bounds) {
        super.onBoundsChange(bounds);
        this.applyTransformation = true;
    }

    @Override // android.graphics.drawable.BitmapDrawable, android.graphics.drawable.Drawable
    public void draw(Canvas canvas) {
        Bitmap bitmap;
        if ((this.nativePtr == 0 && this.decoderCreated) || this.destroyWhenDone) {
            return;
        }
        long now = System.currentTimeMillis();
        if (this.isRunning) {
            if (this.renderingBitmap == null && this.nextRenderingBitmap == null) {
                scheduleNextGetFrame();
            } else if (this.nextRenderingBitmap != null && (this.renderingBitmap == null || Math.abs(now - this.lastFrameTime) >= this.invalidateAfter)) {
                this.renderingBitmap = this.nextRenderingBitmap;
                this.renderingBitmapTime = this.nextRenderingBitmapTime;
                this.renderingShader = this.nextRenderingShader;
                this.nextRenderingBitmap = null;
                this.nextRenderingBitmapTime = 0;
                this.nextRenderingShader = null;
                this.lastFrameTime = now;
            }
        } else if (!this.isRunning && this.decodeSingleFrame && Math.abs(now - this.lastFrameTime) >= this.invalidateAfter && (bitmap = this.nextRenderingBitmap) != null) {
            this.renderingBitmap = bitmap;
            this.renderingBitmapTime = this.nextRenderingBitmapTime;
            this.renderingShader = this.nextRenderingShader;
            this.nextRenderingBitmap = null;
            this.nextRenderingBitmapTime = 0;
            this.nextRenderingShader = null;
            this.lastFrameTime = now;
        }
        Bitmap bitmap2 = this.renderingBitmap;
        if (bitmap2 != null) {
            if (this.applyTransformation) {
                int bitmapW = bitmap2.getWidth();
                int bitmapH = this.renderingBitmap.getHeight();
                int[] iArr = this.metaData;
                if (iArr[2] == 90 || iArr[2] == 270) {
                    bitmapW = bitmapH;
                    bitmapH = bitmapW;
                }
                this.dstRect.set(getBounds());
                this.scaleX = this.dstRect.width() / bitmapW;
                this.scaleY = this.dstRect.height() / bitmapH;
                this.applyTransformation = false;
            }
            if (this.roundRadius != 0) {
                Math.max(this.scaleX, this.scaleY);
                if (this.renderingShader == null) {
                    this.renderingShader = new BitmapShader(this.backgroundBitmap, Shader.TileMode.CLAMP, Shader.TileMode.CLAMP);
                }
                Paint paint = getPaint();
                paint.setShader(this.renderingShader);
                this.shaderMatrix.reset();
                this.shaderMatrix.setTranslate(this.dstRect.left, this.dstRect.top);
                int[] iArr2 = this.metaData;
                if (iArr2[2] == 90) {
                    this.shaderMatrix.preRotate(90.0f);
                    this.shaderMatrix.preTranslate(0.0f, -this.dstRect.width());
                } else if (iArr2[2] == 180) {
                    this.shaderMatrix.preRotate(180.0f);
                    this.shaderMatrix.preTranslate(-this.dstRect.width(), -this.dstRect.height());
                } else if (iArr2[2] == 270) {
                    this.shaderMatrix.preRotate(270.0f);
                    this.shaderMatrix.preTranslate(-this.dstRect.height(), 0.0f);
                }
                this.shaderMatrix.preScale(this.scaleX, this.scaleY);
                this.renderingShader.setLocalMatrix(this.shaderMatrix);
                RectF rectF = this.actualDrawRect;
                int i = this.roundRadius;
                canvas.drawRoundRect(rectF, i, i, paint);
            } else {
                canvas.translate(this.dstRect.left, this.dstRect.top);
                int[] iArr3 = this.metaData;
                if (iArr3[2] == 90) {
                    canvas.rotate(90.0f);
                    canvas.translate(0.0f, -this.dstRect.width());
                } else if (iArr3[2] == 180) {
                    canvas.rotate(180.0f);
                    canvas.translate(-this.dstRect.width(), -this.dstRect.height());
                } else if (iArr3[2] == 270) {
                    canvas.rotate(270.0f);
                    canvas.translate(-this.dstRect.height(), 0.0f);
                }
                canvas.scale(this.scaleX, this.scaleY);
                canvas.drawBitmap(this.renderingBitmap, 0.0f, 0.0f, getPaint());
            }
            if (this.isRunning) {
                long timeToNextFrame = Math.max(1L, (((long) this.invalidateAfter) - (now - this.lastFrameTime)) - 17);
                uiHandler.removeCallbacks(this.mInvalidateTask);
                uiHandler.postDelayed(this.mInvalidateTask, Math.min(timeToNextFrame, this.invalidateAfter));
            }
        }
    }

    @Override // android.graphics.drawable.Drawable
    public int getMinimumHeight() {
        int i = 0;
        if (this.decoderCreated) {
            int[] iArr = this.metaData;
            i = (iArr[2] == 90 || iArr[2] == 270) ? this.metaData[0] : iArr[1];
        }
        int height = i;
        if (height == 0) {
            return AndroidUtilities.dp(100.0f);
        }
        return height;
    }

    @Override // android.graphics.drawable.Drawable
    public int getMinimumWidth() {
        int i = 0;
        if (this.decoderCreated) {
            int[] iArr = this.metaData;
            i = (iArr[2] == 90 || iArr[2] == 270) ? this.metaData[1] : iArr[0];
        }
        int width = i;
        if (width == 0) {
            return AndroidUtilities.dp(100.0f);
        }
        return width;
    }

    public Bitmap getRenderingBitmap() {
        return this.renderingBitmap;
    }

    public Bitmap getNextRenderingBitmap() {
        return this.nextRenderingBitmap;
    }

    public Bitmap getBackgroundBitmap() {
        return this.backgroundBitmap;
    }

    public Bitmap getAnimatedBitmap() {
        Bitmap bitmap = this.renderingBitmap;
        if (bitmap != null) {
            return bitmap;
        }
        Bitmap bitmap2 = this.nextRenderingBitmap;
        if (bitmap2 != null) {
            return bitmap2;
        }
        return null;
    }

    public void setActualDrawRect(float x, float y, float width, float height) {
        this.actualDrawRect.set(x, y, x + width, y + height);
    }

    public void setRoundRadius(int value) {
        this.roundRadius = value;
        getPaint().setFlags(3);
    }

    public boolean hasBitmap() {
        return (this.nativePtr == 0 || (this.renderingBitmap == null && this.nextRenderingBitmap == null)) ? false : true;
    }

    public int getOrientation() {
        return this.metaData[2];
    }

    public AnimatedFileDrawable makeCopy() {
        AnimatedFileDrawable drawable;
        if (this.stream != null) {
            File file = this.path;
            long j = this.streamFileSize;
            TLRPC.Document document = this.stream.getDocument();
            Object parentObject = this.stream.getParentObject();
            int i = this.currentAccount;
            AnimatedFileDrawableStream animatedFileDrawableStream = this.stream;
            drawable = new AnimatedFileDrawable(file, false, j, document, parentObject, i, animatedFileDrawableStream != null && animatedFileDrawableStream.isPreview());
        } else {
            File file2 = this.path;
            long j2 = this.streamFileSize;
            int i2 = this.currentAccount;
            AnimatedFileDrawableStream animatedFileDrawableStream2 = this.stream;
            drawable = new AnimatedFileDrawable(file2, false, j2, null, null, i2, animatedFileDrawableStream2 != null && animatedFileDrawableStream2.isPreview());
        }
        int[] iArr = drawable.metaData;
        int[] iArr2 = this.metaData;
        iArr[0] = iArr2[0];
        iArr[1] = iArr2[1];
        return drawable;
    }
}
