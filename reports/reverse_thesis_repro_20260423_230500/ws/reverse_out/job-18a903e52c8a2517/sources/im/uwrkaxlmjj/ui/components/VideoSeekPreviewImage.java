package im.uwrkaxlmjj.ui.components;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.BitmapShader;
import android.graphics.Canvas;
import android.graphics.Matrix;
import android.graphics.Paint;
import android.graphics.RectF;
import android.graphics.Shader;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.text.TextPaint;
import android.view.View;
import android.view.ViewGroup;
import androidx.recyclerview.widget.ItemTouchHelper;
import com.google.android.exoplayer2.text.ttml.TtmlNode;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.Bitmaps;
import im.uwrkaxlmjj.messenger.DispatchQueue;
import im.uwrkaxlmjj.messenger.FileLoader;
import im.uwrkaxlmjj.messenger.Utilities;
import im.uwrkaxlmjj.tgnet.TLRPC;
import java.io.File;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class VideoSeekPreviewImage extends View {
    private Paint bitmapPaint;
    private RectF bitmapRect;
    private BitmapShader bitmapShader;
    private Bitmap bitmapToDraw;
    private Bitmap bitmapToRecycle;
    private int currentPixel;
    private VideoSeekPreviewImageDelegate delegate;
    private RectF dstR;
    private long duration;
    private AnimatedFileDrawable fileDrawable;
    private Drawable frameDrawable;
    private String frameTime;
    private Runnable loadRunnable;
    private Matrix matrix;
    private Paint paint;
    private float pendingProgress;
    private int pixelWidth;
    private Runnable progressRunnable;
    private boolean ready;
    private TextPaint textPaint;
    private int timeWidth;
    private Uri videoUri;

    public interface VideoSeekPreviewImageDelegate {
        void onReady();
    }

    public VideoSeekPreviewImage(Context context, VideoSeekPreviewImageDelegate videoSeekPreviewImageDelegate) {
        super(context);
        this.currentPixel = -1;
        this.textPaint = new TextPaint(1);
        this.dstR = new RectF();
        this.paint = new Paint(2);
        this.bitmapPaint = new Paint(2);
        this.bitmapRect = new RectF();
        this.matrix = new Matrix();
        setVisibility(4);
        this.frameDrawable = context.getResources().getDrawable(R.drawable.videopreview);
        this.textPaint.setTextSize(AndroidUtilities.dp(13.0f));
        this.textPaint.setColor(-1);
        this.delegate = videoSeekPreviewImageDelegate;
    }

    public void setProgress(final float progress, int w) {
        if (w != 0) {
            this.pixelWidth = w;
            int pixel = ((int) (w * progress)) / 5;
            if (this.currentPixel == pixel) {
                return;
            } else {
                this.currentPixel = pixel;
            }
        }
        final long time = (long) (this.duration * progress);
        int minutes = (int) ((time / 60) / 1000);
        int seconds = ((int) (time - ((long) ((minutes * 60) * 1000)))) / 1000;
        this.frameTime = String.format("%d:%02d", Integer.valueOf(minutes), Integer.valueOf(seconds));
        this.timeWidth = (int) Math.ceil(this.textPaint.measureText(r4));
        invalidate();
        if (this.progressRunnable != null) {
            Utilities.globalQueue.cancelRunnable(this.progressRunnable);
        }
        AnimatedFileDrawable file = this.fileDrawable;
        if (file != null) {
            file.resetStream(false);
        }
        DispatchQueue dispatchQueue = Utilities.globalQueue;
        Runnable runnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$VideoSeekPreviewImage$n0ojN64FKVN_bCLaA_bcoFc1khg
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$setProgress$1$VideoSeekPreviewImage(progress, time);
            }
        };
        this.progressRunnable = runnable;
        dispatchQueue.postRunnable(runnable);
    }

    public /* synthetic */ void lambda$setProgress$1$VideoSeekPreviewImage(float progress, long time) {
        int height;
        int width;
        if (this.fileDrawable == null) {
            this.pendingProgress = progress;
            return;
        }
        int bitmapSize = Math.max(ItemTouchHelper.Callback.DEFAULT_DRAG_ANIMATION_DURATION, AndroidUtilities.dp(100.0f));
        Bitmap bitmap = this.fileDrawable.getFrameAtTime(time);
        if (bitmap != null) {
            int width2 = bitmap.getWidth();
            int height2 = bitmap.getHeight();
            if (width2 > height2) {
                float scale = width2 / bitmapSize;
                width = bitmapSize;
                height = (int) (height2 / scale);
            } else {
                float scale2 = height2 / bitmapSize;
                height = bitmapSize;
                width = (int) (width2 / scale2);
            }
            try {
                Bitmap backgroundBitmap = Bitmaps.createBitmap(width, height, Bitmap.Config.ARGB_8888);
                this.dstR.set(0.0f, 0.0f, width, height);
                Canvas canvas = new Canvas(backgroundBitmap);
                canvas.drawBitmap(bitmap, (android.graphics.Rect) null, this.dstR, this.paint);
                canvas.setBitmap(null);
                bitmap = backgroundBitmap;
            } catch (Throwable th) {
                bitmap = null;
            }
        }
        final Bitmap bitmapFinal = bitmap;
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$VideoSeekPreviewImage$AVGuH9xU5LsdgLkVwqsXU4k9o1Q
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$0$VideoSeekPreviewImage(bitmapFinal);
            }
        });
    }

    public /* synthetic */ void lambda$null$0$VideoSeekPreviewImage(Bitmap bitmapFinal) {
        int viewHeight;
        int viewWidth;
        if (bitmapFinal != null) {
            if (this.bitmapToDraw != null) {
                Bitmap bitmap = this.bitmapToRecycle;
                if (bitmap != null) {
                    bitmap.recycle();
                }
                this.bitmapToRecycle = this.bitmapToDraw;
            }
            this.bitmapToDraw = bitmapFinal;
            BitmapShader bitmapShader = new BitmapShader(this.bitmapToDraw, Shader.TileMode.CLAMP, Shader.TileMode.CLAMP);
            this.bitmapShader = bitmapShader;
            bitmapShader.setLocalMatrix(this.matrix);
            this.bitmapPaint.setShader(this.bitmapShader);
            invalidate();
            int viewSize = AndroidUtilities.dp(150.0f);
            float bitmapWidth = bitmapFinal.getWidth();
            float bitmapHeight = bitmapFinal.getHeight();
            float aspect = bitmapWidth / bitmapHeight;
            if (aspect > 1.0f) {
                viewWidth = viewSize;
                viewHeight = (int) (viewSize / aspect);
            } else {
                viewHeight = viewSize;
                viewWidth = (int) (viewSize * aspect);
            }
            ViewGroup.LayoutParams layoutParams = getLayoutParams();
            if (getVisibility() != 0 || layoutParams.width != viewWidth || layoutParams.height != viewHeight) {
                layoutParams.width = viewWidth;
                layoutParams.height = viewHeight;
                setVisibility(0);
                requestLayout();
            }
        }
        this.progressRunnable = null;
    }

    public void open(final Uri uri) {
        if (uri == null || uri.equals(this.videoUri)) {
            return;
        }
        this.videoUri = uri;
        DispatchQueue dispatchQueue = Utilities.globalQueue;
        Runnable runnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$VideoSeekPreviewImage$yzfGuhIf-OebcAE_fihdzG0akB0
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$open$3$VideoSeekPreviewImage(uri);
            }
        };
        this.loadRunnable = runnable;
        dispatchQueue.postRunnable(runnable);
    }

    public /* synthetic */ void lambda$open$3$VideoSeekPreviewImage(Uri uri) {
        String path;
        String scheme = uri.getScheme();
        if ("hchat".equals(scheme)) {
            int currentAccount = Utilities.parseInt(uri.getQueryParameter("account")).intValue();
            Object parentObject = FileLoader.getInstance(currentAccount).getParentObject(Utilities.parseInt(uri.getQueryParameter("rid")).intValue());
            TLRPC.TL_document document = new TLRPC.TL_document();
            document.access_hash = Utilities.parseLong(uri.getQueryParameter("hash")).longValue();
            document.id = Utilities.parseLong(uri.getQueryParameter(TtmlNode.ATTR_ID)).longValue();
            document.size = Utilities.parseInt(uri.getQueryParameter("size")).intValue();
            document.dc_id = Utilities.parseInt(uri.getQueryParameter("dc")).intValue();
            document.mime_type = uri.getQueryParameter("mime");
            document.file_reference = Utilities.hexToBytes(uri.getQueryParameter("reference"));
            TLRPC.TL_documentAttributeFilename filename = new TLRPC.TL_documentAttributeFilename();
            filename.file_name = uri.getQueryParameter("name");
            document.attributes.add(filename);
            document.attributes.add(new TLRPC.TL_documentAttributeVideo());
            String name = FileLoader.getAttachFileName(document);
            if (FileLoader.getInstance(currentAccount).isLoadingFile(name)) {
                path = new File(FileLoader.getDirectory(4), document.dc_id + "_" + document.id + ".temp").getAbsolutePath();
            } else {
                path = FileLoader.getPathToAttach(document, false).getAbsolutePath();
            }
            this.fileDrawable = new AnimatedFileDrawable(new File(path), true, document.size, document, parentObject, currentAccount, true);
        } else {
            String path2 = uri.getPath();
            this.fileDrawable = new AnimatedFileDrawable(new File(path2), true, 0L, null, null, 0, true);
        }
        this.duration = this.fileDrawable.getDurationMs();
        float f = this.pendingProgress;
        if (f != 0.0f) {
            setProgress(f, this.pixelWidth);
            this.pendingProgress = 0.0f;
        }
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$VideoSeekPreviewImage$eJy6M_Z9LLqhu87vrefnQAtr9Zc
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$2$VideoSeekPreviewImage();
            }
        });
    }

    public /* synthetic */ void lambda$null$2$VideoSeekPreviewImage() {
        this.loadRunnable = null;
        if (this.fileDrawable != null) {
            this.ready = true;
            this.delegate.onReady();
        }
    }

    public boolean isReady() {
        return this.ready;
    }

    @Override // android.view.View
    protected void onDraw(Canvas canvas) {
        Bitmap bitmap = this.bitmapToRecycle;
        if (bitmap != null) {
            bitmap.recycle();
            this.bitmapToRecycle = null;
        }
        if (this.bitmapToDraw != null && this.bitmapShader != null) {
            this.matrix.reset();
            float scale = getMeasuredWidth() / this.bitmapToDraw.getWidth();
            this.matrix.preScale(scale, scale);
            this.bitmapRect.set(0.0f, 0.0f, getMeasuredWidth(), getMeasuredHeight());
            canvas.drawRoundRect(this.bitmapRect, AndroidUtilities.dp(6.0f), AndroidUtilities.dp(6.0f), this.bitmapPaint);
            this.frameDrawable.setBounds(0, 0, getMeasuredWidth(), getMeasuredHeight());
            this.frameDrawable.draw(canvas);
            canvas.drawText(this.frameTime, (getMeasuredWidth() - this.timeWidth) / 2, getMeasuredHeight() - AndroidUtilities.dp(9.0f), this.textPaint);
        }
    }

    public void close() {
        if (this.loadRunnable != null) {
            Utilities.globalQueue.cancelRunnable(this.loadRunnable);
            this.loadRunnable = null;
        }
        if (this.progressRunnable != null) {
            Utilities.globalQueue.cancelRunnable(this.progressRunnable);
            this.progressRunnable = null;
        }
        AnimatedFileDrawable drawable = this.fileDrawable;
        if (drawable != null) {
            drawable.resetStream(true);
        }
        Utilities.globalQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$VideoSeekPreviewImage$TpjbNq-7Q5XnGeTv5Hc1k-1b1HU
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$close$4$VideoSeekPreviewImage();
            }
        });
        setVisibility(4);
        this.bitmapToDraw = null;
        this.bitmapShader = null;
        invalidate();
        this.currentPixel = -1;
        this.videoUri = null;
        this.ready = false;
    }

    public /* synthetic */ void lambda$close$4$VideoSeekPreviewImage() {
        this.pendingProgress = 0.0f;
        AnimatedFileDrawable animatedFileDrawable = this.fileDrawable;
        if (animatedFileDrawable != null) {
            animatedFileDrawable.recycle();
            this.fileDrawable = null;
        }
    }
}
