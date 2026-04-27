package com.ding.rtc;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.net.Uri;
import android.util.AttributeSet;
import android.view.MotionEvent;
import com.github.barteksc.pdfviewer.PDFView;
import com.github.barteksc.pdfviewer.listener.OnErrorListener;
import com.github.barteksc.pdfviewer.listener.OnLoadCompleteListener;
import com.github.barteksc.pdfviewer.listener.OnPageChangeListener;
import com.github.barteksc.pdfviewer.listener.OnPageScrollListener;
import com.github.barteksc.pdfviewer.scroll.ScrollHandle;
import com.shockwave.pdfium.util.SizeF;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import org.webrtc.mozi.Logging;

/* JADX INFO: loaded from: classes.dex */
public class RtcWhiteboardPdfView extends PDFView {
    private static final String TAG = "RtcWhiteboardPdfView";
    private boolean mEnableTouchEvent;
    private boolean mLoaded;
    private long mNativeHandle;
    private String mPageId;
    private int mTotalPages;
    private String mUrl;

    public static native int OnLoadComplete(long nativeHandle, String docId, float[] pageSizes);

    public static native int OnSnapshotComplete(long nativeHandle, String docId, String filename);

    public RtcWhiteboardPdfView(Context context) {
        super(context, (AttributeSet) null);
        this.mEnableTouchEvent = true;
        this.mTotalPages = 0;
        this.mLoaded = false;
    }

    public RtcWhiteboardPdfView(Context context, AttributeSet attrs) {
        super(context, attrs);
        this.mEnableTouchEvent = true;
        this.mTotalPages = 0;
        this.mLoaded = false;
    }

    public void close() {
        Logging.i(TAG, "close");
        this.mLoaded = false;
        recycle();
        this.mNativeHandle = 0L;
        this.mTotalPages = 0;
    }

    public void setEnableTouchEvent(boolean enable) {
        this.mEnableTouchEvent = enable;
        if (!enable) {
            setOnTouchListener(null);
        }
    }

    public boolean onTouchEvent(MotionEvent event) {
        if (this.mEnableTouchEvent) {
            return super.onTouchEvent(event);
        }
        return true;
    }

    public void scrollTo(int page, float pos) {
        if (this.mTotalPages <= 0) {
            return;
        }
        Logging.i(TAG, "scrollTo " + getCurrentYOffset() + "," + getPositionOffset());
        setPositionOffset(pos, true);
    }

    public void scaleTo(float scale, float x, float y) {
        if (!this.mLoaded) {
            return;
        }
        zoomTo(scale);
        moveTo(-x, -y);
        loadPages();
    }

    protected void onAttachedToWindow() {
        super.onAttachedToWindow();
    }

    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        this.mNativeHandle = 0L;
        this.mTotalPages = 0;
        this.mLoaded = false;
        Logging.i(TAG, "onDetachedFromWindow");
    }

    protected void onSizeChanged(int w, int h, int oldw, int oldh) {
        super.onSizeChanged(w, h, oldw, oldh);
        Logging.i(TAG, "view size changed, w " + w + "x" + h);
        float[] pageSizes = new float[this.mTotalPages * 2];
        for (int idx = 0; idx < this.mTotalPages; idx++) {
            SizeF size = getPageSize(idx);
            pageSizes[idx * 2] = size.getWidth();
            pageSizes[(idx * 2) + 1] = size.getHeight();
        }
        OnLoadComplete(this.mNativeHandle, this.mPageId, pageSizes);
    }

    public void setPageId(String pageId) {
        this.mPageId = pageId;
    }

    public String getPageId() {
        return this.mPageId;
    }

    public void setNativeHandle(long nativeHandle) {
        this.mNativeHandle = nativeHandle;
    }

    public void setPdfUrl(String url) {
        String str = this.mUrl;
        if (str == null || !str.equals(url)) {
            this.mUrl = url;
            PDFView.Configurator config = fromUri(Uri.parse(url));
            config.spacing(0).enableSwipe(false).swipeHorizontal(false).scrollHandle((ScrollHandle) null).enableAntialiasing(true).enableAnnotationRendering(false);
            config.onLoad(new OnLoadCompleteListener() { // from class: com.ding.rtc.RtcWhiteboardPdfView.1
                public void loadComplete(int i) {
                    Logging.i(RtcWhiteboardPdfView.TAG, "pdf load completed " + i);
                    RtcWhiteboardPdfView.this.mLoaded = true;
                    RtcWhiteboardPdfView.this.mTotalPages = i;
                    float[] pageSizes = new float[RtcWhiteboardPdfView.this.mTotalPages * 2];
                    for (int idx = 0; idx < RtcWhiteboardPdfView.this.mTotalPages; idx++) {
                        SizeF size = RtcWhiteboardPdfView.this.getPageSize(idx);
                        pageSizes[idx * 2] = size.getWidth();
                        pageSizes[(idx * 2) + 1] = size.getHeight();
                    }
                    RtcWhiteboardPdfView.OnLoadComplete(RtcWhiteboardPdfView.this.mNativeHandle, RtcWhiteboardPdfView.this.mPageId, pageSizes);
                    RtcWhiteboardPdfView.this.setOnTouchListener(null);
                }
            });
            config.onPageChange(new OnPageChangeListener() { // from class: com.ding.rtc.RtcWhiteboardPdfView.2
                public void onPageChanged(int i, int i1) {
                }
            });
            config.onPageScroll(new OnPageScrollListener() { // from class: com.ding.rtc.RtcWhiteboardPdfView.3
                public void onPageScrolled(int i, float v) {
                }
            });
            config.onError(new OnErrorListener() { // from class: com.ding.rtc.RtcWhiteboardPdfView.4
                public void onError(Throwable throwable) {
                    Logging.i(RtcWhiteboardPdfView.TAG, "onError " + throwable.getMessage() + "," + throwable.getLocalizedMessage());
                }
            });
            config.load();
        }
    }

    public void snapshot(String filePath) {
        int viewWidth = getWidth();
        int viewHeight = getHeight();
        Bitmap bitmap = Bitmap.createBitmap(viewWidth, viewHeight, Bitmap.Config.ARGB_8888);
        Canvas canvas = new Canvas(bitmap);
        draw(canvas);
        Bitmap ssBitmap = Bitmap.createBitmap(bitmap, 0, 0, viewWidth, viewHeight);
        try {
            File file = new File(filePath);
            ssBitmap.compress(Bitmap.CompressFormat.JPEG, 85, new FileOutputStream(file));
            OnSnapshotComplete(this.mNativeHandle, this.mPageId, filePath);
            Logging.i(TAG, "snapshot complete " + filePath);
        } catch (FileNotFoundException e) {
        }
    }
}
