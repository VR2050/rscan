package com.ding.rtc;

import android.content.Context;
import android.text.TextUtils;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import java.io.File;
import org.webrtc.mozi.Logging;

/* JADX INFO: loaded from: classes.dex */
public class DingRtcWhiteboardView extends FrameLayout {
    private static final String TAG = "MzwaView";
    private boolean mEnableTouch;
    private boolean mIsOpaque;
    private final RtcWhiteboardLableView mLabelView;
    private long mNativeHandle;
    private int mPdfHeightRatio;
    private int mPdfWidthRatio;
    private final RtcWhiteboardSurfaceView mRtcWbView;

    public DingRtcWhiteboardView(Context context) {
        this(context, null);
    }

    public DingRtcWhiteboardView(Context context, AttributeSet attrs) {
        super(context, attrs);
        this.mIsOpaque = true;
        this.mEnableTouch = true;
        this.mNativeHandle = 0L;
        this.mPdfWidthRatio = 0;
        this.mPdfHeightRatio = 0;
        RtcWhiteboardSurfaceView rtcWhiteboardSurfaceView = new RtcWhiteboardSurfaceView(context, attrs);
        this.mRtcWbView = rtcWhiteboardSurfaceView;
        addView(rtcWhiteboardSurfaceView, new FrameLayout.LayoutParams(-1, -1));
        RtcWhiteboardLableView rtcWhiteboardLableView = new RtcWhiteboardLableView(context, attrs);
        this.mLabelView = rtcWhiteboardLableView;
        addView(rtcWhiteboardLableView, -1, new FrameLayout.LayoutParams(-1, -1));
    }

    public RtcWhiteboardSurfaceView getAttachRtcWbView() {
        return this.mRtcWbView;
    }

    public RtcWhiteboardLableView getAttachLabelView() {
        return this.mLabelView;
    }

    public void setOpaque(final boolean opaque) {
        post(new Runnable() { // from class: com.ding.rtc.-$$Lambda$DingRtcWhiteboardView$kgKs5M9QxbiTrCw7gnqrcaDcDxI
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$setOpaque$0$DingRtcWhiteboardView(opaque);
            }
        });
    }

    public /* synthetic */ void lambda$setOpaque$0$DingRtcWhiteboardView(final boolean opaque) {
        Logging.i(TAG, "setOpaque " + opaque + this.mIsOpaque);
        this.mRtcWbView.setVisibility(8);
        this.mRtcWbView.setTransparent(opaque ^ true);
        this.mRtcWbView.setVisibility(0);
    }

    public void setLimitSize(int w, int h) {
        this.mPdfWidthRatio = w;
        this.mPdfHeightRatio = h;
        Logging.i(TAG, "setLimitSize " + w + ", " + h);
    }

    public void enableTouchEvent(boolean enable) {
        this.mEnableTouch = enable;
        int childCount = getChildCount();
        for (int i = 0; i < childCount; i++) {
            Object childAt = getChildAt(i);
            Logging.i(TAG, "enableTouchEvent " + i + "," + childAt);
            if (childAt instanceof RtcWhiteboardPdfView) {
                ((RtcWhiteboardPdfView) childAt).setEnableTouchEvent(enable);
            }
        }
    }

    public void setNativeHandle(long nativeHandle) {
        this.mNativeHandle = nativeHandle;
    }

    public void close() {
        Logging.i(TAG, "close");
        post(new Runnable() { // from class: com.ding.rtc.-$$Lambda$DingRtcWhiteboardView$GzWnf8M7GYjZlVugL2BdI6H5FjI
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$close$1$DingRtcWhiteboardView();
            }
        });
    }

    /* JADX WARN: Multi-variable type inference failed */
    public /* synthetic */ void lambda$close$1$DingRtcWhiteboardView() {
        int childCount = getChildCount();
        int i = 0;
        while (i < childCount) {
            View childAt = getChildAt(i);
            Logging.i(TAG, "closeall " + i + "," + childAt);
            if (childAt instanceof RtcWhiteboardPdfView) {
                ((RtcWhiteboardPdfView) childAt).close();
                Logging.i(TAG, "closeall " + ((RtcWhiteboardPdfView) childAt));
                removeView(childAt);
                childCount += -1;
                i += -1;
            }
            i++;
        }
    }

    public void addCursor(final String labelId, final String name) {
        post(new Runnable() { // from class: com.ding.rtc.-$$Lambda$DingRtcWhiteboardView$xZbxYzcuM_MavikExQIkH6p5aHM
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$addCursor$2$DingRtcWhiteboardView(labelId, name);
            }
        });
    }

    public /* synthetic */ void lambda$addCursor$2$DingRtcWhiteboardView(final String labelId, final String name) {
        this.mLabelView.addCursor(labelId, name);
        Logging.i(TAG, "addCursor " + labelId + "," + name);
    }

    public void removeCursor(final String labelId) {
        post(new Runnable() { // from class: com.ding.rtc.-$$Lambda$DingRtcWhiteboardView$tmrWQK_cguOmyL-EJOesoAbXOtM
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$removeCursor$3$DingRtcWhiteboardView(labelId);
            }
        });
    }

    public /* synthetic */ void lambda$removeCursor$3$DingRtcWhiteboardView(final String labelId) {
        this.mLabelView.removeCursor(labelId);
        Logging.i(TAG, "removeCursor " + labelId);
    }

    public void updateCursor(final String labelId, final float x, final float y, final int color, final int type, final String name) {
        post(new Runnable() { // from class: com.ding.rtc.-$$Lambda$DingRtcWhiteboardView$c7oZJVKIT5UmzSUGIr-P1Hd28CM
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$updateCursor$4$DingRtcWhiteboardView(labelId, x, y, color, type, name);
            }
        });
    }

    public /* synthetic */ void lambda$updateCursor$4$DingRtcWhiteboardView(final String labelId, final float x, final float y, final int color, final int type, final String name) {
        this.mLabelView.updateCursor(labelId, x, y, color, type, name);
        Logging.i(TAG, "updateCursor " + labelId);
    }

    public void openPdf(final String pageId, final String url) {
        post(new Runnable() { // from class: com.ding.rtc.-$$Lambda$DingRtcWhiteboardView$uuLbXuFviaZ2klKTx3UggrqhOic
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$openPdf$5$DingRtcWhiteboardView(url, pageId);
            }
        });
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r0v0, types: [android.view.View, com.ding.rtc.RtcWhiteboardPdfView] */
    public /* synthetic */ void lambda$openPdf$5$DingRtcWhiteboardView(final String url, final String pageId) {
        int i;
        int w;
        int h;
        ?? rtcWhiteboardPdfView = new RtcWhiteboardPdfView(getContext());
        rtcWhiteboardPdfView.setEnableTouchEvent(this.mEnableTouch);
        int viewWidth = getWidth();
        int viewHeight = getHeight();
        int i2 = this.mPdfWidthRatio;
        if (i2 == 0 || (i = this.mPdfHeightRatio) == 0) {
            addView((View) rtcWhiteboardPdfView, 0, new FrameLayout.LayoutParams(-1, -1));
        } else {
            if (viewWidth * i > viewHeight * i2) {
                int w2 = (i2 * viewHeight) / i;
                h = viewHeight;
                w = w2;
            } else {
                w = viewWidth;
                h = (i * viewWidth) / i2;
            }
            FrameLayout.LayoutParams l = new FrameLayout.LayoutParams(w, h);
            l.gravity = 17;
            Logging.i(TAG, "openpdf " + l.gravity + "," + l.width + "," + l.height + ", view:" + getWidth() + "," + getHeight());
            addView((View) rtcWhiteboardPdfView, 0, l);
        }
        rtcWhiteboardPdfView.setPdfUrl(url);
        rtcWhiteboardPdfView.setPageId(pageId);
        rtcWhiteboardPdfView.setNativeHandle(this.mNativeHandle);
        Logging.i(TAG, "openPdf " + pageId);
    }

    public void hidePdf(final String pageId) {
        post(new Runnable() { // from class: com.ding.rtc.-$$Lambda$DingRtcWhiteboardView$w6Q7QYAIBoSqFxYgGWhpX64BS-U
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$hidePdf$6$DingRtcWhiteboardView(pageId);
            }
        });
    }

    public /* synthetic */ void lambda$hidePdf$6$DingRtcWhiteboardView(final String pageId) {
        RtcWhiteboardPdfView pdfView = getPdfViewById(pageId);
        if (pdfView != null) {
            pdfView.setVisibility(8);
            Logging.i(TAG, "hidePdf " + pageId);
        }
    }

    public void showPdf(final String pageId) {
        post(new Runnable() { // from class: com.ding.rtc.-$$Lambda$DingRtcWhiteboardView$8Iugc8YX85cZjxdbt6iVCzufjAc
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$showPdf$7$DingRtcWhiteboardView(pageId);
            }
        });
    }

    public /* synthetic */ void lambda$showPdf$7$DingRtcWhiteboardView(final String pageId) {
        RtcWhiteboardPdfView pdfView = getPdfViewById(pageId);
        if (pdfView != null) {
            pdfView.setVisibility(0);
            Logging.i(TAG, "showPdf " + pageId);
        }
    }

    public void closePdf(final String pageId) {
        post(new Runnable() { // from class: com.ding.rtc.-$$Lambda$DingRtcWhiteboardView$-80lm3BOqHgWGe_Yp6f-Hk_1jS4
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$closePdf$8$DingRtcWhiteboardView(pageId);
            }
        });
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r0v0, types: [android.view.View, com.ding.rtc.RtcWhiteboardPdfView] */
    public /* synthetic */ void lambda$closePdf$8$DingRtcWhiteboardView(final String pageId) {
        ?? pdfViewById = getPdfViewById(pageId);
        if (pdfViewById != 0) {
            pdfViewById.close();
            removeView(pdfViewById);
            Logging.i(TAG, "closePdf " + pageId);
        }
    }

    public void scrollPdfTo(final String pageId, final int page, final float pos) {
        post(new Runnable() { // from class: com.ding.rtc.-$$Lambda$DingRtcWhiteboardView$BFtENiRYvkKyuMVzxNqFlAOsQv0
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$scrollPdfTo$9$DingRtcWhiteboardView(pageId, page, pos);
            }
        });
    }

    public /* synthetic */ void lambda$scrollPdfTo$9$DingRtcWhiteboardView(final String pageId, final int page, final float pos) {
        RtcWhiteboardPdfView pdfView = getPdfViewById(pageId);
        if (pdfView != null) {
            pdfView.scrollTo(page, pos);
        }
    }

    public void scalePdfTo(final String pageId, final float scale, final float x, final float y) {
        post(new Runnable() { // from class: com.ding.rtc.-$$Lambda$DingRtcWhiteboardView$9pVurpfNkUhLAjDzKoYPbLqjSiY
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$scalePdfTo$10$DingRtcWhiteboardView(pageId, scale, x, y);
            }
        });
    }

    public /* synthetic */ void lambda$scalePdfTo$10$DingRtcWhiteboardView(final String pageId, final float scale, final float x, final float y) {
        RtcWhiteboardPdfView pdfView = getPdfViewById(pageId);
        if (pdfView != null) {
            pdfView.scaleTo(scale, x, y);
        }
    }

    public void snapshotPdf(final String pageId, final String path) {
        post(new Runnable() { // from class: com.ding.rtc.-$$Lambda$DingRtcWhiteboardView$BGsPjq9np1y0xXE6vsqNJu4khOQ
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$snapshotPdf$11$DingRtcWhiteboardView(pageId, path);
            }
        });
    }

    public /* synthetic */ void lambda$snapshotPdf$11$DingRtcWhiteboardView(final String pageId, final String path) {
        RtcWhiteboardPdfView pdfView = getPdfViewById(pageId);
        if (pdfView != null) {
            pdfView.snapshot(path + File.separator + "whiteboard_snapshot_" + pageId + ".jpg");
            StringBuilder sb = new StringBuilder();
            sb.append("snapshot ");
            sb.append(pageId);
            Logging.i(TAG, sb.toString());
        }
    }

    @Override // android.view.View
    protected void onSizeChanged(final int w, final int h, int oldw, int oldh) {
        super.onSizeChanged(w, h, oldw, oldh);
        post(new Runnable() { // from class: com.ding.rtc.DingRtcWhiteboardView.1
            @Override // java.lang.Runnable
            public void run() {
                int nw;
                int nw2;
                if (DingRtcWhiteboardView.this.mPdfWidthRatio != 0 && DingRtcWhiteboardView.this.mPdfHeightRatio != 0) {
                    int i = w;
                    int i2 = h;
                    if (w * DingRtcWhiteboardView.this.mPdfHeightRatio > h * DingRtcWhiteboardView.this.mPdfWidthRatio) {
                        nw = (h * DingRtcWhiteboardView.this.mPdfWidthRatio) / DingRtcWhiteboardView.this.mPdfHeightRatio;
                        nw2 = h;
                    } else {
                        nw = w;
                        int nw3 = w;
                        nw2 = (nw3 * DingRtcWhiteboardView.this.mPdfHeightRatio) / DingRtcWhiteboardView.this.mPdfWidthRatio;
                    }
                    int childCount = DingRtcWhiteboardView.this.getChildCount();
                    for (int i3 = 0; i3 < childCount; i3++) {
                        View childView = DingRtcWhiteboardView.this.getChildAt(i3);
                        if (childView instanceof RtcWhiteboardPdfView) {
                            ViewGroup.LayoutParams params = childView.getLayoutParams();
                            if (params instanceof FrameLayout.LayoutParams) {
                                FrameLayout.LayoutParams lp = new FrameLayout.LayoutParams(nw, nw2);
                                lp.gravity = 17;
                                Logging.i(DingRtcWhiteboardView.TAG, "onSizeChanged " + lp.gravity + "," + lp.width + "," + lp.height);
                                childView.setLayoutParams(lp);
                            }
                        }
                    }
                }
            }
        });
    }

    private RtcWhiteboardPdfView getPdfViewById(String pageId) {
        if (TextUtils.isEmpty(pageId)) {
            return null;
        }
        int childCount = getChildCount();
        for (int i = 0; i < childCount; i++) {
            Object childAt = getChildAt(i);
            if (childAt instanceof RtcWhiteboardPdfView) {
                RtcWhiteboardPdfView pdfView = (RtcWhiteboardPdfView) childAt;
                if (pageId.equals(pdfView.getPageId())) {
                    return pdfView;
                }
            }
        }
        return null;
    }
}
