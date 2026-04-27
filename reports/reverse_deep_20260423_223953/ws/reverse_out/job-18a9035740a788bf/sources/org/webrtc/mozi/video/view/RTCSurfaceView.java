package org.webrtc.mozi.video.view;

import android.content.Context;
import android.util.AttributeSet;
import android.view.Surface;
import android.view.SurfaceHolder;
import android.view.SurfaceView;
import android.view.View;
import org.webrtc.mozi.Logging;
import org.webrtc.mozi.ThreadUtils;
import org.webrtc.mozi.video.view.RTCRenderViewDelegate;

/* JADX INFO: loaded from: classes3.dex */
public class RTCSurfaceView extends SurfaceView implements SurfaceHolder.Callback, RTCRenderViewDelegate.RenderStub {
    private static final String TAG = "RTCSurfaceView";
    private boolean isSurfaceCreated;
    private int measureHeight;
    private int measureWidth;
    protected int rotatedFrameHeight;
    protected int rotatedFrameWidth;
    private int surfaceHeight;
    private int surfaceWidth;
    private RTCRenderViewDelegate videoRenderDelegate;

    public RTCSurfaceView(Context context) {
        this(context, null);
    }

    public RTCSurfaceView(Context context, AttributeSet attrs) {
        super(context, attrs);
        this.isSurfaceCreated = false;
        this.measureWidth = -1;
        this.measureHeight = -1;
        getHolder().addCallback(this);
    }

    @Override // org.webrtc.mozi.video.view.RTCRenderViewDelegate.RenderStub
    public Surface getSurface() {
        if (this.isSurfaceCreated) {
            return getHolder().getSurface();
        }
        return null;
    }

    @Override // org.webrtc.mozi.video.view.RTCRenderViewDelegate.RenderStub
    public boolean applyAutoFitViewport() {
        return true;
    }

    @Override // org.webrtc.mozi.video.view.RTCRenderViewDelegate.RenderStub
    public void setRenderDimension(int width, int height) {
        setMeasuredDimension(width, height);
    }

    @Override // org.webrtc.mozi.video.view.RTCRenderViewDelegate.RenderStub
    public View getView() {
        return this;
    }

    @Override // org.webrtc.mozi.video.view.RTCRenderViewDelegate.RenderStub
    public boolean isTransparent() {
        return false;
    }

    @Override // org.webrtc.mozi.video.view.RTCRenderViewDelegate.RenderStub
    public void attachRenderDelegate(RTCRenderViewDelegate videoRenderDelegate) {
        int i;
        this.videoRenderDelegate = videoRenderDelegate;
        if (videoRenderDelegate != null) {
            Surface surface = getSurface();
            if (surface != null) {
                videoRenderDelegate.onSurfaceAvailable(surface);
                Logging.d(TAG, "surface already ready. render:" + toString());
            } else {
                Logging.d(TAG, "surface not ready. render:" + toString());
            }
            int i2 = this.measureWidth;
            if (i2 != -1 && (i = this.measureHeight) != -1) {
                videoRenderDelegate.measureSize(i2, i);
            }
        }
    }

    @Override // android.view.SurfaceView, android.view.View
    protected void onMeasure(int widthSpec, int heightSpec) {
        this.measureWidth = widthSpec;
        this.measureHeight = heightSpec;
        RTCRenderViewDelegate rTCRenderViewDelegate = this.videoRenderDelegate;
        if (rTCRenderViewDelegate == null) {
            Logging.w(TAG, "onMeasure, videoRenderDelegate is null " + toString());
            super.onMeasure(widthSpec, heightSpec);
            return;
        }
        if (!rTCRenderViewDelegate.measureSize(widthSpec, heightSpec)) {
            super.onMeasure(widthSpec, heightSpec);
        }
    }

    @Override // android.view.View
    protected void onSizeChanged(int w, int h, int oldw, int oldh) {
        if (w != oldw || h != oldh) {
            updateSurfaceSize();
        }
    }

    protected void updateSurfaceSize() {
        int drawnFrameWidth;
        int drawnFrameWidth2;
        ThreadUtils.checkIsOnMainThread();
        if (this.rotatedFrameWidth != 0 && this.rotatedFrameHeight != 0 && getWidth() != 0 && getHeight() != 0) {
            float layoutAspectRatio = getWidth() / getHeight();
            int i = this.rotatedFrameWidth;
            int i2 = this.rotatedFrameHeight;
            float frameAspectRatio = i / i2;
            if (frameAspectRatio > layoutAspectRatio) {
                drawnFrameWidth2 = (int) (i2 * layoutAspectRatio);
                drawnFrameWidth = this.rotatedFrameHeight;
            } else {
                int drawnFrameHeight = this.rotatedFrameWidth;
                drawnFrameWidth = (int) (i / layoutAspectRatio);
                drawnFrameWidth2 = drawnFrameHeight;
            }
            int width = Math.min(getWidth(), drawnFrameWidth2);
            int height = Math.min(getHeight(), drawnFrameWidth);
            Logging.d(TAG, "updateSurfaceSize. Layout size: " + getWidth() + "x" + getHeight() + ", frame size: " + this.rotatedFrameWidth + "x" + this.rotatedFrameHeight + ", requested surface size: " + width + "x" + height + ", old surface size: " + this.surfaceWidth + "x" + this.surfaceHeight);
            if (width != this.surfaceWidth || height != this.surfaceHeight) {
                this.surfaceWidth = width;
                this.surfaceHeight = height;
                getHolder().setFixedSize(width, height);
                return;
            }
            return;
        }
        this.surfaceHeight = 0;
        this.surfaceWidth = 0;
        getHolder().setSizeFromLayout();
    }

    @Override // android.view.SurfaceHolder.Callback
    public void surfaceCreated(SurfaceHolder holder) {
        this.isSurfaceCreated = true;
        this.surfaceHeight = 0;
        this.surfaceWidth = 0;
        updateSurfaceSize();
        RTCRenderViewDelegate rTCRenderViewDelegate = this.videoRenderDelegate;
        if (rTCRenderViewDelegate == null) {
            Logging.w(TAG, "surfaceCreated, videoRenderDelegate is null " + toString());
            return;
        }
        rTCRenderViewDelegate.onSurfaceAvailable(holder.getSurface());
    }

    @Override // android.view.SurfaceHolder.Callback
    public void surfaceDestroyed(SurfaceHolder holder) {
        this.isSurfaceCreated = false;
        RTCRenderViewDelegate rTCRenderViewDelegate = this.videoRenderDelegate;
        if (rTCRenderViewDelegate == null) {
            Logging.w(TAG, "surfaceDestroyed, videoRenderDelegate is null " + toString());
            return;
        }
        rTCRenderViewDelegate.onSurfaceDestroyed();
    }

    @Override // android.view.SurfaceHolder.Callback
    public void surfaceChanged(SurfaceHolder holder, int format, int width, int height) {
        RTCRenderViewDelegate rTCRenderViewDelegate = this.videoRenderDelegate;
        if (rTCRenderViewDelegate == null) {
            Logging.w(TAG, "surfaceChanged, videoRenderDelegate is null " + toString());
            return;
        }
        rTCRenderViewDelegate.onSurfaceChange(width, height);
    }

    @Override // android.view.View
    public String toString() {
        return "RTCSurfaceView@" + Integer.toHexString(hashCode());
    }
}
