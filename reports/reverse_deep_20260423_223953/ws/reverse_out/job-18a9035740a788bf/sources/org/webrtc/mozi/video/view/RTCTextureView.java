package org.webrtc.mozi.video.view;

import android.content.Context;
import android.graphics.SurfaceTexture;
import android.util.AttributeSet;
import android.view.Surface;
import android.view.TextureView;
import android.view.View;
import org.webrtc.mozi.Logging;
import org.webrtc.mozi.video.view.RTCRenderViewDelegate;

/* JADX INFO: loaded from: classes3.dex */
public class RTCTextureView extends TextureView implements TextureView.SurfaceTextureListener, RTCRenderViewDelegate.RenderStub {
    private static final String TAG = "RTCTextureView";
    private int measureHeight;
    private int measureWidth;
    private Surface renderSurface;
    private RTCRenderViewDelegate videoRenderDelegate;

    public RTCTextureView(Context context) {
        this(context, null);
    }

    public RTCTextureView(Context context, AttributeSet attrs) {
        this(context, attrs, 0);
    }

    public RTCTextureView(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        this.measureWidth = -1;
        this.measureHeight = -1;
        setSurfaceTextureListener(this);
    }

    @Override // org.webrtc.mozi.video.view.RTCRenderViewDelegate.RenderStub
    public Surface getSurface() {
        return this.renderSurface;
    }

    @Override // org.webrtc.mozi.video.view.RTCRenderViewDelegate.RenderStub
    public boolean applyAutoFitViewport() {
        setOpaque(false);
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
        return !isOpaque();
    }

    @Override // org.webrtc.mozi.video.view.RTCRenderViewDelegate.RenderStub
    public void attachRenderDelegate(RTCRenderViewDelegate videoRenderDelegate) {
        int i;
        this.videoRenderDelegate = videoRenderDelegate;
        if (videoRenderDelegate != null) {
            Surface surface = this.renderSurface;
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

    @Override // android.view.View
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

    @Override // android.view.TextureView.SurfaceTextureListener
    public void onSurfaceTextureAvailable(SurfaceTexture surface, int width, int height) {
        if (this.renderSurface == null) {
            this.renderSurface = new Surface(getSurfaceTexture());
        }
        RTCRenderViewDelegate rTCRenderViewDelegate = this.videoRenderDelegate;
        if (rTCRenderViewDelegate == null) {
            Logging.w(TAG, "onSurfaceTextureAvailable, videoRenderDelegate is null " + toString());
            return;
        }
        rTCRenderViewDelegate.onSurfaceAvailable(this.renderSurface);
    }

    @Override // android.view.TextureView.SurfaceTextureListener
    public void onSurfaceTextureSizeChanged(SurfaceTexture surface, int width, int height) {
        RTCRenderViewDelegate rTCRenderViewDelegate = this.videoRenderDelegate;
        if (rTCRenderViewDelegate == null) {
            Logging.w(TAG, "onSurfaceTextureSizeChanged, videoRenderDelegate is null " + toString());
            return;
        }
        rTCRenderViewDelegate.onSurfaceChange(width, height);
    }

    @Override // android.view.TextureView.SurfaceTextureListener
    public boolean onSurfaceTextureDestroyed(SurfaceTexture surface) {
        Surface surface2 = this.renderSurface;
        if (surface2 != null) {
            surface2.release();
        }
        this.renderSurface = null;
        RTCRenderViewDelegate rTCRenderViewDelegate = this.videoRenderDelegate;
        if (rTCRenderViewDelegate == null) {
            Logging.w(TAG, "onSurfaceTextureDestroyed, videoRenderDelegate is null " + toString());
            return true;
        }
        rTCRenderViewDelegate.onSurfaceDestroyed();
        return true;
    }

    @Override // android.view.TextureView.SurfaceTextureListener
    public void onSurfaceTextureUpdated(SurfaceTexture surface) {
    }

    @Override // android.view.View
    public String toString() {
        return "RTCTextureView@" + Integer.toHexString(hashCode());
    }
}
