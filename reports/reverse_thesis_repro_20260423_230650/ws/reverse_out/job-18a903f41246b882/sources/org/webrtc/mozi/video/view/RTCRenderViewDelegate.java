package org.webrtc.mozi.video.view;

import android.graphics.Matrix;
import android.graphics.Point;
import android.view.Surface;
import android.view.View;
import com.litesuits.orm.db.assit.SQLBuilder;
import org.webrtc.mozi.EglBase;
import org.webrtc.mozi.GlRectDrawer;
import org.webrtc.mozi.Logging;
import org.webrtc.mozi.RendererCommon;
import org.webrtc.mozi.video.render.IRTCVideoRender;
import org.webrtc.mozi.video.render.RTCVideoEglGenericRender;
import org.webrtc.mozi.video.render.RTCVideoRenderOptions;
import org.webrtc.mozi.video.render.egl.RTCEglPool;

/* JADX INFO: loaded from: classes3.dex */
public class RTCRenderViewDelegate implements IRTCVideoRender.FrameRenderListener {
    private static final String TAG = "MoziRenderViewDelegate";
    private int backgroundColor;
    private final IRTCVideoRender eglRenderer;
    private int heightMeasureSpec;
    private String mTraceId;
    private final RenderStub renderStub;
    private IRTCVideoRender.FrameRenderListener rendererEvents;
    private int rotatedFrameHeight;
    private int rotatedFrameWidth;
    private int widthMeasureSpec;
    private final RendererCommon.VideoLayoutMeasure videoLayoutMeasure = new RendererCommon.VideoLayoutMeasure();
    private boolean autoFitEglViewport = true;

    public interface RenderStub {
        boolean applyAutoFitViewport();

        void attachRenderDelegate(RTCRenderViewDelegate rTCRenderViewDelegate);

        Surface getSurface();

        View getView();

        boolean isTransparent();

        void setRenderDimension(int i, int i2);
    }

    public RTCRenderViewDelegate(String traceId, RenderStub renderStub, IRTCVideoRender eglRenderer) {
        this.mTraceId = traceId;
        this.renderStub = renderStub;
        this.eglRenderer = eglRenderer;
        renderStub.attachRenderDelegate(this);
    }

    public void init(EglBase.Context sharedContext, IRTCVideoRender.FrameRenderListener events) {
        traceLog("init.");
        this.rendererEvents = events;
        this.rotatedFrameWidth = 0;
        this.rotatedFrameHeight = 0;
        int[] configAttributes = this.renderStub.isTransparent() ? EglBase.CONFIG_RGBA : EglBase.CONFIG_PLAIN;
        this.eglRenderer.init(sharedContext, this, configAttributes, new GlRectDrawer());
    }

    public void release() {
        traceLog("release.");
        this.eglRenderer.release();
    }

    public View getRenderView() {
        return this.renderStub.getView();
    }

    public IRTCVideoRender getRenderer() {
        return this.eglRenderer;
    }

    public void setScalingType(RendererCommon.ScalingType hMatchScaleType, RendererCommon.ScalingType hMismatchScaleType, RendererCommon.ScalingType vMatchScaleType, RendererCommon.ScalingType vMismatchScaleType) {
        if (!this.autoFitEglViewport) {
            this.videoLayoutMeasure.setScalingType(hMatchScaleType, hMismatchScaleType, vMatchScaleType, vMismatchScaleType);
            this.renderStub.getView().post(new Runnable() { // from class: org.webrtc.mozi.video.view.RTCRenderViewDelegate.1
                @Override // java.lang.Runnable
                public void run() {
                    RTCRenderViewDelegate.this.renderStub.getView().requestLayout();
                }
            });
        } else {
            this.eglRenderer.setScalingType(hMatchScaleType, hMismatchScaleType, vMatchScaleType, vMismatchScaleType);
        }
    }

    public void setBackgroundColor(int color) {
        if (this.autoFitEglViewport) {
            this.backgroundColor = color;
        }
    }

    @Override // org.webrtc.mozi.video.render.IRTCVideoRender.FrameRenderListener
    public void onReceiveFrame(IRTCVideoRender.VideoFrameType frameType) {
        IRTCVideoRender.FrameRenderListener frameRenderListener = this.rendererEvents;
        if (frameRenderListener != null) {
            frameRenderListener.onReceiveFrame(frameType);
        }
    }

    @Override // org.webrtc.mozi.video.render.IRTCVideoRender.FrameRenderListener
    public void onRenderFrame(IRTCVideoRender.VideoFrameType frameType) {
        IRTCVideoRender.FrameRenderListener frameRenderListener = this.rendererEvents;
        if (frameRenderListener != null) {
            frameRenderListener.onRenderFrame(frameType);
        }
    }

    @Override // org.webrtc.mozi.video.render.IRTCVideoRender.FrameRenderListener
    public void onRenderRegionChange(int width, int height) {
        IRTCVideoRender.FrameRenderListener frameRenderListener = this.rendererEvents;
        if (frameRenderListener != null) {
            frameRenderListener.onRenderRegionChange(width, height);
        }
    }

    @Override // org.webrtc.mozi.RendererCommon.RendererEvents
    public void onFirstFrameRendered() {
    }

    @Override // org.webrtc.mozi.video.render.IRTCVideoRender.FrameRenderListener
    public void onFirstFrameRenderedWithResolution(int width, int height) {
        traceLog("onFirstFrameRenderedWithResolution.");
        IRTCVideoRender.FrameRenderListener frameRenderListener = this.rendererEvents;
        if (frameRenderListener != null) {
            frameRenderListener.onFirstFrameRenderedWithResolution(width, height);
        }
    }

    @Override // org.webrtc.mozi.video.render.IRTCVideoRender.FrameRenderListener
    public void onFrameRenderedWithResolution(int width, int height) {
        IRTCVideoRender.FrameRenderListener frameRenderListener = this.rendererEvents;
        if (frameRenderListener != null) {
            frameRenderListener.onFrameRenderedWithResolution(width, height);
        }
    }

    @Override // org.webrtc.mozi.RendererCommon.RendererEvents
    public void onFrameResolutionChanged(int videoWidth, int videoHeight, int rotation) {
        traceLog("onFrameResolutionChanged. " + videoWidth + "x" + videoHeight + ", " + rotation);
        IRTCVideoRender.FrameRenderListener frameRenderListener = this.rendererEvents;
        if (frameRenderListener != null) {
            frameRenderListener.onFrameResolutionChanged(videoWidth, videoHeight, rotation);
        }
        if (!this.autoFitEglViewport) {
            int rotatedWidth = (rotation == 0 || rotation == 180) ? videoWidth : videoHeight;
            int rotatedHeight = (rotation == 0 || rotation == 180) ? videoHeight : videoWidth;
            this.rotatedFrameWidth = rotatedWidth;
            this.rotatedFrameHeight = rotatedHeight;
            this.renderStub.getView().post(new Runnable() { // from class: org.webrtc.mozi.video.view.RTCRenderViewDelegate.2
                @Override // java.lang.Runnable
                public void run() {
                    RTCRenderViewDelegate.this.renderStub.getView().requestLayout();
                }
            });
        }
    }

    boolean measureSize(int widthSpec, int heightSpec) {
        if (this.widthMeasureSpec != widthSpec || this.heightMeasureSpec != heightSpec) {
            this.eglRenderer.setSurfaceMeasureSpec(widthSpec, heightSpec);
            traceLog("measureSize. New spec: " + widthSpec + "x" + heightSpec + ", Default size:" + View.getDefaultSize(Integer.MAX_VALUE, this.widthMeasureSpec) + "x" + View.getDefaultSize(Integer.MAX_VALUE, this.heightMeasureSpec) + ", Spec size: " + View.MeasureSpec.getSize(this.widthMeasureSpec) + "x" + View.MeasureSpec.getSize(this.heightMeasureSpec));
        }
        this.widthMeasureSpec = widthSpec;
        this.heightMeasureSpec = heightSpec;
        if (!this.autoFitEglViewport) {
            Point size = this.videoLayoutMeasure.measure(widthSpec, heightSpec);
            this.renderStub.setRenderDimension(size.x, size.y);
            traceLog("measureSize. New size: " + size.x + "x" + size.y);
            return true;
        }
        return false;
    }

    void onSurfaceAvailable(Surface surface) {
        this.eglRenderer.createSurface(surface, this.autoFitEglViewport, this.backgroundColor);
    }

    void onSurfaceChange(int width, int height) {
        this.eglRenderer.setSurfaceSize(width, height);
    }

    void onSurfaceDestroyed() {
        this.eglRenderer.destroySurface();
    }

    public void setRotateByOrientation(boolean rotateByOrientation) {
        this.eglRenderer.setRotateByOrientation(rotateByOrientation);
    }

    public void setTransformMatrix(Matrix matrix) {
        this.eglRenderer.setTransformMatrix(matrix);
    }

    private void setAutoFitEglViewport(boolean autoFitEglViewport) {
        if (autoFitEglViewport) {
            this.autoFitEglViewport = this.renderStub.applyAutoFitViewport();
        }
    }

    private void traceLog(String string) {
        Logging.d(TAG, string + " render: " + this.renderStub.toString() + ", egl: " + this.eglRenderer.toString() + ", trace:" + this.mTraceId);
    }

    public static RTCRenderViewDelegate delegate(String traceId, RenderStub renderStub, RTCEglPool RTCEglPool) {
        IRTCVideoRender renderer = new RTCVideoEglGenericRender("MoziEglRender(" + traceId + SQLBuilder.PARENTHESES_RIGHT, true);
        renderer.setRenderOptions(RTCVideoRenderOptions.EMPTY);
        renderer.setEglPool(RTCEglPool);
        RTCRenderViewDelegate delegate = new RTCRenderViewDelegate(traceId, renderStub, renderer);
        return delegate;
    }
}
