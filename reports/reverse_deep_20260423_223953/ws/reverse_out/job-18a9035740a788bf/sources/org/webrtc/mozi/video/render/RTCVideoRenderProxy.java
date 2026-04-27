package org.webrtc.mozi.video.render;

import android.graphics.Matrix;
import com.litesuits.orm.db.assit.SQLBuilder;
import org.webrtc.mozi.CodecMonitorHelper;
import org.webrtc.mozi.EglBase;
import org.webrtc.mozi.Logging;
import org.webrtc.mozi.RendererCommon;
import org.webrtc.mozi.VideoFrame;
import org.webrtc.mozi.video.render.IRTCVideoRender;
import org.webrtc.mozi.video.view.RTCRenderViewDelegate;

/* JADX INFO: loaded from: classes3.dex */
public class RTCVideoRenderProxy implements IRTCVideoRender.FrameRenderListener {
    private static final String TAG = "VideoRenderProxy";
    private long mNativeHandler;
    private String mTraceId;
    private IRTCVideoRender mRenderer = null;
    private RTCRenderViewDelegate mDelegate = null;

    private static native void nativeOnFirstFrameRenderedWithResolution(long j, int i, int i2);

    private static native void nativeOnFrameRenderedWithResolution(long j, int i, int i2);

    public RTCVideoRenderProxy(long nativeHandler, String traceId) {
        this.mNativeHandler = 0L;
        this.mNativeHandler = nativeHandler;
        this.mTraceId = traceId;
        traceLog("ctor");
    }

    public void init(Object viewDelegate, EglBase.Context sharedContext) {
        traceLog(CodecMonitorHelper.EVENT_INIT);
        try {
            RTCRenderViewDelegate rTCRenderViewDelegate = (RTCRenderViewDelegate) viewDelegate;
            this.mDelegate = rTCRenderViewDelegate;
            rTCRenderViewDelegate.init(sharedContext, this);
            this.mRenderer = this.mDelegate.getRenderer();
        } catch (Exception e) {
            e.printStackTrace();
            traceLog("init failed:" + e.getMessage());
        }
    }

    public void release() {
        traceLog("release");
        if (this.mRenderer != null) {
            this.mDelegate.release();
        }
    }

    public void setMirror(boolean mirror) {
        traceLog("setMirror, mirror:" + mirror);
        IRTCVideoRender iRTCVideoRender = this.mRenderer;
        if (iRTCVideoRender != null) {
            iRTCVideoRender.setMirror(mirror);
        }
    }

    public void setRotateByOrientation(boolean autoRotateByOrientation) {
        IRTCVideoRender iRTCVideoRender = this.mRenderer;
        if (iRTCVideoRender != null) {
            iRTCVideoRender.setRotateByOrientation(autoRotateByOrientation);
        }
    }

    public void setTransformMatrix(Matrix matrix) {
        IRTCVideoRender iRTCVideoRender = this.mRenderer;
        if (iRTCVideoRender != null) {
            iRTCVideoRender.setTransformMatrix(matrix);
        }
    }

    public void setScalingType(int hMatchScaleType, int hMismatchScaleType, int vMatchScaleType, int vMismatchScaleType) {
        IRTCVideoRender iRTCVideoRender = this.mRenderer;
        if (iRTCVideoRender != null) {
            iRTCVideoRender.setScalingType(convertToScalingType(hMatchScaleType), convertToScalingType(hMismatchScaleType), convertToScalingType(vMatchScaleType), convertToScalingType(vMismatchScaleType));
        }
    }

    public void renderFrame(VideoFrame frame) {
        IRTCVideoRender iRTCVideoRender = this.mRenderer;
        if (iRTCVideoRender != null) {
            iRTCVideoRender.renderFrame(frame);
        }
    }

    private void traceLog(String msg) {
        Logging.d("VideoRenderProxy(" + this.mTraceId + SQLBuilder.PARENTHESES_RIGHT, msg);
    }

    @Override // org.webrtc.mozi.video.render.IRTCVideoRender.FrameRenderListener
    public void onReceiveFrame(IRTCVideoRender.VideoFrameType frameType) {
    }

    @Override // org.webrtc.mozi.video.render.IRTCVideoRender.FrameRenderListener
    public void onRenderFrame(IRTCVideoRender.VideoFrameType frameType) {
    }

    @Override // org.webrtc.mozi.video.render.IRTCVideoRender.FrameRenderListener
    public void onRenderRegionChange(int width, int height) {
    }

    @Override // org.webrtc.mozi.RendererCommon.RendererEvents
    public void onFirstFrameRendered() {
    }

    @Override // org.webrtc.mozi.video.render.IRTCVideoRender.FrameRenderListener
    public void onFirstFrameRenderedWithResolution(int width, int height) {
        nativeOnFirstFrameRenderedWithResolution(this.mNativeHandler, width, height);
    }

    @Override // org.webrtc.mozi.video.render.IRTCVideoRender.FrameRenderListener
    public void onFrameRenderedWithResolution(int width, int height) {
        nativeOnFrameRenderedWithResolution(this.mNativeHandler, width, height);
    }

    @Override // org.webrtc.mozi.RendererCommon.RendererEvents
    public void onFrameResolutionChanged(int videoWidth, int videoHeight, int rotation) {
    }

    private RendererCommon.ScalingType convertToScalingType(int type) {
        if (type == 0) {
            return RendererCommon.ScalingType.SCALE_ASPECT_FIT;
        }
        if (type == 1) {
            return RendererCommon.ScalingType.SCALE_ASPECT_FILL;
        }
        return RendererCommon.ScalingType.SCALE_FILL;
    }
}
