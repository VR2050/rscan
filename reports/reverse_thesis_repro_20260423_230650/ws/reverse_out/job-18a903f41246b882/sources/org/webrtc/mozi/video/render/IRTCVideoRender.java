package org.webrtc.mozi.video.render;

import android.graphics.Matrix;
import android.view.Surface;
import org.webrtc.mozi.EglBase;
import org.webrtc.mozi.RendererCommon;
import org.webrtc.mozi.VideoFrame;
import org.webrtc.mozi.video.render.egl.RTCEglPool;

/* JADX INFO: loaded from: classes3.dex */
public interface IRTCVideoRender {

    public interface FrameRenderInterceptor {
        boolean onInterceptFrame(EglBase eglBase);
    }

    public interface FrameRenderListener extends RendererCommon.RendererEvents {
        void onFirstFrameRenderedWithResolution(int i, int i2);

        void onFrameRenderedWithResolution(int i, int i2);

        void onReceiveFrame(VideoFrameType videoFrameType);

        void onRenderFrame(VideoFrameType videoFrameType);

        void onRenderRegionChange(int i, int i2);
    }

    public enum VideoFrameType {
        TEXTURE,
        I420,
        OTHER
    }

    void createSurface(Surface surface, boolean z, int i);

    void destroySurface();

    void init(EglBase.Context context, FrameRenderListener frameRenderListener, int[] iArr, RendererCommon.GlDrawer glDrawer);

    void release();

    void renderFrame(VideoFrame videoFrame);

    void setEglPool(RTCEglPool rTCEglPool);

    void setMirror(boolean z);

    void setRenderInterceptor(FrameRenderInterceptor frameRenderInterceptor);

    void setRenderOptions(RTCVideoRenderOptions rTCVideoRenderOptions);

    void setRotateByOrientation(boolean z);

    void setScalingType(RendererCommon.ScalingType scalingType, RendererCommon.ScalingType scalingType2, RendererCommon.ScalingType scalingType3, RendererCommon.ScalingType scalingType4);

    void setSurfaceMeasureSpec(int i, int i2);

    void setSurfaceSize(int i, int i2);

    void setTransformMatrix(Matrix matrix);
}
