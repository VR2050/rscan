package org.webrtc.mozi.video.render;

/* JADX INFO: loaded from: classes3.dex */
public class RTCVideoRenderOptions {
    public static final RTCVideoRenderOptions EMPTY = new RTCVideoRenderOptions();
    public boolean optSurfaceSizeLatency = true;
    public boolean redrawLastFrameWhenSurfaceSizeChange = true;
    public boolean enableRenderOpenGLMatrixScale = true;
    public boolean optEglRenderResetLocker = true;
}
