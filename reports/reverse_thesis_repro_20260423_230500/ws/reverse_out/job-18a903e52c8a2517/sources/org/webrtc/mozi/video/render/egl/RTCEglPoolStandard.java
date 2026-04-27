package org.webrtc.mozi.video.render.egl;

import org.webrtc.mozi.EglBase;

/* JADX INFO: loaded from: classes3.dex */
public class RTCEglPoolStandard implements RTCEglPool {
    private static RTCEglPoolStandard sInstance = new RTCEglPoolStandard();

    private RTCEglPoolStandard() {
    }

    public static RTCEglPoolStandard getInstance() {
        return sInstance;
    }

    @Override // org.webrtc.mozi.video.render.egl.RTCEglPool
    public RTCEglController create(EglBase.Context sharedContext, int[] configAttributes) {
        return new RTCEglStandardController(sharedContext, configAttributes);
    }

    @Override // org.webrtc.mozi.video.render.egl.RTCEglPool
    public void release() {
    }
}
