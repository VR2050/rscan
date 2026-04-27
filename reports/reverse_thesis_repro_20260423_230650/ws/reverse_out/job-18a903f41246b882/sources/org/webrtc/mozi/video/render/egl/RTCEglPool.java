package org.webrtc.mozi.video.render.egl;

import org.webrtc.mozi.EglBase;

/* JADX INFO: loaded from: classes3.dex */
public interface RTCEglPool {
    RTCEglController create(EglBase.Context context, int[] iArr);

    void release();
}
