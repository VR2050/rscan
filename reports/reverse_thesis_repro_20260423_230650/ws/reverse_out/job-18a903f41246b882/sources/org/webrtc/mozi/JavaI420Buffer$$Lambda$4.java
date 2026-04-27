package org.webrtc.mozi;

import org.webrtc.mozi.VideoFrame;

/* JADX INFO: loaded from: classes3.dex */
final /* synthetic */ class JavaI420Buffer$$Lambda$4 implements Runnable {
    private final VideoFrame.I420Buffer arg$1;

    private JavaI420Buffer$$Lambda$4(VideoFrame.I420Buffer i420Buffer) {
        this.arg$1 = i420Buffer;
    }

    public static Runnable lambdaFactory$(VideoFrame.I420Buffer i420Buffer) {
        return new JavaI420Buffer$$Lambda$4(i420Buffer);
    }

    @Override // java.lang.Runnable
    public void run() {
        this.arg$1.release();
    }
}
