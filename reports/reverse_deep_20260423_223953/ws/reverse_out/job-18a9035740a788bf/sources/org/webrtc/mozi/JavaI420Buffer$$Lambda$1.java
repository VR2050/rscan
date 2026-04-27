package org.webrtc.mozi;

import java.nio.ByteBuffer;

/* JADX INFO: loaded from: classes3.dex */
final /* synthetic */ class JavaI420Buffer$$Lambda$1 implements Runnable {
    private final ByteBuffer arg$1;

    private JavaI420Buffer$$Lambda$1(ByteBuffer byteBuffer) {
        this.arg$1 = byteBuffer;
    }

    public static Runnable lambdaFactory$(ByteBuffer byteBuffer) {
        return new JavaI420Buffer$$Lambda$1(byteBuffer);
    }

    @Override // java.lang.Runnable
    public void run() {
        JniCommon.nativeFreeByteBuffer(this.arg$1);
    }
}
