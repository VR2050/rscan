package org.webrtc.mozi;

import java.nio.ByteBuffer;

/* JADX INFO: loaded from: classes3.dex */
final /* synthetic */ class YuvConverter$$Lambda$2 implements Runnable {
    private final ByteBuffer arg$1;

    private YuvConverter$$Lambda$2(ByteBuffer byteBuffer) {
        this.arg$1 = byteBuffer;
    }

    public static Runnable lambdaFactory$(ByteBuffer byteBuffer) {
        return new YuvConverter$$Lambda$2(byteBuffer);
    }

    @Override // java.lang.Runnable
    public void run() {
        JniCommon.nativeFreeByteBuffer(this.arg$1);
    }
}
