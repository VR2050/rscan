package org.webrtc.mozi;

import java.util.concurrent.Callable;

/* JADX INFO: loaded from: classes3.dex */
final /* synthetic */ class TextureBufferImpl$$Lambda$2 implements Callable {
    private final TextureBufferImpl arg$1;
    private final int arg$2;

    private TextureBufferImpl$$Lambda$2(TextureBufferImpl textureBufferImpl, int i) {
        this.arg$1 = textureBufferImpl;
        this.arg$2 = i;
    }

    public static Callable lambdaFactory$(TextureBufferImpl textureBufferImpl, int i) {
        return new TextureBufferImpl$$Lambda$2(textureBufferImpl, i);
    }

    @Override // java.util.concurrent.Callable
    public Object call() {
        return TextureBufferImpl.lambda$toI420ByRotation$20(this.arg$1, this.arg$2);
    }
}
