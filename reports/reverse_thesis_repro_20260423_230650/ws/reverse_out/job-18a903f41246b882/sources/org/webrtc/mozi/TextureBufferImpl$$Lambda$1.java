package org.webrtc.mozi;

import java.util.concurrent.Callable;

/* JADX INFO: loaded from: classes3.dex */
final /* synthetic */ class TextureBufferImpl$$Lambda$1 implements Callable {
    private final TextureBufferImpl arg$1;

    private TextureBufferImpl$$Lambda$1(TextureBufferImpl textureBufferImpl) {
        this.arg$1 = textureBufferImpl;
    }

    public static Callable lambdaFactory$(TextureBufferImpl textureBufferImpl) {
        return new TextureBufferImpl$$Lambda$1(textureBufferImpl);
    }

    @Override // java.util.concurrent.Callable
    public Object call() {
        return TextureBufferImpl.lambda$toI420$19(this.arg$1);
    }
}
