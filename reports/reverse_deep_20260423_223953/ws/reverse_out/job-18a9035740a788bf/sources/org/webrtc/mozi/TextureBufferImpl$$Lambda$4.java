package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
final /* synthetic */ class TextureBufferImpl$$Lambda$4 implements Runnable {
    private final TextureBufferImpl arg$1;

    private TextureBufferImpl$$Lambda$4(TextureBufferImpl textureBufferImpl) {
        this.arg$1 = textureBufferImpl;
    }

    public static Runnable lambdaFactory$(TextureBufferImpl textureBufferImpl) {
        return new TextureBufferImpl$$Lambda$4(textureBufferImpl);
    }

    @Override // java.lang.Runnable
    public void run() {
        this.arg$1.release();
    }
}
