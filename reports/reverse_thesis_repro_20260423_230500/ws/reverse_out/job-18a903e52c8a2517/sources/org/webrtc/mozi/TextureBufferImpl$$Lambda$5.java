package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
final /* synthetic */ class TextureBufferImpl$$Lambda$5 implements Runnable {
    private final TextureBufferImpl arg$1;
    private final int arg$2;

    private TextureBufferImpl$$Lambda$5(TextureBufferImpl textureBufferImpl, int i) {
        this.arg$1 = textureBufferImpl;
        this.arg$2 = i;
    }

    public static Runnable lambdaFactory$(TextureBufferImpl textureBufferImpl, int i) {
        return new TextureBufferImpl$$Lambda$5(textureBufferImpl, i);
    }

    @Override // java.lang.Runnable
    public void run() {
        TextureBufferImpl textureBufferImpl = this.arg$1;
        textureBufferImpl.alignmentDrawer.alignDraw(textureBufferImpl, this.arg$2);
    }
}
