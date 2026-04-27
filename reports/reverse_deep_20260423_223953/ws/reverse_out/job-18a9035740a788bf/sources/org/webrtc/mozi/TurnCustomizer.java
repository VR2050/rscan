package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
public class TurnCustomizer {
    final long nativeTurnCustomizer;

    private static native void nativeFreeTurnCustomizer(long j);

    public TurnCustomizer(long nativeTurnCustomizer) {
        this.nativeTurnCustomizer = nativeTurnCustomizer;
    }

    public void dispose() {
        nativeFreeTurnCustomizer(this.nativeTurnCustomizer);
    }

    long getNativeTurnCustomizer() {
        return this.nativeTurnCustomizer;
    }
}
