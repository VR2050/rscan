package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
class BaseBitrateAdjuster implements BitrateAdjuster {
    protected int targetBitrateBps = 0;
    protected int targetFps = 0;

    BaseBitrateAdjuster() {
    }

    @Override // org.webrtc.mozi.BitrateAdjuster
    public void setTargets(int targetBitrateBps, int targetFps) {
        this.targetBitrateBps = targetBitrateBps;
        this.targetFps = targetFps;
    }

    @Override // org.webrtc.mozi.BitrateAdjuster
    public void reportEncodedFrame(int size) {
    }

    @Override // org.webrtc.mozi.BitrateAdjuster
    public int getAdjustedBitrateBps() {
        return this.targetBitrateBps;
    }

    @Override // org.webrtc.mozi.BitrateAdjuster
    public int getCodecConfigFramerate() {
        return this.targetFps;
    }
}
