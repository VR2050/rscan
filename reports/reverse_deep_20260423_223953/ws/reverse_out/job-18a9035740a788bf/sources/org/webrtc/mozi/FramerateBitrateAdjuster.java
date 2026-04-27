package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
class FramerateBitrateAdjuster extends BaseBitrateAdjuster {
    private static final int INITIAL_FPS = 30;

    FramerateBitrateAdjuster() {
    }

    @Override // org.webrtc.mozi.BaseBitrateAdjuster, org.webrtc.mozi.BitrateAdjuster
    public void setTargets(int targetBitrateBps, int targetFps) {
        if (this.targetFps == 0) {
            targetFps = 30;
        }
        super.setTargets(targetBitrateBps, targetFps);
        this.targetBitrateBps = (this.targetBitrateBps * 30) / this.targetFps;
    }

    @Override // org.webrtc.mozi.BaseBitrateAdjuster, org.webrtc.mozi.BitrateAdjuster
    public int getCodecConfigFramerate() {
        return 30;
    }
}
