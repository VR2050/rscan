package org.webrtc.mozi;

import com.google.firebase.remoteconfig.FirebaseRemoteConfig;

/* JADX INFO: loaded from: classes3.dex */
class DynamicBitrateAdjuster extends BaseBitrateAdjuster {
    private static final double BITRATE_ADJUSTMENT_MAX_SCALE = 4.0d;
    private static final double BITRATE_ADJUSTMENT_SEC = 3.0d;
    private static final int BITRATE_ADJUSTMENT_STEPS = 20;
    private static final double BITS_PER_BYTE = 8.0d;
    private double deviationBytes = FirebaseRemoteConfig.DEFAULT_VALUE_FOR_DOUBLE;
    private double timeSinceLastAdjustmentMs = FirebaseRemoteConfig.DEFAULT_VALUE_FOR_DOUBLE;
    private int bitrateAdjustmentScaleExp = 0;

    DynamicBitrateAdjuster() {
    }

    @Override // org.webrtc.mozi.BaseBitrateAdjuster, org.webrtc.mozi.BitrateAdjuster
    public void setTargets(int targetBitrateBps, int targetFps) {
        if (this.targetBitrateBps > 0 && targetBitrateBps < this.targetBitrateBps) {
            this.deviationBytes = (this.deviationBytes * ((double) targetBitrateBps)) / ((double) this.targetBitrateBps);
        }
        super.setTargets(targetBitrateBps, targetFps);
    }

    @Override // org.webrtc.mozi.BaseBitrateAdjuster, org.webrtc.mozi.BitrateAdjuster
    public void reportEncodedFrame(int size) {
        if (this.targetFps == 0) {
            return;
        }
        double expectedBytesPerFrame = (((double) this.targetBitrateBps) / BITS_PER_BYTE) / ((double) this.targetFps);
        this.deviationBytes += ((double) size) - expectedBytesPerFrame;
        this.timeSinceLastAdjustmentMs += 1000.0d / ((double) this.targetFps);
        double deviationThresholdBytes = ((double) this.targetBitrateBps) / BITS_PER_BYTE;
        double deviationCap = BITRATE_ADJUSTMENT_SEC * deviationThresholdBytes;
        double dMin = Math.min(this.deviationBytes, deviationCap);
        this.deviationBytes = dMin;
        double dMax = Math.max(dMin, -deviationCap);
        this.deviationBytes = dMax;
        if (this.timeSinceLastAdjustmentMs <= 3000.0d) {
            return;
        }
        if (dMax > deviationThresholdBytes) {
            int bitrateAdjustmentInc = (int) ((dMax / deviationThresholdBytes) + 0.5d);
            int i = this.bitrateAdjustmentScaleExp - bitrateAdjustmentInc;
            this.bitrateAdjustmentScaleExp = i;
            this.bitrateAdjustmentScaleExp = Math.max(i, -20);
            this.deviationBytes = deviationThresholdBytes;
        } else if (dMax < (-deviationThresholdBytes)) {
            int bitrateAdjustmentInc2 = (int) (((-dMax) / deviationThresholdBytes) + 0.5d);
            int i2 = this.bitrateAdjustmentScaleExp + bitrateAdjustmentInc2;
            this.bitrateAdjustmentScaleExp = i2;
            this.bitrateAdjustmentScaleExp = Math.min(i2, 20);
            this.deviationBytes = -deviationThresholdBytes;
        }
        this.timeSinceLastAdjustmentMs = FirebaseRemoteConfig.DEFAULT_VALUE_FOR_DOUBLE;
    }

    private double getBitrateAdjustmentScale() {
        return Math.pow(BITRATE_ADJUSTMENT_MAX_SCALE, ((double) this.bitrateAdjustmentScaleExp) / 20.0d);
    }

    @Override // org.webrtc.mozi.BaseBitrateAdjuster, org.webrtc.mozi.BitrateAdjuster
    public int getAdjustedBitrateBps() {
        return (int) (((double) this.targetBitrateBps) * getBitrateAdjustmentScale());
    }
}
