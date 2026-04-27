package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
public class BbrConfig {
    private final double congestionEncoderRateGain;
    private final boolean debugLogs;
    private final int degradeStrategy;
    private final boolean enable;
    private final boolean enableBbrWebrtc;
    private final boolean enableDegrade;
    private final double encoderRateGain;
    private final boolean fecSeparation;
    private final int inherentLossDectectMs;
    private final double lossEncoderRateGain;
    private final double maxPacingGainOffset;
    private final double minPacingGainOffset;
    private final int strategy;

    public BbrConfig(boolean enable, boolean debugLogs, boolean enableDegrade, double encoderRateGain, double lossEncoderRateGain, double congestionEncoderRateGain, int strategy, int inherentLossDectectMs, double minPacingGainOffset, double maxPacingGainOffset, int degradeStrategy, boolean fecSeparation, boolean enableBbrWebrtc) {
        this.enable = enable;
        this.debugLogs = debugLogs;
        this.enableDegrade = enableDegrade;
        this.encoderRateGain = encoderRateGain;
        this.lossEncoderRateGain = lossEncoderRateGain;
        this.congestionEncoderRateGain = congestionEncoderRateGain;
        this.strategy = strategy;
        this.inherentLossDectectMs = inherentLossDectectMs;
        this.minPacingGainOffset = minPacingGainOffset;
        this.maxPacingGainOffset = maxPacingGainOffset;
        this.degradeStrategy = degradeStrategy;
        this.fecSeparation = fecSeparation;
        this.enableBbrWebrtc = enableBbrWebrtc;
    }

    public boolean isEnable() {
        return this.enable;
    }

    public boolean isDebugLogs() {
        return this.debugLogs;
    }

    public boolean isEnableDegrade() {
        return this.enableDegrade;
    }

    public double encoderRateGain() {
        return this.encoderRateGain;
    }

    public double lossEncoderRateGain() {
        return this.lossEncoderRateGain;
    }

    public double congestionEncoderRateGain() {
        return this.congestionEncoderRateGain;
    }

    public int strategy() {
        return this.strategy;
    }

    public int inherentLossDectectMs() {
        return this.inherentLossDectectMs;
    }

    public double minPacingGainOffset() {
        return this.minPacingGainOffset;
    }

    public double maxPacingGainOffset() {
        return this.maxPacingGainOffset;
    }

    public int degradeStrategy() {
        return this.degradeStrategy;
    }

    public boolean isFecSeparation() {
        return this.fecSeparation;
    }

    public boolean isEnableBbrWebrtc() {
        return this.enableBbrWebrtc;
    }

    static BbrConfig create(boolean enable, boolean debugLogs, boolean enableDegrade, double encoderRateGain, double lossEncoderRateGain, double congestionEncoderRateGain, int strategy, int inherentLossDectectMs, double minPacingGainOffset, double maxPacingGainOffset, int degradeStrategy, boolean fecSeparation, boolean enableBbrWebrtc) {
        return new BbrConfig(enable, debugLogs, enableDegrade, encoderRateGain, lossEncoderRateGain, congestionEncoderRateGain, strategy, inherentLossDectectMs, minPacingGainOffset, maxPacingGainOffset, degradeStrategy, fecSeparation, enableBbrWebrtc);
    }
}
