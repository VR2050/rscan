package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
public class AudioTransportConfig {
    private final boolean csrcEnable;
    private final float defaultInterpretationLimitGain;
    private final boolean enableAudioSFU;
    private final boolean extLossRate;
    private final boolean fix61363094;
    private final boolean fixSfuFailoverSsrc;
    private final boolean lossRateBasedRR;
    private final boolean newRedLogic;
    private final boolean opusExtendInbandFec;
    private final boolean red;
    private final boolean roundTripRTTEnable;
    private final boolean rtcpDelayEnable;
    private final boolean sendSideBwe;
    private final boolean supportSimultaneousInterpretation;

    public AudioTransportConfig(boolean red, boolean csrcEnable, boolean roundTripRTTEnable, boolean newRedLogic, boolean lossRateBasedRR, boolean opusExtendInbandFec, boolean extLossRate, boolean enableAudioSFU, boolean fixSfuFailoverSsrc, boolean supportSimultaneousInterpretation, boolean rtcpDelayEnable, boolean sendSideBwe, float defaultInterpretationLimitGain, boolean fix61363094) {
        this.red = red;
        this.csrcEnable = csrcEnable;
        this.roundTripRTTEnable = roundTripRTTEnable;
        this.newRedLogic = newRedLogic;
        this.lossRateBasedRR = lossRateBasedRR;
        this.opusExtendInbandFec = opusExtendInbandFec;
        this.extLossRate = extLossRate;
        this.enableAudioSFU = enableAudioSFU;
        this.fixSfuFailoverSsrc = fixSfuFailoverSsrc;
        this.supportSimultaneousInterpretation = supportSimultaneousInterpretation;
        this.rtcpDelayEnable = rtcpDelayEnable;
        this.sendSideBwe = sendSideBwe;
        this.defaultInterpretationLimitGain = defaultInterpretationLimitGain;
        this.fix61363094 = fix61363094;
    }

    public boolean isSupportRed() {
        return this.red;
    }

    public boolean isSupportCSRC() {
        return this.csrcEnable;
    }

    public boolean isSupportRoundTripRTT() {
        return this.roundTripRTTEnable;
    }

    public boolean isSupportNewRedLogic() {
        return this.newRedLogic;
    }

    public boolean isSupportLossRateBasedRR() {
        return this.lossRateBasedRR;
    }

    public boolean isSupportOpusExtendInbandFec() {
        return this.opusExtendInbandFec;
    }

    public boolean isSupportRTCPDelay() {
        return this.rtcpDelayEnable;
    }

    public boolean isSupportExtLossRate() {
        return this.extLossRate;
    }

    public boolean isSupportAudioSFU() {
        return this.enableAudioSFU;
    }

    public boolean isFixSfuFailoverSsrc() {
        return this.fixSfuFailoverSsrc;
    }

    public boolean isSupportSimultaneousInterpretation() {
        return this.supportSimultaneousInterpretation;
    }

    public boolean isSupportSendSideBwe() {
        return this.sendSideBwe;
    }

    public float getDefaultInterpretationLimitGain() {
        return this.defaultInterpretationLimitGain;
    }

    public boolean isFix61363094() {
        return this.fix61363094;
    }

    static AudioTransportConfig create(boolean red, boolean csrcEnable, boolean roundTripRTTEnable, boolean newRedLogic, boolean lossRateBasedRR, boolean opusExtendInbandFec, boolean extLossRate, boolean enableAudioSFU, boolean fixSfuFailoverSsrc, boolean supportSimultaneousInterpretation, boolean rtcpDelayEnable, boolean sendSideBwe, float defaultInterpretationLimitGain, boolean fix61363094) {
        return new AudioTransportConfig(red, csrcEnable, roundTripRTTEnable, newRedLogic, lossRateBasedRR, opusExtendInbandFec, extLossRate, enableAudioSFU, fixSfuFailoverSsrc, supportSimultaneousInterpretation, rtcpDelayEnable, sendSideBwe, defaultInterpretationLimitGain, fix61363094);
    }
}
