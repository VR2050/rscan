package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
public class SdkConfig {
    private final boolean disableP2pAudioRtxSend;
    private final boolean enhanceStreamMute;

    public SdkConfig(boolean enhanceStreamMute, boolean disableP2pAudioRtxSend) {
        this.enhanceStreamMute = enhanceStreamMute;
        this.disableP2pAudioRtxSend = disableP2pAudioRtxSend;
    }

    public boolean isEnhanceStreamMute() {
        return this.enhanceStreamMute;
    }

    public boolean isDisableP2pAudioRtxSend() {
        return this.disableP2pAudioRtxSend;
    }

    static SdkConfig create(boolean enhanceStreamMute, boolean disableP2pAudioRtxSend) {
        return new SdkConfig(enhanceStreamMute, disableP2pAudioRtxSend);
    }
}
