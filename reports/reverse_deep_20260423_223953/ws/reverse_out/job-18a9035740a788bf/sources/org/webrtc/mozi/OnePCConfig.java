package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
public class OnePCConfig {
    private final String defaultPubVideoCodec;
    private final boolean enableLiSync;
    private final boolean enableOnePC;
    private final boolean isFixSrtpFailure;
    private final boolean needPersonalityAudioStream;

    public OnePCConfig(boolean enableOnePC, boolean enableLiSync, boolean needPersonalityAudioStream, boolean isFixSrtpFailure, String defaultPubVideoCodec) {
        this.enableOnePC = enableOnePC;
        this.enableLiSync = enableLiSync;
        this.needPersonalityAudioStream = needPersonalityAudioStream;
        this.isFixSrtpFailure = isFixSrtpFailure;
        this.defaultPubVideoCodec = defaultPubVideoCodec;
    }

    public boolean isEnableOnePC() {
        return this.enableOnePC;
    }

    public boolean isEnableLiSync() {
        return this.enableLiSync;
    }

    public boolean isNeedPersonalityAudioStream() {
        return this.needPersonalityAudioStream;
    }

    public boolean isEnablePubSubCompleteStatistics() {
        return true;
    }

    public boolean isFixFailover() {
        return true;
    }

    public boolean isFixSrtpFailure() {
        return this.isFixSrtpFailure;
    }

    public String getDefaultPubVideoCodec() {
        return this.defaultPubVideoCodec;
    }

    static OnePCConfig create(boolean enableOnePC, boolean enableLiSync, boolean needPersonalityAudioStream, boolean isFixSrtpFailure, String defaultPubVideoCodec) {
        return new OnePCConfig(enableOnePC, enableLiSync, needPersonalityAudioStream, isFixSrtpFailure, defaultPubVideoCodec);
    }
}
