package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
public class ConnectionTrialConfig {
    private final boolean enableCandidateOpt;

    public ConnectionTrialConfig(boolean enableCandidateOpt) {
        this.enableCandidateOpt = enableCandidateOpt;
    }

    public boolean isEnableCandidateOpt() {
        return this.enableCandidateOpt;
    }

    static ConnectionTrialConfig create(boolean enableCandidateOpt) {
        return new ConnectionTrialConfig(enableCandidateOpt);
    }
}
