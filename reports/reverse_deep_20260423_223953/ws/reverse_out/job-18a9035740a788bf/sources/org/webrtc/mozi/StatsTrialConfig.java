package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
public class StatsTrialConfig {
    private final boolean enableAudioFecStats;
    private final boolean enableP2pStatsRemoteUid;
    private final boolean enableRecvTransportLossrateStats;

    public StatsTrialConfig(boolean enableAudioFecStats, boolean enableRecvTransportLossrateStats, boolean enableP2pStatsRemoteUid) {
        this.enableAudioFecStats = enableAudioFecStats;
        this.enableRecvTransportLossrateStats = enableRecvTransportLossrateStats;
        this.enableP2pStatsRemoteUid = enableP2pStatsRemoteUid;
    }

    public boolean isEnableAudioFecStats() {
        return this.enableAudioFecStats;
    }

    public boolean isEnableRecvTransportLossrateStats() {
        return this.enableRecvTransportLossrateStats;
    }

    public boolean isEnableP2pStatsRemoteUid() {
        return this.enableP2pStatsRemoteUid;
    }

    static StatsTrialConfig create(boolean enableAudioFecStats, boolean enableRecvTransportLossrateStats, boolean enableP2pStatsRemoteUid) {
        return new StatsTrialConfig(enableAudioFecStats, enableRecvTransportLossrateStats, enableP2pStatsRemoteUid);
    }
}
