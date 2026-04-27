package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
public class BWEConfig {
    private boolean enableP2pProjBpsConfig;
    private long maxBandwidthBps;
    private long minBandwidthBps;
    private long startBandwidthBps;

    public BWEConfig(long startBandwidthBps, long minBandwidthBps, long maxBandwidthBps, boolean enableP2pProjBpsConfig) {
        this.startBandwidthBps = startBandwidthBps;
        this.minBandwidthBps = minBandwidthBps;
        this.maxBandwidthBps = maxBandwidthBps;
        this.enableP2pProjBpsConfig = enableP2pProjBpsConfig;
    }

    public long getStartBandwidthBps() {
        return this.startBandwidthBps;
    }

    public long getMinBandwidthBps() {
        return this.minBandwidthBps;
    }

    public long getMaxBandwidthBps() {
        return this.maxBandwidthBps;
    }

    public boolean isEnableP2pProjBpsConfig() {
        return this.enableP2pProjBpsConfig;
    }

    static BWEConfig create(long startBandwidthBps, long minBandwidthBps, long maxBandwidthBps, boolean enableP2pProjBpsConfig) {
        return new BWEConfig(startBandwidthBps, minBandwidthBps, maxBandwidthBps, enableP2pProjBpsConfig);
    }
}
