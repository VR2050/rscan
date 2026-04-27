package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
public class StatsConfig {
    private boolean enableAudioBweStats;
    private long innerStatsIntervalMs;
    private long level;
    private long metricUploadIntervalMs;
    private long processIntervalMs;
    private long qualityStatsIntervalMs;
    private long statsIntervalMs;
    private long uplinkNetworkCallbackCount;
    private long uploadIntervalMs;

    public StatsConfig(long statsIntervalMs, long uploadIntervalMs, long level, long innerStatsIntervalMs, long uplinkNetworkCallbackCount, long processIntervalMs, long qualityStatsIntervalMs, long metricUploadIntervalMs, boolean enableAudioBweStats) {
        this.statsIntervalMs = statsIntervalMs;
        this.uploadIntervalMs = uploadIntervalMs;
        this.level = level;
        this.innerStatsIntervalMs = innerStatsIntervalMs;
        this.uplinkNetworkCallbackCount = uplinkNetworkCallbackCount;
        this.processIntervalMs = processIntervalMs;
        this.qualityStatsIntervalMs = qualityStatsIntervalMs;
        this.metricUploadIntervalMs = metricUploadIntervalMs;
        this.enableAudioBweStats = enableAudioBweStats;
    }

    public long getStatsIntervalMs() {
        return this.statsIntervalMs;
    }

    public long getUploadIntervalMs() {
        return this.uploadIntervalMs;
    }

    public long getLevel() {
        return this.level;
    }

    public long getInnerStatsIntervalMs() {
        return this.innerStatsIntervalMs;
    }

    public long getUplinkNetworkCallbackCount() {
        return this.uplinkNetworkCallbackCount;
    }

    public long getProcessIntervalMs() {
        return this.processIntervalMs;
    }

    public long getQualityStatsIntervalMs() {
        return this.qualityStatsIntervalMs;
    }

    public long getMetricUploadIntervalMs() {
        return this.metricUploadIntervalMs;
    }

    public boolean isEnableAudioBweStats() {
        return this.enableAudioBweStats;
    }

    static StatsConfig create(long statsIntervalMs, long uploadIntervalMs, long level, long innerStatsIntervalMs, long uplinkNetworkCallbackCount, long processIntervalMs, long qualityStatsIntervalMs, long metricUploadIntervalMs, boolean enableAudioBweStats) {
        return new StatsConfig(statsIntervalMs, uploadIntervalMs, level, innerStatsIntervalMs, uplinkNetworkCallbackCount, processIntervalMs, qualityStatsIntervalMs, metricUploadIntervalMs, enableAudioBweStats);
    }
}
