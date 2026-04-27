package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
public class HardwareInfoConfig {
    private boolean enableThreadCpuMonitor;
    private boolean systemPerformanceMonitor;
    private long systemPerformanceStatsIntervalMs;

    public HardwareInfoConfig(boolean systemPerformanceMonitor, long systemPerformanceStatsIntervalMs, boolean enableThreadCpuMonitor) {
        this.systemPerformanceMonitor = systemPerformanceMonitor;
        this.systemPerformanceStatsIntervalMs = systemPerformanceStatsIntervalMs;
        this.enableThreadCpuMonitor = enableThreadCpuMonitor;
    }

    public boolean isEnablePerformanceMonitor() {
        return this.systemPerformanceMonitor;
    }

    public long getPerformanceStatsIntervalMs() {
        return this.systemPerformanceStatsIntervalMs;
    }

    public boolean isEnableThreadCpuMonitor() {
        return this.enableThreadCpuMonitor;
    }

    static HardwareInfoConfig create(boolean systemPerformanceMonitor, long systemPerformanceStatsIntervalMs, boolean enableThreadCpuMonitor) {
        return new HardwareInfoConfig(systemPerformanceMonitor, systemPerformanceStatsIntervalMs, enableThreadCpuMonitor);
    }
}
