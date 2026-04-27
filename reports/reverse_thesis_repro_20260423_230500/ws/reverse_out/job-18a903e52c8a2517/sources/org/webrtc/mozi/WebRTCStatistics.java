package org.webrtc.mozi;

import java.util.List;

/* JADX INFO: loaded from: classes3.dex */
public class WebRTCStatistics {
    private final long mNativeMcsConfigPtr;
    private long mNativeStatsObserver;
    private McsStatsObserver mStatsObserver;
    private McsTimeSyncObserver mTimeSyncObserver;

    private native void nativeAddVideoProcessDetail(long j, String str, int i);

    private native void nativeAddVideoProcessTime(long j, int i);

    private native void nativeClearMcsTimeSyncObserver(long j);

    private native void nativeClearObserver(long j, long j2);

    private static native Long nativeGetNtpTimestamp();

    private native List<StatsContent> nativeGetStatisticsContent(long j, String str, String str2);

    private native StatsInfo nativeGetStatisticsInfo(long j, String str, String str2);

    private static native Long nativeGetTimestamp();

    private native void nativeProcessPerSecond(long j, String str, String str2);

    private native StatsInfo nativeProcessQualityMonitorStatistics(long j, String str, String str2);

    private native void nativeProcessStatisticsData(long j, String str, String str2);

    private static native boolean nativeSequenceNumberAheadOf(long j, long j2);

    private native void nativeSetMcsTimeSyncObserver(long j, McsTimeSyncObserver mcsTimeSyncObserver);

    private native long nativeSetObserver(long j, McsStatsObserver mcsStatsObserver);

    private native void nativeSetStatus(long j, String str, String str2);

    public WebRTCStatistics(long mcsConfigPtr) {
        this.mNativeMcsConfigPtr = mcsConfigPtr;
    }

    public static long getTimestamp() {
        return nativeGetTimestamp().longValue();
    }

    public static long getNtpTimestamp() {
        return nativeGetNtpTimestamp().longValue();
    }

    public static boolean sequenceNumberAheadOf(long a, long b) {
        return nativeSequenceNumberAheadOf(a, b);
    }

    public List<StatsContent> getStatisticsContent(String module, String index) {
        return nativeGetStatisticsContent(this.mNativeMcsConfigPtr, module, index);
    }

    public void processStatisticsData(String module, String index) {
        nativeProcessStatisticsData(this.mNativeMcsConfigPtr, module, index);
    }

    public StatsInfo getStatisticsInfo(String module, String index) {
        return nativeGetStatisticsInfo(this.mNativeMcsConfigPtr, module, index);
    }

    public StatsInfo processQualityMonitorStatistics(String module, String index) {
        return nativeProcessQualityMonitorStatistics(this.mNativeMcsConfigPtr, module, index);
    }

    public void setStatus(String index, String status) {
        nativeSetStatus(this.mNativeMcsConfigPtr, index, status);
    }

    public void setObserver(McsStatsObserver observer) {
        if (this.mStatsObserver != null) {
            clearObserver();
        }
        this.mStatsObserver = observer;
        this.mNativeStatsObserver = nativeSetObserver(this.mNativeMcsConfigPtr, observer);
    }

    private void clearObserver() {
        nativeClearObserver(this.mNativeMcsConfigPtr, this.mNativeStatsObserver);
        this.mStatsObserver = null;
        this.mNativeStatsObserver = 0L;
    }

    public void removeObserver(McsStatsObserver observer) {
        if (this.mStatsObserver == observer) {
            clearObserver();
        }
    }

    public void processPerSecond(String module, String index) {
        nativeProcessPerSecond(this.mNativeMcsConfigPtr, module, index);
    }

    public void setMcsTimeSyncObserver(McsTimeSyncObserver observer) {
        if (this.mTimeSyncObserver != null) {
            clearMcsTimeSyncObserver();
        }
        this.mTimeSyncObserver = observer;
        nativeSetMcsTimeSyncObserver(this.mNativeMcsConfigPtr, observer);
    }

    public void removetMcsTimeSyncObserver(McsTimeSyncObserver observer) {
        if (this.mTimeSyncObserver == observer) {
            clearMcsTimeSyncObserver();
        }
    }

    public void addVideoProcessTime(int cost) {
        nativeAddVideoProcessTime(this.mNativeMcsConfigPtr, cost);
    }

    public void addVideoProcessDetail(String module_name, int cost) {
        nativeAddVideoProcessDetail(this.mNativeMcsConfigPtr, module_name, cost);
    }

    private void clearMcsTimeSyncObserver() {
        nativeClearMcsTimeSyncObserver(this.mNativeMcsConfigPtr);
        this.mTimeSyncObserver = null;
    }
}
