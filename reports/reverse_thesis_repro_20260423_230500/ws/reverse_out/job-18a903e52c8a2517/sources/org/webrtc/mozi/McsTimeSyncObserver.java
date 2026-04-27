package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
public interface McsTimeSyncObserver {
    Long getMediaDelayBasedOnSSRC(long j, long j2);

    void onPeriodicallySendMediaInfo(long j, int i, long j2);

    void onReceiveMediaInfo(long j, long j2, long j3);

    void onReceiveMediaPayload(long j, int i);

    void sendInfoForTimeSyncFix(long j, long j2);
}
