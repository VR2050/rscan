package com.ding.rtc.model;

import com.ding.rtc.DingRtcEngine;

/* JADX INFO: loaded from: classes.dex */
public class RemoteAudioStats {
    private String userId;
    private int packetLossRate = 0;
    private int recvBitrate = 0;
    private int totalFrozenTime = 0;
    private int speechExpandRate = 0;

    private RemoteAudioStats() {
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public void setAudioLossRate(int packetLossRate) {
        this.packetLossRate = packetLossRate;
    }

    public void setRecvBitrate(int recvBitrate) {
        this.recvBitrate = recvBitrate;
    }

    public void setTotalFrozenTime(int totalFrozenTime) {
        this.totalFrozenTime = totalFrozenTime;
    }

    public void setSpeechExpandRate(int speechExpandRate) {
        this.speechExpandRate = speechExpandRate;
    }

    public DingRtcEngine.DingRtcRemoteAudioStats convert() {
        DingRtcEngine.DingRtcRemoteAudioStats stats = new DingRtcEngine.DingRtcRemoteAudioStats();
        stats.userId = this.userId;
        stats.packetLossRate = this.packetLossRate;
        stats.recvBitrate = this.recvBitrate;
        stats.totalFrozenTime = this.totalFrozenTime;
        stats.speechExpandRate = this.speechExpandRate;
        return stats;
    }
}
