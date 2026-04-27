package com.ding.rtc.model;

import com.ding.rtc.DingRtcEngine;

/* JADX INFO: loaded from: classes.dex */
public class RemoteVideoStats {
    private int decoderOutputFrameRate;
    private int packetLossRate;
    private int recvBitrate;
    private int rendererOutputFrameRate;
    private int stuckTime;
    private int track;
    private String userId;
    private int width = 0;
    private int height = 0;

    private RemoteVideoStats() {
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public void setTrack(int track) {
        this.track = track;
    }

    public void setWidth(int width) {
        this.width = width;
    }

    public void setHeight(int height) {
        this.height = height;
    }

    public void setStuckTime(int stucktime) {
        this.stuckTime = stucktime;
    }

    public void setReceivedBitrate(int recvBitrate) {
        this.recvBitrate = recvBitrate;
    }

    public void setDecoderOutputFrameRate(int decoderOutputFrameRate) {
        this.decoderOutputFrameRate = decoderOutputFrameRate;
    }

    public void setRendererOutputFrameRate(int rendererOutputFrameRate) {
        this.rendererOutputFrameRate = rendererOutputFrameRate;
    }

    public void setPacketLossRate(int packetLossRate) {
        this.packetLossRate = packetLossRate;
    }

    public DingRtcEngine.DingRtcRemoteVideoStats convert() {
        DingRtcEngine.DingRtcRemoteVideoStats stats = new DingRtcEngine.DingRtcRemoteVideoStats();
        stats.userId = this.userId;
        stats.track = DingRtcEngine.DingRtcVideoTrack.fromValue(this.track);
        stats.width = this.width;
        stats.height = this.height;
        stats.recvBitrate = this.recvBitrate;
        stats.decoderOutputFrameRate = this.decoderOutputFrameRate;
        stats.rendererOutputFrameRate = this.rendererOutputFrameRate;
        stats.packetLossRate = this.packetLossRate;
        stats.stuckTime = this.stuckTime;
        return stats;
    }
}
