package com.ding.rtc.model;

import com.ding.rtc.DingRtcEngine;

/* JADX INFO: loaded from: classes.dex */
public class LocalVideoStats {
    private int track;
    private int targetEncodeBitrate = 0;
    private int actualEncodeBitrate = 0;
    private int sentBitrate = 0;
    private int sentFps = 0;
    private int encodeFps = 0;
    private int captureFps = 0;
    private int renderFps = 0;
    private int avgQpPerSec = 0;
    private int encoderFrameWidth = 0;
    private int encoderFrameHeight = 0;
    private int captureFrameWidth = 0;
    private int captureFrameHeight = 0;

    private LocalVideoStats() {
    }

    public void setTrack(int track) {
        this.track = track;
    }

    public void setTargetEncodeBitrate(int targetEncodeBitrate) {
        this.targetEncodeBitrate = targetEncodeBitrate;
    }

    public void setActualEncodeBitrate(int actualEncodeBitrate) {
        this.actualEncodeBitrate = actualEncodeBitrate;
    }

    public void setSentBitrate(int sentBitrate) {
        this.sentBitrate = sentBitrate;
    }

    public void setSentFps(int sentFps) {
        this.sentFps = sentFps;
    }

    public void setEncodeFps(int encodeFps) {
        this.encodeFps = encodeFps;
    }

    public void setCaptureFps(int captureFps) {
        this.captureFps = captureFps;
    }

    public void setRenderFps(int renderFps) {
        this.renderFps = renderFps;
    }

    public void setAvgQpPerSec(int avgQpPerSec) {
        this.avgQpPerSec = avgQpPerSec;
    }

    public void setEncoderFrameWidth(int encoderFrameWidth) {
        this.encoderFrameWidth = encoderFrameWidth;
    }

    public void setEncoderFrameHeight(int encoderFrameHeight) {
        this.encoderFrameHeight = encoderFrameHeight;
    }

    public void setCaptureFrameWidth(int captureFrameWidth) {
        this.captureFrameWidth = captureFrameWidth;
    }

    public void setCaptureFrameHeight(int captureFrameHeight) {
        this.captureFrameHeight = captureFrameHeight;
    }

    public DingRtcEngine.DingRtcLocalVideoStats convert() {
        DingRtcEngine.DingRtcLocalVideoStats stats = new DingRtcEngine.DingRtcLocalVideoStats();
        stats.track = DingRtcEngine.DingRtcVideoTrack.fromValue(this.track);
        stats.targetEncodeBitrate = this.targetEncodeBitrate;
        stats.actualEncodeBitrate = this.actualEncodeBitrate;
        stats.sentBitrate = this.sentBitrate;
        stats.sentFps = this.sentFps;
        stats.encodeFps = this.encodeFps;
        stats.captureFps = this.captureFps;
        stats.renderFps = this.renderFps;
        stats.avgQpPerSec = this.avgQpPerSec;
        stats.encoderFrameWidth = this.encoderFrameWidth;
        stats.encoderFrameHeight = this.encoderFrameHeight;
        stats.captureFrameWidth = this.captureFrameWidth;
        stats.captureFrameHeight = this.captureFrameHeight;
        return stats;
    }
}
