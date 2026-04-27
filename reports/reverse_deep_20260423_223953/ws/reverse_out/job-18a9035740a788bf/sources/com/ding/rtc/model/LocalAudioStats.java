package com.ding.rtc.model;

import com.ding.rtc.DingRtcEngine;

/* JADX INFO: loaded from: classes.dex */
public class LocalAudioStats {
    private int track;
    private int sentBitrate = 0;
    private int sentSamplerate = 0;
    private int numChannel = 0;
    private int inputLevel = 0;

    private LocalAudioStats() {
    }

    public void setTrack(int track) {
        this.track = track;
    }

    public void setSentBitrate(int sentBitrate) {
        this.sentBitrate = sentBitrate;
    }

    public void setSentSamplerate(int sentSamplerate) {
        this.sentSamplerate = sentSamplerate;
    }

    public void setNumChannel(int numChannel) {
        this.numChannel = numChannel;
    }

    public void setInputLevel(int inputLevel) {
        this.inputLevel = inputLevel;
    }

    public DingRtcEngine.DingRtcLocalAudioStats convert() {
        DingRtcEngine.DingRtcLocalAudioStats stats = new DingRtcEngine.DingRtcLocalAudioStats();
        stats.track = DingRtcEngine.DingRtcAudioTrack.fromValue(this.track);
        stats.sentBitrate = this.sentBitrate;
        stats.sentSamplerate = this.sentSamplerate;
        stats.numChannel = this.numChannel;
        stats.inputLevel = this.inputLevel;
        return stats;
    }
}
