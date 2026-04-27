package com.ding.rtc.model;

import com.ding.rtc.DingRtcEngine;

/* JADX INFO: loaded from: classes.dex */
public class AudioMixingStats {
    private String fileName;
    private int status = 0;
    private int errorCode = 0;
    private int id = -1;
    private long durationMs = 0;

    private AudioMixingStats() {
    }

    public void setStatus(int status) {
        this.status = status;
    }

    public void setErrorCode(int errorCode) {
        this.errorCode = errorCode;
    }

    public void setFileName(String fileName) {
        this.fileName = fileName;
    }

    public void setId(int id) {
        this.id = id;
    }

    public void setDuration(long durationMs) {
        this.durationMs = durationMs;
    }

    public DingRtcEngine.DingRtcAudioMixingStatusConfig convert() {
        DingRtcEngine.DingRtcAudioMixingStatusConfig stats = new DingRtcEngine.DingRtcAudioMixingStatusConfig();
        stats.status = DingRtcEngine.DingRtcAudioMixingStatus.fromNativeIndex(this.status);
        stats.errorCode = DingRtcEngine.DingRtcAudioMixingErrorCode.fromNativeIndex(this.errorCode);
        stats.fileName = this.fileName;
        stats.id = this.id;
        stats.durationMs = this.durationMs;
        return stats;
    }
}
