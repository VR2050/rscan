package com.ding.rtc.model;

import com.ding.rtc.DingRtcEngine;

/* JADX INFO: loaded from: classes.dex */
public class AudioVolumeInfo {
    private String userId;
    private int volume = 0;
    private int speechState = 0;

    private AudioVolumeInfo() {
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public void setVolume(int volume) {
        this.volume = volume;
    }

    public void setSpeechState(int speechState) {
        this.speechState = speechState;
    }

    public DingRtcEngine.DingRtcAudioVolumeInfo convert() {
        DingRtcEngine.DingRtcAudioVolumeInfo volumeInfo = new DingRtcEngine.DingRtcAudioVolumeInfo();
        volumeInfo.userId = this.userId;
        volumeInfo.volume = this.volume;
        volumeInfo.speechState = this.speechState;
        return volumeInfo;
    }
}
