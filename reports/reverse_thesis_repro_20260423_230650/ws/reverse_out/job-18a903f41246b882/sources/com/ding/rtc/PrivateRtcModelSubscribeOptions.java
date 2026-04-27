package com.ding.rtc;

/* JADX INFO: loaded from: classes.dex */
class PrivateRtcModelSubscribeOptions {
    boolean isSimultaneousTranslateAudio = false;
    int profile = 2;
    int keyframeInterval = 0;
    int timeoutMs = 120000;

    PrivateRtcModelSubscribeOptions() {
    }

    public boolean isSimultaneousTranslateAudio() {
        return this.isSimultaneousTranslateAudio;
    }

    public int getProfile() {
        return this.profile;
    }

    public int getKeyframeInterval() {
        return this.keyframeInterval;
    }

    public int getTimeoutMs() {
        return this.timeoutMs;
    }
}
