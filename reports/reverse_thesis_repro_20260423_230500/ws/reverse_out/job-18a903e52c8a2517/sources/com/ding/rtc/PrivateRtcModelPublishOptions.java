package com.ding.rtc;

/* JADX INFO: loaded from: classes.dex */
class PrivateRtcModelPublishOptions {
    int timeoutMs = 120000;
    boolean disableForwardOnly = false;

    PrivateRtcModelPublishOptions() {
    }

    public int getTimeoutMs() {
        return this.timeoutMs;
    }

    public boolean isDisableForwardOnly() {
        return this.disableForwardOnly;
    }
}
