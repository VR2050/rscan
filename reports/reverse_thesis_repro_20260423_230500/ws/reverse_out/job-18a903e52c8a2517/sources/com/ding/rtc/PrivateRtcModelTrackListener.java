package com.ding.rtc;

/* JADX INFO: loaded from: classes.dex */
interface PrivateRtcModelTrackListener {
    void onEnded();

    void onFirstPacketReceived(int elapseMs);

    void onFirstPacketSent(int elapseMs);

    void onFirstVideoFrameReceived(int elapseMs);

    void onFirstVideoFrameRendered(int width, int height, int elapseMs);

    void onMuteOrUnmute(boolean muted);

    void onVideoFrame(PrivateRtcModelVideoFrame frame);
}
