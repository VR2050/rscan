package com.ding.rtc;

import com.google.android.exoplayer2.extractor.ts.TsExtractor;

/* JADX INFO: loaded from: classes.dex */
class PrivateRtcModelVideoEnhanceParams {
    int yThreshold = TsExtractor.TS_STREAM_TYPE_HDMV_DTS;
    int deltaThreshold = 20;
    int mode = 0;

    PrivateRtcModelVideoEnhanceParams() {
    }

    public int getyThreshold() {
        return this.yThreshold;
    }

    public int getDeltaThreshold() {
        return this.deltaThreshold;
    }

    public int getMode() {
        return this.mode;
    }
}
