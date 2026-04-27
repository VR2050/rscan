package com.ding.rtc;

import com.ding.rtc.api.DingRtcWhiteBoardTypes;

/* JADX INFO: loaded from: classes.dex */
public interface DingRtcEngineWhiteboardManagerListener {
    void onWhiteboardServerStateChanged(DingRtcWhiteBoardTypes.DingRtcWBServerState state, int reason);

    void onWhiteboardStart(String whiteboardId, DingRtcWhiteBoardTypes.DingRtcWBConfig cfg);

    void onWhiteboardStop(String whiteboardId);
}
