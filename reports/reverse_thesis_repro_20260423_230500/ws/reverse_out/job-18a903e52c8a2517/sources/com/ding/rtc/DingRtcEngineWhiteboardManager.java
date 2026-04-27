package com.ding.rtc;

import com.ding.rtc.api.DingRtcWhiteBoardTypes;

/* JADX INFO: loaded from: classes.dex */
public interface DingRtcEngineWhiteboardManager {
    DingRtcEngineWhiteboard createWhiteboard(String whiteboardId, DingRtcWhiteBoardTypes.DingRtcWBConfig config);

    DingRtcEngineWhiteboard getWhiteboard(String whiteboardId);

    int setWhiteboardManagerEventListener(DingRtcEngineWhiteboardManagerListener listener);
}
