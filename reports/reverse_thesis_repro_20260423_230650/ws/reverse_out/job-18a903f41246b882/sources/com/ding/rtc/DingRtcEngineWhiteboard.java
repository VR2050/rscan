package com.ding.rtc;

import com.ding.rtc.api.DingRtcWhiteBoardTypes;

/* JADX INFO: loaded from: classes.dex */
public interface DingRtcEngineWhiteboard extends RtcWhiteboardBase {
    int addImageFile(String imageUrl);

    int clearContents(DingRtcWhiteBoardTypes.DingRtcWBClearParam param);

    void destroy();

    int resetVision();

    int saveDocToThumbnails(String docId, String outputDir);

    int setBackgroundColor(DingRtcWhiteBoardTypes.DingRtcWBColor color);

    int setBackgroundImage(String imageUrl, int pageNo);

    int setBooleanOption(DingRtcWhiteBoardTypes.DingRtcWBOption option, boolean param);

    int setEventListener(DingRtcEngineWhiteboardEventListener listener);

    int setFloatOption(DingRtcWhiteBoardTypes.DingRtcWBOption option, float param);

    int setIntOption(DingRtcWhiteBoardTypes.DingRtcWBOption option, int param);

    int setStringOption(DingRtcWhiteBoardTypes.DingRtcWBOption option, String param);

    int snapshot(DingRtcWhiteBoardTypes.DingRtcWBSnapshotMode mode, String outputDir);

    int startFollowVision();

    int startShareVision();

    int stopFollowVision();

    int stopShareVision();
}
