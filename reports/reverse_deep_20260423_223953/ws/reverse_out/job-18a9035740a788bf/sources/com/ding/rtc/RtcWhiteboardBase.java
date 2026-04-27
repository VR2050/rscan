package com.ding.rtc;

import com.ding.rtc.api.DingRtcWhiteBoardTypes;
import java.util.List;

/* JADX INFO: loaded from: classes.dex */
public interface RtcWhiteboardBase {
    int addPage(boolean autoSwitch);

    int addStamp(DingRtcWhiteBoardTypes.DingRtcWBStamp stamp);

    int broadcastMessage(String msg, int size);

    int close();

    int copyDocPage(String srcDocId, int srcPageNum, String dstDocId, int dstPageNum, boolean clearDstPage);

    String createDoc(DingRtcWhiteBoardTypes.DingRtcWBDocContents contents, boolean autoSwitch);

    String createDoc(DingRtcWhiteBoardTypes.DingRtcWBDocExtContents contents, boolean autoSwitch);

    int deleteDoc(String docId);

    String getCurrentDocID();

    int getCurrentPageNumber();

    DingRtcWhiteboardDocInfo getDocInfo(String docId);

    List<String> getDocList();

    float getMaxZoomScale();

    float getMinZoomScale();

    boolean getRedoStatus();

    DingRtcWhiteBoardTypes.DingRtcWBToolType getToolType();

    int getTotalNumberOfPages();

    boolean getUndoStatus();

    float getZoomScale();

    int gotoPage(int pageNo);

    int insertPage(int pageNo, boolean autoSwitch);

    int join();

    int leave();

    int nextPage();

    int open(DingRtcWhiteboardView view);

    int prevPage();

    int redo();

    int removePage(int pageNo, boolean switchNext);

    int saveDocToImages(String docId, String outputDir);

    int sendUserMessage(String userId, String msg, int size);

    int setColor(DingRtcWhiteBoardTypes.DingRtcWBColor color);

    int setFillColor(DingRtcWhiteBoardTypes.DingRtcWBColor color);

    int setFillType(DingRtcWhiteBoardTypes.DingRtcWBFillType type);

    int setFontSize(int size);

    int setFontStyle(DingRtcWhiteBoardTypes.DingRtcWBFontStyle style);

    int setLineWidth(int size);

    int setMaxZoomScale(float scale);

    int setMinZoomScale(float scale);

    int setRole(DingRtcWhiteBoardTypes.DingRtcWBRoleType role);

    int setScalingMode(DingRtcWhiteBoardTypes.DingRtcWBScalingMode mode);

    int setStamp(String stampId);

    int setToolType(DingRtcWhiteBoardTypes.DingRtcWBToolType toolType);

    int setZoomScale(float scale);

    int setZoomScaleWithTranslate(float scale, float tx, float ty);

    int stop();

    int switchDoc(String docId);

    int undo();
}
