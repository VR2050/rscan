package com.ding.rtc;

import com.ding.rtc.api.DingRtcWhiteBoardTypes;
import java.util.List;

/* JADX INFO: loaded from: classes.dex */
public abstract class DingRtcEngineWhiteboardEventListener {
    public void onJoinResult(int result) {
    }

    public void onLeaveResult(int result) {
    }

    public void onUserMemberUpdate(int action, List<DingRtcWhiteBoardTypes.DingRtcWBUserMember> members, int memberCount) {
    }

    public void onSnapshotComplete(int result, String filename) {
    }

    public void onUndoStatus(boolean undo) {
    }

    public void onRedoStatus(boolean redo) {
    }

    public void onZoomScaleChanged(float scale) {
    }

    public void onDrawEvent(DingRtcWhiteBoardTypes.DingRtcWBDrawEvent event) {
    }

    public void onContentUpdate(DingRtcWhiteBoardTypes.DingRtcWBContentUpdateType type) {
    }

    public void onPageNumberChanged(int curPage, int totalPages) {
    }

    public void onCreateDoc(int result, String docId) {
    }

    public void onDeleteDoc(int result, String docId) {
    }

    public void onSwitchDoc(int result, String docId) {
    }

    public void onSaveDocComplete(int result, String docId, String outputDir) {
    }

    public void onSaveDocProgress(String docId, int current, int total) {
    }

    public void onReceiveMessage(String userId, String msg, int size) {
    }

    public void onVisionShareStarted(String userId) {
    }

    public void onVisionShareStopped(String userId) {
    }

    public void OnImageStateChanged(String url, DingRtcWhiteBoardTypes.DingRtcWBImageState state) {
    }

    public void OnFileTranscodeState(String docId, String transDocId, DingRtcWhiteBoardTypes.DingRtcWBFileTransState state) {
    }

    public void onSaveDocThumbnailComplete(int result, String docId, String outputDir) {
    }

    public void onSaveDocThumbnailProgress(String docId, int current, int total) {
    }
}
