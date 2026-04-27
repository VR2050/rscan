package com.ding.rtc;

import com.ding.rtc.api.DingRtcWhiteBoardTypes;
import java.util.ArrayList;
import java.util.List;
import org.webrtc.mozi.Logging;

/* JADX INFO: loaded from: classes.dex */
class RtcWhiteboardEventListener {
    private static final String TAG = RtcWhiteboardEventListener.class.getSimpleName();
    private DingRtcEngineWhiteboardEventListener mRtcEngineWbEventListener;
    private final Object mWbEventListenerLock = new Object();
    private RtcWhiteboardImpl mWhiteboard;

    RtcWhiteboardEventListener(RtcWhiteboardImpl whiteboard) {
        this.mWhiteboard = whiteboard;
    }

    public void setWbEventListener(DingRtcEngineWhiteboardEventListener wbEventListener) {
        synchronized (this.mWbEventListenerLock) {
            this.mRtcEngineWbEventListener = wbEventListener;
        }
    }

    private void onJoinResult(int result) {
        synchronized (this.mWbEventListenerLock) {
            if (this.mRtcEngineWbEventListener != null) {
                this.mRtcEngineWbEventListener.onJoinResult(result);
            }
        }
    }

    private void onLeaveResult(int result) {
        synchronized (this.mWbEventListenerLock) {
            if (this.mRtcEngineWbEventListener != null) {
                this.mRtcEngineWbEventListener.onJoinResult(result);
            }
        }
    }

    private void onUserMemberUpdate(int action, String[] userIds, int memberCount) {
        synchronized (this.mWbEventListenerLock) {
            if (this.mRtcEngineWbEventListener != null) {
                List<DingRtcWhiteBoardTypes.DingRtcWBUserMember> memberList = new ArrayList<>();
                for (String userId : userIds) {
                    memberList.add(new DingRtcWhiteBoardTypes.DingRtcWBUserMember(userId));
                }
                this.mRtcEngineWbEventListener.onUserMemberUpdate(action, memberList, memberCount);
            }
        }
    }

    private void onVisionShareStarted(String userId) {
        synchronized (this.mWbEventListenerLock) {
            if (this.mRtcEngineWbEventListener != null) {
                this.mRtcEngineWbEventListener.onVisionShareStarted(userId);
            }
        }
    }

    private void onVisionShareStopped(String userId) {
        synchronized (this.mWbEventListenerLock) {
            if (this.mRtcEngineWbEventListener != null) {
                this.mRtcEngineWbEventListener.onVisionShareStopped(userId);
            }
        }
    }

    private void OnImageStateChanged(String url, int state) {
        synchronized (this.mWbEventListenerLock) {
            if (this.mRtcEngineWbEventListener != null) {
                this.mRtcEngineWbEventListener.OnImageStateChanged(url, DingRtcWhiteBoardTypes.DingRtcWBImageState.fromValue(state));
            }
        }
    }

    private void OnFileTranscodeState(String docId, String transDocId, int state) {
        synchronized (this.mWbEventListenerLock) {
            if (this.mRtcEngineWbEventListener != null) {
                this.mRtcEngineWbEventListener.OnFileTranscodeState(docId, transDocId, DingRtcWhiteBoardTypes.DingRtcWBFileTransState.fromValue(state));
            }
        }
    }

    private void onSaveDocThumbnailComplete(int result, String docId, String outputDir) {
        synchronized (this.mWbEventListenerLock) {
            if (this.mRtcEngineWbEventListener != null) {
                this.mRtcEngineWbEventListener.onSaveDocThumbnailComplete(result, docId, outputDir);
            }
        }
    }

    private void onSaveDocThumbnailProgress(String docId, int current, int total) {
        synchronized (this.mWbEventListenerLock) {
            if (this.mRtcEngineWbEventListener != null) {
                this.mRtcEngineWbEventListener.onSaveDocThumbnailProgress(docId, current, total);
            }
        }
    }

    private void onSnapshotComplete(int result, String filename) {
        synchronized (this.mWbEventListenerLock) {
            if (this.mRtcEngineWbEventListener != null) {
                this.mRtcEngineWbEventListener.onSnapshotComplete(result, filename);
            }
        }
    }

    private void onUndoStatus(boolean undo) {
        synchronized (this.mWbEventListenerLock) {
            if (this.mRtcEngineWbEventListener != null) {
                this.mRtcEngineWbEventListener.onUndoStatus(undo);
            }
        }
    }

    private void onRedoStatus(boolean redo) {
        synchronized (this.mWbEventListenerLock) {
            if (this.mRtcEngineWbEventListener != null) {
                this.mRtcEngineWbEventListener.onRedoStatus(redo);
            }
        }
    }

    private void onZoomScaleChanged(float scale) {
        synchronized (this.mWbEventListenerLock) {
            if (this.mRtcEngineWbEventListener != null) {
                this.mRtcEngineWbEventListener.onZoomScaleChanged(scale);
            }
        }
    }

    private void onDrawEvent(int event) {
        synchronized (this.mWbEventListenerLock) {
            if (this.mRtcEngineWbEventListener != null) {
                this.mRtcEngineWbEventListener.onDrawEvent(DingRtcWhiteBoardTypes.DingRtcWBDrawEvent.fromValue(event));
            }
        }
    }

    private void onContentUpdate(int type) {
        synchronized (this.mWbEventListenerLock) {
            if (this.mRtcEngineWbEventListener != null) {
                this.mRtcEngineWbEventListener.onContentUpdate(DingRtcWhiteBoardTypes.DingRtcWBContentUpdateType.fromValue(type));
            }
        }
    }

    private void onPageNumberChanged(int curPage, int totalPages) {
        synchronized (this.mWbEventListenerLock) {
            if (this.mRtcEngineWbEventListener != null) {
                this.mRtcEngineWbEventListener.onPageNumberChanged(curPage, totalPages);
            }
        }
    }

    private void onCreateDoc(int result, String docId) {
        synchronized (this.mWbEventListenerLock) {
            if (this.mRtcEngineWbEventListener != null) {
                this.mRtcEngineWbEventListener.onCreateDoc(result, docId);
            }
        }
    }

    private void onDeleteDoc(int result, String docId) {
        synchronized (this.mWbEventListenerLock) {
            if (this.mRtcEngineWbEventListener != null) {
                this.mRtcEngineWbEventListener.onDeleteDoc(result, docId);
            }
        }
    }

    private void onSwitchDoc(int result, String docId) {
        synchronized (this.mWbEventListenerLock) {
            if (this.mRtcEngineWbEventListener != null) {
                this.mRtcEngineWbEventListener.onSwitchDoc(result, docId);
            }
        }
    }

    private void onSaveDocComplete(int result, String docId, String outputDir) {
        synchronized (this.mWbEventListenerLock) {
            if (this.mRtcEngineWbEventListener != null) {
                this.mRtcEngineWbEventListener.onSaveDocComplete(result, docId, outputDir);
            }
        }
    }

    private void onSaveDocProgress(String docId, int current, int total) {
        synchronized (this.mWbEventListenerLock) {
            if (this.mRtcEngineWbEventListener != null) {
                this.mRtcEngineWbEventListener.onSaveDocProgress(docId, current, total);
            }
        }
    }

    private void onReceiveMessage(String userId, String msg, int size) {
        synchronized (this.mWbEventListenerLock) {
            if (this.mRtcEngineWbEventListener != null) {
                this.mRtcEngineWbEventListener.onReceiveMessage(userId, msg, size);
            }
        }
    }

    public void setOpaque(boolean opaque) {
        Logging.i(TAG, "setOpaque begin.");
        RtcWhiteboardImpl rtcWhiteboardImpl = this.mWhiteboard;
        if (rtcWhiteboardImpl != null) {
            rtcWhiteboardImpl.setOpaque(opaque);
            Logging.i(TAG, "setOpaque end.");
        }
    }

    public boolean getOpaque() {
        Logging.i(TAG, "getOpaque begin.");
        RtcWhiteboardImpl rtcWhiteboardImpl = this.mWhiteboard;
        if (rtcWhiteboardImpl != null) {
            boolean result = rtcWhiteboardImpl.getOpaque();
            Logging.i(TAG, "getOpaque end.");
            return result;
        }
        return false;
    }

    public void setLimitSize(int w, int h) {
        Logging.i(TAG, "setLimitSize begin.");
        RtcWhiteboardImpl rtcWhiteboardImpl = this.mWhiteboard;
        if (rtcWhiteboardImpl != null) {
            rtcWhiteboardImpl.setLimitSize(w, h);
            Logging.i(TAG, "setLimitSize end.");
        }
    }

    public void addCursor(String labelId, String name) {
        Logging.i(TAG, "addCursor begin.");
        RtcWhiteboardImpl rtcWhiteboardImpl = this.mWhiteboard;
        if (rtcWhiteboardImpl != null) {
            rtcWhiteboardImpl.addCursor(labelId, name);
            Logging.i(TAG, "addCursor end.");
        }
    }

    public void removeCursor(String labelId) {
        Logging.i(TAG, "removeCursor begin.");
        RtcWhiteboardImpl rtcWhiteboardImpl = this.mWhiteboard;
        if (rtcWhiteboardImpl != null) {
            rtcWhiteboardImpl.removeCursor(labelId);
            Logging.i(TAG, "removeCursor end.");
        }
    }

    public void updateCursor(String labelId, float x, float y, int color, int type, String name) {
        Logging.i(TAG, "updateCursor begin.");
        RtcWhiteboardImpl rtcWhiteboardImpl = this.mWhiteboard;
        if (rtcWhiteboardImpl != null) {
            rtcWhiteboardImpl.updateCursor(labelId, x, y, color, type, name);
            Logging.i(TAG, "updateCursor end.");
        }
    }

    public void openPdf(String pageId, String url) {
        DingRtcWhiteboardView view;
        Logging.i(TAG, "openPdf begin.");
        RtcWhiteboardImpl rtcWhiteboardImpl = this.mWhiteboard;
        if (rtcWhiteboardImpl != null && (view = rtcWhiteboardImpl.getView()) != null) {
            view.openPdf(pageId, url);
            Logging.i(TAG, "openPdf end.");
        }
    }

    public void showPdf(String pageId) {
        DingRtcWhiteboardView view;
        Logging.i(TAG, "showPdf begin.");
        RtcWhiteboardImpl rtcWhiteboardImpl = this.mWhiteboard;
        if (rtcWhiteboardImpl != null && (view = rtcWhiteboardImpl.getView()) != null) {
            view.showPdf(pageId);
            Logging.i(TAG, "showPdf end.");
        }
    }

    public void hidePdf(String pageId) {
        DingRtcWhiteboardView view;
        Logging.i(TAG, "hidePdf begin.");
        RtcWhiteboardImpl rtcWhiteboardImpl = this.mWhiteboard;
        if (rtcWhiteboardImpl != null && (view = rtcWhiteboardImpl.getView()) != null) {
            view.hidePdf(pageId);
            Logging.i(TAG, "hidePdf end.");
        }
    }

    public void closePdf(String pageId) {
        DingRtcWhiteboardView view;
        Logging.i(TAG, "closePdf begin.");
        RtcWhiteboardImpl rtcWhiteboardImpl = this.mWhiteboard;
        if (rtcWhiteboardImpl != null && (view = rtcWhiteboardImpl.getView()) != null) {
            view.closePdf(pageId);
            Logging.i(TAG, "closePdf end.");
        }
    }

    public void scrollPdfTo(String pageId, int page, float pos) {
        DingRtcWhiteboardView view;
        Logging.i(TAG, "scrollPdfTo begin.");
        RtcWhiteboardImpl rtcWhiteboardImpl = this.mWhiteboard;
        if (rtcWhiteboardImpl != null && (view = rtcWhiteboardImpl.getView()) != null) {
            view.scrollPdfTo(pageId, page, pos);
            Logging.i(TAG, "scrollPdfTo end.");
        }
    }

    public void scalePdfTo(String pageId, float scale, float x, float y) {
        DingRtcWhiteboardView view;
        Logging.i(TAG, "scalePdfTo begin.");
        RtcWhiteboardImpl rtcWhiteboardImpl = this.mWhiteboard;
        if (rtcWhiteboardImpl != null && (view = rtcWhiteboardImpl.getView()) != null) {
            view.scalePdfTo(pageId, scale, x, y);
            Logging.i(TAG, "scalePdfTo end.");
        }
    }

    public void snapshotPdf(String pageId, String filePath) {
        DingRtcWhiteboardView view;
        Logging.i(TAG, "snapshotPdf begin.");
        RtcWhiteboardImpl rtcWhiteboardImpl = this.mWhiteboard;
        if (rtcWhiteboardImpl != null && (view = rtcWhiteboardImpl.getView()) != null) {
            view.snapshotPdf(pageId, filePath);
            Logging.i(TAG, "snapshotPdf end.");
        }
    }
}
