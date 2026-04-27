package com.ding.rtc;

import com.ding.rtc.api.DingRtcWhiteBoardTypes;

/* JADX INFO: loaded from: classes.dex */
class RtcWhiteboardManagerListener {
    private DingRtcEngineWhiteboardManagerListener mRtcEngineWbManagerListener;
    private final Object mWbManagerListenerLock = new Object();

    RtcWhiteboardManagerListener() {
    }

    public void setWhiteboardManagerListener(DingRtcEngineWhiteboardManagerListener listener) {
        synchronized (this.mWbManagerListenerLock) {
            this.mRtcEngineWbManagerListener = listener;
        }
    }

    private void onWhiteboardServerStateChanged(int state, int reason) {
        synchronized (this.mWbManagerListenerLock) {
            if (this.mRtcEngineWbManagerListener != null) {
                this.mRtcEngineWbManagerListener.onWhiteboardServerStateChanged(DingRtcWhiteBoardTypes.DingRtcWBServerState.fromValue(state), reason);
            }
        }
    }

    private void onWhiteboardStart(String whiteboardId, int width, int height, int mode) {
        synchronized (this.mWbManagerListenerLock) {
            if (this.mRtcEngineWbManagerListener != null) {
                DingRtcWhiteBoardTypes.DingRtcWBConfig config = new DingRtcWhiteBoardTypes.DingRtcWBConfig(width, height, DingRtcWhiteBoardTypes.DingRtcWBMode.fromValue(mode));
                this.mRtcEngineWbManagerListener.onWhiteboardStart(whiteboardId, config);
            }
        }
    }

    private void onWhiteboardStop(String whiteboardId) {
        synchronized (this.mWbManagerListenerLock) {
            if (this.mRtcEngineWbManagerListener != null) {
                this.mRtcEngineWbManagerListener.onWhiteboardStop(whiteboardId);
            }
        }
    }
}
