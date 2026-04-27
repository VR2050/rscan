package com.ding.rtc;

import com.ding.rtc.DingRtmClient;

/* JADX INFO: loaded from: classes.dex */
class RtmEventListenerWrapper {
    private DingRtmEventListener mListener;

    RtmEventListenerWrapper() {
    }

    void setListener(DingRtmEventListener listener) {
        this.mListener = listener;
    }

    private void onRtmServerStateChanged(int state, int reason) {
        DingRtmEventListener dingRtmEventListener = this.mListener;
        if (dingRtmEventListener != null) {
            dingRtmEventListener.onRtmServerStateChanged(DingRtmClient.DingRtmServerState.fromValue(state), reason);
        }
    }

    private void onJoinSessionResult(String sessionId, int result) {
        DingRtmEventListener dingRtmEventListener = this.mListener;
        if (dingRtmEventListener != null) {
            dingRtmEventListener.onJoinSessionResult(sessionId, result);
        }
    }

    private void onLeaveSessionResult(String sessionId, int result) {
        DingRtmEventListener dingRtmEventListener = this.mListener;
        if (dingRtmEventListener != null) {
            dingRtmEventListener.onLeaveSessionResult(sessionId, result);
        }
    }

    private void onCloseSessionResult(String sessionId, int result) {
        DingRtmEventListener dingRtmEventListener = this.mListener;
        if (dingRtmEventListener != null) {
            dingRtmEventListener.onCloseSessionResult(sessionId, result);
        }
    }

    private void onRemovedFromSession(String sessionId, int reason) {
        DingRtmEventListener dingRtmEventListener = this.mListener;
        if (dingRtmEventListener != null) {
            dingRtmEventListener.onRemovedFromSession(sessionId, reason);
        }
    }

    private void onSessionCreate(String sessionId) {
        DingRtmEventListener dingRtmEventListener = this.mListener;
        if (dingRtmEventListener != null) {
            dingRtmEventListener.onSessionCreate(sessionId);
        }
    }

    private void onSessionClose(String sessionId) {
        DingRtmEventListener dingRtmEventListener = this.mListener;
        if (dingRtmEventListener != null) {
            dingRtmEventListener.onSessionClose(sessionId);
        }
    }

    private void onSessionRemoteUserJoin(String sessionId, String uid) {
        DingRtmEventListener dingRtmEventListener = this.mListener;
        if (dingRtmEventListener != null) {
            dingRtmEventListener.onSessionRemoteUserJoin(sessionId, uid);
        }
    }

    private void onSessionRemoteUserLeave(String sessionId, String uid) {
        DingRtmEventListener dingRtmEventListener = this.mListener;
        if (dingRtmEventListener != null) {
            dingRtmEventListener.onSessionRemoteUserLeave(sessionId, uid);
        }
    }

    private void onMessage(String sessionId, String fromUid, boolean broadcast, byte[] data) {
        DingRtmEventListener dingRtmEventListener = this.mListener;
        if (dingRtmEventListener != null) {
            dingRtmEventListener.onMessage(sessionId, fromUid, broadcast, data);
        }
    }
}
