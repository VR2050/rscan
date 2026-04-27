package com.ding.rtc;

import com.ding.rtc.DingRtmClient;

/* JADX INFO: loaded from: classes.dex */
public abstract class DingRtmEventListener {
    public void onRtmServerStateChanged(DingRtmClient.DingRtmServerState state, int errorCode) {
    }

    public void onJoinSessionResult(String sessionId, int result) {
    }

    public void onLeaveSessionResult(String sessionId, int reason) {
    }

    public void onCloseSessionResult(String sessionId, int result) {
    }

    public void onRemovedFromSession(String sessionId, int reason) {
    }

    public void onSessionCreate(String sessionId) {
    }

    public void onSessionClose(String sessionId) {
    }

    public void onSessionRemoteUserJoin(String sessionId, String uid) {
    }

    public void onSessionRemoteUserLeave(String sessionId, String uid) {
    }

    public void onMessage(String sessionId, String fromUid, boolean broadcast, byte[] data) {
    }
}
