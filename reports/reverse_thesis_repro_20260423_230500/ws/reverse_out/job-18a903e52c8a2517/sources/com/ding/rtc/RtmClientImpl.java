package com.ding.rtc;

/* JADX INFO: loaded from: classes.dex */
class RtmClientImpl extends DingRtmClient {
    private final RtmEventListenerWrapper mListenerWrapper;
    private final long mNativeHandle;

    private native int nativeBroadcastData(long instance, String sessionId, byte[] data);

    private native int nativeCloseSession(long instance, String sessionId);

    private native int nativeJoinSession(long instance, String sessionId);

    private native int nativeLeaveSession(long instance, String sessionId);

    private native int nativeSendData(long instance, String sessionId, String toUid, byte[] data);

    private native void nativeSetListener(long instance, Object listener);

    RtmClientImpl(long nativeHandle) {
        RtmEventListenerWrapper rtmEventListenerWrapper = new RtmEventListenerWrapper();
        this.mListenerWrapper = rtmEventListenerWrapper;
        this.mNativeHandle = nativeHandle;
        nativeSetListener(nativeHandle, rtmEventListenerWrapper);
    }

    @Override // com.ding.rtc.DingRtmClient
    public void setListener(DingRtmEventListener listener) {
        this.mListenerWrapper.setListener(listener);
    }

    @Override // com.ding.rtc.DingRtmClient
    public int joinSession(String sessionId) {
        return nativeJoinSession(this.mNativeHandle, sessionId);
    }

    @Override // com.ding.rtc.DingRtmClient
    public int leaveSession(String sessionId) {
        return nativeLeaveSession(this.mNativeHandle, sessionId);
    }

    @Override // com.ding.rtc.DingRtmClient
    public int closeSession(String sessionId) {
        return nativeCloseSession(this.mNativeHandle, sessionId);
    }

    @Override // com.ding.rtc.DingRtmClient
    public int sendData(String sessionId, String toUid, byte[] data) {
        return nativeSendData(this.mNativeHandle, sessionId, toUid, data);
    }

    @Override // com.ding.rtc.DingRtmClient
    public int broadcastData(String sessionId, byte[] data) {
        return nativeBroadcastData(this.mNativeHandle, sessionId, data);
    }
}
