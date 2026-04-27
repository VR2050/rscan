package org.webrtc.mozi.p2p;

import org.webrtc.mozi.Logging;

/* JADX INFO: loaded from: classes3.dex */
public class P2pSignalingClient {
    private static final String TAG = "P2pClient";
    private static boolean sSdkInitialised;
    private long mNativePtr;

    public interface P2pSignalingClientObserver {
        void OnRemoteStatusChanged(String str, boolean z, boolean z2);

        void onCalleeAccept(String str, Peer peer, String str2);

        void onCalleeRing(String str, Peer peer, String str2);

        void onCalleeTry(String str, Peer peer, String str2);

        void onCallerConfirmed(String str, Peer peer);

        void onHangup(String str, Peer peer, int i, String str2);

        void onIncomingCall(String str, Peer peer, String str2, String str3, String str4, String str5);

        void onReceiveCustomMessage(String str, String str2, String str3, String str4);

        void onReceiveCustomMessageResponse(String str, String str2, String str3);

        void onSessionUpdate(String str, Peer peer, int i, String str2);

        void onTerminated();
    }

    private static native void nativeAcceptCall(long j, String str, String str2, boolean z, boolean z2, Callback callback);

    private static native void nativeConfirmCall(long j, String str, Callback callback);

    private static native long nativeCreate(long j, Peer peer, P2pSignalingTransport p2pSignalingTransport, P2pSignalingClientObserver p2pSignalingClientObserver);

    private static native void nativeEnableVideoCall(long j, boolean z);

    private static native void nativeHangup(long j, String str, int i, String str2, boolean z, Callback callback);

    private static native int nativeInitSdk();

    private static native void nativeKeepCallAlive(long j, String str);

    private static native void nativeMakeCall(long j, String str, Peer peer, String str2, String str3, String str4, boolean z, boolean z2, String str5, Callback callback);

    private static native void nativeRelease(long j);

    private static native void nativeRespondCustomMessage(long j, String str, String str2, String str3, Callback callback);

    private static native void nativeSendCustomMessage(long j, String str, String str2, String str3, Callback2 callback2);

    private static native void nativeSetRingAttachment(long j, String str);

    private static native int nativeUninitSdk();

    private static native void nativeUpdateSession(long j, String str, int i, String str2, Callback callback);

    private static native void nativeUpdateSessionStatus(long j, String str, boolean z, boolean z2, Callback callback);

    public static boolean initSdk() {
        if (sSdkInitialised) {
            return true;
        }
        Logging.d(TAG, "initSdk");
        int result = nativeInitSdk();
        Logging.d(TAG, "initSdk result = " + result);
        boolean z = result == 0;
        sSdkInitialised = z;
        return z;
    }

    public static void uninitSdk() {
        if (sSdkInitialised) {
            Logging.d(TAG, "uninitSdk");
            nativeUninitSdk();
            sSdkInitialised = false;
        }
    }

    public static P2pSignalingClient create(long owtFactoryPtr, Peer peer, P2pSignalingTransport transport, P2pSignalingClientObserver observer) {
        return new P2pSignalingClient(owtFactoryPtr, peer, transport, observer);
    }

    private P2pSignalingClient(long owtFactoryPtr, Peer peer, P2pSignalingTransport transport, P2pSignalingClientObserver observer) {
        this.mNativePtr = nativeCreate(owtFactoryPtr, peer, transport, observer);
    }

    public void makeCall(String callId, Peer peer, String callType, String bizType, String sdp, boolean audioMuted, boolean videoMuted, String attachment, Callback callback) {
        Logging.d(TAG, "makeCall");
        nativeMakeCall(this.mNativePtr, callId, peer, callType, bizType, sdp, audioMuted, videoMuted, attachment, callback);
    }

    public void acceptCall(String callId, String sdp, boolean audioMuted, boolean videoMuted, Callback callback) {
        Logging.d(TAG, "acceptCall");
        nativeAcceptCall(this.mNativePtr, callId, sdp, audioMuted, videoMuted, callback);
    }

    public void confirmCall(String callId, Callback callback) {
        Logging.d(TAG, "confirmCall");
        nativeConfirmCall(this.mNativePtr, callId, callback);
    }

    public void updateSession(String callId, int action, String payload, Callback callback) {
        nativeUpdateSession(this.mNativePtr, callId, action, payload, callback);
    }

    public void sendCustomMessage(String callId, String contentType, String content, Callback2 callback) {
        Logging.d(TAG, "sendCustomMessage");
        nativeSendCustomMessage(this.mNativePtr, callId, contentType, content, callback);
    }

    public void respondCustomMessage(String messageId, String contentType, String content, Callback callback) {
        Logging.d(TAG, "respondCustomMessage");
        nativeRespondCustomMessage(this.mNativePtr, messageId, contentType, content, callback);
    }

    public void hangup(String callId, int reasonCode, String extraMsg, boolean localOnly, Callback callback) {
        Logging.d(TAG, "hangup");
        nativeHangup(this.mNativePtr, callId, reasonCode, extraMsg, localOnly, callback);
    }

    public void keepCallAlive(String callId) {
        Logging.d(TAG, "keepCallAlive");
        nativeKeepCallAlive(this.mNativePtr, callId);
    }

    public void setRingAttachment(String attachment) {
        Logging.d(TAG, "setRingAttachment");
        nativeSetRingAttachment(this.mNativePtr, attachment);
    }

    public void updateSessionStatus(String callId, boolean audioMuted, boolean videoMuted, Callback callback) {
        Logging.d(TAG, "UpdateSessionStatus");
        nativeUpdateSessionStatus(this.mNativePtr, callId, audioMuted, videoMuted, callback);
    }

    public void enableVideoCall(boolean enable) {
        Logging.d(TAG, "enableVideoCall");
        nativeEnableVideoCall(this.mNativePtr, enable);
    }

    public void release() {
        nativeRelease(this.mNativePtr);
    }
}
