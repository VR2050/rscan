package org.webrtc.mozi.p2p;

import org.webrtc.mozi.p2p.P2pSignalingTransport;

/* JADX INFO: loaded from: classes3.dex */
class P2pSignalingTransportObserverWrapper implements P2pSignalingTransport.P2pSignalingTransportObserver {
    private final long mNativePtr;

    private static native void nativeOnReceiveSignaling(long j, P2pSignaling p2pSignaling);

    public P2pSignalingTransportObserverWrapper(long nativePtr) {
        this.mNativePtr = nativePtr;
    }

    @Override // org.webrtc.mozi.p2p.P2pSignalingTransport.P2pSignalingTransportObserver
    public void onReceiveSignaling(P2pSignaling signaling) {
        nativeOnReceiveSignaling(this.mNativePtr, signaling);
    }
}
