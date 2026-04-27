package org.webrtc.mozi.p2p;

/* JADX INFO: loaded from: classes3.dex */
public interface P2pSignalingTransport {

    public interface P2pSignalingTransportObserver {
        void onReceiveSignaling(P2pSignaling p2pSignaling);
    }

    void addObserver(P2pSignalingTransportObserver p2pSignalingTransportObserver);

    void sendSignaling(P2pSignaling p2pSignaling, Callback callback);
}
