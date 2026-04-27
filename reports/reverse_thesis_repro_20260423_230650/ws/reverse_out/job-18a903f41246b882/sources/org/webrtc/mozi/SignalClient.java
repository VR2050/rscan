package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
public class SignalClient {
    private Listener listener;
    private long nativeOwtConfig;
    private long nativeSignalClient = 0;
    private SignalTransportFactory signalTransportFactory;

    public interface Ack {
        void call(String str);
    }

    public interface Listener {
        void onCustomMessage(String str, String str2, String str3);

        void onNetworkState(String str);

        void onPropertiesRemoved(String str, String str2);

        void onPropertiesUpdated(String str, String str2);

        void onServerDeletedChannel(String str);

        void onServerDisconnected(String str);

        void onServerFailover(String str);

        void onServerFailoverSummary(String str);

        void onServerMigration(String str, String[] strArr);

        void onSignalHeartbeatAlive();

        void onSignalHeartbeatTimeout();

        void onSignalState(String str);

        void onSignalingMessage(String str);

        void onStreamAdded(String str);

        void onStreamError(String str);

        void onStreamRemoved(String str);

        void onStreamUpdated(String str);

        void onSync(String str);

        void onUserJoined(String str);

        void onUserLeft(String str);
    }

    private static native void nativeAllocateStreamSession(long j, String str);

    private static native long nativeCreateSignalClient(Listener listener, SignalTransportFactory signalTransportFactory, long j);

    private static native void nativeDeallocateStreamSession(long j, String str);

    private static native void nativeDestroySignalClient(long j);

    private static native void nativeJoin(long j, String str, Ack ack);

    private static native void nativeLeave(long j, Ack ack);

    private static native void nativeMigrate(long j, String str, Ack ack);

    private static native void nativeSendMsg(long j, String str, String str2, Ack ack);

    public SignalClient(Listener listener, SignalTransportFactory factory, long nativeOwtConfig) {
        this.nativeOwtConfig = 0L;
        this.listener = listener;
        this.signalTransportFactory = factory;
        this.nativeOwtConfig = nativeOwtConfig;
    }

    public synchronized boolean init() {
        this.nativeSignalClient = nativeCreateSignalClient(this.listener, this.signalTransportFactory, this.nativeOwtConfig);
        return true;
    }

    public synchronized void uninit() {
        if (this.nativeSignalClient != 0) {
            nativeDestroySignalClient(this.nativeSignalClient);
            this.nativeSignalClient = 0L;
        }
    }

    public synchronized void join(String token, Ack ack) {
        if (this.nativeSignalClient == 0) {
            return;
        }
        nativeJoin(this.nativeSignalClient, token, ack);
    }

    public synchronized void leave(Ack ack) {
        if (this.nativeSignalClient == 0) {
            return;
        }
        nativeLeave(this.nativeSignalClient, ack);
    }

    public synchronized void sendMsg(String event, String msg, Ack ack) {
        if (this.nativeSignalClient == 0) {
            return;
        }
        nativeSendMsg(this.nativeSignalClient, event, msg, ack);
    }

    public synchronized void allocateStreamSession(String sessionId) {
        if (this.nativeSignalClient == 0) {
            return;
        }
        nativeAllocateStreamSession(this.nativeSignalClient, sessionId);
    }

    public synchronized void deallocateStreamSession(String sessionId) {
        if (this.nativeSignalClient == 0) {
            return;
        }
        nativeDeallocateStreamSession(this.nativeSignalClient, sessionId);
    }

    public synchronized void migrate(String token, Ack ack) {
        if (this.nativeSignalClient == 0) {
            return;
        }
        nativeMigrate(this.nativeSignalClient, token, ack);
    }
}
