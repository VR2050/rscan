package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
public interface SignalTransport {

    public interface Ack {
        void call(String str, String str2);
    }

    public interface EventHandler {
        void process(String str, String str2);
    }

    public interface Listener {
        void OnReceiveAckOrEvent(String str, String str2, String str3);

        void onDisconnected(String str);
    }

    public interface OnConnectFail {
        void call(long j, String str);
    }

    public interface OnConnectSuccess {
        void call();
    }

    void addListener(Listener listener);

    int connect(String str, NetInterfaceInfo netInterfaceInfo, OnConnectSuccess onConnectSuccess, OnConnectFail onConnectFail);

    int disconnect();

    String id();

    void registReceivedEvent(String str, EventHandler eventHandler);

    void removeListener(Listener listener);

    int send(Message message, Ack ack);

    public static final class Message {
        public String data;
        public String event;
        public String tid;

        public Message(String event, String tid, String data) {
            this.event = event;
            this.tid = tid;
            this.data = data;
        }

        public String toString() {
            return "event=" + this.event + ", tid=" + this.tid + ", data=" + this.data;
        }
    }
}
