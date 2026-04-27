package org.webrtc.mozi;

import java.util.HashMap;
import org.webrtc.mozi.SignalTransport;

/* JADX INFO: loaded from: classes3.dex */
public class SignalTransportAdapter {
    private SignalTransport transport;
    private HashMap<Long, ListenerWrapper> listenerWrapperMap = new HashMap<>();
    private HashMap<String, EventHandlerWrapper> eventHandlerWrapperMap = new HashMap<>();
    private HashMap<Long, AckWrapper> ackWrapperMap = new HashMap<>();
    private OnConnectSuccessWrapper onConnectSuccessWrapper = null;
    private OnConnectFailWrapper onConnectFailWrapper = null;

    /* JADX INFO: Access modifiers changed from: private */
    public static native void nativeAckCall(long j, String str, String str2);

    /* JADX INFO: Access modifiers changed from: private */
    public static native void nativeConnectCallbackWrapperCall(long j, long j2, String str);

    /* JADX INFO: Access modifiers changed from: private */
    public static native void nativeEventHandlerProcess(long j, String str, String str2);

    /* JADX INFO: Access modifiers changed from: private */
    public static native void nativeListenerOnDisconnected(long j, String str);

    /* JADX INFO: Access modifiers changed from: private */
    public static native void nativeListenerOnReceiveAckOrEvent(long j, String str, String str2, String str3);

    public class ListenerWrapper implements SignalTransport.Listener {
        private long nativeObj;

        public ListenerWrapper(long obj) {
            this.nativeObj = 0L;
            this.nativeObj = obj;
        }

        public void reset() {
            synchronized (this) {
                this.nativeObj = 0L;
            }
        }

        @Override // org.webrtc.mozi.SignalTransport.Listener
        public void onDisconnected(String code) {
            synchronized (this) {
                if (this.nativeObj == 0) {
                    return;
                }
                SignalTransportAdapter.nativeListenerOnDisconnected(this.nativeObj, code);
                this.nativeObj = 0L;
            }
        }

        @Override // org.webrtc.mozi.SignalTransport.Listener
        public void OnReceiveAckOrEvent(String transportId, String tid, String name) {
            synchronized (this) {
                if (this.nativeObj == 0) {
                    return;
                }
                SignalTransportAdapter.nativeListenerOnReceiveAckOrEvent(this.nativeObj, transportId, tid, name);
            }
        }
    }

    public class EventHandlerWrapper implements SignalTransport.EventHandler {
        private long nativeObj;

        public EventHandlerWrapper(long obj) {
            this.nativeObj = 0L;
            this.nativeObj = obj;
        }

        public void reset() {
            synchronized (this) {
                this.nativeObj = 0L;
            }
        }

        @Override // org.webrtc.mozi.SignalTransport.EventHandler
        public void process(String event, String message) {
            synchronized (this) {
                if (this.nativeObj == 0) {
                    return;
                }
                SignalTransportAdapter.nativeEventHandlerProcess(this.nativeObj, event, message);
            }
        }
    }

    public class AckWrapper implements SignalTransport.Ack {
        private SignalTransportAdapter adapter;
        private long nativeObj;

        public AckWrapper(SignalTransportAdapter adapter, long obj) {
            this.nativeObj = 0L;
            this.adapter = null;
            this.adapter = adapter;
            this.nativeObj = obj;
        }

        public void reset() {
            synchronized (this) {
                this.nativeObj = 0L;
            }
        }

        @Override // org.webrtc.mozi.SignalTransport.Ack
        public void call(String result, String message) {
            synchronized (this) {
                if (this.nativeObj == 0) {
                    return;
                }
                SignalTransportAdapter.nativeAckCall(this.nativeObj, result, message);
                long nativeTmpObj = this.nativeObj;
                this.nativeObj = 0L;
                this.adapter.removeAck(Long.valueOf(nativeTmpObj));
            }
        }

        public void addAck() {
            SignalTransportAdapter signalTransportAdapter = this.adapter;
            if (signalTransportAdapter != null) {
                signalTransportAdapter.addAck(this.nativeObj, this);
            }
        }
    }

    public class OnConnectSuccessWrapper implements SignalTransport.OnConnectSuccess {
        private long nativeObj;

        public OnConnectSuccessWrapper(long obj) {
            this.nativeObj = 0L;
            this.nativeObj = obj;
        }

        public void reset() {
            synchronized (this) {
                this.nativeObj = 0L;
            }
        }

        @Override // org.webrtc.mozi.SignalTransport.OnConnectSuccess
        public void call() {
            synchronized (this) {
                if (this.nativeObj == 0) {
                    return;
                }
                SignalTransportAdapter.nativeConnectCallbackWrapperCall(this.nativeObj, 0L, "ok");
            }
        }
    }

    public class OnConnectFailWrapper implements SignalTransport.OnConnectFail {
        private long nativeObj;

        public OnConnectFailWrapper(long obj) {
            this.nativeObj = 0L;
            this.nativeObj = obj;
        }

        public void reset() {
            synchronized (this) {
                this.nativeObj = 0L;
            }
        }

        @Override // org.webrtc.mozi.SignalTransport.OnConnectFail
        public void call(long type, String message) {
            synchronized (this) {
                if (this.nativeObj == 0) {
                    return;
                }
                SignalTransportAdapter.nativeConnectCallbackWrapperCall(this.nativeObj, type, message);
            }
        }
    }

    public SignalTransportAdapter(SignalTransport transport) {
        this.transport = null;
        this.transport = transport;
    }

    public void addAck(long ackObj, AckWrapper ack) {
        synchronized (this) {
            this.ackWrapperMap.put(Long.valueOf(ackObj), ack);
        }
    }

    public void removeAck(Long obj) {
        synchronized (this) {
            this.ackWrapperMap.remove(obj);
        }
    }

    public String id() {
        return this.transport.id();
    }

    public void addListener(long listenerObj) {
        ListenerWrapper listenerWrapper = new ListenerWrapper(listenerObj);
        this.listenerWrapperMap.put(Long.valueOf(listenerObj), listenerWrapper);
        this.transport.addListener(listenerWrapper);
    }

    public void removeListener(long listenerObj) {
        if (!this.listenerWrapperMap.containsKey(Long.valueOf(listenerObj))) {
            return;
        }
        ListenerWrapper listenerWrapper = this.listenerWrapperMap.get(Long.valueOf(listenerObj));
        listenerWrapper.reset();
        this.transport.removeListener(listenerWrapper);
        this.listenerWrapperMap.remove(Long.valueOf(listenerObj));
    }

    public int send(String event, String data, String tid, long ackObj) {
        if (this.transport == null) {
            return -1;
        }
        AckWrapper ack = new AckWrapper(this, ackObj);
        SignalTransport.Message message = new SignalTransport.Message(event, tid, data);
        return this.transport.send(message, ack);
    }

    public int connect(String uri, NetInterfaceInfo info, long onConnectCallbackObj) {
        if (this.transport == null) {
            return -1;
        }
        this.onConnectSuccessWrapper = new OnConnectSuccessWrapper(onConnectCallbackObj);
        OnConnectFailWrapper onConnectFailWrapper = new OnConnectFailWrapper(onConnectCallbackObj);
        this.onConnectFailWrapper = onConnectFailWrapper;
        return this.transport.connect(uri, info, this.onConnectSuccessWrapper, onConnectFailWrapper);
    }

    public int disconnect() {
        SignalTransport signalTransport = this.transport;
        if (signalTransport == null) {
            return -1;
        }
        return signalTransport.disconnect();
    }

    public void registReceivedEvent(String event, long handlerObj) {
        if (this.transport == null) {
            return;
        }
        if (this.eventHandlerWrapperMap.containsKey(event)) {
            EventHandlerWrapper wrapper = this.eventHandlerWrapperMap.get(event);
            if (wrapper != null) {
                wrapper.reset();
            }
            this.eventHandlerWrapperMap.remove(event);
        }
        if (handlerObj == 0) {
            this.transport.registReceivedEvent(event, null);
            return;
        }
        EventHandlerWrapper eventHandlerWrapper = new EventHandlerWrapper(handlerObj);
        this.eventHandlerWrapperMap.put(event, eventHandlerWrapper);
        this.transport.registReceivedEvent(event, eventHandlerWrapper);
    }

    public void destory() {
        OnConnectSuccessWrapper onConnectSuccessWrapper = this.onConnectSuccessWrapper;
        if (onConnectSuccessWrapper != null) {
            onConnectSuccessWrapper.reset();
        }
        OnConnectFailWrapper onConnectFailWrapper = this.onConnectFailWrapper;
        if (onConnectFailWrapper != null) {
            onConnectFailWrapper.reset();
        }
        synchronized (this) {
            for (AckWrapper ack : this.ackWrapperMap.values()) {
                ack.reset();
            }
            this.ackWrapperMap.clear();
        }
    }
}
