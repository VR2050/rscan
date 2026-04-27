package org.webrtc.mozi.p2p;

import java.util.Map;

/* JADX INFO: loaded from: classes3.dex */
public class P2pSignaling {
    public String bizType;
    public String callId;
    public String callType;
    public int cseq;
    public Peer from;
    public String method;
    public Map<String, String> optionalFields;
    public int reasonCode;
    public String route;
    public int statusCode;
    public String statusMsg;
    public Peer to;
    public String type;

    public P2pSignaling() {
    }

    public P2pSignaling(String type, String method, int statusCode, String statusMsg, String callId, int cseq, Peer from, Peer to, String route, String callType, String bizType, int reasonCode, Map<String, String> optionalFields) {
        this.type = type;
        this.method = method;
        this.statusCode = statusCode;
        this.statusMsg = statusMsg;
        this.callId = callId;
        this.cseq = cseq;
        this.from = from;
        this.to = to;
        this.route = route;
        this.callType = callType;
        this.bizType = bizType;
        this.reasonCode = reasonCode;
        this.optionalFields = optionalFields;
    }

    public String getType() {
        return this.type;
    }

    public String getMethod() {
        return this.method;
    }

    public int getStatusCode() {
        return this.statusCode;
    }

    public String getStatusMsg() {
        return this.statusMsg;
    }

    public String getCallId() {
        return this.callId;
    }

    public int getCseq() {
        return this.cseq;
    }

    public Peer getFrom() {
        return this.from;
    }

    public Peer getTo() {
        return this.to;
    }

    public String getRoute() {
        return this.route;
    }

    public String getCallType() {
        return this.callType;
    }

    public String getBizType() {
        return this.bizType;
    }

    public int getReasonCode() {
        return this.reasonCode;
    }

    public Map getOptionalFields() {
        return this.optionalFields;
    }
}
