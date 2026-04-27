package org.webrtc.mozi;

import com.king.zxing.util.LogUtils;

/* JADX INFO: loaded from: classes3.dex */
public class IceCandidate {
    public final String sdp;
    public final int sdpMLineIndex;
    public final String sdpMid;
    public final String serverUrl;

    public IceCandidate(String sdpMid, int sdpMLineIndex, String sdp) {
        this.sdpMid = sdpMid;
        this.sdpMLineIndex = sdpMLineIndex;
        this.sdp = sdp;
        this.serverUrl = "";
    }

    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof IceCandidate)) {
            return false;
        }
        IceCandidate other = (IceCandidate) obj;
        return other.sdpMid.equals(this.sdpMid) && other.sdpMLineIndex == this.sdpMLineIndex && other.sdp.equals(this.sdp) && other.serverUrl.equals(this.serverUrl) && other.sdpMLineIndex == this.sdpMLineIndex;
    }

    IceCandidate(String sdpMid, int sdpMLineIndex, String sdp, String serverUrl) {
        this.sdpMid = sdpMid;
        this.sdpMLineIndex = sdpMLineIndex;
        this.sdp = sdp;
        this.serverUrl = serverUrl;
    }

    public String toString() {
        return this.sdpMid + LogUtils.COLON + this.sdpMLineIndex + LogUtils.COLON + this.sdp + LogUtils.COLON + this.serverUrl;
    }

    String getSdpMid() {
        return this.sdpMid;
    }

    String getSdp() {
        return this.sdp;
    }
}
