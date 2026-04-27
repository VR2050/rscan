package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
public class SessionDescriptionParser {
    private native SdpStatsIndex nativeParseSessionDescription(String str, String str2, boolean z);

    public SdpStatsIndex parseSessionDescription(String type, String sdp) {
        return nativeParseSessionDescription(type, sdp, false);
    }

    public SdpStatsIndex parseSessionDescriptionWithStreamDetail(String type, String sdp) {
        return nativeParseSessionDescription(type, sdp, true);
    }
}
