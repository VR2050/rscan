package org.webrtc.alirtcInterface;

/* JADX INFO: loaded from: classes3.dex */
public class AliSubscriberInfo {
    public String session;
    public String stream_type;
    public String user_id;

    public String getUser_id() {
        return this.user_id;
    }

    public void setUser_id(String user_id) {
        this.user_id = user_id;
    }

    public String getSession() {
        return this.session;
    }

    public void setSession(String session) {
        this.session = session;
    }

    public String getStream_type() {
        return this.stream_type;
    }

    public void setStream_type(String stream_type) {
        this.stream_type = stream_type;
    }
}
