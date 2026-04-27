package org.webrtc.mozi.p2p;

/* JADX INFO: loaded from: classes3.dex */
public class Peer {
    public String did;
    public String domain;
    public String nick;
    public String ua;
    public String uid;

    public Peer() {
    }

    public Peer(String uid, String domain, String nick, String did, String ua) {
        this.uid = uid;
        this.domain = domain;
        this.nick = nick;
        this.did = did;
        this.ua = ua;
    }

    public String getUid() {
        return this.uid;
    }

    public String getDomain() {
        return this.domain;
    }

    public String getNick() {
        return this.nick;
    }

    public String getDid() {
        return this.did;
    }

    public String getUa() {
        return this.ua;
    }
}
