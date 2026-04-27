package com.ding.rtc;

import java.util.List;

/* JADX INFO: loaded from: classes.dex */
class PrivateRtcModelIceServer {
    public String password;
    public List<String> urls;
    public String username;

    PrivateRtcModelIceServer() {
    }

    public List<String> getIceUrls() {
        return this.urls;
    }

    public String getIceUserName() {
        return this.username;
    }

    public String getIcePassword() {
        return this.password;
    }
}
