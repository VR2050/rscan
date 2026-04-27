package com.ding.rtc;

/* JADX INFO: loaded from: classes.dex */
public class DingRtcAuthInfo {
    public String appId;
    public String channelId;
    public String gslbServer;
    public String token;
    public String userId;

    public String getChannelId() {
        return this.channelId;
    }

    public String getUserId() {
        return this.userId;
    }

    public String getToken() {
        return this.token;
    }

    public String getAppId() {
        return this.appId;
    }

    public String getGslbServer() {
        return this.gslbServer;
    }

    public String toString() {
        return "DingRtcAuthInfo{, channelId='" + this.channelId + "', userId='" + this.userId + "', token='" + this.token + "', appId='" + this.appId + "', gslbServer='" + this.gslbServer + '}';
    }
}
