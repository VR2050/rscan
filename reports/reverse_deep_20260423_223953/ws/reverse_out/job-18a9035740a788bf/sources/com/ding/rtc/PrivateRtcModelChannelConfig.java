package com.ding.rtc;

import java.util.List;

/* JADX INFO: loaded from: classes.dex */
class PrivateRtcModelChannelConfig {
    public String appId;
    public String channelId;
    public String gslbServer;
    public List<PrivateRtcModelIceServer> iceServers;
    public String proxyAddress;
    public String proxyPassword;
    public String proxyType;
    public String proxyUsername;
    public String roleInfo;
    public String token;
    public String userId;
    public String userName;
    public int candidateNetworkPolicy = 1;
    public int iceTransportsType = 1;
    public boolean downgradeSsl = false;
    short proxyPort = 0;

    PrivateRtcModelChannelConfig() {
    }

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

    public String getUserName() {
        return this.userName;
    }

    public String getRoleInfo() {
        return this.roleInfo;
    }

    public List<PrivateRtcModelIceServer> getIceServers() {
        return this.iceServers;
    }

    public int getCandidateNetworkPolicy() {
        return this.candidateNetworkPolicy;
    }

    public int getIceTransportsType() {
        return this.iceTransportsType;
    }

    public boolean getDowngradeSsl() {
        return this.downgradeSsl;
    }

    public String getProxyType() {
        return this.proxyType;
    }

    public String getProxyAddress() {
        return this.proxyAddress;
    }

    public int getProxyPort() {
        return this.proxyPort;
    }

    public String getProxyUsername() {
        return this.proxyUsername;
    }

    public String getProxyPassword() {
        return this.proxyPassword;
    }

    public String toString() {
        return "PrivateRtcModelChannelConfig{channelId='" + this.channelId + "', userId='" + this.userId + "', appId='" + this.appId + "', token='" + this.token + "', gslbServer='" + this.gslbServer + "', userName='" + this.userName + "', roleInfo='" + this.roleInfo + "', iceServers=" + this.iceServers + ", candidateNetworkPolicy=" + this.candidateNetworkPolicy + ", iceTransportsType=" + this.iceTransportsType + ", downgradeSsl=" + this.downgradeSsl + ", proxyType='" + this.proxyType + "', proxyAddress='" + this.proxyAddress + "', proxyPort=" + ((int) this.proxyPort) + ", proxyUsername='" + this.proxyUsername + "', ProxyPassword='" + this.proxyPassword + "'}";
    }
}
