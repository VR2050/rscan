package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
public class ProxyInfo {
    public static final String TYPE_HTTPS = "https";
    public static final String TYPE_SOCKS5 = "socks5";
    public final String address;
    public final String password;
    public final int port;
    public final String type;
    public final String user;

    public ProxyInfo(String type, String address, int port, String user, String passwd) {
        this.type = type;
        this.address = address;
        this.port = port;
        this.user = user;
        this.password = passwd;
    }

    public String getType() {
        return this.type;
    }

    public String getAddress() {
        return this.address;
    }

    public int getPort() {
        return this.port;
    }

    public String getUser() {
        return this.user;
    }

    public String getPassword() {
        return this.password;
    }

    public boolean isValid() {
        String str;
        String str2 = this.type;
        return (str2 == null || str2.isEmpty() || (str = this.address) == null || str.isEmpty() || this.port == 0) ? false : true;
    }
}
