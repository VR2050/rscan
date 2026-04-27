package com.bjz.comm.net.bean;

import java.io.Serializable;

/* JADX INFO: loaded from: classes4.dex */
public class RefreshUserFCStateBean implements Serializable {
    private String Version;

    public String getVersion() {
        return this.Version;
    }

    public void setVersion(String version) {
        this.Version = version;
    }

    public String toString() {
        return "RefreshUserFCStateBean{Version='" + this.Version + "'}";
    }
}
