package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
public class NetInterfaceInfo {
    public long handle;
    public String name;

    public NetInterfaceInfo() {
        this.handle = 0L;
        this.name = "default";
    }

    public NetInterfaceInfo(Long handle, String name) {
        this.handle = handle.longValue();
        this.name = name;
    }
}
