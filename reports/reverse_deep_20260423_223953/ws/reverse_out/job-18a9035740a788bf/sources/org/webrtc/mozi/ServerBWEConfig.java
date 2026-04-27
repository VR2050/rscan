package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
public class ServerBWEConfig {
    private boolean enablePccLossDetect;

    public ServerBWEConfig(boolean enablePccLossDetect) {
        this.enablePccLossDetect = enablePccLossDetect;
    }

    public boolean isEnablePccLossDetect() {
        return this.enablePccLossDetect;
    }

    static ServerBWEConfig create(boolean enablePccLossDetect) {
        return new ServerBWEConfig(enablePccLossDetect);
    }
}
