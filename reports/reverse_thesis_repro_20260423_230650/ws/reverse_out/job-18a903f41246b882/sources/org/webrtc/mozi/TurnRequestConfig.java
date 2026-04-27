package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
public class TurnRequestConfig {
    private final boolean enable;

    public TurnRequestConfig(boolean enable) {
        this.enable = enable;
    }

    public boolean isEnabled() {
        return this.enable;
    }

    static TurnRequestConfig create(boolean enable) {
        return new TurnRequestConfig(enable);
    }
}
