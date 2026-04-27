package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
public class EndToEndDelayConfig {
    private boolean enable;

    public EndToEndDelayConfig(boolean enable) {
        this.enable = enable;
    }

    public boolean isEnabled() {
        return this.enable;
    }

    static EndToEndDelayConfig create(boolean enable) {
        return new EndToEndDelayConfig(enable);
    }
}
