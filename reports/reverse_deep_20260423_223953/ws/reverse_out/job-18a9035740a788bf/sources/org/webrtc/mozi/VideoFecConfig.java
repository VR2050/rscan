package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
public class VideoFecConfig {
    private final boolean enableFec;

    public VideoFecConfig(boolean enableFec) {
        this.enableFec = enableFec;
    }

    public boolean isEnableFec() {
        return this.enableFec;
    }

    static VideoFecConfig create(boolean enableFec) {
        return new VideoFecConfig(enableFec);
    }
}
