package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
public class MediaCodecLevelConfig {
    private boolean enable;
    private int h264Level;
    private boolean useSpecific;

    public MediaCodecLevelConfig(boolean enable, boolean useSpecific, int h264Level) {
        this.enable = false;
        this.useSpecific = false;
        this.h264Level = 4096;
        this.enable = enable;
        this.useSpecific = useSpecific;
        this.h264Level = h264Level;
    }

    public boolean enable() {
        return this.enable;
    }

    public boolean useSpecific() {
        return this.useSpecific;
    }

    public int getH264Level() {
        return this.h264Level;
    }

    static MediaCodecLevelConfig create(boolean enable, boolean useSpecific, int h264Level) {
        return new MediaCodecLevelConfig(enable, useSpecific, h264Level);
    }
}
