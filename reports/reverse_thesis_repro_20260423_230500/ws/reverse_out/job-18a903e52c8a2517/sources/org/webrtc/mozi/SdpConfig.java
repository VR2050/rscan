package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
public class SdpConfig {
    private final boolean useHwDecodeCaps;

    public SdpConfig(boolean useHwDecodeCaps) {
        this.useHwDecodeCaps = useHwDecodeCaps;
    }

    public boolean useHwDecodeCaps() {
        return this.useHwDecodeCaps;
    }

    static SdpConfig create(boolean useHwDecodeCaps) {
        return new SdpConfig(useHwDecodeCaps);
    }
}
