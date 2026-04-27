package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
public class H264Config {
    private boolean forceHighProfile4Camera;
    private boolean forceHighProfile4Screen;
    private boolean forceSWDecoder;
    private boolean forceSWEncoder;
    private boolean forceSWEncoderScreen;
    private boolean hwFallbackCB;
    private boolean supportCHP;

    public H264Config(boolean forceHighProfile4Camera, boolean forceHighProfile4Screen, boolean forceSWEncoder, boolean forceSWDecoder, boolean supportCHP, boolean hwFallbackCB, boolean forceSWEncoderScreen) {
        this.forceHighProfile4Camera = forceHighProfile4Camera;
        this.forceHighProfile4Screen = forceHighProfile4Screen;
        this.forceSWEncoder = forceSWEncoder;
        this.forceSWDecoder = forceSWDecoder;
        this.supportCHP = supportCHP;
        this.hwFallbackCB = hwFallbackCB;
        this.forceSWEncoderScreen = forceSWEncoderScreen;
    }

    public boolean forceHighProfileForCamera() {
        return this.forceHighProfile4Camera;
    }

    public boolean forceHighProfileForScreen() {
        return this.forceHighProfile4Screen;
    }

    public boolean forceSWEncoder() {
        return this.forceSWEncoder;
    }

    public boolean forceSWDecoder() {
        return this.forceSWDecoder;
    }

    public boolean supportCHP() {
        return this.supportCHP;
    }

    public boolean hwFallbackCB() {
        return this.hwFallbackCB;
    }

    public boolean forceSWEncoderScreen() {
        return this.forceSWEncoderScreen;
    }

    static H264Config create(boolean forceHighProfile4Camera, boolean forceHighProfile4Screen, boolean forceSWEncoder, boolean forceSWDecoder, boolean supportCHP, boolean hwFallbackCB, boolean forceSWEncoderScreen) {
        return new H264Config(forceHighProfile4Camera, forceHighProfile4Screen, forceSWEncoder, forceSWDecoder, supportCHP, hwFallbackCB, forceSWEncoderScreen);
    }
}
