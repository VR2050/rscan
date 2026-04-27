package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
public class VideoCodecConfig {
    private boolean enableDecodeMaxResCheck;
    private boolean enableGetCodecProfiles;
    private int encoderAlignment;
    private boolean fixAlignDrawer;
    private boolean fixAlignDrawerBlack;
    private boolean fixMCCrash;
    private boolean fixTextureAlignment;

    public VideoCodecConfig(int encoderAlignment, boolean fixMCCrash, boolean enableGetCodecProfiles, boolean fixTextureAlignment, boolean enableDecodeMaxResCheck, boolean fixAlignDrawer, boolean fixAlignDrawerBlack) {
        this.encoderAlignment = encoderAlignment;
        this.fixMCCrash = fixMCCrash;
        this.enableGetCodecProfiles = enableGetCodecProfiles;
        this.fixTextureAlignment = fixTextureAlignment;
        this.enableDecodeMaxResCheck = enableDecodeMaxResCheck;
        this.fixAlignDrawer = fixAlignDrawer;
        this.fixAlignDrawerBlack = fixAlignDrawerBlack;
    }

    public int getEncoderAlignment() {
        return this.encoderAlignment;
    }

    public boolean isFixMCCrashEnabled() {
        return this.fixMCCrash;
    }

    public boolean isEnableGetCodecProfiles() {
        return this.enableGetCodecProfiles;
    }

    public boolean isFixTextureAlignmentEnabled() {
        return this.fixTextureAlignment;
    }

    public boolean isEnableDecodeMaxResCheck() {
        return this.enableDecodeMaxResCheck;
    }

    public boolean isFixAlignDrawer() {
        return this.fixAlignDrawer;
    }

    public boolean isFixAlignDrawerBlack() {
        return this.fixAlignDrawerBlack;
    }

    static VideoCodecConfig create(int encoderAlignment, boolean fixMCCrash, boolean enableGetCodecProfiles, boolean fixTextureAlignment, boolean enableDecodeMaxResCheck, boolean fixAlignDrawer, boolean fixAlignDrawerBlack) {
        return new VideoCodecConfig(encoderAlignment, fixMCCrash, enableGetCodecProfiles, fixTextureAlignment, enableDecodeMaxResCheck, fixAlignDrawer, fixAlignDrawerBlack);
    }
}
