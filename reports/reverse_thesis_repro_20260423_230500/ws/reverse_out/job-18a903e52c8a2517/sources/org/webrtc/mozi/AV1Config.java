package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
public class AV1Config {
    private boolean asymmetricCodecs;
    private float cameraBitrateRatio;
    private boolean enableCamera;
    private boolean enableDecode;
    private boolean enableScreen;
    private final long mcsConfigPtr;
    private float screenBitrateRatio;

    private native void nativeVerifyOnePC(long j, boolean z);

    public AV1Config(boolean asymmetricCodecs, boolean enableCamera, boolean enableScreen, boolean enableDecode, float cameraBitrateRatio, float screenBitrateRatio, long mcsConfigPtr) {
        this.asymmetricCodecs = asymmetricCodecs;
        this.enableCamera = enableCamera;
        this.enableScreen = enableScreen;
        this.enableDecode = enableDecode;
        this.cameraBitrateRatio = cameraBitrateRatio;
        this.screenBitrateRatio = screenBitrateRatio;
        this.mcsConfigPtr = mcsConfigPtr;
    }

    public boolean isAsymmetricCodecs() {
        return this.asymmetricCodecs;
    }

    public boolean isEnableCamera() {
        return this.enableCamera;
    }

    public boolean isEnableScreen() {
        return this.enableScreen;
    }

    public boolean isEnableDecode() {
        return this.enableDecode;
    }

    public float getCameraBitrateRatio() {
        return this.cameraBitrateRatio;
    }

    public float getScreenBitrateRatio() {
        return this.screenBitrateRatio;
    }

    public void VerifyOnePC(boolean isOnePcEnabled) {
        if (!isOnePcEnabled) {
            this.asymmetricCodecs = false;
            this.enableDecode = false;
            this.enableCamera = false;
            this.enableScreen = false;
        }
        nativeVerifyOnePC(this.mcsConfigPtr, isOnePcEnabled);
    }

    public boolean isAV1ConfigEnabled() {
        return this.enableDecode || this.enableCamera || this.enableScreen;
    }

    static AV1Config create(boolean asymmetricCodecs, boolean enableCamera, boolean enableScreen, boolean enableDecode, float cameraBitrateRatio, float screenBitrateRatio, long mcsConfigPtr) {
        return new AV1Config(asymmetricCodecs, enableCamera, enableScreen, enableDecode, cameraBitrateRatio, screenBitrateRatio, mcsConfigPtr);
    }
}
