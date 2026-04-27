package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
public class OneRTCAudioConfig {
    private final boolean audioDeviceManagerAndroid;
    private final boolean enableAudioRouteOpt;
    private final boolean enableGeneralAudioOpt;

    public OneRTCAudioConfig(boolean audioDeviceManagerAndroid, boolean enableGeneralAudioOpt, boolean enableAudioRouteOpt) {
        this.audioDeviceManagerAndroid = audioDeviceManagerAndroid;
        this.enableGeneralAudioOpt = enableGeneralAudioOpt;
        this.enableAudioRouteOpt = enableAudioRouteOpt;
    }

    public boolean getAudioDeviceManagerAndroid() {
        return this.audioDeviceManagerAndroid;
    }

    public boolean getGeneralAudioOpt() {
        return this.enableGeneralAudioOpt;
    }

    public boolean getAudioRouteOpt() {
        return this.enableAudioRouteOpt;
    }

    static OneRTCAudioConfig create(boolean audioDeviceManagerAndroid, boolean enableGeneralAudioOpt, boolean enableAudioRouteOpt) {
        return new OneRTCAudioConfig(audioDeviceManagerAndroid, enableGeneralAudioOpt, enableAudioRouteOpt);
    }
}
