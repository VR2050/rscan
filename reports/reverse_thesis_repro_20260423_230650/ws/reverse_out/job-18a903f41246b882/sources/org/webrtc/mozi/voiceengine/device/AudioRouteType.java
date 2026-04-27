package org.webrtc.mozi.voiceengine.device;

/* JADX INFO: loaded from: classes3.dex */
public enum AudioRouteType {
    None(0),
    Speakerphone(1),
    Earpiece(2),
    WiredHeadset(3),
    Bluetooth(4),
    A2dp(5);

    private final int value;

    AudioRouteType(int value) {
        this.value = value;
    }

    public int getValue() {
        return this.value;
    }
}
