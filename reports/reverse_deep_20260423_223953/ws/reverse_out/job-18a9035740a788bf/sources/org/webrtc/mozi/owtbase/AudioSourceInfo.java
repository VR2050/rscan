package org.webrtc.mozi.owtbase;

/* JADX INFO: loaded from: classes3.dex */
public enum AudioSourceInfo {
    kMic(1),
    kScreenCast(2),
    kFile(3),
    kMixed(4),
    kUnknown(5);

    private int mIntValue;

    AudioSourceInfo(int intValue) {
        this.mIntValue = intValue;
    }

    public int intValue() {
        return this.mIntValue;
    }
}
