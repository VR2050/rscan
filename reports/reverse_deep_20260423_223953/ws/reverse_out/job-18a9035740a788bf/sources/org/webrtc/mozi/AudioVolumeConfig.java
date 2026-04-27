package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
public class AudioVolumeConfig {
    private final long audioVolumeIndicationIntervalMs;

    public AudioVolumeConfig(long audioVolumeIndicationIntervalMs) {
        this.audioVolumeIndicationIntervalMs = audioVolumeIndicationIntervalMs;
    }

    public long getAudioVolumeIndicationIntervalMs() {
        return this.audioVolumeIndicationIntervalMs;
    }

    static AudioVolumeConfig create(long audioVolumeIndicationIntervalMs) {
        return new AudioVolumeConfig(audioVolumeIndicationIntervalMs);
    }
}
