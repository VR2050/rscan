package org.webrtc.mozi.voiceengine.device;

/* JADX INFO: loaded from: classes3.dex */
public interface AudioDeviceListener {
    void onAudioDeviceAvailable(AbstractAudioDevice abstractAudioDevice);

    void onAudioDeviceChange(AbstractAudioDevice abstractAudioDevice);

    void onAudioDeviceUnavailable(AbstractAudioDevice abstractAudioDevice);
}
