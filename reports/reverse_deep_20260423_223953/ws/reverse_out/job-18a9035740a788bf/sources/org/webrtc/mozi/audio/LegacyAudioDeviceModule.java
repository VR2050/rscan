package org.webrtc.mozi.audio;

/* JADX INFO: loaded from: classes3.dex */
@Deprecated
public class LegacyAudioDeviceModule implements AudioDeviceModule {
    @Override // org.webrtc.mozi.audio.AudioDeviceModule
    public long getNativeAudioDeviceModulePointer() {
        return 0L;
    }

    @Override // org.webrtc.mozi.audio.AudioDeviceModule
    public void release() {
    }

    @Override // org.webrtc.mozi.audio.AudioDeviceModule
    public void setSpeakerMute(boolean mute) {
        org.webrtc.mozi.voiceengine.WebRtcAudioTrack.setSpeakerMute(mute);
    }

    @Override // org.webrtc.mozi.audio.AudioDeviceModule
    public void setMicrophoneMute(boolean mute) {
        org.webrtc.mozi.voiceengine.WebRtcAudioRecord.setMicrophoneMute(mute);
    }
}
