package com.ding.rtc;

/* JADX INFO: loaded from: classes.dex */
interface PrivateRtcModelEngineAudioMgrListener {
    void onAudioDefaultDeviceChanged(int type, String deviceId);

    void onAudioDeviceChanged(int type, String deviceId, int state);

    void onAudioDeviceException(int type, String deviceId, String deviceName);

    void onAudioLevel(int level);

    void onAudioLoopbackMute(boolean mute);

    void onAudioLoopbackVol(int vol);

    void onAudioMicMute(boolean mute);

    void onAudioMicVol(int vol);

    void onAudioPlayEnded(int id);

    void onAudioSpeakerMute(boolean mute);

    void onAudioSpeakerVol(int vol);
}
