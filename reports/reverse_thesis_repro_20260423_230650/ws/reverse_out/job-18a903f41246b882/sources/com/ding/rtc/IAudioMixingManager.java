package com.ding.rtc;

import com.ding.rtc.DingRtcEngine;

/* JADX INFO: loaded from: classes.dex */
public interface IAudioMixingManager {
    int createAudioMixing(int id, String filePath);

    int destroyAudioMixing(int id);

    long getAudioMixingCurrentPosition(int id);

    long getAudioMixingDuration(int id);

    int getAudioMixingPlayoutVolume(int id);

    int getAudioMixingPublishVolume(int id);

    int getAudioMixingVolume(int id);

    int pauseAudioMixing(int id);

    int resumeAudioMixing(int id);

    int setAudioMixingPlayoutVolume(int id, int volume);

    int setAudioMixingPosition(int id, long position);

    int setAudioMixingPublishVolume(int id, int volume);

    int setAudioMixingVolume(int id, int volume);

    int startAudioMixing(int id, DingRtcEngine.DingRtcAudioMixingConfig config);

    int stopAudioMixing(int id);
}
