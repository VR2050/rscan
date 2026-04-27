package com.ding.rtc;

import java.util.List;

/* JADX INFO: loaded from: classes.dex */
interface PrivateRtcModelEngineListener {
    void onActiveAudioInputChange(List<String> participantIds);

    void onActiveVideoInputChanged(String participantId);

    void onChannelLeft(int reason);

    void onConnectionStatusChanged(int status, int reason);

    void onMcsEvent(PrivateRtcModelMcsEvent event);

    void onMediaTrackAdded(PrivateRtcModelTrack track);

    void onParticipantJoined(PrivateRtcModelParticipant participant);
}
