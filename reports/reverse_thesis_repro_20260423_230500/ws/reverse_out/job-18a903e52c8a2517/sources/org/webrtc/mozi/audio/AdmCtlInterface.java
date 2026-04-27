package org.webrtc.mozi.audio;

/* JADX INFO: loaded from: classes3.dex */
public interface AdmCtlInterface {
    long init();

    boolean playing();

    boolean recording();

    void release();

    int startPlayout();

    int startRecording();

    int stopPlayout();

    int stopRecording();
}
