package org.webrtc.mozi.audio;

import org.webrtc.mozi.JniCommon;

/* JADX INFO: loaded from: classes3.dex */
public class AdmCtl implements AdmCtlInterface {
    private long nativeAdmCtl;
    private final Object nativeLock;

    private static native long nativeCreateAdmCtl();

    private static native boolean nativePlaying(long j);

    private static native boolean nativeRecording(long j);

    private static native int nativeStartPlayout(long j);

    private static native int nativeStartRecording(long j);

    private static native int nativeStopPlayout(long j);

    private static native int nativeStopRecording(long j);

    public static AdmCtl getInstance() {
        return SingleInstanceHolder.INSTANCE;
    }

    private static final class SingleInstanceHolder {
        private static final AdmCtl INSTANCE = new AdmCtl();

        private SingleInstanceHolder() {
        }
    }

    private AdmCtl() {
        this.nativeLock = new Object();
    }

    @Override // org.webrtc.mozi.audio.AdmCtlInterface
    public long init() {
        long j;
        synchronized (this.nativeLock) {
            if (this.nativeAdmCtl == 0) {
                this.nativeAdmCtl = nativeCreateAdmCtl();
            }
            j = this.nativeAdmCtl;
        }
        return j;
    }

    @Override // org.webrtc.mozi.audio.AdmCtlInterface
    public void release() {
        synchronized (this.nativeLock) {
            if (this.nativeAdmCtl != 0) {
                JniCommon.nativeReleaseRef(this.nativeAdmCtl);
                this.nativeAdmCtl = 0L;
            }
        }
    }

    @Override // org.webrtc.mozi.audio.AdmCtlInterface
    public int startPlayout() {
        long j = this.nativeAdmCtl;
        if (j > 0) {
            return nativeStartPlayout(j);
        }
        return -1;
    }

    @Override // org.webrtc.mozi.audio.AdmCtlInterface
    public int stopPlayout() {
        long j = this.nativeAdmCtl;
        if (j > 0) {
            return nativeStopPlayout(j);
        }
        return -1;
    }

    @Override // org.webrtc.mozi.audio.AdmCtlInterface
    public boolean playing() {
        long j = this.nativeAdmCtl;
        if (j > 0) {
            return nativePlaying(j);
        }
        return false;
    }

    @Override // org.webrtc.mozi.audio.AdmCtlInterface
    public int startRecording() {
        long j = this.nativeAdmCtl;
        if (j > 0) {
            return nativeStartRecording(j);
        }
        return -1;
    }

    @Override // org.webrtc.mozi.audio.AdmCtlInterface
    public int stopRecording() {
        long j = this.nativeAdmCtl;
        if (j > 0) {
            return nativeStopRecording(j);
        }
        return -1;
    }

    @Override // org.webrtc.mozi.audio.AdmCtlInterface
    public boolean recording() {
        long j = this.nativeAdmCtl;
        if (j > 0) {
            return nativeRecording(j);
        }
        return false;
    }
}
