package org.webrtc.mozi;

import javax.annotation.Nullable;
import org.webrtc.mozi.MediaStreamTrack;

/* JADX INFO: loaded from: classes3.dex */
public class RtpReceiver {

    @Nullable
    private MediaStreamTrack cachedTrack;
    private long nativeObserver;
    final long nativeRtpReceiver;

    public interface Observer {
        void onFirstPacketReceived(MediaStreamTrack.MediaType mediaType);
    }

    private static native String nativeGetId(long j);

    private static native RtpParameters nativeGetParameters(long j);

    private static native long nativeGetTrack(long j);

    private static native long nativeSetObserver(long j, Observer observer);

    private static native boolean nativeSetParameters(long j, RtpParameters rtpParameters);

    private static native void nativeUnsetObserver(long j, long j2);

    public RtpReceiver(long nativeRtpReceiver) {
        this.nativeRtpReceiver = nativeRtpReceiver;
        long nativeTrack = nativeGetTrack(nativeRtpReceiver);
        this.cachedTrack = MediaStreamTrack.createMediaStreamTrack(nativeTrack);
    }

    @Nullable
    public MediaStreamTrack track() {
        return this.cachedTrack;
    }

    public boolean setParameters(@Nullable RtpParameters parameters) {
        if (parameters == null) {
            return false;
        }
        return nativeSetParameters(this.nativeRtpReceiver, parameters);
    }

    public RtpParameters getParameters() {
        return nativeGetParameters(this.nativeRtpReceiver);
    }

    public String id() {
        return nativeGetId(this.nativeRtpReceiver);
    }

    public void dispose() {
        this.cachedTrack.dispose();
        long j = this.nativeObserver;
        if (j != 0) {
            nativeUnsetObserver(this.nativeRtpReceiver, j);
            this.nativeObserver = 0L;
        }
        JniCommon.nativeReleaseRef(this.nativeRtpReceiver);
    }

    public void SetObserver(Observer observer) {
        long j = this.nativeObserver;
        if (j != 0) {
            nativeUnsetObserver(this.nativeRtpReceiver, j);
        }
        this.nativeObserver = nativeSetObserver(this.nativeRtpReceiver, observer);
    }
}
