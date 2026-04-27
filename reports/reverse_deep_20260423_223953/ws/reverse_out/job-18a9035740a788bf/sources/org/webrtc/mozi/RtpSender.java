package org.webrtc.mozi;

import javax.annotation.Nullable;

/* JADX INFO: loaded from: classes3.dex */
public class RtpSender {

    @Nullable
    private MediaStreamTrack cachedTrack;

    @Nullable
    private final DtmfSender dtmfSender;
    final long nativeRtpSender;
    protected boolean disposed = false;
    protected final Object disposeLock = new Object();
    private boolean ownsTrack = true;

    private static native long nativeGetDtmfSender(long j);

    private static native String nativeGetId(long j);

    private static native RtpParameters nativeGetParameters(long j);

    private static native long nativeGetTrack(long j);

    private static native boolean nativeSetParameters(long j, RtpParameters rtpParameters);

    private static native boolean nativeSetTrack(long j, long j2);

    public RtpSender(long nativeRtpSender) {
        this.nativeRtpSender = nativeRtpSender;
        long nativeTrack = nativeGetTrack(nativeRtpSender);
        this.cachedTrack = MediaStreamTrack.createMediaStreamTrack(nativeTrack);
        long nativeDtmfSender = nativeGetDtmfSender(nativeRtpSender);
        this.dtmfSender = nativeDtmfSender != 0 ? new DtmfSender(nativeDtmfSender) : null;
    }

    public boolean setTrack(@Nullable MediaStreamTrack track, boolean takeOwnership) {
        if (!nativeSetTrack(this.nativeRtpSender, track == null ? 0L : track.nativeTrack)) {
            return false;
        }
        MediaStreamTrack mediaStreamTrack = this.cachedTrack;
        if (mediaStreamTrack != null && this.ownsTrack) {
            mediaStreamTrack.dispose();
        }
        this.cachedTrack = track;
        this.ownsTrack = takeOwnership;
        return true;
    }

    @Nullable
    public MediaStreamTrack track() {
        return this.cachedTrack;
    }

    public boolean setParameters(RtpParameters parameters) {
        return nativeSetParameters(this.nativeRtpSender, parameters);
    }

    public RtpParameters getParameters() {
        return nativeGetParameters(this.nativeRtpSender);
    }

    public String id() {
        return nativeGetId(this.nativeRtpSender);
    }

    @Nullable
    public DtmfSender dtmf() {
        return this.dtmfSender;
    }

    public void dispose() {
        synchronized (this.disposeLock) {
            this.disposed = true;
        }
        DtmfSender dtmfSender = this.dtmfSender;
        if (dtmfSender != null) {
            dtmfSender.dispose();
        }
        MediaStreamTrack mediaStreamTrack = this.cachedTrack;
        if (mediaStreamTrack != null && this.ownsTrack) {
            mediaStreamTrack.dispose();
        }
        JniCommon.nativeReleaseRef(this.nativeRtpSender);
    }

    public boolean disposed() {
        boolean z;
        synchronized (this.disposeLock) {
            z = this.disposed;
        }
        return z;
    }
}
