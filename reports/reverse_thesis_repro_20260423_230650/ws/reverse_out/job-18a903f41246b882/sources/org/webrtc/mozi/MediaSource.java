package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
public class MediaSource {
    final long nativeSource;

    private static native State nativeGetState(long j);

    public enum State {
        INITIALIZING,
        LIVE,
        ENDED,
        MUTED;

        static State fromNativeIndex(int nativeIndex) {
            return values()[nativeIndex];
        }
    }

    public MediaSource(long nativeSource) {
        this.nativeSource = nativeSource;
    }

    public State state() {
        return nativeGetState(this.nativeSource);
    }

    public void dispose() {
        JniCommon.nativeReleaseRef(this.nativeSource);
    }
}
