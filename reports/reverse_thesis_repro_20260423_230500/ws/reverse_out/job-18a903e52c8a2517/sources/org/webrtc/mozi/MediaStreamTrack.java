package org.webrtc.mozi;

import javax.annotation.Nullable;

/* JADX INFO: loaded from: classes3.dex */
public class MediaStreamTrack {
    public static final String AUDIO_TRACK_KIND = "audio";
    public static final String VIDEO_TRACK_KIND = "video";
    final long nativeTrack;

    private static native boolean nativeGetEnabled(long j);

    private static native String nativeGetId(long j);

    private static native String nativeGetKind(long j);

    private static native State nativeGetState(long j);

    private static native boolean nativeSetEnabled(long j, boolean z);

    public enum State {
        LIVE,
        ENDED;

        static State fromNativeIndex(int nativeIndex) {
            return values()[nativeIndex];
        }
    }

    public enum MediaType {
        MEDIA_TYPE_AUDIO(0),
        MEDIA_TYPE_VIDEO(1);

        private final int nativeIndex;

        MediaType(int nativeIndex) {
            this.nativeIndex = nativeIndex;
        }

        int getNative() {
            return this.nativeIndex;
        }

        static MediaType fromNativeIndex(int nativeIndex) {
            for (MediaType type : values()) {
                if (type.getNative() == nativeIndex) {
                    return type;
                }
            }
            throw new IllegalArgumentException("Unknown native media type: " + nativeIndex);
        }
    }

    @Nullable
    static MediaStreamTrack createMediaStreamTrack(long nativeTrack) {
        if (nativeTrack == 0) {
            return null;
        }
        String trackKind = nativeGetKind(nativeTrack);
        if (trackKind.equals("audio")) {
            return new AudioTrack(nativeTrack);
        }
        if (!trackKind.equals("video")) {
            return null;
        }
        return new VideoTrack(nativeTrack);
    }

    public MediaStreamTrack(long nativeTrack) {
        this.nativeTrack = nativeTrack;
    }

    public String id() {
        return nativeGetId(this.nativeTrack);
    }

    public String kind() {
        return nativeGetKind(this.nativeTrack);
    }

    public boolean enabled() {
        return nativeGetEnabled(this.nativeTrack);
    }

    public boolean setEnabled(boolean enable) {
        return nativeSetEnabled(this.nativeTrack, enable);
    }

    public State state() {
        return nativeGetState(this.nativeTrack);
    }

    public void dispose() {
        JniCommon.nativeReleaseRef(this.nativeTrack);
    }
}
