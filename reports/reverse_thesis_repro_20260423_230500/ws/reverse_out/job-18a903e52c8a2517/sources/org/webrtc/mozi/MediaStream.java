package org.webrtc.mozi;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/* JADX INFO: loaded from: classes3.dex */
public class MediaStream {
    private static final String TAG = "MediaStream";
    final long nativeStream;
    public final List<AudioTrack> audioTracks = new ArrayList();
    public final List<VideoTrack> videoTracks = new ArrayList();
    public final List<VideoTrack> preservedVideoTracks = new ArrayList();
    private volatile boolean isValid = true;

    private static native boolean nativeAddAudioTrackToNativeStream(long j, long j2);

    private static native boolean nativeAddVideoTrackToNativeStream(long j, long j2);

    private static native String nativeGetId(long j);

    private static native boolean nativeRemoveAudioTrack(long j, long j2);

    private static native boolean nativeRemoveVideoTrack(long j, long j2);

    public MediaStream(long nativeStream) {
        this.nativeStream = nativeStream;
    }

    public void setValid(boolean isValid) {
        this.isValid = isValid;
    }

    public boolean isValid() {
        return this.isValid;
    }

    public boolean addTrack(AudioTrack track) {
        if (nativeAddAudioTrackToNativeStream(this.nativeStream, track.nativeTrack)) {
            this.audioTracks.add(track);
            return true;
        }
        return false;
    }

    public boolean addTrack(VideoTrack track) {
        if (nativeAddVideoTrackToNativeStream(this.nativeStream, track.nativeTrack)) {
            this.videoTracks.add(track);
            return true;
        }
        return false;
    }

    public boolean addPreservedTrack(VideoTrack track) {
        if (nativeAddVideoTrackToNativeStream(this.nativeStream, track.nativeTrack)) {
            this.preservedVideoTracks.add(track);
            return true;
        }
        return false;
    }

    public boolean removeTrack(AudioTrack track) {
        this.audioTracks.remove(track);
        return nativeRemoveAudioTrack(this.nativeStream, track.nativeTrack);
    }

    public boolean removeTrack(VideoTrack track) {
        this.videoTracks.remove(track);
        this.preservedVideoTracks.remove(track);
        return nativeRemoveVideoTrack(this.nativeStream, track.nativeTrack);
    }

    public void dispose() {
        this.isValid = false;
        while (!this.audioTracks.isEmpty()) {
            AudioTrack track = this.audioTracks.get(0);
            removeTrack(track);
            track.dispose();
        }
        while (!this.videoTracks.isEmpty()) {
            VideoTrack track2 = this.videoTracks.get(0);
            removeTrack(track2);
            track2.dispose();
        }
        while (!this.preservedVideoTracks.isEmpty()) {
            removeTrack(this.preservedVideoTracks.get(0));
        }
        JniCommon.nativeReleaseRef(this.nativeStream);
    }

    public String getId() {
        return nativeGetId(this.nativeStream);
    }

    public String toString() {
        return "[" + getId() + ":A=" + this.audioTracks.size() + ":V=" + this.videoTracks.size() + "]";
    }

    public long nativeStream() {
        return this.nativeStream;
    }

    void addNativeAudioTrack(long nativeTrack) {
        this.audioTracks.add(new AudioTrack(nativeTrack));
    }

    void addNativeVideoTrack(long nativeTrack) {
        this.videoTracks.add(new VideoTrack(nativeTrack));
    }

    void removeAudioTrack(long nativeTrack) {
        removeMediaStreamTrack(this.audioTracks, nativeTrack);
    }

    void removeVideoTrack(long nativeTrack) {
        removeMediaStreamTrack(this.videoTracks, nativeTrack);
    }

    private static void removeMediaStreamTrack(List<? extends MediaStreamTrack> tracks, long nativeTrack) {
        Iterator<? extends MediaStreamTrack> it = tracks.iterator();
        while (it.hasNext()) {
            MediaStreamTrack track = it.next();
            if (track.nativeTrack == nativeTrack) {
                track.dispose();
                it.remove();
                return;
            }
        }
        Logging.e(TAG, "Couldn't not find track");
    }
}
