package org.webrtc.mozi;

import java.util.IdentityHashMap;
import java.util.Iterator;

/* JADX INFO: loaded from: classes3.dex */
public class VideoTrack extends MediaStreamTrack {
    private final IdentityHashMap<VideoSink, Long> sinks;

    private static native void nativeAddSink(long j, long j2, boolean z);

    private static native void nativeFreeSink(long j);

    private static native void nativeRemoveSink(long j, long j2);

    private static native long nativeWrapSink(VideoSink videoSink);

    public VideoTrack(long nativeTrack) {
        super(nativeTrack);
        this.sinks = new IdentityHashMap<>();
    }

    public void addSink(VideoSink sink, boolean wantRawFrames) {
        if (sink == null) {
            throw new IllegalArgumentException("The VideoSink is not allowed to be null");
        }
        if (!this.sinks.containsKey(sink)) {
            long nativeSink = nativeWrapSink(sink);
            this.sinks.put(sink, Long.valueOf(nativeSink));
            nativeAddSink(this.nativeTrack, nativeSink, wantRawFrames);
        }
    }

    public void addSink(VideoSink sink) {
        addSink(sink, false);
    }

    public void removeSink(VideoSink sink) {
        Long nativeSink = this.sinks.remove(sink);
        if (nativeSink != null) {
            nativeRemoveSink(this.nativeTrack, nativeSink.longValue());
            nativeFreeSink(nativeSink.longValue());
        }
    }

    @Override // org.webrtc.mozi.MediaStreamTrack
    public void dispose() {
        Iterator<Long> it = this.sinks.values().iterator();
        while (it.hasNext()) {
            long nativeSink = it.next().longValue();
            nativeRemoveSink(this.nativeTrack, nativeSink);
            nativeFreeSink(nativeSink);
        }
        this.sinks.clear();
        super.dispose();
    }
}
