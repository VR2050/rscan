package org.webrtc.mozi;

import java.util.IdentityHashMap;
import java.util.Iterator;

/* JADX INFO: loaded from: classes3.dex */
public class AudioTrack extends MediaStreamTrack {
    private final IdentityHashMap<AudioSink, Long> sinks;

    private static native void nativeAddSink(long j, long j2);

    private static native void nativeFreeSink(long j);

    private static native void nativeRemoveSink(long j, long j2);

    private static native void nativeSetVolume(long j, double d);

    private static native long nativeWrapSink(AudioSink audioSink);

    public AudioTrack(long nativeTrack) {
        super(nativeTrack);
        this.sinks = new IdentityHashMap<>();
    }

    public void addSink(AudioSink sink) {
        if (sink == null) {
            throw new IllegalArgumentException("The AudioSink is not allowed to be null");
        }
        if (!this.sinks.containsKey(sink)) {
            long nativeSink = nativeWrapSink(sink);
            this.sinks.put(sink, Long.valueOf(nativeSink));
            nativeAddSink(this.nativeTrack, nativeSink);
        }
    }

    public void removeSink(AudioSink sink) {
        Long nativeSink = this.sinks.remove(sink);
        if (nativeSink != null) {
            nativeRemoveSink(this.nativeTrack, nativeSink.longValue());
            nativeFreeSink(nativeSink.longValue());
        }
    }

    public void setVolume(double volume) {
        nativeSetVolume(this.nativeTrack, volume);
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
