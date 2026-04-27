package com.google.android.exoplayer2.trackselection;

import com.google.android.exoplayer2.C;
import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.source.chunk.MediaChunk;
import com.google.android.exoplayer2.source.chunk.MediaChunkIterator;
import java.util.List;

/* JADX INFO: loaded from: classes2.dex */
public final class WindowedTrackBitrateEstimator implements TrackBitrateEstimator {
    private final long maxFutureDurationUs;
    private final long maxPastDurationUs;
    private final boolean useFormatBitrateAsLowerBound;

    public WindowedTrackBitrateEstimator(long maxPastDurationMs, long maxFutureDurationMs, boolean useFormatBitrateAsLowerBound) {
        this.maxPastDurationUs = C.msToUs(maxPastDurationMs);
        this.maxFutureDurationUs = C.msToUs(maxFutureDurationMs);
        this.useFormatBitrateAsLowerBound = useFormatBitrateAsLowerBound;
    }

    @Override // com.google.android.exoplayer2.trackselection.TrackBitrateEstimator
    public int[] getBitrates(Format[] formats, List<? extends MediaChunk> queue, MediaChunkIterator[] iterators, int[] bitrates) {
        if (this.maxFutureDurationUs > 0 || this.maxPastDurationUs > 0) {
            return TrackSelectionUtil.getBitratesUsingPastAndFutureInfo(formats, queue, this.maxPastDurationUs, iterators, this.maxFutureDurationUs, this.useFormatBitrateAsLowerBound, bitrates);
        }
        return TrackSelectionUtil.getFormatBitrates(formats, bitrates);
    }
}
