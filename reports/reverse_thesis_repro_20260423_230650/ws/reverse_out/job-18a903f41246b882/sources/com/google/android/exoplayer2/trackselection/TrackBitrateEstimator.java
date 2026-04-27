package com.google.android.exoplayer2.trackselection;

import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.source.chunk.MediaChunk;
import com.google.android.exoplayer2.source.chunk.MediaChunkIterator;
import java.util.List;

/* JADX INFO: loaded from: classes2.dex */
public interface TrackBitrateEstimator {
    public static final TrackBitrateEstimator DEFAULT = new TrackBitrateEstimator() { // from class: com.google.android.exoplayer2.trackselection.-$$Lambda$TrackBitrateEstimator$2lQ5lBvmOkJuNPw2qehuzXBInmI
        @Override // com.google.android.exoplayer2.trackselection.TrackBitrateEstimator
        public final int[] getBitrates(Format[] formatArr, List list, MediaChunkIterator[] mediaChunkIteratorArr, int[] iArr) {
            return TrackSelectionUtil.getFormatBitrates(formatArr, iArr);
        }
    };

    int[] getBitrates(Format[] formatArr, List<? extends MediaChunk> list, MediaChunkIterator[] mediaChunkIteratorArr, int[] iArr);

    /* JADX INFO: renamed from: com.google.android.exoplayer2.trackselection.TrackBitrateEstimator$-CC, reason: invalid class name */
    public final /* synthetic */ class CC {
    }
}
