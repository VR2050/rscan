package com.google.android.exoplayer2.trackselection;

import com.google.android.exoplayer2.C;
import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.source.TrackGroup;
import com.google.android.exoplayer2.source.chunk.MediaChunk;
import com.google.android.exoplayer2.source.chunk.MediaChunkIterator;
import com.google.android.exoplayer2.trackselection.TrackSelection;
import com.google.android.exoplayer2.upstream.BandwidthMeter;
import com.google.android.exoplayer2.util.Clock;
import com.google.android.exoplayer2.util.Util;
import com.zhy.http.okhttp.OkHttpUtils;
import java.util.List;

/* JADX INFO: loaded from: classes2.dex */
public class AdaptiveTrackSelection extends BaseTrackSelection {
    public static final float DEFAULT_BANDWIDTH_FRACTION = 0.75f;
    public static final float DEFAULT_BUFFERED_FRACTION_TO_LIVE_EDGE_FOR_QUALITY_INCREASE = 0.75f;
    public static final int DEFAULT_MAX_DURATION_FOR_QUALITY_DECREASE_MS = 25000;
    public static final int DEFAULT_MIN_DURATION_FOR_QUALITY_INCREASE_MS = 10000;
    public static final int DEFAULT_MIN_DURATION_TO_RETAIN_AFTER_DISCARD_MS = 25000;
    public static final long DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS = 2000;
    private final BandwidthProvider bandwidthProvider;
    private final float bufferedFractionToLiveEdgeForQualityIncrease;
    private final Clock clock;
    private final int[] formatBitrates;
    private final Format[] formats;
    private long lastBufferEvaluationMs;
    private final long maxDurationForQualityDecreaseUs;
    private final long minDurationForQualityIncreaseUs;
    private final long minDurationToRetainAfterDiscardUs;
    private final long minTimeBetweenBufferReevaluationMs;
    private float playbackSpeed;
    private int reason;
    private int selectedIndex;
    private TrackBitrateEstimator trackBitrateEstimator;
    private final int[] trackBitrates;

    private interface BandwidthProvider {
        long getAllocatedBandwidth();
    }

    public static final class Factory implements TrackSelection.Factory {
        private final float bandwidthFraction;
        private final BandwidthMeter bandwidthMeter;
        private boolean blockFixedTrackSelectionBandwidth;
        private final float bufferedFractionToLiveEdgeForQualityIncrease;
        private final Clock clock;
        private final int maxDurationForQualityDecreaseMs;
        private final int minDurationForQualityIncreaseMs;
        private final int minDurationToRetainAfterDiscardMs;
        private final long minTimeBetweenBufferReevaluationMs;
        private TrackBitrateEstimator trackBitrateEstimator;

        @Override // com.google.android.exoplayer2.trackselection.TrackSelection.Factory
        @Deprecated
        public /* synthetic */ TrackSelection createTrackSelection(TrackGroup trackGroup, BandwidthMeter bandwidthMeter, int... iArr) {
            return TrackSelection.Factory.CC.$default$createTrackSelection(this, trackGroup, bandwidthMeter, iArr);
        }

        public Factory() {
            this(10000, 25000, 25000, 0.75f, 0.75f, AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS, Clock.DEFAULT);
        }

        @Deprecated
        public Factory(BandwidthMeter bandwidthMeter) {
            this(bandwidthMeter, 10000, 25000, 25000, 0.75f, 0.75f, AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS, Clock.DEFAULT);
        }

        public Factory(int minDurationForQualityIncreaseMs, int maxDurationForQualityDecreaseMs, int minDurationToRetainAfterDiscardMs, float bandwidthFraction) {
            this(minDurationForQualityIncreaseMs, maxDurationForQualityDecreaseMs, minDurationToRetainAfterDiscardMs, bandwidthFraction, 0.75f, AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS, Clock.DEFAULT);
        }

        @Deprecated
        public Factory(BandwidthMeter bandwidthMeter, int minDurationForQualityIncreaseMs, int maxDurationForQualityDecreaseMs, int minDurationToRetainAfterDiscardMs, float bandwidthFraction) {
            this(bandwidthMeter, minDurationForQualityIncreaseMs, maxDurationForQualityDecreaseMs, minDurationToRetainAfterDiscardMs, bandwidthFraction, 0.75f, AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS, Clock.DEFAULT);
        }

        public Factory(int minDurationForQualityIncreaseMs, int maxDurationForQualityDecreaseMs, int minDurationToRetainAfterDiscardMs, float bandwidthFraction, float bufferedFractionToLiveEdgeForQualityIncrease, long minTimeBetweenBufferReevaluationMs, Clock clock) {
            this(null, minDurationForQualityIncreaseMs, maxDurationForQualityDecreaseMs, minDurationToRetainAfterDiscardMs, bandwidthFraction, bufferedFractionToLiveEdgeForQualityIncrease, minTimeBetweenBufferReevaluationMs, clock);
        }

        @Deprecated
        public Factory(BandwidthMeter bandwidthMeter, int minDurationForQualityIncreaseMs, int maxDurationForQualityDecreaseMs, int minDurationToRetainAfterDiscardMs, float bandwidthFraction, float bufferedFractionToLiveEdgeForQualityIncrease, long minTimeBetweenBufferReevaluationMs, Clock clock) {
            this.bandwidthMeter = bandwidthMeter;
            this.minDurationForQualityIncreaseMs = minDurationForQualityIncreaseMs;
            this.maxDurationForQualityDecreaseMs = maxDurationForQualityDecreaseMs;
            this.minDurationToRetainAfterDiscardMs = minDurationToRetainAfterDiscardMs;
            this.bandwidthFraction = bandwidthFraction;
            this.bufferedFractionToLiveEdgeForQualityIncrease = bufferedFractionToLiveEdgeForQualityIncrease;
            this.minTimeBetweenBufferReevaluationMs = minTimeBetweenBufferReevaluationMs;
            this.clock = clock;
            this.trackBitrateEstimator = TrackBitrateEstimator.DEFAULT;
        }

        public void experimental_setTrackBitrateEstimator(TrackBitrateEstimator trackBitrateEstimator) {
            this.trackBitrateEstimator = trackBitrateEstimator;
        }

        public void experimental_enableBlockFixedTrackSelectionBandwidth() {
            this.blockFixedTrackSelectionBandwidth = true;
        }

        @Override // com.google.android.exoplayer2.trackselection.TrackSelection.Factory
        public TrackSelection[] createTrackSelections(TrackSelection.Definition[] definitions, BandwidthMeter bandwidthMeter) {
            TrackSelection[] selections = new TrackSelection[definitions.length];
            AdaptiveTrackSelection adaptiveSelection = null;
            int totalFixedBandwidth = 0;
            for (int i = 0; i < definitions.length; i++) {
                TrackSelection.Definition definition = definitions[i];
                if (definition != null) {
                    if (definition.tracks.length > 1) {
                        adaptiveSelection = createAdaptiveTrackSelection(definition.group, bandwidthMeter, definition.tracks);
                        selections[i] = adaptiveSelection;
                    } else {
                        selections[i] = new FixedTrackSelection(definition.group, definition.tracks[0]);
                        int trackBitrate = definition.group.getFormat(definition.tracks[0]).bitrate;
                        if (trackBitrate != -1) {
                            totalFixedBandwidth += trackBitrate;
                        }
                    }
                }
            }
            if (this.blockFixedTrackSelectionBandwidth && adaptiveSelection != null) {
                adaptiveSelection.experimental_setNonAllocatableBandwidth(totalFixedBandwidth);
            }
            return selections;
        }

        private AdaptiveTrackSelection createAdaptiveTrackSelection(TrackGroup group, BandwidthMeter bandwidthMeter, int[] tracks) {
            BandwidthMeter bandwidthMeter2;
            if (this.bandwidthMeter == null) {
                bandwidthMeter2 = bandwidthMeter;
            } else {
                bandwidthMeter2 = this.bandwidthMeter;
            }
            AdaptiveTrackSelection adaptiveTrackSelection = new AdaptiveTrackSelection(group, tracks, new DefaultBandwidthProvider(bandwidthMeter2, this.bandwidthFraction), this.minDurationForQualityIncreaseMs, this.maxDurationForQualityDecreaseMs, this.minDurationToRetainAfterDiscardMs, this.bufferedFractionToLiveEdgeForQualityIncrease, this.minTimeBetweenBufferReevaluationMs, this.clock);
            adaptiveTrackSelection.experimental_setTrackBitrateEstimator(this.trackBitrateEstimator);
            return adaptiveTrackSelection;
        }
    }

    public AdaptiveTrackSelection(TrackGroup group, int[] tracks, BandwidthMeter bandwidthMeter) {
        this(group, tracks, bandwidthMeter, OkHttpUtils.DEFAULT_MILLISECONDS, 25000L, 25000L, 0.75f, 0.75f, DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS, Clock.DEFAULT);
    }

    public AdaptiveTrackSelection(TrackGroup group, int[] tracks, BandwidthMeter bandwidthMeter, long minDurationForQualityIncreaseMs, long maxDurationForQualityDecreaseMs, long minDurationToRetainAfterDiscardMs, float bandwidthFraction, float bufferedFractionToLiveEdgeForQualityIncrease, long minTimeBetweenBufferReevaluationMs, Clock clock) {
        this(group, tracks, new DefaultBandwidthProvider(bandwidthMeter, bandwidthFraction), minDurationForQualityIncreaseMs, maxDurationForQualityDecreaseMs, minDurationToRetainAfterDiscardMs, bufferedFractionToLiveEdgeForQualityIncrease, minTimeBetweenBufferReevaluationMs, clock);
    }

    private AdaptiveTrackSelection(TrackGroup group, int[] tracks, BandwidthProvider bandwidthProvider, long minDurationForQualityIncreaseMs, long maxDurationForQualityDecreaseMs, long minDurationToRetainAfterDiscardMs, float bufferedFractionToLiveEdgeForQualityIncrease, long minTimeBetweenBufferReevaluationMs, Clock clock) {
        super(group, tracks);
        this.bandwidthProvider = bandwidthProvider;
        this.minDurationForQualityIncreaseUs = minDurationForQualityIncreaseMs * 1000;
        this.maxDurationForQualityDecreaseUs = maxDurationForQualityDecreaseMs * 1000;
        this.minDurationToRetainAfterDiscardUs = 1000 * minDurationToRetainAfterDiscardMs;
        this.bufferedFractionToLiveEdgeForQualityIncrease = bufferedFractionToLiveEdgeForQualityIncrease;
        this.minTimeBetweenBufferReevaluationMs = minTimeBetweenBufferReevaluationMs;
        this.clock = clock;
        this.playbackSpeed = 1.0f;
        this.reason = 0;
        this.lastBufferEvaluationMs = C.TIME_UNSET;
        this.trackBitrateEstimator = TrackBitrateEstimator.DEFAULT;
        this.formats = new Format[this.length];
        this.formatBitrates = new int[this.length];
        this.trackBitrates = new int[this.length];
        for (int i = 0; i < this.length; i++) {
            Format format = getFormat(i);
            Format[] formatArr = this.formats;
            formatArr[i] = format;
            this.formatBitrates[i] = formatArr[i].bitrate;
        }
    }

    public void experimental_setTrackBitrateEstimator(TrackBitrateEstimator trackBitrateEstimator) {
        this.trackBitrateEstimator = trackBitrateEstimator;
    }

    public void experimental_setNonAllocatableBandwidth(long nonAllocatableBandwidth) {
        ((DefaultBandwidthProvider) this.bandwidthProvider).experimental_setNonAllocatableBandwidth(nonAllocatableBandwidth);
    }

    @Override // com.google.android.exoplayer2.trackselection.BaseTrackSelection, com.google.android.exoplayer2.trackselection.TrackSelection
    public void enable() {
        this.lastBufferEvaluationMs = C.TIME_UNSET;
    }

    @Override // com.google.android.exoplayer2.trackselection.BaseTrackSelection, com.google.android.exoplayer2.trackselection.TrackSelection
    public void onPlaybackSpeed(float playbackSpeed) {
        this.playbackSpeed = playbackSpeed;
    }

    @Override // com.google.android.exoplayer2.trackselection.BaseTrackSelection, com.google.android.exoplayer2.trackselection.TrackSelection
    public void updateSelectedTrack(long playbackPositionUs, long bufferedDurationUs, long availableDurationUs, List<? extends MediaChunk> queue, MediaChunkIterator[] mediaChunkIterators) {
        long nowMs = this.clock.elapsedRealtime();
        this.trackBitrateEstimator.getBitrates(this.formats, queue, mediaChunkIterators, this.trackBitrates);
        if (this.reason == 0) {
            this.reason = 1;
            this.selectedIndex = determineIdealSelectedIndex(nowMs, this.trackBitrates);
            return;
        }
        int currentSelectedIndex = this.selectedIndex;
        int iDetermineIdealSelectedIndex = determineIdealSelectedIndex(nowMs, this.trackBitrates);
        this.selectedIndex = iDetermineIdealSelectedIndex;
        if (iDetermineIdealSelectedIndex == currentSelectedIndex) {
            return;
        }
        if (!isBlacklisted(currentSelectedIndex, nowMs)) {
            Format currentFormat = getFormat(currentSelectedIndex);
            Format selectedFormat = getFormat(this.selectedIndex);
            if (selectedFormat.bitrate > currentFormat.bitrate && bufferedDurationUs < minDurationForQualityIncreaseUs(availableDurationUs)) {
                this.selectedIndex = currentSelectedIndex;
            } else if (selectedFormat.bitrate < currentFormat.bitrate && bufferedDurationUs >= this.maxDurationForQualityDecreaseUs) {
                this.selectedIndex = currentSelectedIndex;
            }
        }
        if (this.selectedIndex != currentSelectedIndex) {
            this.reason = 3;
        }
    }

    @Override // com.google.android.exoplayer2.trackselection.TrackSelection
    public int getSelectedIndex() {
        return this.selectedIndex;
    }

    @Override // com.google.android.exoplayer2.trackselection.TrackSelection
    public int getSelectionReason() {
        return this.reason;
    }

    @Override // com.google.android.exoplayer2.trackselection.TrackSelection
    public Object getSelectionData() {
        return null;
    }

    @Override // com.google.android.exoplayer2.trackselection.BaseTrackSelection, com.google.android.exoplayer2.trackselection.TrackSelection
    public int evaluateQueueSize(long playbackPositionUs, List<? extends MediaChunk> queue) {
        AdaptiveTrackSelection adaptiveTrackSelection = this;
        List<? extends MediaChunk> list = queue;
        long nowMs = adaptiveTrackSelection.clock.elapsedRealtime();
        if (!adaptiveTrackSelection.shouldEvaluateQueueSize(nowMs)) {
            return queue.size();
        }
        adaptiveTrackSelection.lastBufferEvaluationMs = nowMs;
        if (queue.isEmpty()) {
            return 0;
        }
        int queueSize = queue.size();
        MediaChunk lastChunk = list.get(queueSize - 1);
        long playoutBufferedDurationBeforeLastChunkUs = Util.getPlayoutDurationForMediaDuration(lastChunk.startTimeUs - playbackPositionUs, adaptiveTrackSelection.playbackSpeed);
        long minDurationToRetainAfterDiscardUs = getMinDurationToRetainAfterDiscardUs();
        if (playoutBufferedDurationBeforeLastChunkUs < minDurationToRetainAfterDiscardUs) {
            return queueSize;
        }
        int idealSelectedIndex = adaptiveTrackSelection.determineIdealSelectedIndex(nowMs, adaptiveTrackSelection.formatBitrates);
        Format idealFormat = adaptiveTrackSelection.getFormat(idealSelectedIndex);
        int i = 0;
        while (i < queueSize) {
            MediaChunk chunk = list.get(i);
            Format format = chunk.trackFormat;
            long nowMs2 = nowMs;
            long mediaDurationBeforeThisChunkUs = chunk.startTimeUs - playbackPositionUs;
            long playoutDurationBeforeThisChunkUs = Util.getPlayoutDurationForMediaDuration(mediaDurationBeforeThisChunkUs, adaptiveTrackSelection.playbackSpeed);
            if (playoutDurationBeforeThisChunkUs < minDurationToRetainAfterDiscardUs || format.bitrate >= idealFormat.bitrate || format.height == -1 || format.height >= 720 || format.width == -1 || format.width >= 1280 || format.height >= idealFormat.height) {
                i++;
                adaptiveTrackSelection = this;
                list = queue;
                nowMs = nowMs2;
            } else {
                return i;
            }
        }
        return queueSize;
    }

    protected boolean canSelectFormat(Format format, int trackBitrate, float playbackSpeed, long effectiveBitrate) {
        return ((long) Math.round(((float) trackBitrate) * playbackSpeed)) <= effectiveBitrate;
    }

    protected boolean shouldEvaluateQueueSize(long nowMs) {
        long j = this.lastBufferEvaluationMs;
        return j == C.TIME_UNSET || nowMs - j >= this.minTimeBetweenBufferReevaluationMs;
    }

    protected long getMinDurationToRetainAfterDiscardUs() {
        return this.minDurationToRetainAfterDiscardUs;
    }

    private int determineIdealSelectedIndex(long nowMs, int[] trackBitrates) {
        long effectiveBitrate = this.bandwidthProvider.getAllocatedBandwidth();
        int lowestBitrateNonBlacklistedIndex = 0;
        for (int i = 0; i < this.length; i++) {
            if (nowMs == Long.MIN_VALUE || !isBlacklisted(i, nowMs)) {
                Format format = getFormat(i);
                if (canSelectFormat(format, trackBitrates[i], this.playbackSpeed, effectiveBitrate)) {
                    return i;
                }
                lowestBitrateNonBlacklistedIndex = i;
            }
        }
        return lowestBitrateNonBlacklistedIndex;
    }

    private long minDurationForQualityIncreaseUs(long availableDurationUs) {
        boolean isAvailableDurationTooShort = availableDurationUs != C.TIME_UNSET && availableDurationUs <= this.minDurationForQualityIncreaseUs;
        return isAvailableDurationTooShort ? (long) (availableDurationUs * this.bufferedFractionToLiveEdgeForQualityIncrease) : this.minDurationForQualityIncreaseUs;
    }

    private static final class DefaultBandwidthProvider implements BandwidthProvider {
        private final float bandwidthFraction;
        private final BandwidthMeter bandwidthMeter;
        private long nonAllocatableBandwidth;

        DefaultBandwidthProvider(BandwidthMeter bandwidthMeter, float bandwidthFraction) {
            this.bandwidthMeter = bandwidthMeter;
            this.bandwidthFraction = bandwidthFraction;
        }

        @Override // com.google.android.exoplayer2.trackselection.AdaptiveTrackSelection.BandwidthProvider
        public long getAllocatedBandwidth() {
            long totalBandwidth = (long) (this.bandwidthMeter.getBitrateEstimate() * this.bandwidthFraction);
            return Math.max(0L, totalBandwidth - this.nonAllocatableBandwidth);
        }

        void experimental_setNonAllocatableBandwidth(long nonAllocatableBandwidth) {
            this.nonAllocatableBandwidth = nonAllocatableBandwidth;
        }
    }
}
