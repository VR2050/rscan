package com.google.android.exoplayer2.trackselection;

import android.util.Pair;
import com.google.android.exoplayer2.C;
import com.google.android.exoplayer2.DefaultLoadControl;
import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.LoadControl;
import com.google.android.exoplayer2.source.TrackGroup;
import com.google.android.exoplayer2.source.chunk.MediaChunk;
import com.google.android.exoplayer2.source.chunk.MediaChunkIterator;
import com.google.android.exoplayer2.trackselection.BufferSizeAdaptationBuilder;
import com.google.android.exoplayer2.trackselection.TrackSelection;
import com.google.android.exoplayer2.trackselection.TrackSelectionUtil;
import com.google.android.exoplayer2.upstream.BandwidthMeter;
import com.google.android.exoplayer2.upstream.DefaultAllocator;
import com.google.android.exoplayer2.util.Assertions;
import com.google.android.exoplayer2.util.Clock;
import com.google.android.exoplayer2.util.PriorityTaskManager;
import java.util.List;

/* JADX INFO: loaded from: classes2.dex */
public final class BufferSizeAdaptationBuilder {
    public static final int DEFAULT_BUFFER_FOR_PLAYBACK_AFTER_REBUFFER_MS = 5000;
    public static final int DEFAULT_BUFFER_FOR_PLAYBACK_MS = 2500;
    public static final int DEFAULT_HYSTERESIS_BUFFER_MS = 5000;
    public static final int DEFAULT_MAX_BUFFER_MS = 50000;
    public static final int DEFAULT_MIN_BUFFER_MS = 15000;
    public static final float DEFAULT_START_UP_BANDWIDTH_FRACTION = 0.75f;
    public static final int DEFAULT_START_UP_MIN_BUFFER_FOR_QUALITY_INCREASE_MS = 10000;
    private DefaultAllocator allocator;
    boolean buildCalled;
    private PriorityTaskManager priorityTaskManager;
    private Clock clock = Clock.DEFAULT;
    private int minBufferMs = 15000;
    private int maxBufferMs = 50000;
    private int bufferForPlaybackMs = 2500;
    private int bufferForPlaybackAfterRebufferMs = 5000;
    private int hysteresisBufferMs = 5000;
    private float startUpBandwidthFraction = 0.75f;
    private int startUpMinBufferForQualityIncreaseMs = 10000;
    private DynamicFormatFilter dynamicFormatFilter = DynamicFormatFilter.NO_FILTER;

    public interface DynamicFormatFilter {
        public static final DynamicFormatFilter NO_FILTER = new DynamicFormatFilter() { // from class: com.google.android.exoplayer2.trackselection.-$$Lambda$BufferSizeAdaptationBuilder$DynamicFormatFilter$hnu1-HCrmBtPvCKLt3AEEwgWv3M
            @Override // com.google.android.exoplayer2.trackselection.BufferSizeAdaptationBuilder.DynamicFormatFilter
            public final boolean isFormatAllowed(Format format, int i) {
                return BufferSizeAdaptationBuilder.DynamicFormatFilter.CC.lambda$static$0(format, i);
            }
        };

        boolean isFormatAllowed(Format format, int i);

        /* JADX INFO: renamed from: com.google.android.exoplayer2.trackselection.BufferSizeAdaptationBuilder$DynamicFormatFilter$-CC, reason: invalid class name */
        public final /* synthetic */ class CC {
            public static /* synthetic */ boolean lambda$static$0(Format format, int trackBitrate) {
                return true;
            }
        }
    }

    public BufferSizeAdaptationBuilder setClock(Clock clock) {
        Assertions.checkState(!this.buildCalled);
        this.clock = clock;
        return this;
    }

    public BufferSizeAdaptationBuilder setAllocator(DefaultAllocator allocator) {
        Assertions.checkState(!this.buildCalled);
        this.allocator = allocator;
        return this;
    }

    public BufferSizeAdaptationBuilder setBufferDurationsMs(int minBufferMs, int maxBufferMs, int bufferForPlaybackMs, int bufferForPlaybackAfterRebufferMs) {
        Assertions.checkState(!this.buildCalled);
        this.minBufferMs = minBufferMs;
        this.maxBufferMs = maxBufferMs;
        this.bufferForPlaybackMs = bufferForPlaybackMs;
        this.bufferForPlaybackAfterRebufferMs = bufferForPlaybackAfterRebufferMs;
        return this;
    }

    public BufferSizeAdaptationBuilder setHysteresisBufferMs(int hysteresisBufferMs) {
        Assertions.checkState(!this.buildCalled);
        this.hysteresisBufferMs = hysteresisBufferMs;
        return this;
    }

    public BufferSizeAdaptationBuilder setStartUpTrackSelectionParameters(float bandwidthFraction, int minBufferForQualityIncreaseMs) {
        Assertions.checkState(!this.buildCalled);
        this.startUpBandwidthFraction = bandwidthFraction;
        this.startUpMinBufferForQualityIncreaseMs = minBufferForQualityIncreaseMs;
        return this;
    }

    public BufferSizeAdaptationBuilder setPriorityTaskManager(PriorityTaskManager priorityTaskManager) {
        Assertions.checkState(!this.buildCalled);
        this.priorityTaskManager = priorityTaskManager;
        return this;
    }

    public BufferSizeAdaptationBuilder setDynamicFormatFilter(DynamicFormatFilter dynamicFormatFilter) {
        Assertions.checkState(!this.buildCalled);
        this.dynamicFormatFilter = dynamicFormatFilter;
        return this;
    }

    public Pair<TrackSelection.Factory, LoadControl> buildPlayerComponents() {
        Assertions.checkArgument(this.hysteresisBufferMs < this.maxBufferMs - this.minBufferMs);
        Assertions.checkState(!this.buildCalled);
        this.buildCalled = true;
        DefaultLoadControl.Builder targetBufferBytes = new DefaultLoadControl.Builder().setTargetBufferBytes(Integer.MAX_VALUE);
        int i = this.maxBufferMs;
        DefaultLoadControl.Builder loadControlBuilder = targetBufferBytes.setBufferDurationsMs(i, i, this.bufferForPlaybackMs, this.bufferForPlaybackAfterRebufferMs);
        PriorityTaskManager priorityTaskManager = this.priorityTaskManager;
        if (priorityTaskManager != null) {
            loadControlBuilder.setPriorityTaskManager(priorityTaskManager);
        }
        DefaultAllocator defaultAllocator = this.allocator;
        if (defaultAllocator != null) {
            loadControlBuilder.setAllocator(defaultAllocator);
        }
        TrackSelection.Factory trackSelectionFactory = new AnonymousClass1();
        return Pair.create(trackSelectionFactory, loadControlBuilder.createDefaultLoadControl());
    }

    /* JADX INFO: renamed from: com.google.android.exoplayer2.trackselection.BufferSizeAdaptationBuilder$1, reason: invalid class name */
    class AnonymousClass1 implements TrackSelection.Factory {
        @Override // com.google.android.exoplayer2.trackselection.TrackSelection.Factory
        @Deprecated
        public /* synthetic */ TrackSelection createTrackSelection(TrackGroup trackGroup, BandwidthMeter bandwidthMeter, int... iArr) {
            return TrackSelection.Factory.CC.$default$createTrackSelection(this, trackGroup, bandwidthMeter, iArr);
        }

        AnonymousClass1() {
        }

        @Override // com.google.android.exoplayer2.trackselection.TrackSelection.Factory
        public TrackSelection[] createTrackSelections(TrackSelection.Definition[] definitions, final BandwidthMeter bandwidthMeter) {
            return TrackSelectionUtil.createTrackSelectionsForDefinitions(definitions, new TrackSelectionUtil.AdaptiveTrackSelectionFactory() { // from class: com.google.android.exoplayer2.trackselection.-$$Lambda$BufferSizeAdaptationBuilder$1$UONJeWXlkCCwGq1UB0TMjfEMmOM
                @Override // com.google.android.exoplayer2.trackselection.TrackSelectionUtil.AdaptiveTrackSelectionFactory
                public final TrackSelection createAdaptiveTrackSelection(TrackSelection.Definition definition) {
                    return this.f$0.lambda$createTrackSelections$0$BufferSizeAdaptationBuilder$1(bandwidthMeter, definition);
                }
            });
        }

        public /* synthetic */ TrackSelection lambda$createTrackSelections$0$BufferSizeAdaptationBuilder$1(BandwidthMeter bandwidthMeter, TrackSelection.Definition definition) {
            return new BufferSizeAdaptiveTrackSelection(definition.group, definition.tracks, bandwidthMeter, BufferSizeAdaptationBuilder.this.minBufferMs, BufferSizeAdaptationBuilder.this.maxBufferMs, BufferSizeAdaptationBuilder.this.hysteresisBufferMs, BufferSizeAdaptationBuilder.this.startUpBandwidthFraction, BufferSizeAdaptationBuilder.this.startUpMinBufferForQualityIncreaseMs, BufferSizeAdaptationBuilder.this.dynamicFormatFilter, BufferSizeAdaptationBuilder.this.clock, null);
        }
    }

    private static final class BufferSizeAdaptiveTrackSelection extends BaseTrackSelection {
        private static final int BITRATE_BLACKLISTED = -1;
        private final BandwidthMeter bandwidthMeter;
        private final double bitrateToBufferFunctionIntercept;
        private final double bitrateToBufferFunctionSlope;
        private final Clock clock;
        private final DynamicFormatFilter dynamicFormatFilter;
        private final int[] formatBitrates;
        private final long hysteresisBufferUs;
        private boolean isInSteadyState;
        private final int maxBitrate;
        private final long maxBufferUs;
        private final int minBitrate;
        private final long minBufferUs;
        private float playbackSpeed;
        private int selectedIndex;
        private int selectionReason;
        private final float startUpBandwidthFraction;
        private final long startUpMinBufferForQualityIncreaseUs;

        /* synthetic */ BufferSizeAdaptiveTrackSelection(TrackGroup x0, int[] x1, BandwidthMeter x2, int x3, int x4, int x5, float x6, int x7, DynamicFormatFilter x8, Clock x9, AnonymousClass1 x10) {
            this(x0, x1, x2, x3, x4, x5, x6, x7, x8, x9);
        }

        private BufferSizeAdaptiveTrackSelection(TrackGroup trackGroup, int[] tracks, BandwidthMeter bandwidthMeter, int minBufferMs, int maxBufferMs, int hysteresisBufferMs, float startUpBandwidthFraction, int startUpMinBufferForQualityIncreaseMs, DynamicFormatFilter dynamicFormatFilter, Clock clock) {
            super(trackGroup, tracks);
            this.bandwidthMeter = bandwidthMeter;
            this.minBufferUs = C.msToUs(minBufferMs);
            this.maxBufferUs = C.msToUs(maxBufferMs);
            this.hysteresisBufferUs = C.msToUs(hysteresisBufferMs);
            this.startUpBandwidthFraction = startUpBandwidthFraction;
            this.startUpMinBufferForQualityIncreaseUs = C.msToUs(startUpMinBufferForQualityIncreaseMs);
            this.dynamicFormatFilter = dynamicFormatFilter;
            this.clock = clock;
            this.formatBitrates = new int[this.length];
            this.maxBitrate = getFormat(0).bitrate;
            this.minBitrate = getFormat(this.length - 1).bitrate;
            this.selectionReason = 1;
            this.playbackSpeed = 1.0f;
            double dLog = ((this.maxBufferUs - this.hysteresisBufferUs) - this.minBufferUs) / Math.log(this.maxBitrate / r9);
            this.bitrateToBufferFunctionSlope = dLog;
            this.bitrateToBufferFunctionIntercept = this.minBufferUs - (dLog * Math.log(this.minBitrate));
            updateFormatBitrates(Long.MIN_VALUE);
            this.selectedIndex = selectIdealIndexUsingBandwidth();
        }

        @Override // com.google.android.exoplayer2.trackselection.BaseTrackSelection, com.google.android.exoplayer2.trackselection.TrackSelection
        public void onPlaybackSpeed(float playbackSpeed) {
            this.playbackSpeed = playbackSpeed;
        }

        @Override // com.google.android.exoplayer2.trackselection.BaseTrackSelection, com.google.android.exoplayer2.trackselection.TrackSelection
        public void onDiscontinuity() {
            this.isInSteadyState = false;
        }

        @Override // com.google.android.exoplayer2.trackselection.TrackSelection
        public int getSelectedIndex() {
            return this.selectedIndex;
        }

        @Override // com.google.android.exoplayer2.trackselection.TrackSelection
        public int getSelectionReason() {
            return this.selectionReason;
        }

        @Override // com.google.android.exoplayer2.trackselection.TrackSelection
        public Object getSelectionData() {
            return null;
        }

        @Override // com.google.android.exoplayer2.trackselection.BaseTrackSelection, com.google.android.exoplayer2.trackselection.TrackSelection
        public void updateSelectedTrack(long playbackPositionUs, long bufferedDurationUs, long availableDurationUs, List<? extends MediaChunk> queue, MediaChunkIterator[] mediaChunkIterators) {
            updateFormatBitrates(this.clock.elapsedRealtime());
            long bufferUs = getCurrentPeriodBufferedDurationUs(playbackPositionUs, bufferedDurationUs);
            int oldSelectedIndex = this.selectedIndex;
            if (this.isInSteadyState) {
                selectIndexSteadyState(bufferUs);
            } else {
                selectIndexStartUpPhase(bufferUs);
            }
            if (this.selectedIndex != oldSelectedIndex) {
                this.selectionReason = 3;
            }
        }

        private void selectIndexSteadyState(long bufferUs) {
            if (isOutsideHysteresis(bufferUs)) {
                this.selectedIndex = selectIdealIndexUsingBufferSize(bufferUs);
            }
        }

        private boolean isOutsideHysteresis(long bufferUs) {
            int[] iArr = this.formatBitrates;
            int i = this.selectedIndex;
            if (iArr[i] == -1) {
                return true;
            }
            long targetBufferForCurrentBitrateUs = getTargetBufferForBitrateUs(iArr[i]);
            long bufferDiffUs = bufferUs - targetBufferForCurrentBitrateUs;
            return Math.abs(bufferDiffUs) > this.hysteresisBufferUs;
        }

        private int selectIdealIndexUsingBufferSize(long bufferUs) {
            int lowestBitrateNonBlacklistedIndex = 0;
            int i = 0;
            while (true) {
                int[] iArr = this.formatBitrates;
                if (i < iArr.length) {
                    if (iArr[i] != -1) {
                        if (getTargetBufferForBitrateUs(iArr[i]) < bufferUs && this.dynamicFormatFilter.isFormatAllowed(getFormat(i), this.formatBitrates[i])) {
                            return i;
                        }
                        lowestBitrateNonBlacklistedIndex = i;
                    }
                    i++;
                } else {
                    return lowestBitrateNonBlacklistedIndex;
                }
            }
        }

        private void selectIndexStartUpPhase(long bufferUs) {
            int startUpSelectedIndex = selectIdealIndexUsingBandwidth();
            int steadyStateSelectedIndex = selectIdealIndexUsingBufferSize(bufferUs);
            int i = this.selectedIndex;
            if (steadyStateSelectedIndex <= i) {
                this.selectedIndex = steadyStateSelectedIndex;
                this.isInSteadyState = true;
            } else {
                if (bufferUs < this.startUpMinBufferForQualityIncreaseUs && startUpSelectedIndex < i && this.formatBitrates[i] != -1) {
                    return;
                }
                this.selectedIndex = startUpSelectedIndex;
            }
        }

        private int selectIdealIndexUsingBandwidth() {
            long effectiveBitrate = (long) (this.bandwidthMeter.getBitrateEstimate() * this.startUpBandwidthFraction);
            int lowestBitrateNonBlacklistedIndex = 0;
            int i = 0;
            while (true) {
                int[] iArr = this.formatBitrates;
                if (i < iArr.length) {
                    if (iArr[i] != -1) {
                        if (Math.round(iArr[i] * this.playbackSpeed) <= effectiveBitrate && this.dynamicFormatFilter.isFormatAllowed(getFormat(i), this.formatBitrates[i])) {
                            return i;
                        }
                        lowestBitrateNonBlacklistedIndex = i;
                    }
                    i++;
                } else {
                    return lowestBitrateNonBlacklistedIndex;
                }
            }
        }

        private void updateFormatBitrates(long nowMs) {
            for (int i = 0; i < this.length; i++) {
                if (nowMs == Long.MIN_VALUE || !isBlacklisted(i, nowMs)) {
                    this.formatBitrates[i] = getFormat(i).bitrate;
                } else {
                    this.formatBitrates[i] = -1;
                }
            }
        }

        private long getTargetBufferForBitrateUs(int bitrate) {
            if (bitrate <= this.minBitrate) {
                return this.minBufferUs;
            }
            if (bitrate >= this.maxBitrate) {
                return this.maxBufferUs - this.hysteresisBufferUs;
            }
            return (int) ((this.bitrateToBufferFunctionSlope * Math.log(bitrate)) + this.bitrateToBufferFunctionIntercept);
        }

        private static long getCurrentPeriodBufferedDurationUs(long playbackPositionUs, long bufferedDurationUs) {
            return playbackPositionUs >= 0 ? bufferedDurationUs : playbackPositionUs + bufferedDurationUs;
        }
    }
}
