package com.google.android.exoplayer2.offline;

import android.net.Uri;
import android.os.Handler;
import android.os.Looper;
import android.util.SparseIntArray;
import com.google.android.exoplayer2.ExoPlaybackException;
import com.google.android.exoplayer2.RendererCapabilities;
import com.google.android.exoplayer2.RenderersFactory;
import com.google.android.exoplayer2.Timeline;
import com.google.android.exoplayer2.drm.DrmSessionManager;
import com.google.android.exoplayer2.drm.FrameworkMediaCrypto;
import com.google.android.exoplayer2.source.MediaSource;
import com.google.android.exoplayer2.source.TrackGroup;
import com.google.android.exoplayer2.source.TrackGroupArray;
import com.google.android.exoplayer2.trackselection.BaseTrackSelection;
import com.google.android.exoplayer2.trackselection.DefaultTrackSelector;
import com.google.android.exoplayer2.trackselection.MappingTrackSelector;
import com.google.android.exoplayer2.trackselection.TrackSelection;
import com.google.android.exoplayer2.trackselection.TrackSelector;
import com.google.android.exoplayer2.trackselection.TrackSelectorResult;
import com.google.android.exoplayer2.upstream.BandwidthMeter;
import com.google.android.exoplayer2.upstream.TransferListener;
import com.google.android.exoplayer2.util.Assertions;
import com.google.android.exoplayer2.util.Util;
import java.io.IOException;
import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.checkerframework.checker.nullness.qual.EnsuresNonNull;
import org.checkerframework.checker.nullness.qual.RequiresNonNull;

/* JADX INFO: loaded from: classes2.dex */
public abstract class DownloadHelper<T> {
    public static final DefaultTrackSelector.Parameters DEFAULT_TRACK_SELECTOR_PARAMETERS = new DefaultTrackSelector.ParametersBuilder().setForceHighestSupportedBitrate(true).build();
    private final String cacheKey;
    private int currentTrackSelectionPeriodIndex;
    private final String downloadType;
    private List<TrackSelection>[][] immutableTrackSelectionsByPeriodAndRenderer;
    private T manifest;
    private MappingTrackSelector.MappedTrackInfo[] mappedTrackInfos;
    private final RendererCapabilities[] rendererCapabilities;
    private final SparseIntArray scratchSet = new SparseIntArray();
    private TrackGroupArray[] trackGroupArrays;
    private List<TrackSelection>[][] trackSelectionsByPeriodAndRenderer;
    private final DefaultTrackSelector trackSelector;
    private final Uri uri;

    public interface Callback {
        void onPrepareError(DownloadHelper<?> downloadHelper, IOException iOException);

        void onPrepared(DownloadHelper<?> downloadHelper);
    }

    protected abstract TrackGroupArray[] getTrackGroupArrays(T t);

    protected abstract T loadManifest(Uri uri) throws IOException;

    protected abstract StreamKey toStreamKey(int i, int i2, int i3);

    public DownloadHelper(String downloadType, Uri uri, String cacheKey, DefaultTrackSelector.Parameters trackSelectorParameters, RenderersFactory renderersFactory, DrmSessionManager<FrameworkMediaCrypto> drmSessionManager) {
        this.downloadType = downloadType;
        this.uri = uri;
        this.cacheKey = cacheKey;
        this.trackSelector = new DefaultTrackSelector(new DownloadTrackSelection.Factory());
        this.rendererCapabilities = Util.getRendererCapabilities(renderersFactory, drmSessionManager);
        this.trackSelector.setParameters(trackSelectorParameters);
        this.trackSelector.init(new TrackSelector.InvalidationListener() { // from class: com.google.android.exoplayer2.offline.-$$Lambda$DownloadHelper$7Z-k9CqspX3ZiYWCChYkf8Ai-TY
            @Override // com.google.android.exoplayer2.trackselection.TrackSelector.InvalidationListener
            public final void onTrackSelectionsInvalidated() {
                DownloadHelper.lambda$new$0();
            }
        }, new DummyBandwidthMeter());
    }

    static /* synthetic */ void lambda$new$0() {
    }

    public final void prepare(final Callback callback) {
        final Handler handler = new Handler(Looper.myLooper() != null ? Looper.myLooper() : Looper.getMainLooper());
        new Thread(new Runnable() { // from class: com.google.android.exoplayer2.offline.-$$Lambda$DownloadHelper$nyj6edQv5O15mBYo-Gau5u6d-Lw
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$prepare$3$DownloadHelper(handler, callback);
            }
        }).start();
    }

    public /* synthetic */ void lambda$prepare$3$DownloadHelper(Handler handler, final Callback callback) {
        try {
            T tLoadManifest = loadManifest(this.uri);
            this.manifest = tLoadManifest;
            TrackGroupArray[] trackGroupArrays = getTrackGroupArrays(tLoadManifest);
            this.trackGroupArrays = trackGroupArrays;
            initializeTrackSelectionLists(trackGroupArrays.length, this.rendererCapabilities.length);
            this.mappedTrackInfos = new MappingTrackSelector.MappedTrackInfo[this.trackGroupArrays.length];
            for (int i = 0; i < this.trackGroupArrays.length; i++) {
                TrackSelectorResult trackSelectorResult = runTrackSelection(i);
                this.trackSelector.onSelectionActivated(trackSelectorResult.info);
                this.mappedTrackInfos[i] = (MappingTrackSelector.MappedTrackInfo) Assertions.checkNotNull(this.trackSelector.getCurrentMappedTrackInfo());
            }
            handler.post(new Runnable() { // from class: com.google.android.exoplayer2.offline.-$$Lambda$DownloadHelper$mwjzy8WVCMvC2MDmjlfj6q5fAGg
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$1$DownloadHelper(callback);
                }
            });
        } catch (IOException e) {
            handler.post(new Runnable() { // from class: com.google.android.exoplayer2.offline.-$$Lambda$DownloadHelper$RWmTWzB-HvCIBrns5h5DpGV7zgg
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$2$DownloadHelper(callback, e);
                }
            });
        }
    }

    public /* synthetic */ void lambda$null$1$DownloadHelper(Callback callback) {
        callback.onPrepared(this);
    }

    public /* synthetic */ void lambda$null$2$DownloadHelper(Callback callback, IOException e) {
        callback.onPrepareError(this, e);
    }

    public final T getManifest() {
        Assertions.checkNotNull(this.manifest);
        return this.manifest;
    }

    public final int getPeriodCount() {
        Assertions.checkNotNull(this.trackGroupArrays);
        return this.trackGroupArrays.length;
    }

    public final TrackGroupArray getTrackGroups(int periodIndex) {
        Assertions.checkNotNull(this.trackGroupArrays);
        return this.trackGroupArrays[periodIndex];
    }

    public final MappingTrackSelector.MappedTrackInfo getMappedTrackInfo(int periodIndex) {
        Assertions.checkNotNull(this.mappedTrackInfos);
        return this.mappedTrackInfos[periodIndex];
    }

    public final List<TrackSelection> getTrackSelections(int periodIndex, int rendererIndex) {
        Assertions.checkNotNull(this.immutableTrackSelectionsByPeriodAndRenderer);
        return this.immutableTrackSelectionsByPeriodAndRenderer[periodIndex][rendererIndex];
    }

    public final void clearTrackSelections(int periodIndex) {
        Assertions.checkNotNull(this.trackSelectionsByPeriodAndRenderer);
        for (int i = 0; i < this.rendererCapabilities.length; i++) {
            this.trackSelectionsByPeriodAndRenderer[periodIndex][i].clear();
        }
    }

    public final void replaceTrackSelections(int periodIndex, DefaultTrackSelector.Parameters trackSelectorParameters) {
        clearTrackSelections(periodIndex);
        addTrackSelection(periodIndex, trackSelectorParameters);
    }

    public final void addTrackSelection(int periodIndex, DefaultTrackSelector.Parameters trackSelectorParameters) {
        Assertions.checkNotNull(this.trackGroupArrays);
        Assertions.checkNotNull(this.trackSelectionsByPeriodAndRenderer);
        this.trackSelector.setParameters(trackSelectorParameters);
        runTrackSelection(periodIndex);
    }

    public final DownloadAction getDownloadAction(byte[] data) {
        Assertions.checkNotNull(this.trackSelectionsByPeriodAndRenderer);
        Assertions.checkNotNull(this.trackGroupArrays);
        List<StreamKey> streamKeys = new ArrayList<>();
        int periodCount = this.trackSelectionsByPeriodAndRenderer.length;
        for (int periodIndex = 0; periodIndex < periodCount; periodIndex++) {
            int rendererCount = this.trackSelectionsByPeriodAndRenderer[periodIndex].length;
            for (int rendererIndex = 0; rendererIndex < rendererCount; rendererIndex++) {
                List<TrackSelection> trackSelectionList = this.trackSelectionsByPeriodAndRenderer[periodIndex][rendererIndex];
                for (int selectionIndex = 0; selectionIndex < trackSelectionList.size(); selectionIndex++) {
                    TrackSelection trackSelection = trackSelectionList.get(selectionIndex);
                    int trackGroupIndex = this.trackGroupArrays[periodIndex].indexOf(trackSelection.getTrackGroup());
                    int trackCount = trackSelection.length();
                    for (int trackListIndex = 0; trackListIndex < trackCount; trackListIndex++) {
                        int trackIndex = trackSelection.getIndexInTrackGroup(trackListIndex);
                        streamKeys.add(toStreamKey(periodIndex, trackGroupIndex, trackIndex));
                    }
                }
            }
        }
        return DownloadAction.createDownloadAction(this.downloadType, this.uri, streamKeys, this.cacheKey, data);
    }

    public final DownloadAction getRemoveAction() {
        return DownloadAction.createRemoveAction(this.downloadType, this.uri, this.cacheKey);
    }

    @EnsuresNonNull({"trackSelectionsByPeriodAndRenderer"})
    private void initializeTrackSelectionLists(int periodCount, int rendererCount) {
        this.trackSelectionsByPeriodAndRenderer = (List[][]) Array.newInstance((Class<?>) List.class, periodCount, rendererCount);
        this.immutableTrackSelectionsByPeriodAndRenderer = (List[][]) Array.newInstance((Class<?>) List.class, periodCount, rendererCount);
        for (int i = 0; i < periodCount; i++) {
            for (int j = 0; j < rendererCount; j++) {
                this.trackSelectionsByPeriodAndRenderer[i][j] = new ArrayList();
                this.immutableTrackSelectionsByPeriodAndRenderer[i][j] = Collections.unmodifiableList(this.trackSelectionsByPeriodAndRenderer[i][j]);
            }
        }
    }

    @RequiresNonNull({"trackGroupArrays", "trackSelectionsByPeriodAndRenderer"})
    private TrackSelectorResult runTrackSelection(int periodIndex) {
        MediaSource.MediaPeriodId dummyMediaPeriodId = new MediaSource.MediaPeriodId(new Object());
        Timeline dummyTimeline = Timeline.EMPTY;
        this.currentTrackSelectionPeriodIndex = periodIndex;
        try {
            TrackSelectorResult trackSelectorResult = this.trackSelector.selectTracks(this.rendererCapabilities, this.trackGroupArrays[periodIndex], dummyMediaPeriodId, dummyTimeline);
            for (int i = 0; i < trackSelectorResult.length; i++) {
                TrackSelection newSelection = trackSelectorResult.selections.get(i);
                if (newSelection != null) {
                    List<TrackSelection> existingSelectionList = this.trackSelectionsByPeriodAndRenderer[this.currentTrackSelectionPeriodIndex][i];
                    boolean mergedWithExistingSelection = false;
                    int j = 0;
                    while (true) {
                        if (j >= existingSelectionList.size()) {
                            break;
                        }
                        TrackSelection existingSelection = existingSelectionList.get(j);
                        if (existingSelection.getTrackGroup() != newSelection.getTrackGroup()) {
                            j++;
                        } else {
                            this.scratchSet.clear();
                            for (int k = 0; k < existingSelection.length(); k++) {
                                this.scratchSet.put(existingSelection.getIndexInTrackGroup(k), 0);
                            }
                            for (int k2 = 0; k2 < newSelection.length(); k2++) {
                                this.scratchSet.put(newSelection.getIndexInTrackGroup(k2), 0);
                            }
                            int[] mergedTracks = new int[this.scratchSet.size()];
                            for (int k3 = 0; k3 < this.scratchSet.size(); k3++) {
                                mergedTracks[k3] = this.scratchSet.keyAt(k3);
                            }
                            existingSelectionList.set(j, new DownloadTrackSelection(existingSelection.getTrackGroup(), mergedTracks));
                            mergedWithExistingSelection = true;
                        }
                    }
                    if (!mergedWithExistingSelection) {
                        existingSelectionList.add(newSelection);
                    }
                }
            }
            return trackSelectorResult;
        } catch (ExoPlaybackException e) {
            throw new UnsupportedOperationException(e);
        }
    }

    private static final class DownloadTrackSelection extends BaseTrackSelection {

        private static final class Factory implements TrackSelection.Factory {
            @Override // com.google.android.exoplayer2.trackselection.TrackSelection.Factory
            @Deprecated
            public /* synthetic */ TrackSelection createTrackSelection(TrackGroup trackGroup, BandwidthMeter bandwidthMeter, int... iArr) {
                return TrackSelection.Factory.CC.$default$createTrackSelection(this, trackGroup, bandwidthMeter, iArr);
            }

            private Factory() {
            }

            @Override // com.google.android.exoplayer2.trackselection.TrackSelection.Factory
            public TrackSelection[] createTrackSelections(TrackSelection.Definition[] definitions, BandwidthMeter bandwidthMeter) {
                TrackSelection[] selections = new TrackSelection[definitions.length];
                for (int i = 0; i < definitions.length; i++) {
                    selections[i] = definitions[i] == null ? null : new DownloadTrackSelection(definitions[i].group, definitions[i].tracks);
                }
                return selections;
            }
        }

        public DownloadTrackSelection(TrackGroup trackGroup, int[] tracks) {
            super(trackGroup, tracks);
        }

        @Override // com.google.android.exoplayer2.trackselection.TrackSelection
        public int getSelectedIndex() {
            return 0;
        }

        @Override // com.google.android.exoplayer2.trackselection.TrackSelection
        public int getSelectionReason() {
            return 0;
        }

        @Override // com.google.android.exoplayer2.trackselection.TrackSelection
        public Object getSelectionData() {
            return null;
        }
    }

    private static final class DummyBandwidthMeter implements BandwidthMeter {
        private DummyBandwidthMeter() {
        }

        @Override // com.google.android.exoplayer2.upstream.BandwidthMeter
        public long getBitrateEstimate() {
            return 0L;
        }

        @Override // com.google.android.exoplayer2.upstream.BandwidthMeter
        public TransferListener getTransferListener() {
            return null;
        }

        @Override // com.google.android.exoplayer2.upstream.BandwidthMeter
        public void addEventListener(Handler eventHandler, BandwidthMeter.EventListener eventListener) {
        }

        @Override // com.google.android.exoplayer2.upstream.BandwidthMeter
        public void removeEventListener(BandwidthMeter.EventListener eventListener) {
        }
    }
}
