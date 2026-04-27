package com.google.android.exoplayer2.source.hls;

import com.google.android.exoplayer2.C;
import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.SeekParameters;
import com.google.android.exoplayer2.offline.StreamKey;
import com.google.android.exoplayer2.source.CompositeSequenceableLoaderFactory;
import com.google.android.exoplayer2.source.MediaPeriod;
import com.google.android.exoplayer2.source.MediaSourceEventListener;
import com.google.android.exoplayer2.source.SampleStream;
import com.google.android.exoplayer2.source.SequenceableLoader;
import com.google.android.exoplayer2.source.TrackGroup;
import com.google.android.exoplayer2.source.TrackGroupArray;
import com.google.android.exoplayer2.source.hls.HlsSampleStreamWrapper;
import com.google.android.exoplayer2.source.hls.playlist.HlsMasterPlaylist;
import com.google.android.exoplayer2.source.hls.playlist.HlsPlaylistTracker;
import com.google.android.exoplayer2.trackselection.TrackSelection;
import com.google.android.exoplayer2.upstream.Allocator;
import com.google.android.exoplayer2.upstream.LoadErrorHandlingPolicy;
import com.google.android.exoplayer2.upstream.TransferListener;
import com.google.android.exoplayer2.util.Assertions;
import com.google.android.exoplayer2.util.MimeTypes;
import com.google.android.exoplayer2.util.Util;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;

/* JADX INFO: loaded from: classes2.dex */
public final class HlsMediaPeriod implements MediaPeriod, HlsSampleStreamWrapper.Callback, HlsPlaylistTracker.PlaylistEventListener {
    private final Allocator allocator;
    private final boolean allowChunklessPreparation;
    private MediaPeriod.Callback callback;
    private SequenceableLoader compositeSequenceableLoader;
    private final CompositeSequenceableLoaderFactory compositeSequenceableLoaderFactory;
    private final HlsDataSourceFactory dataSourceFactory;
    private final MediaSourceEventListener.EventDispatcher eventDispatcher;
    private final HlsExtractorFactory extractorFactory;
    private final LoadErrorHandlingPolicy loadErrorHandlingPolicy;
    private final TransferListener mediaTransferListener;
    private boolean notifiedReadingStarted;
    private int pendingPrepareCount;
    private final HlsPlaylistTracker playlistTracker;
    private TrackGroupArray trackGroups;
    private final IdentityHashMap<SampleStream, Integer> streamWrapperIndices = new IdentityHashMap<>();
    private final TimestampAdjusterProvider timestampAdjusterProvider = new TimestampAdjusterProvider();
    private HlsSampleStreamWrapper[] sampleStreamWrappers = new HlsSampleStreamWrapper[0];
    private HlsSampleStreamWrapper[] enabledSampleStreamWrappers = new HlsSampleStreamWrapper[0];

    @Override // com.google.android.exoplayer2.source.MediaPeriod
    public /* synthetic */ List<StreamKey> getStreamKeys(TrackSelection trackSelection) {
        return Collections.emptyList();
    }

    public HlsMediaPeriod(HlsExtractorFactory extractorFactory, HlsPlaylistTracker playlistTracker, HlsDataSourceFactory dataSourceFactory, TransferListener mediaTransferListener, LoadErrorHandlingPolicy loadErrorHandlingPolicy, MediaSourceEventListener.EventDispatcher eventDispatcher, Allocator allocator, CompositeSequenceableLoaderFactory compositeSequenceableLoaderFactory, boolean allowChunklessPreparation) {
        this.extractorFactory = extractorFactory;
        this.playlistTracker = playlistTracker;
        this.dataSourceFactory = dataSourceFactory;
        this.mediaTransferListener = mediaTransferListener;
        this.loadErrorHandlingPolicy = loadErrorHandlingPolicy;
        this.eventDispatcher = eventDispatcher;
        this.allocator = allocator;
        this.compositeSequenceableLoaderFactory = compositeSequenceableLoaderFactory;
        this.allowChunklessPreparation = allowChunklessPreparation;
        this.compositeSequenceableLoader = compositeSequenceableLoaderFactory.createCompositeSequenceableLoader(new SequenceableLoader[0]);
        eventDispatcher.mediaPeriodCreated();
    }

    public void release() {
        this.playlistTracker.removeListener(this);
        for (HlsSampleStreamWrapper sampleStreamWrapper : this.sampleStreamWrappers) {
            sampleStreamWrapper.release();
        }
        this.callback = null;
        this.eventDispatcher.mediaPeriodReleased();
    }

    @Override // com.google.android.exoplayer2.source.MediaPeriod
    public void prepare(MediaPeriod.Callback callback, long positionUs) {
        this.callback = callback;
        this.playlistTracker.addListener(this);
        buildAndPrepareSampleStreamWrappers(positionUs);
    }

    @Override // com.google.android.exoplayer2.source.MediaPeriod
    public void maybeThrowPrepareError() throws IOException {
        for (HlsSampleStreamWrapper sampleStreamWrapper : this.sampleStreamWrappers) {
            sampleStreamWrapper.maybeThrowPrepareError();
        }
    }

    @Override // com.google.android.exoplayer2.source.MediaPeriod
    public TrackGroupArray getTrackGroups() {
        return this.trackGroups;
    }

    /* JADX WARN: Removed duplicated region for block: B:60:0x00f5  */
    @Override // com.google.android.exoplayer2.source.MediaPeriod
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public long selectTracks(com.google.android.exoplayer2.trackselection.TrackSelection[] r21, boolean[] r22, com.google.android.exoplayer2.source.SampleStream[] r23, boolean[] r24, long r25) {
        /*
            Method dump skipped, instruction units count: 302
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.exoplayer2.source.hls.HlsMediaPeriod.selectTracks(com.google.android.exoplayer2.trackselection.TrackSelection[], boolean[], com.google.android.exoplayer2.source.SampleStream[], boolean[], long):long");
    }

    @Override // com.google.android.exoplayer2.source.MediaPeriod
    public void discardBuffer(long positionUs, boolean toKeyframe) {
        for (HlsSampleStreamWrapper sampleStreamWrapper : this.enabledSampleStreamWrappers) {
            sampleStreamWrapper.discardBuffer(positionUs, toKeyframe);
        }
    }

    @Override // com.google.android.exoplayer2.source.MediaPeriod, com.google.android.exoplayer2.source.SequenceableLoader
    public void reevaluateBuffer(long positionUs) {
        this.compositeSequenceableLoader.reevaluateBuffer(positionUs);
    }

    @Override // com.google.android.exoplayer2.source.MediaPeriod, com.google.android.exoplayer2.source.SequenceableLoader
    public boolean continueLoading(long positionUs) {
        if (this.trackGroups == null) {
            for (HlsSampleStreamWrapper wrapper : this.sampleStreamWrappers) {
                wrapper.continuePreparing();
            }
            return false;
        }
        return this.compositeSequenceableLoader.continueLoading(positionUs);
    }

    @Override // com.google.android.exoplayer2.source.MediaPeriod, com.google.android.exoplayer2.source.SequenceableLoader
    public long getNextLoadPositionUs() {
        return this.compositeSequenceableLoader.getNextLoadPositionUs();
    }

    @Override // com.google.android.exoplayer2.source.MediaPeriod
    public long readDiscontinuity() {
        if (!this.notifiedReadingStarted) {
            this.eventDispatcher.readingStarted();
            this.notifiedReadingStarted = true;
            return C.TIME_UNSET;
        }
        return C.TIME_UNSET;
    }

    @Override // com.google.android.exoplayer2.source.MediaPeriod, com.google.android.exoplayer2.source.SequenceableLoader
    public long getBufferedPositionUs() {
        return this.compositeSequenceableLoader.getBufferedPositionUs();
    }

    @Override // com.google.android.exoplayer2.source.MediaPeriod
    public long seekToUs(long positionUs) {
        HlsSampleStreamWrapper[] hlsSampleStreamWrapperArr = this.enabledSampleStreamWrappers;
        if (hlsSampleStreamWrapperArr.length > 0) {
            boolean forceReset = hlsSampleStreamWrapperArr[0].seekToUs(positionUs, false);
            int i = 1;
            while (true) {
                HlsSampleStreamWrapper[] hlsSampleStreamWrapperArr2 = this.enabledSampleStreamWrappers;
                if (i >= hlsSampleStreamWrapperArr2.length) {
                    break;
                }
                hlsSampleStreamWrapperArr2[i].seekToUs(positionUs, forceReset);
                i++;
            }
            if (forceReset) {
                this.timestampAdjusterProvider.reset();
            }
        }
        return positionUs;
    }

    @Override // com.google.android.exoplayer2.source.MediaPeriod
    public long getAdjustedSeekPositionUs(long positionUs, SeekParameters seekParameters) {
        return positionUs;
    }

    @Override // com.google.android.exoplayer2.source.hls.HlsSampleStreamWrapper.Callback
    public void onPrepared() {
        int i = this.pendingPrepareCount - 1;
        this.pendingPrepareCount = i;
        if (i > 0) {
            return;
        }
        int totalTrackGroupCount = 0;
        for (HlsSampleStreamWrapper hlsSampleStreamWrapper : this.sampleStreamWrappers) {
            totalTrackGroupCount += hlsSampleStreamWrapper.getTrackGroups().length;
        }
        TrackGroup[] trackGroupArray = new TrackGroup[totalTrackGroupCount];
        int trackGroupIndex = 0;
        for (HlsSampleStreamWrapper sampleStreamWrapper : this.sampleStreamWrappers) {
            int wrapperTrackGroupCount = sampleStreamWrapper.getTrackGroups().length;
            int j = 0;
            while (j < wrapperTrackGroupCount) {
                trackGroupArray[trackGroupIndex] = sampleStreamWrapper.getTrackGroups().get(j);
                j++;
                trackGroupIndex++;
            }
        }
        this.trackGroups = new TrackGroupArray(trackGroupArray);
        this.callback.onPrepared(this);
    }

    @Override // com.google.android.exoplayer2.source.hls.HlsSampleStreamWrapper.Callback
    public void onPlaylistRefreshRequired(HlsMasterPlaylist.HlsUrl url) {
        this.playlistTracker.refreshPlaylist(url);
    }

    @Override // com.google.android.exoplayer2.source.SequenceableLoader.Callback
    public void onContinueLoadingRequested(HlsSampleStreamWrapper sampleStreamWrapper) {
        this.callback.onContinueLoadingRequested(this);
    }

    @Override // com.google.android.exoplayer2.source.hls.playlist.HlsPlaylistTracker.PlaylistEventListener
    public void onPlaylistChanged() {
        this.callback.onContinueLoadingRequested(this);
    }

    @Override // com.google.android.exoplayer2.source.hls.playlist.HlsPlaylistTracker.PlaylistEventListener
    public boolean onPlaylistError(HlsMasterPlaylist.HlsUrl url, long blacklistDurationMs) {
        boolean noBlacklistingFailure = true;
        for (HlsSampleStreamWrapper streamWrapper : this.sampleStreamWrappers) {
            noBlacklistingFailure &= streamWrapper.onPlaylistError(url, blacklistDurationMs);
        }
        this.callback.onContinueLoadingRequested(this);
        return noBlacklistingFailure;
    }

    /* JADX WARN: Incorrect condition in loop: B:4:0x002c */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private void buildAndPrepareSampleStreamWrappers(long r19) {
        /*
            Method dump skipped, instruction units count: 215
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.exoplayer2.source.hls.HlsMediaPeriod.buildAndPrepareSampleStreamWrappers(long):void");
    }

    private void buildAndPrepareMainSampleStreamWrapper(HlsMasterPlaylist masterPlaylist, long positionUs) {
        List<HlsMasterPlaylist.HlsUrl> selectedVariants;
        List<HlsMasterPlaylist.HlsUrl> selectedVariants2 = new ArrayList<>(masterPlaylist.variants);
        ArrayList<HlsMasterPlaylist.HlsUrl> definiteVideoVariants = new ArrayList<>();
        ArrayList<HlsMasterPlaylist.HlsUrl> definiteAudioOnlyVariants = new ArrayList<>();
        for (int i = 0; i < selectedVariants2.size(); i++) {
            HlsMasterPlaylist.HlsUrl variant = selectedVariants2.get(i);
            Format format = variant.format;
            if (format.height > 0 || Util.getCodecsOfType(format.codecs, 2) != null) {
                definiteVideoVariants.add(variant);
            } else if (Util.getCodecsOfType(format.codecs, 1) != null) {
                definiteAudioOnlyVariants.add(variant);
            }
        }
        if (!definiteVideoVariants.isEmpty()) {
            selectedVariants = definiteVideoVariants;
        } else {
            if (definiteAudioOnlyVariants.size() < selectedVariants2.size()) {
                selectedVariants2.removeAll(definiteAudioOnlyVariants);
            }
            selectedVariants = selectedVariants2;
        }
        Assertions.checkArgument(!selectedVariants.isEmpty());
        HlsMasterPlaylist.HlsUrl[] variants = (HlsMasterPlaylist.HlsUrl[]) selectedVariants.toArray(new HlsMasterPlaylist.HlsUrl[0]);
        String codecs = variants[0].format.codecs;
        HlsSampleStreamWrapper sampleStreamWrapper = buildSampleStreamWrapper(0, variants, masterPlaylist.muxedAudioFormat, masterPlaylist.muxedCaptionFormats, positionUs);
        this.sampleStreamWrappers[0] = sampleStreamWrapper;
        if (this.allowChunklessPreparation && codecs != null) {
            boolean variantsContainVideoCodecs = Util.getCodecsOfType(codecs, 2) != null;
            boolean variantsContainAudioCodecs = Util.getCodecsOfType(codecs, 1) != null;
            List<TrackGroup> muxedTrackGroups = new ArrayList<>();
            if (variantsContainVideoCodecs) {
                Format[] videoFormats = new Format[selectedVariants.size()];
                for (int i2 = 0; i2 < videoFormats.length; i2++) {
                    videoFormats[i2] = deriveVideoFormat(variants[i2].format);
                }
                muxedTrackGroups.add(new TrackGroup(videoFormats));
                if (variantsContainAudioCodecs && (masterPlaylist.muxedAudioFormat != null || masterPlaylist.audios.isEmpty())) {
                    muxedTrackGroups.add(new TrackGroup(deriveAudioFormat(variants[0].format, masterPlaylist.muxedAudioFormat, false)));
                }
                List<Format> ccFormats = masterPlaylist.muxedCaptionFormats;
                if (ccFormats != null) {
                    for (int i3 = 0; i3 < ccFormats.size(); i3++) {
                        muxedTrackGroups.add(new TrackGroup(ccFormats.get(i3)));
                    }
                }
            } else if (variantsContainAudioCodecs) {
                Format[] audioFormats = new Format[selectedVariants.size()];
                for (int i4 = 0; i4 < audioFormats.length; i4++) {
                    Format variantFormat = variants[i4].format;
                    audioFormats[i4] = deriveAudioFormat(variantFormat, masterPlaylist.muxedAudioFormat, true);
                }
                muxedTrackGroups.add(new TrackGroup(audioFormats));
            } else {
                throw new IllegalArgumentException("Unexpected codecs attribute: " + codecs);
            }
            TrackGroup id3TrackGroup = new TrackGroup(Format.createSampleFormat("ID3", MimeTypes.APPLICATION_ID3, null, -1, null));
            muxedTrackGroups.add(id3TrackGroup);
            sampleStreamWrapper.prepareWithMasterPlaylistInfo(new TrackGroupArray((TrackGroup[]) muxedTrackGroups.toArray(new TrackGroup[0])), 0, new TrackGroupArray(id3TrackGroup));
            return;
        }
        sampleStreamWrapper.setIsTimestampMaster(true);
        sampleStreamWrapper.continuePreparing();
    }

    private HlsSampleStreamWrapper buildSampleStreamWrapper(int trackType, HlsMasterPlaylist.HlsUrl[] variants, Format muxedAudioFormat, List<Format> muxedCaptionFormats, long positionUs) {
        HlsChunkSource defaultChunkSource = new HlsChunkSource(this.extractorFactory, this.playlistTracker, variants, this.dataSourceFactory, this.mediaTransferListener, this.timestampAdjusterProvider, muxedCaptionFormats);
        return new HlsSampleStreamWrapper(trackType, this, defaultChunkSource, this.allocator, positionUs, muxedAudioFormat, this.loadErrorHandlingPolicy, this.eventDispatcher);
    }

    private static Format deriveVideoFormat(Format variantFormat) {
        String codecs = Util.getCodecsOfType(variantFormat.codecs, 2);
        String sampleMimeType = MimeTypes.getMediaMimeType(codecs);
        return Format.createVideoContainerFormat(variantFormat.id, variantFormat.label, variantFormat.containerMimeType, sampleMimeType, codecs, variantFormat.bitrate, variantFormat.width, variantFormat.height, variantFormat.frameRate, null, variantFormat.selectionFlags);
    }

    private static Format deriveAudioFormat(Format variantFormat, Format mediaTagFormat, boolean isPrimaryTrackInVariant) {
        String codecs;
        int channelCount = -1;
        int selectionFlags = 0;
        String language = null;
        String label = null;
        if (mediaTagFormat != null) {
            codecs = mediaTagFormat.codecs;
            channelCount = mediaTagFormat.channelCount;
            selectionFlags = mediaTagFormat.selectionFlags;
            language = mediaTagFormat.language;
            label = mediaTagFormat.label;
        } else {
            codecs = Util.getCodecsOfType(variantFormat.codecs, 1);
            if (isPrimaryTrackInVariant) {
                channelCount = variantFormat.channelCount;
                selectionFlags = variantFormat.selectionFlags;
                language = variantFormat.label;
                label = variantFormat.label;
            }
        }
        String sampleMimeType = MimeTypes.getMediaMimeType(codecs);
        int bitrate = isPrimaryTrackInVariant ? variantFormat.bitrate : -1;
        return Format.createAudioContainerFormat(variantFormat.id, label, variantFormat.containerMimeType, sampleMimeType, codecs, bitrate, channelCount, -1, null, selectionFlags, language);
    }
}
