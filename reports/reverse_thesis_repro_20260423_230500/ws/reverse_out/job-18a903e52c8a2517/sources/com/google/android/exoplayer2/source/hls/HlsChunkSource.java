package com.google.android.exoplayer2.source.hls;

import android.net.Uri;
import android.os.SystemClock;
import com.google.android.exoplayer2.C;
import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.source.BehindLiveWindowException;
import com.google.android.exoplayer2.source.TrackGroup;
import com.google.android.exoplayer2.source.chunk.BaseMediaChunkIterator;
import com.google.android.exoplayer2.source.chunk.Chunk;
import com.google.android.exoplayer2.source.chunk.DataChunk;
import com.google.android.exoplayer2.source.chunk.MediaChunk;
import com.google.android.exoplayer2.source.chunk.MediaChunkIterator;
import com.google.android.exoplayer2.source.hls.playlist.HlsMasterPlaylist;
import com.google.android.exoplayer2.source.hls.playlist.HlsMediaPlaylist;
import com.google.android.exoplayer2.source.hls.playlist.HlsPlaylistTracker;
import com.google.android.exoplayer2.trackselection.BaseTrackSelection;
import com.google.android.exoplayer2.trackselection.TrackSelection;
import com.google.android.exoplayer2.upstream.DataSource;
import com.google.android.exoplayer2.upstream.DataSpec;
import com.google.android.exoplayer2.upstream.TransferListener;
import com.google.android.exoplayer2.util.TimestampAdjuster;
import com.google.android.exoplayer2.util.UriUtil;
import com.google.android.exoplayer2.util.Util;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

/* JADX INFO: loaded from: classes2.dex */
class HlsChunkSource {
    private final DataSource encryptionDataSource;
    private byte[] encryptionIv;
    private String encryptionIvString;
    private byte[] encryptionKey;
    private Uri encryptionKeyUri;
    private HlsMasterPlaylist.HlsUrl expectedPlaylistUrl;
    private final HlsExtractorFactory extractorFactory;
    private IOException fatalError;
    private boolean independentSegments;
    private boolean isTimestampMaster;
    private long liveEdgeInPeriodTimeUs = C.TIME_UNSET;
    private final DataSource mediaDataSource;
    private final List<Format> muxedCaptionFormats;
    private final HlsPlaylistTracker playlistTracker;
    private byte[] scratchSpace;
    private boolean seenExpectedPlaylistError;
    private final TimestampAdjusterProvider timestampAdjusterProvider;
    private final TrackGroup trackGroup;
    private TrackSelection trackSelection;
    private final HlsMasterPlaylist.HlsUrl[] variants;

    public static final class HlsChunkHolder {
        public Chunk chunk;
        public boolean endOfStream;
        public HlsMasterPlaylist.HlsUrl playlist;

        public HlsChunkHolder() {
            clear();
        }

        public void clear() {
            this.chunk = null;
            this.endOfStream = false;
            this.playlist = null;
        }
    }

    public HlsChunkSource(HlsExtractorFactory extractorFactory, HlsPlaylistTracker playlistTracker, HlsMasterPlaylist.HlsUrl[] variants, HlsDataSourceFactory dataSourceFactory, TransferListener mediaTransferListener, TimestampAdjusterProvider timestampAdjusterProvider, List<Format> muxedCaptionFormats) {
        this.extractorFactory = extractorFactory;
        this.playlistTracker = playlistTracker;
        this.variants = variants;
        this.timestampAdjusterProvider = timestampAdjusterProvider;
        this.muxedCaptionFormats = muxedCaptionFormats;
        Format[] variantFormats = new Format[variants.length];
        int[] initialTrackSelection = new int[variants.length];
        for (int i = 0; i < variants.length; i++) {
            variantFormats[i] = variants[i].format;
            initialTrackSelection[i] = i;
        }
        DataSource dataSourceCreateDataSource = dataSourceFactory.createDataSource(1);
        this.mediaDataSource = dataSourceCreateDataSource;
        if (mediaTransferListener != null) {
            dataSourceCreateDataSource.addTransferListener(mediaTransferListener);
        }
        this.encryptionDataSource = dataSourceFactory.createDataSource(3);
        TrackGroup trackGroup = new TrackGroup(variantFormats);
        this.trackGroup = trackGroup;
        this.trackSelection = new InitializationTrackSelection(trackGroup, initialTrackSelection);
    }

    public void maybeThrowError() throws IOException {
        IOException iOException = this.fatalError;
        if (iOException != null) {
            throw iOException;
        }
        HlsMasterPlaylist.HlsUrl hlsUrl = this.expectedPlaylistUrl;
        if (hlsUrl != null && this.seenExpectedPlaylistError) {
            this.playlistTracker.maybeThrowPlaylistRefreshError(hlsUrl);
        }
    }

    public TrackGroup getTrackGroup() {
        return this.trackGroup;
    }

    public void selectTracks(TrackSelection trackSelection) {
        this.trackSelection = trackSelection;
    }

    public TrackSelection getTrackSelection() {
        return this.trackSelection;
    }

    public void reset() {
        this.fatalError = null;
    }

    public void setIsTimestampMaster(boolean isTimestampMaster) {
        this.isTimestampMaster = isTimestampMaster;
    }

    public void getNextChunk(long playbackPositionUs, long loadPositionUs, List<HlsMediaChunk> queue, HlsChunkHolder out) {
        long timeToLiveEdgeUs;
        long bufferedDurationUs;
        long chunkMediaSequence;
        int selectedVariantIndex;
        long startOfPlaylistInPeriodUs;
        HlsMasterPlaylist.HlsUrl selectedUrl;
        HlsMediaPlaylist.Segment segment;
        HlsMediaChunk previous = queue.isEmpty() ? null : queue.get(queue.size() - 1);
        int oldVariantIndex = previous == null ? -1 : this.trackGroup.indexOf(previous.trackFormat);
        long bufferedDurationUs2 = loadPositionUs - playbackPositionUs;
        long timeToLiveEdgeUs2 = resolveTimeToLiveEdgeUs(playbackPositionUs);
        if (previous != null && !this.independentSegments) {
            long subtractedDurationUs = previous.getDurationUs();
            bufferedDurationUs = Math.max(0L, bufferedDurationUs2 - subtractedDurationUs);
            if (timeToLiveEdgeUs2 == C.TIME_UNSET) {
                timeToLiveEdgeUs = timeToLiveEdgeUs2;
            } else {
                timeToLiveEdgeUs = Math.max(0L, timeToLiveEdgeUs2 - subtractedDurationUs);
            }
        } else {
            timeToLiveEdgeUs = timeToLiveEdgeUs2;
            bufferedDurationUs = bufferedDurationUs2;
        }
        MediaChunkIterator[] mediaChunkIterators = createMediaChunkIterators(previous, loadPositionUs);
        this.trackSelection.updateSelectedTrack(playbackPositionUs, bufferedDurationUs, timeToLiveEdgeUs, queue, mediaChunkIterators);
        int selectedVariantIndex2 = this.trackSelection.getSelectedIndexInTrackGroup();
        boolean switchingVariant = oldVariantIndex != selectedVariantIndex2;
        HlsMasterPlaylist.HlsUrl selectedUrl2 = this.variants[selectedVariantIndex2];
        if (!this.playlistTracker.isSnapshotValid(selectedUrl2)) {
            out.playlist = selectedUrl2;
            this.seenExpectedPlaylistError &= this.expectedPlaylistUrl == selectedUrl2;
            this.expectedPlaylistUrl = selectedUrl2;
            return;
        }
        HlsMediaPlaylist mediaPlaylist = this.playlistTracker.getPlaylistSnapshot(selectedUrl2, true);
        this.independentSegments = mediaPlaylist.hasIndependentSegments;
        updateLiveEdgeTimeUs(mediaPlaylist);
        long startOfPlaylistInPeriodUs2 = mediaPlaylist.startTimeUs - this.playlistTracker.getInitialStartTimeUs();
        HlsMediaPlaylist mediaPlaylist2 = mediaPlaylist;
        long chunkMediaSequence2 = getChunkMediaSequence(previous, switchingVariant, mediaPlaylist, startOfPlaylistInPeriodUs2, loadPositionUs);
        if (chunkMediaSequence2 >= mediaPlaylist2.mediaSequence) {
            chunkMediaSequence = chunkMediaSequence2;
            selectedVariantIndex = selectedVariantIndex2;
            startOfPlaylistInPeriodUs = startOfPlaylistInPeriodUs2;
            selectedUrl = selectedUrl2;
        } else {
            if (previous == null || !switchingVariant) {
                this.fatalError = new BehindLiveWindowException();
                return;
            }
            HlsMasterPlaylist.HlsUrl selectedUrl3 = this.variants[oldVariantIndex];
            HlsMediaPlaylist mediaPlaylist3 = this.playlistTracker.getPlaylistSnapshot(selectedUrl3, true);
            mediaPlaylist2 = mediaPlaylist3;
            selectedVariantIndex = oldVariantIndex;
            startOfPlaylistInPeriodUs = mediaPlaylist3.startTimeUs - this.playlistTracker.getInitialStartTimeUs();
            selectedUrl = selectedUrl3;
            chunkMediaSequence = previous.getNextChunkIndex();
        }
        int chunkIndex = (int) (chunkMediaSequence - mediaPlaylist2.mediaSequence);
        if (chunkIndex < mediaPlaylist2.segments.size()) {
            this.seenExpectedPlaylistError = false;
            this.expectedPlaylistUrl = null;
            HlsMediaPlaylist.Segment segment2 = mediaPlaylist2.segments.get(chunkIndex);
            if (segment2.fullSegmentEncryptionKeyUri != null) {
                Uri keyUri = UriUtil.resolveToUri(mediaPlaylist2.baseUri, segment2.fullSegmentEncryptionKeyUri);
                if (keyUri.equals(this.encryptionKeyUri)) {
                    segment = segment2;
                    if (!Util.areEqual(segment.encryptionIV, this.encryptionIvString)) {
                        setEncryptionData(keyUri, segment.encryptionIV, this.encryptionKey);
                    }
                } else {
                    out.chunk = newEncryptionKeyChunk(keyUri, segment2.encryptionIV, selectedVariantIndex, this.trackSelection.getSelectionReason(), this.trackSelection.getSelectionData());
                    return;
                }
            } else {
                segment = segment2;
                clearEncryptionData();
            }
            DataSpec initDataSpec = null;
            HlsMediaPlaylist.Segment initSegment = segment.initializationSegment;
            if (initSegment != null) {
                Uri initSegmentUri = UriUtil.resolveToUri(mediaPlaylist2.baseUri, initSegment.url);
                initDataSpec = new DataSpec(initSegmentUri, initSegment.byterangeOffset, initSegment.byterangeLength, null);
            }
            long segmentStartTimeInPeriodUs = startOfPlaylistInPeriodUs + segment.relativeStartTimeUs;
            int discontinuitySequence = mediaPlaylist2.discontinuitySequence + segment.relativeDiscontinuitySequence;
            TimestampAdjuster timestampAdjuster = this.timestampAdjusterProvider.getAdjuster(discontinuitySequence);
            Uri chunkUri = UriUtil.resolveToUri(mediaPlaylist2.baseUri, segment.url);
            DataSpec dataSpec = new DataSpec(chunkUri, segment.byterangeOffset, segment.byterangeLength, null);
            out.chunk = new HlsMediaChunk(this.extractorFactory, this.mediaDataSource, dataSpec, initDataSpec, selectedUrl, this.muxedCaptionFormats, this.trackSelection.getSelectionReason(), this.trackSelection.getSelectionData(), segmentStartTimeInPeriodUs, segmentStartTimeInPeriodUs + segment.durationUs, chunkMediaSequence, discontinuitySequence, segment.hasGapTag, this.isTimestampMaster, timestampAdjuster, previous, segment.drmInitData, this.encryptionKey, this.encryptionIv);
            return;
        }
        if (mediaPlaylist2.hasEndTag) {
            out.endOfStream = true;
            return;
        }
        out.playlist = selectedUrl;
        this.seenExpectedPlaylistError = (this.expectedPlaylistUrl == selectedUrl) & this.seenExpectedPlaylistError;
        this.expectedPlaylistUrl = selectedUrl;
    }

    public void onChunkLoadCompleted(Chunk chunk) {
        if (chunk instanceof EncryptionKeyChunk) {
            EncryptionKeyChunk encryptionKeyChunk = (EncryptionKeyChunk) chunk;
            this.scratchSpace = encryptionKeyChunk.getDataHolder();
            setEncryptionData(encryptionKeyChunk.dataSpec.uri, encryptionKeyChunk.iv, encryptionKeyChunk.getResult());
        }
    }

    public boolean maybeBlacklistTrack(Chunk chunk, long blacklistDurationMs) {
        TrackSelection trackSelection = this.trackSelection;
        return trackSelection.blacklist(trackSelection.indexOf(this.trackGroup.indexOf(chunk.trackFormat)), blacklistDurationMs);
    }

    public boolean onPlaylistError(HlsMasterPlaylist.HlsUrl url, long blacklistDurationMs) {
        int trackSelectionIndex;
        int trackGroupIndex = this.trackGroup.indexOf(url.format);
        if (trackGroupIndex == -1 || (trackSelectionIndex = this.trackSelection.indexOf(trackGroupIndex)) == -1) {
            return true;
        }
        this.seenExpectedPlaylistError |= this.expectedPlaylistUrl == url;
        return blacklistDurationMs == C.TIME_UNSET || this.trackSelection.blacklist(trackSelectionIndex, blacklistDurationMs);
    }

    public MediaChunkIterator[] createMediaChunkIterators(HlsMediaChunk previous, long loadPositionUs) {
        HlsChunkSource hlsChunkSource = this;
        int oldVariantIndex = previous == null ? -1 : hlsChunkSource.trackGroup.indexOf(previous.trackFormat);
        MediaChunkIterator[] chunkIterators = new MediaChunkIterator[hlsChunkSource.trackSelection.length()];
        int i = 0;
        while (i < chunkIterators.length) {
            int variantIndex = hlsChunkSource.trackSelection.getIndexInTrackGroup(i);
            HlsMasterPlaylist.HlsUrl variantUrl = hlsChunkSource.variants[variantIndex];
            if (!hlsChunkSource.playlistTracker.isSnapshotValid(variantUrl)) {
                chunkIterators[i] = MediaChunkIterator.EMPTY;
            } else {
                HlsMediaPlaylist playlist = hlsChunkSource.playlistTracker.getPlaylistSnapshot(variantUrl, false);
                long startOfPlaylistInPeriodUs = playlist.startTimeUs - hlsChunkSource.playlistTracker.getInitialStartTimeUs();
                boolean switchingVariant = variantIndex != oldVariantIndex;
                long chunkMediaSequence = getChunkMediaSequence(previous, switchingVariant, playlist, startOfPlaylistInPeriodUs, loadPositionUs);
                if (chunkMediaSequence < playlist.mediaSequence) {
                    chunkIterators[i] = MediaChunkIterator.EMPTY;
                } else {
                    int chunkIndex = (int) (chunkMediaSequence - playlist.mediaSequence);
                    chunkIterators[i] = new HlsMediaPlaylistSegmentIterator(playlist, startOfPlaylistInPeriodUs, chunkIndex);
                }
            }
            i++;
            hlsChunkSource = this;
        }
        return chunkIterators;
    }

    private long getChunkMediaSequence(HlsMediaChunk previous, boolean switchingVariant, HlsMediaPlaylist mediaPlaylist, long startOfPlaylistInPeriodUs, long loadPositionUs) {
        if (previous == null || switchingVariant) {
            long endOfPlaylistInPeriodUs = startOfPlaylistInPeriodUs + mediaPlaylist.durationUs;
            long targetPositionInPeriodUs = (previous == null || this.independentSegments) ? loadPositionUs : previous.startTimeUs;
            if (!mediaPlaylist.hasEndTag && targetPositionInPeriodUs >= endOfPlaylistInPeriodUs) {
                return mediaPlaylist.mediaSequence + ((long) mediaPlaylist.segments.size());
            }
            long targetPositionInPlaylistUs = targetPositionInPeriodUs - startOfPlaylistInPeriodUs;
            return ((long) Util.binarySearchFloor((List<? extends Comparable<? super Long>>) mediaPlaylist.segments, Long.valueOf(targetPositionInPlaylistUs), true, !this.playlistTracker.isLive() || previous == null)) + mediaPlaylist.mediaSequence;
        }
        return previous.getNextChunkIndex();
    }

    private long resolveTimeToLiveEdgeUs(long playbackPositionUs) {
        boolean resolveTimeToLiveEdgePossible = this.liveEdgeInPeriodTimeUs != C.TIME_UNSET;
        return resolveTimeToLiveEdgePossible ? this.liveEdgeInPeriodTimeUs - playbackPositionUs : C.TIME_UNSET;
    }

    private void updateLiveEdgeTimeUs(HlsMediaPlaylist mediaPlaylist) {
        this.liveEdgeInPeriodTimeUs = mediaPlaylist.hasEndTag ? C.TIME_UNSET : mediaPlaylist.getEndTimeUs() - this.playlistTracker.getInitialStartTimeUs();
    }

    private EncryptionKeyChunk newEncryptionKeyChunk(Uri keyUri, String iv, int variantIndex, int trackSelectionReason, Object trackSelectionData) {
        DataSpec dataSpec = new DataSpec(keyUri, 0L, -1L, null, 1);
        return new EncryptionKeyChunk(this.encryptionDataSource, dataSpec, this.variants[variantIndex].format, trackSelectionReason, trackSelectionData, this.scratchSpace, iv);
    }

    private void setEncryptionData(Uri keyUri, String iv, byte[] secretKey) {
        String trimmedIv;
        if (Util.toLowerInvariant(iv).startsWith("0x")) {
            trimmedIv = iv.substring(2);
        } else {
            trimmedIv = iv;
        }
        byte[] ivData = new BigInteger(trimmedIv, 16).toByteArray();
        byte[] ivDataWithPadding = new byte[16];
        int offset = ivData.length > 16 ? ivData.length - 16 : 0;
        System.arraycopy(ivData, offset, ivDataWithPadding, (ivDataWithPadding.length - ivData.length) + offset, ivData.length - offset);
        this.encryptionKeyUri = keyUri;
        this.encryptionKey = secretKey;
        this.encryptionIvString = iv;
        this.encryptionIv = ivDataWithPadding;
    }

    private void clearEncryptionData() {
        this.encryptionKeyUri = null;
        this.encryptionKey = null;
        this.encryptionIvString = null;
        this.encryptionIv = null;
    }

    private static final class InitializationTrackSelection extends BaseTrackSelection {
        private int selectedIndex;

        public InitializationTrackSelection(TrackGroup group, int[] tracks) {
            super(group, tracks);
            this.selectedIndex = indexOf(group.getFormat(0));
        }

        @Override // com.google.android.exoplayer2.trackselection.BaseTrackSelection, com.google.android.exoplayer2.trackselection.TrackSelection
        public void updateSelectedTrack(long playbackPositionUs, long bufferedDurationUs, long availableDurationUs, List<? extends MediaChunk> queue, MediaChunkIterator[] mediaChunkIterators) {
            long nowMs = SystemClock.elapsedRealtime();
            if (!isBlacklisted(this.selectedIndex, nowMs)) {
                return;
            }
            for (int i = this.length - 1; i >= 0; i--) {
                if (!isBlacklisted(i, nowMs)) {
                    this.selectedIndex = i;
                    return;
                }
            }
            throw new IllegalStateException();
        }

        @Override // com.google.android.exoplayer2.trackselection.TrackSelection
        public int getSelectedIndex() {
            return this.selectedIndex;
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

    private static final class EncryptionKeyChunk extends DataChunk {
        public final String iv;
        private byte[] result;

        public EncryptionKeyChunk(DataSource dataSource, DataSpec dataSpec, Format trackFormat, int trackSelectionReason, Object trackSelectionData, byte[] scratchSpace, String iv) {
            super(dataSource, dataSpec, 3, trackFormat, trackSelectionReason, trackSelectionData, scratchSpace);
            this.iv = iv;
        }

        @Override // com.google.android.exoplayer2.source.chunk.DataChunk
        protected void consume(byte[] data, int limit) throws IOException {
            this.result = Arrays.copyOf(data, limit);
        }

        public byte[] getResult() {
            return this.result;
        }
    }

    private static final class HlsMediaPlaylistSegmentIterator extends BaseMediaChunkIterator {
        private final HlsMediaPlaylist playlist;
        private final long startOfPlaylistInPeriodUs;

        public HlsMediaPlaylistSegmentIterator(HlsMediaPlaylist playlist, long startOfPlaylistInPeriodUs, int chunkIndex) {
            super(chunkIndex, playlist.segments.size() - 1);
            this.playlist = playlist;
            this.startOfPlaylistInPeriodUs = startOfPlaylistInPeriodUs;
        }

        @Override // com.google.android.exoplayer2.source.chunk.MediaChunkIterator
        public DataSpec getDataSpec() {
            checkInBounds();
            HlsMediaPlaylist.Segment segment = this.playlist.segments.get((int) getCurrentIndex());
            Uri chunkUri = UriUtil.resolveToUri(this.playlist.baseUri, segment.url);
            return new DataSpec(chunkUri, segment.byterangeOffset, segment.byterangeLength, null);
        }

        @Override // com.google.android.exoplayer2.source.chunk.MediaChunkIterator
        public long getChunkStartTimeUs() {
            checkInBounds();
            HlsMediaPlaylist.Segment segment = this.playlist.segments.get((int) getCurrentIndex());
            return this.startOfPlaylistInPeriodUs + segment.relativeStartTimeUs;
        }

        @Override // com.google.android.exoplayer2.source.chunk.MediaChunkIterator
        public long getChunkEndTimeUs() {
            checkInBounds();
            HlsMediaPlaylist.Segment segment = this.playlist.segments.get((int) getCurrentIndex());
            long segmentStartTimeInPeriodUs = this.startOfPlaylistInPeriodUs + segment.relativeStartTimeUs;
            return segment.durationUs + segmentStartTimeInPeriodUs;
        }
    }
}
