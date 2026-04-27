package com.google.android.exoplayer2.source.hls;

import android.util.Pair;
import com.google.android.exoplayer2.C;
import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.drm.DrmInitData;
import com.google.android.exoplayer2.extractor.DefaultExtractorInput;
import com.google.android.exoplayer2.extractor.Extractor;
import com.google.android.exoplayer2.extractor.ExtractorInput;
import com.google.android.exoplayer2.metadata.Metadata;
import com.google.android.exoplayer2.metadata.id3.Id3Decoder;
import com.google.android.exoplayer2.metadata.id3.PrivFrame;
import com.google.android.exoplayer2.source.chunk.MediaChunk;
import com.google.android.exoplayer2.source.hls.playlist.HlsMasterPlaylist;
import com.google.android.exoplayer2.upstream.DataSource;
import com.google.android.exoplayer2.upstream.DataSpec;
import com.google.android.exoplayer2.util.ParsableByteArray;
import com.google.android.exoplayer2.util.TimestampAdjuster;
import com.google.android.exoplayer2.util.Util;
import java.io.EOFException;
import java.io.IOException;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/* JADX INFO: loaded from: classes2.dex */
final class HlsMediaChunk extends MediaChunk {
    public static final String PRIV_TIMESTAMP_FRAME_OWNER = "com.apple.streaming.transportStreamTimestamp";
    private static final AtomicInteger uidSource = new AtomicInteger();
    public final int discontinuitySequenceNumber;
    private final DrmInitData drmInitData;
    private Extractor extractor;
    private final HlsExtractorFactory extractorFactory;
    private final boolean hasGapTag;
    public final HlsMasterPlaylist.HlsUrl hlsUrl;
    private final ParsableByteArray id3Data;
    private final Id3Decoder id3Decoder;
    private final DataSource initDataSource;
    private final DataSpec initDataSpec;
    private boolean initLoadCompleted;
    private int initSegmentBytesLoaded;
    private final boolean isEncrypted;
    private final boolean isMasterTimestampSource;
    private volatile boolean loadCanceled;
    private boolean loadCompleted;
    private final List<Format> muxedCaptionFormats;
    private int nextLoadPosition;
    private HlsSampleStreamWrapper output;
    private final Extractor previousExtractor;
    private final boolean shouldSpliceIn;
    private final TimestampAdjuster timestampAdjuster;
    public final int uid;

    public HlsMediaChunk(HlsExtractorFactory extractorFactory, DataSource dataSource, DataSpec dataSpec, DataSpec initDataSpec, HlsMasterPlaylist.HlsUrl hlsUrl, List<Format> muxedCaptionFormats, int trackSelectionReason, Object trackSelectionData, long startTimeUs, long endTimeUs, long chunkMediaSequence, int discontinuitySequenceNumber, boolean hasGapTag, boolean isMasterTimestampSource, TimestampAdjuster timestampAdjuster, HlsMediaChunk previousChunk, DrmInitData drmInitData, byte[] fullSegmentEncryptionKey, byte[] encryptionIv) {
        super(buildDataSource(dataSource, fullSegmentEncryptionKey, encryptionIv), dataSpec, hlsUrl.format, trackSelectionReason, trackSelectionData, startTimeUs, endTimeUs, chunkMediaSequence);
        this.discontinuitySequenceNumber = discontinuitySequenceNumber;
        this.initDataSpec = initDataSpec;
        this.hlsUrl = hlsUrl;
        this.isMasterTimestampSource = isMasterTimestampSource;
        this.timestampAdjuster = timestampAdjuster;
        boolean z = true;
        this.isEncrypted = fullSegmentEncryptionKey != null;
        this.hasGapTag = hasGapTag;
        this.extractorFactory = extractorFactory;
        this.muxedCaptionFormats = muxedCaptionFormats;
        this.drmInitData = drmInitData;
        Extractor previousExtractor = null;
        if (previousChunk != null) {
            this.id3Decoder = previousChunk.id3Decoder;
            this.id3Data = previousChunk.id3Data;
            if (previousChunk.hlsUrl == hlsUrl && previousChunk.loadCompleted) {
                z = false;
            }
            this.shouldSpliceIn = z;
            previousExtractor = (previousChunk.discontinuitySequenceNumber != discontinuitySequenceNumber || z) ? null : previousChunk.extractor;
        } else {
            this.id3Decoder = new Id3Decoder();
            this.id3Data = new ParsableByteArray(10);
            this.shouldSpliceIn = false;
        }
        this.previousExtractor = previousExtractor;
        this.initDataSource = dataSource;
        this.uid = uidSource.getAndIncrement();
    }

    public void init(HlsSampleStreamWrapper output) {
        this.output = output;
    }

    @Override // com.google.android.exoplayer2.source.chunk.MediaChunk
    public boolean isLoadCompleted() {
        return this.loadCompleted;
    }

    @Override // com.google.android.exoplayer2.upstream.Loader.Loadable
    public void cancelLoad() {
        this.loadCanceled = true;
    }

    @Override // com.google.android.exoplayer2.upstream.Loader.Loadable
    public void load() throws InterruptedException, IOException {
        maybeLoadInitData();
        if (!this.loadCanceled) {
            if (!this.hasGapTag) {
                loadMedia();
            }
            this.loadCompleted = true;
        }
    }

    private void maybeLoadInitData() throws InterruptedException, IOException {
        DataSpec dataSpec;
        if (this.initLoadCompleted || (dataSpec = this.initDataSpec) == null) {
            return;
        }
        DataSpec initSegmentDataSpec = dataSpec.subrange(this.initSegmentBytesLoaded);
        try {
            DefaultExtractorInput input = prepareExtraction(this.initDataSource, initSegmentDataSpec);
            int result = 0;
            while (result == 0) {
                try {
                    if (this.loadCanceled) {
                        break;
                    } else {
                        result = this.extractor.read(input, null);
                    }
                } finally {
                    this.initSegmentBytesLoaded = (int) (input.getPosition() - this.initDataSpec.absoluteStreamPosition);
                }
            }
            Util.closeQuietly(this.initDataSource);
            this.initLoadCompleted = true;
        } catch (Throwable th) {
            Util.closeQuietly(this.initDataSource);
            throw th;
        }
    }

    private void loadMedia() throws InterruptedException, IOException {
        DataSpec loadDataSpec;
        boolean skipLoadedBytes;
        if (this.isEncrypted) {
            loadDataSpec = this.dataSpec;
            skipLoadedBytes = this.nextLoadPosition != 0;
        } else {
            DataSpec loadDataSpec2 = this.dataSpec;
            loadDataSpec = loadDataSpec2.subrange(this.nextLoadPosition);
            skipLoadedBytes = false;
        }
        if (!this.isMasterTimestampSource) {
            this.timestampAdjuster.waitUntilInitialized();
        } else if (this.timestampAdjuster.getFirstSampleTimestampUs() == Long.MAX_VALUE) {
            this.timestampAdjuster.setFirstSampleTimestampUs(this.startTimeUs);
        }
        try {
            ExtractorInput input = prepareExtraction(this.dataSource, loadDataSpec);
            if (skipLoadedBytes) {
                input.skipFully(this.nextLoadPosition);
            }
            int result = 0;
            while (result == 0) {
                try {
                    if (this.loadCanceled) {
                        break;
                    } else {
                        result = this.extractor.read(input, null);
                    }
                } finally {
                    this.nextLoadPosition = (int) (input.getPosition() - this.dataSpec.absoluteStreamPosition);
                }
            }
        } finally {
            Util.closeQuietly(this.dataSource);
        }
    }

    private DefaultExtractorInput prepareExtraction(DataSource dataSource, DataSpec dataSpec) throws InterruptedException, IOException {
        long jAdjustTsTimestamp;
        long bytesToRead = dataSource.open(dataSpec);
        DefaultExtractorInput extractorInput = new DefaultExtractorInput(dataSource, dataSpec.absoluteStreamPosition, bytesToRead);
        if (this.extractor == null) {
            long id3Timestamp = peekId3PrivTimestamp(extractorInput);
            extractorInput.resetPeekPosition();
            Pair<Extractor, Boolean> extractorData = this.extractorFactory.createExtractor(this.previousExtractor, dataSpec.uri, this.trackFormat, this.muxedCaptionFormats, this.drmInitData, this.timestampAdjuster, dataSource.getResponseHeaders(), extractorInput);
            Extractor extractor = (Extractor) extractorData.first;
            this.extractor = extractor;
            boolean reusingExtractor = extractor == this.previousExtractor;
            boolean isPackedAudioExtractor = ((Boolean) extractorData.second).booleanValue();
            if (isPackedAudioExtractor) {
                HlsSampleStreamWrapper hlsSampleStreamWrapper = this.output;
                if (id3Timestamp == C.TIME_UNSET) {
                    jAdjustTsTimestamp = this.startTimeUs;
                } else {
                    jAdjustTsTimestamp = this.timestampAdjuster.adjustTsTimestamp(id3Timestamp);
                }
                hlsSampleStreamWrapper.setSampleOffsetUs(jAdjustTsTimestamp);
            }
            this.initLoadCompleted = reusingExtractor && this.initDataSpec != null;
            this.output.init(this.uid, this.shouldSpliceIn, reusingExtractor);
            if (!reusingExtractor) {
                this.extractor.init(this.output);
            }
        }
        return extractorInput;
    }

    private long peekId3PrivTimestamp(ExtractorInput input) throws InterruptedException, IOException {
        input.resetPeekPosition();
        try {
            input.peekFully(this.id3Data.data, 0, 10);
            this.id3Data.reset(10);
            int id = this.id3Data.readUnsignedInt24();
            if (id != Id3Decoder.ID3_TAG) {
                return C.TIME_UNSET;
            }
            this.id3Data.skipBytes(3);
            int id3Size = this.id3Data.readSynchSafeInt();
            int requiredCapacity = id3Size + 10;
            if (requiredCapacity > this.id3Data.capacity()) {
                byte[] data = this.id3Data.data;
                this.id3Data.reset(requiredCapacity);
                System.arraycopy(data, 0, this.id3Data.data, 0, 10);
            }
            input.peekFully(this.id3Data.data, 10, id3Size);
            Metadata metadata = this.id3Decoder.decode(this.id3Data.data, id3Size);
            if (metadata == null) {
                return C.TIME_UNSET;
            }
            int metadataLength = metadata.length();
            for (int i = 0; i < metadataLength; i++) {
                Metadata.Entry frame = metadata.get(i);
                if (frame instanceof PrivFrame) {
                    PrivFrame privFrame = (PrivFrame) frame;
                    if (PRIV_TIMESTAMP_FRAME_OWNER.equals(privFrame.owner)) {
                        System.arraycopy(privFrame.privateData, 0, this.id3Data.data, 0, 8);
                        this.id3Data.reset(8);
                        return this.id3Data.readLong() & 8589934591L;
                    }
                }
            }
            return C.TIME_UNSET;
        } catch (EOFException e) {
            return C.TIME_UNSET;
        }
    }

    private static DataSource buildDataSource(DataSource dataSource, byte[] fullSegmentEncryptionKey, byte[] encryptionIv) {
        if (fullSegmentEncryptionKey != null) {
            return new Aes128DataSource(dataSource, fullSegmentEncryptionKey, encryptionIv);
        }
        return dataSource;
    }
}
