package com.google.android.exoplayer2.ext.flac;

import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.ext.flac.FlacDecoderJni;
import com.google.android.exoplayer2.extractor.BinarySearchSeeker;
import com.google.android.exoplayer2.extractor.Extractor;
import com.google.android.exoplayer2.extractor.ExtractorInput;
import com.google.android.exoplayer2.extractor.ExtractorOutput;
import com.google.android.exoplayer2.extractor.ExtractorsFactory;
import com.google.android.exoplayer2.extractor.Id3Peeker;
import com.google.android.exoplayer2.extractor.PositionHolder;
import com.google.android.exoplayer2.extractor.SeekMap;
import com.google.android.exoplayer2.extractor.SeekPoint;
import com.google.android.exoplayer2.extractor.TrackOutput;
import com.google.android.exoplayer2.metadata.Metadata;
import com.google.android.exoplayer2.metadata.id3.Id3Decoder;
import com.google.android.exoplayer2.util.FlacStreamInfo;
import com.google.android.exoplayer2.util.MimeTypes;
import com.google.android.exoplayer2.util.ParsableByteArray;
import com.google.android.exoplayer2.util.Util;
import java.io.IOException;
import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.nio.ByteBuffer;
import java.util.Arrays;

/* JADX INFO: loaded from: classes2.dex */
public final class FlacExtractor implements Extractor {
    public static final ExtractorsFactory FACTORY = new ExtractorsFactory() { // from class: com.google.android.exoplayer2.ext.flac.-$$Lambda$FlacExtractor$hclvvK8AqHrca9y8kXj1zx0IKB4
        @Override // com.google.android.exoplayer2.extractor.ExtractorsFactory
        public final Extractor[] createExtractors() {
            return FlacExtractor.lambda$static$0();
        }
    };
    private static final byte[] FLAC_SIGNATURE = {102, 76, 97, 67, 0, 0, 0, 34};
    public static final int FLAG_DISABLE_ID3_METADATA = 1;
    private FlacDecoderJni decoderJni;
    private ExtractorOutput extractorOutput;
    private FlacBinarySearchSeeker flacBinarySearchSeeker;
    private Metadata id3Metadata;
    private final Id3Peeker id3Peeker;
    private final boolean isId3MetadataDisabled;
    private ParsableByteArray outputBuffer;
    private ByteBuffer outputByteBuffer;
    private BinarySearchSeeker.OutputFrameHolder outputFrameHolder;
    private boolean readPastStreamInfo;
    private FlacStreamInfo streamInfo;
    private TrackOutput trackOutput;

    @Documented
    @Retention(RetentionPolicy.SOURCE)
    public @interface Flags {
    }

    static /* synthetic */ Extractor[] lambda$static$0() {
        return new Extractor[]{new FlacExtractor()};
    }

    public FlacExtractor() {
        this(0);
    }

    public FlacExtractor(int flags) {
        this.id3Peeker = new Id3Peeker();
        this.isId3MetadataDisabled = (flags & 1) != 0;
    }

    @Override // com.google.android.exoplayer2.extractor.Extractor
    public void init(ExtractorOutput output) {
        this.extractorOutput = output;
        this.trackOutput = output.track(0, 1);
        this.extractorOutput.endTracks();
        try {
            this.decoderJni = new FlacDecoderJni();
        } catch (FlacDecoderException e) {
            throw new RuntimeException(e);
        }
    }

    @Override // com.google.android.exoplayer2.extractor.Extractor
    public boolean sniff(ExtractorInput input) throws InterruptedException, IOException {
        if (input.getPosition() == 0) {
            this.id3Metadata = peekId3Data(input);
        }
        return peekFlacSignature(input);
    }

    @Override // com.google.android.exoplayer2.extractor.Extractor
    public int read(ExtractorInput input, PositionHolder seekPosition) throws Throwable {
        if (input.getPosition() == 0 && !this.isId3MetadataDisabled && this.id3Metadata == null) {
            this.id3Metadata = peekId3Data(input);
        }
        this.decoderJni.setData(input);
        readPastStreamInfo(input);
        FlacBinarySearchSeeker flacBinarySearchSeeker = this.flacBinarySearchSeeker;
        if (flacBinarySearchSeeker != null && flacBinarySearchSeeker.isSeeking()) {
            return handlePendingSeek(input, seekPosition);
        }
        long lastDecodePosition = this.decoderJni.getDecodePosition();
        try {
            this.decoderJni.decodeSampleWithBacktrackPosition(this.outputByteBuffer, lastDecodePosition);
            int outputSize = this.outputByteBuffer.limit();
            if (outputSize == 0) {
                return -1;
            }
            writeLastSampleToOutput(outputSize, this.decoderJni.getLastFrameTimestamp());
            return this.decoderJni.isEndOfData() ? -1 : 0;
        } catch (FlacDecoderJni.FlacFrameDecodeException e) {
            throw new IOException("Cannot read frame at position " + lastDecodePosition, e);
        }
    }

    @Override // com.google.android.exoplayer2.extractor.Extractor
    public void seek(long position, long timeUs) {
        if (position == 0) {
            this.readPastStreamInfo = false;
        }
        FlacDecoderJni flacDecoderJni = this.decoderJni;
        if (flacDecoderJni != null) {
            flacDecoderJni.reset(position);
        }
        FlacBinarySearchSeeker flacBinarySearchSeeker = this.flacBinarySearchSeeker;
        if (flacBinarySearchSeeker != null) {
            flacBinarySearchSeeker.setSeekTargetUs(timeUs);
        }
    }

    @Override // com.google.android.exoplayer2.extractor.Extractor
    public void release() {
        this.flacBinarySearchSeeker = null;
        FlacDecoderJni flacDecoderJni = this.decoderJni;
        if (flacDecoderJni != null) {
            flacDecoderJni.release();
            this.decoderJni = null;
        }
    }

    private Metadata peekId3Data(ExtractorInput input) throws InterruptedException, IOException {
        input.resetPeekPosition();
        Id3Decoder.FramePredicate id3FramePredicate = this.isId3MetadataDisabled ? Id3Decoder.NO_FRAMES_PREDICATE : null;
        return this.id3Peeker.peekId3Data(input, id3FramePredicate);
    }

    private boolean peekFlacSignature(ExtractorInput input) throws InterruptedException, IOException {
        byte[] bArr = FLAC_SIGNATURE;
        byte[] header = new byte[bArr.length];
        input.peekFully(header, 0, bArr.length);
        return Arrays.equals(header, FLAC_SIGNATURE);
    }

    private void readPastStreamInfo(ExtractorInput input) throws Throwable {
        if (this.readPastStreamInfo) {
            return;
        }
        FlacStreamInfo streamInfo = decodeStreamInfo(input);
        this.readPastStreamInfo = true;
        if (this.streamInfo == null) {
            updateFlacStreamInfo(input, streamInfo);
        }
    }

    private void updateFlacStreamInfo(ExtractorInput input, FlacStreamInfo streamInfo) {
        this.streamInfo = streamInfo;
        outputSeekMap(input, streamInfo);
        outputFormat(streamInfo);
        ParsableByteArray parsableByteArray = new ParsableByteArray(streamInfo.maxDecodedFrameSize());
        this.outputBuffer = parsableByteArray;
        ByteBuffer byteBufferWrap = ByteBuffer.wrap(parsableByteArray.data);
        this.outputByteBuffer = byteBufferWrap;
        this.outputFrameHolder = new BinarySearchSeeker.OutputFrameHolder(byteBufferWrap);
    }

    private FlacStreamInfo decodeStreamInfo(ExtractorInput input) throws Throwable {
        try {
            FlacStreamInfo streamInfo = this.decoderJni.decodeMetadata();
            if (streamInfo == null) {
                throw new IOException("Metadata decoding failed");
            }
            return streamInfo;
        } catch (IOException e) {
            this.decoderJni.reset(0L);
            input.setRetryPosition(0L, e);
            throw e;
        }
    }

    private void outputSeekMap(ExtractorInput input, FlacStreamInfo streamInfo) {
        SeekMap seekMap;
        boolean hasSeekTable = this.decoderJni.getSeekPosition(0L) != -1;
        if (hasSeekTable) {
            seekMap = new FlacSeekMap(streamInfo.durationUs(), this.decoderJni);
        } else {
            seekMap = getSeekMapForNonSeekTableFlac(input, streamInfo);
        }
        this.extractorOutput.seekMap(seekMap);
    }

    private SeekMap getSeekMapForNonSeekTableFlac(ExtractorInput input, FlacStreamInfo streamInfo) {
        long inputLength = input.getLength();
        if (inputLength != -1) {
            long firstFramePosition = this.decoderJni.getDecodePosition();
            FlacBinarySearchSeeker flacBinarySearchSeeker = new FlacBinarySearchSeeker(streamInfo, firstFramePosition, inputLength, this.decoderJni);
            this.flacBinarySearchSeeker = flacBinarySearchSeeker;
            return flacBinarySearchSeeker.getSeekMap();
        }
        return new SeekMap.Unseekable(streamInfo.durationUs());
    }

    private void outputFormat(FlacStreamInfo streamInfo) {
        Format mediaFormat = Format.createAudioSampleFormat(null, MimeTypes.AUDIO_RAW, null, streamInfo.bitRate(), streamInfo.maxDecodedFrameSize(), streamInfo.channels, streamInfo.sampleRate, Util.getPcmEncoding(streamInfo.bitsPerSample), 0, 0, null, null, 0, null, this.isId3MetadataDisabled ? null : this.id3Metadata);
        this.trackOutput.format(mediaFormat);
    }

    private int handlePendingSeek(ExtractorInput input, PositionHolder seekPosition) throws InterruptedException, IOException {
        int seekResult = this.flacBinarySearchSeeker.handlePendingSeek(input, seekPosition, this.outputFrameHolder);
        ByteBuffer outputByteBuffer = this.outputFrameHolder.byteBuffer;
        if (seekResult == 0 && outputByteBuffer.limit() > 0) {
            writeLastSampleToOutput(outputByteBuffer.limit(), this.outputFrameHolder.timeUs);
        }
        return seekResult;
    }

    private void writeLastSampleToOutput(int size, long lastSampleTimestamp) {
        this.outputBuffer.setPosition(0);
        this.trackOutput.sampleData(this.outputBuffer, size);
        this.trackOutput.sampleMetadata(lastSampleTimestamp, 1, size, 0, null);
    }

    private static final class FlacSeekMap implements SeekMap {
        private final FlacDecoderJni decoderJni;
        private final long durationUs;

        public FlacSeekMap(long durationUs, FlacDecoderJni decoderJni) {
            this.durationUs = durationUs;
            this.decoderJni = decoderJni;
        }

        @Override // com.google.android.exoplayer2.extractor.SeekMap
        public boolean isSeekable() {
            return true;
        }

        @Override // com.google.android.exoplayer2.extractor.SeekMap
        public SeekMap.SeekPoints getSeekPoints(long timeUs) {
            return new SeekMap.SeekPoints(new SeekPoint(timeUs, this.decoderJni.getSeekPosition(timeUs)));
        }

        @Override // com.google.android.exoplayer2.extractor.SeekMap
        public long getDurationUs() {
            return this.durationUs;
        }
    }
}
