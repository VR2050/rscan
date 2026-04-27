package com.google.android.exoplayer2.ext.flac;

import com.google.android.exoplayer2.ext.flac.FlacDecoderJni;
import com.google.android.exoplayer2.extractor.BinarySearchSeeker;
import com.google.android.exoplayer2.extractor.ExtractorInput;
import com.google.android.exoplayer2.util.Assertions;
import com.google.android.exoplayer2.util.FlacStreamInfo;
import java.nio.ByteBuffer;

/* JADX INFO: loaded from: classes2.dex */
final class FlacBinarySearchSeeker extends BinarySearchSeeker {
    private final FlacDecoderJni decoderJni;

    public FlacBinarySearchSeeker(FlacStreamInfo streamInfo, long firstFramePosition, long inputLength, FlacDecoderJni decoderJni) {
        super(new FlacSeekTimestampConverter(streamInfo), new FlacTimestampSeeker(decoderJni), streamInfo.durationUs(), 0L, streamInfo.totalSamples, firstFramePosition, inputLength, streamInfo.getApproxBytesPerFrame(), Math.max(1, streamInfo.minFrameSize));
        this.decoderJni = (FlacDecoderJni) Assertions.checkNotNull(decoderJni);
    }

    @Override // com.google.android.exoplayer2.extractor.BinarySearchSeeker
    protected void onSeekOperationFinished(boolean foundTargetFrame, long resultPosition) {
        if (!foundTargetFrame) {
            this.decoderJni.reset(resultPosition);
        }
    }

    private static final class FlacTimestampSeeker implements BinarySearchSeeker.TimestampSeeker {
        private final FlacDecoderJni decoderJni;

        @Override // com.google.android.exoplayer2.extractor.BinarySearchSeeker.TimestampSeeker
        public /* synthetic */ void onSeekFinished() {
            BinarySearchSeeker.TimestampSeeker.CC.$default$onSeekFinished(this);
        }

        private FlacTimestampSeeker(FlacDecoderJni decoderJni) {
            this.decoderJni = decoderJni;
        }

        @Override // com.google.android.exoplayer2.extractor.BinarySearchSeeker.TimestampSeeker
        public BinarySearchSeeker.TimestampSearchResult searchForTimestamp(ExtractorInput input, long targetSampleIndex, BinarySearchSeeker.OutputFrameHolder outputFrameHolder) throws Throwable {
            ByteBuffer outputBuffer = outputFrameHolder.byteBuffer;
            long searchPosition = input.getPosition();
            this.decoderJni.reset(searchPosition);
            try {
                this.decoderJni.decodeSampleWithBacktrackPosition(outputBuffer, searchPosition);
                if (outputBuffer.limit() == 0) {
                    return BinarySearchSeeker.TimestampSearchResult.NO_TIMESTAMP_IN_RANGE_RESULT;
                }
                long lastFrameSampleIndex = this.decoderJni.getLastFrameFirstSampleIndex();
                long nextFrameSampleIndex = this.decoderJni.getNextFrameFirstSampleIndex();
                long nextFrameSamplePosition = this.decoderJni.getDecodePosition();
                boolean targetSampleInLastFrame = lastFrameSampleIndex <= targetSampleIndex && nextFrameSampleIndex > targetSampleIndex;
                if (targetSampleInLastFrame) {
                    outputFrameHolder.timeUs = this.decoderJni.getLastFrameTimestamp();
                    return BinarySearchSeeker.TimestampSearchResult.targetFoundResult(input.getPosition());
                }
                if (nextFrameSampleIndex <= targetSampleIndex) {
                    return BinarySearchSeeker.TimestampSearchResult.underestimatedResult(nextFrameSampleIndex, nextFrameSamplePosition);
                }
                return BinarySearchSeeker.TimestampSearchResult.overestimatedResult(lastFrameSampleIndex, searchPosition);
            } catch (FlacDecoderJni.FlacFrameDecodeException e) {
                return BinarySearchSeeker.TimestampSearchResult.NO_TIMESTAMP_IN_RANGE_RESULT;
            }
        }
    }

    private static final class FlacSeekTimestampConverter implements BinarySearchSeeker.SeekTimestampConverter {
        private final FlacStreamInfo streamInfo;

        public FlacSeekTimestampConverter(FlacStreamInfo streamInfo) {
            this.streamInfo = streamInfo;
        }

        @Override // com.google.android.exoplayer2.extractor.BinarySearchSeeker.SeekTimestampConverter
        public long timeUsToTargetTime(long timeUs) {
            return ((FlacStreamInfo) Assertions.checkNotNull(this.streamInfo)).getSampleIndex(timeUs);
        }
    }
}
