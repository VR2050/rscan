package com.google.android.exoplayer2.extractor.ogg;

import com.google.android.exoplayer2.extractor.ExtractorInput;
import com.google.android.exoplayer2.extractor.SeekMap;
import com.google.android.exoplayer2.extractor.SeekPoint;
import com.google.android.exoplayer2.util.Assertions;
import java.io.EOFException;
import java.io.IOException;

/* JADX INFO: loaded from: classes2.dex */
final class DefaultOggSeeker implements OggSeeker {
    private static final int DEFAULT_OFFSET = 30000;
    public static final int MATCH_BYTE_RANGE = 100000;
    public static final int MATCH_RANGE = 72000;
    private static final int STATE_IDLE = 3;
    private static final int STATE_READ_LAST_PAGE = 1;
    private static final int STATE_SEEK = 2;
    private static final int STATE_SEEK_TO_END = 0;
    private long end;
    private long endGranule;
    private final long endPosition;
    private final OggPageHeader pageHeader = new OggPageHeader();
    private long positionBeforeSeekToEnd;
    private long start;
    private long startGranule;
    private final long startPosition;
    private int state;
    private final StreamReader streamReader;
    private long targetGranule;
    private long totalGranules;

    public DefaultOggSeeker(long startPosition, long endPosition, StreamReader streamReader, long firstPayloadPageSize, long firstPayloadPageGranulePosition, boolean firstPayloadPageIsLastPage) {
        Assertions.checkArgument(startPosition >= 0 && endPosition > startPosition);
        this.streamReader = streamReader;
        this.startPosition = startPosition;
        this.endPosition = endPosition;
        if (firstPayloadPageSize == endPosition - startPosition || firstPayloadPageIsLastPage) {
            this.totalGranules = firstPayloadPageGranulePosition;
            this.state = 3;
        } else {
            this.state = 0;
        }
    }

    @Override // com.google.android.exoplayer2.extractor.ogg.OggSeeker
    public long read(ExtractorInput input) throws InterruptedException, IOException {
        long position;
        int i = this.state;
        if (i == 0) {
            long position2 = input.getPosition();
            this.positionBeforeSeekToEnd = position2;
            this.state = 1;
            long lastPageSearchPosition = this.endPosition - 65307;
            if (lastPageSearchPosition > position2) {
                return lastPageSearchPosition;
            }
        } else if (i != 1) {
            if (i != 2) {
                if (i == 3) {
                    return -1L;
                }
                throw new IllegalStateException();
            }
            long currentGranule = this.targetGranule;
            if (currentGranule == 0) {
                position = 0;
            } else {
                long position3 = getNextSeekPosition(currentGranule, input);
                if (position3 >= 0) {
                    return position3;
                }
                position = skipToPageOfGranule(input, this.targetGranule, -(position3 + 2));
            }
            this.state = 3;
            return -(2 + position);
        }
        this.totalGranules = readGranuleOfLastPage(input);
        this.state = 3;
        return this.positionBeforeSeekToEnd;
    }

    @Override // com.google.android.exoplayer2.extractor.ogg.OggSeeker
    public long startSeek(long timeUs) {
        int i = this.state;
        Assertions.checkArgument(i == 3 || i == 2);
        this.targetGranule = timeUs != 0 ? this.streamReader.convertTimeToGranule(timeUs) : 0L;
        this.state = 2;
        resetSeeking();
        return this.targetGranule;
    }

    @Override // com.google.android.exoplayer2.extractor.ogg.OggSeeker
    public OggSeekMap createSeekMap() {
        if (this.totalGranules != 0) {
            return new OggSeekMap();
        }
        return null;
    }

    public void resetSeeking() {
        this.start = this.startPosition;
        this.end = this.endPosition;
        this.startGranule = 0L;
        this.endGranule = this.totalGranules;
    }

    public long getNextSeekPosition(long targetGranule, ExtractorInput input) throws InterruptedException, IOException {
        if (this.start == this.end) {
            return -(this.startGranule + 2);
        }
        long initialPosition = input.getPosition();
        if (!skipToNextPage(input, this.end)) {
            long j = this.start;
            if (j == initialPosition) {
                throw new IOException("No ogg page can be found.");
            }
            return j;
        }
        this.pageHeader.populate(input, false);
        input.resetPeekPosition();
        long granuleDistance = targetGranule - this.pageHeader.granulePosition;
        int pageSize = this.pageHeader.headerSize + this.pageHeader.bodySize;
        if (granuleDistance < 0 || granuleDistance > 72000) {
            if (granuleDistance >= 0) {
                this.start = input.getPosition() + ((long) pageSize);
                this.startGranule = this.pageHeader.granulePosition;
                if ((this.end - this.start) + ((long) pageSize) < 100000) {
                    input.skipFully(pageSize);
                    return -(this.startGranule + 2);
                }
            } else {
                this.end = initialPosition;
                this.endGranule = this.pageHeader.granulePosition;
            }
            long j2 = this.end;
            long j3 = this.start;
            if (j2 - j3 < 100000) {
                this.end = j3;
                return j3;
            }
            long offset = ((long) pageSize) * (granuleDistance > 0 ? 1L : 2L);
            long position = input.getPosition() - offset;
            long j4 = this.end;
            long j5 = this.start;
            long nextPosition = position + (((j4 - j5) * granuleDistance) / (this.endGranule - this.startGranule));
            return Math.min(Math.max(nextPosition, j5), this.end - 1);
        }
        input.skipFully(pageSize);
        return -(this.pageHeader.granulePosition + 2);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public long getEstimatedPosition(long position, long granuleDistance, long offset) {
        long j = this.endPosition;
        long j2 = this.startPosition;
        long position2 = position + ((((j - j2) * granuleDistance) / this.totalGranules) - offset);
        if (position2 < j2) {
            position2 = this.startPosition;
        }
        long j3 = this.endPosition;
        if (position2 >= j3) {
            long position3 = j3 - 1;
            return position3;
        }
        return position2;
    }

    private class OggSeekMap implements SeekMap {
        private OggSeekMap() {
        }

        @Override // com.google.android.exoplayer2.extractor.SeekMap
        public boolean isSeekable() {
            return true;
        }

        @Override // com.google.android.exoplayer2.extractor.SeekMap
        public SeekMap.SeekPoints getSeekPoints(long timeUs) {
            if (timeUs != 0) {
                long granule = DefaultOggSeeker.this.streamReader.convertTimeToGranule(timeUs);
                DefaultOggSeeker defaultOggSeeker = DefaultOggSeeker.this;
                long estimatedPosition = defaultOggSeeker.getEstimatedPosition(defaultOggSeeker.startPosition, granule, 30000L);
                return new SeekMap.SeekPoints(new SeekPoint(timeUs, estimatedPosition));
            }
            return new SeekMap.SeekPoints(new SeekPoint(0L, DefaultOggSeeker.this.startPosition));
        }

        @Override // com.google.android.exoplayer2.extractor.SeekMap
        public long getDurationUs() {
            return DefaultOggSeeker.this.streamReader.convertGranuleToTime(DefaultOggSeeker.this.totalGranules);
        }
    }

    void skipToNextPage(ExtractorInput input) throws InterruptedException, IOException {
        if (!skipToNextPage(input, this.endPosition)) {
            throw new EOFException();
        }
    }

    boolean skipToNextPage(ExtractorInput input, long limit) throws InterruptedException, IOException {
        long limit2 = Math.min(3 + limit, this.endPosition);
        byte[] buffer = new byte[2048];
        int peekLength = buffer.length;
        while (true) {
            if (input.getPosition() + ((long) peekLength) > limit2 && (peekLength = (int) (limit2 - input.getPosition())) < 4) {
                return false;
            }
            input.peekFully(buffer, 0, peekLength, false);
            for (int i = 0; i < peekLength - 3; i++) {
                if (buffer[i] == 79 && buffer[i + 1] == 103 && buffer[i + 2] == 103 && buffer[i + 3] == 83) {
                    input.skipFully(i);
                    return true;
                }
            }
            int i2 = peekLength - 3;
            input.skipFully(i2);
        }
    }

    long readGranuleOfLastPage(ExtractorInput input) throws InterruptedException, IOException {
        skipToNextPage(input);
        this.pageHeader.reset();
        while ((this.pageHeader.type & 4) != 4 && input.getPosition() < this.endPosition) {
            this.pageHeader.populate(input, false);
            input.skipFully(this.pageHeader.headerSize + this.pageHeader.bodySize);
        }
        return this.pageHeader.granulePosition;
    }

    long skipToPageOfGranule(ExtractorInput input, long targetGranule, long currentGranule) throws InterruptedException, IOException {
        this.pageHeader.populate(input, false);
        while (this.pageHeader.granulePosition < targetGranule) {
            input.skipFully(this.pageHeader.headerSize + this.pageHeader.bodySize);
            currentGranule = this.pageHeader.granulePosition;
            this.pageHeader.populate(input, false);
        }
        input.resetPeekPosition();
        return currentGranule;
    }
}
