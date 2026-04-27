package com.google.android.exoplayer2.extractor.ts;

import com.google.android.exoplayer2.extractor.BinarySearchSeeker;
import com.google.android.exoplayer2.extractor.ExtractorInput;
import com.google.android.exoplayer2.util.ParsableByteArray;
import com.google.android.exoplayer2.util.TimestampAdjuster;
import com.google.android.exoplayer2.util.Util;
import java.io.IOException;

/* JADX INFO: loaded from: classes2.dex */
final class TsBinarySearchSeeker extends BinarySearchSeeker {
    private static final int MINIMUM_SEARCH_RANGE_BYTES = 940;
    private static final long SEEK_TOLERANCE_US = 100000;
    private static final int TIMESTAMP_SEARCH_BYTES = 112800;

    public TsBinarySearchSeeker(TimestampAdjuster pcrTimestampAdjuster, long streamDurationUs, long inputLength, int pcrPid) {
        super(new BinarySearchSeeker.DefaultSeekTimestampConverter(), new TsPcrSeeker(pcrPid, pcrTimestampAdjuster), streamDurationUs, 0L, streamDurationUs + 1, 0L, inputLength, 188L, MINIMUM_SEARCH_RANGE_BYTES);
    }

    private static final class TsPcrSeeker implements BinarySearchSeeker.TimestampSeeker {
        private final ParsableByteArray packetBuffer = new ParsableByteArray();
        private final int pcrPid;
        private final TimestampAdjuster pcrTimestampAdjuster;

        public TsPcrSeeker(int pcrPid, TimestampAdjuster pcrTimestampAdjuster) {
            this.pcrPid = pcrPid;
            this.pcrTimestampAdjuster = pcrTimestampAdjuster;
        }

        @Override // com.google.android.exoplayer2.extractor.BinarySearchSeeker.TimestampSeeker
        public BinarySearchSeeker.TimestampSearchResult searchForTimestamp(ExtractorInput input, long targetTimestamp, BinarySearchSeeker.OutputFrameHolder outputFrameHolder) throws InterruptedException, IOException {
            long inputPosition = input.getPosition();
            int bytesToSearch = (int) Math.min(112800L, input.getLength() - inputPosition);
            this.packetBuffer.reset(bytesToSearch);
            input.peekFully(this.packetBuffer.data, 0, bytesToSearch);
            return searchForPcrValueInBuffer(this.packetBuffer, targetTimestamp, inputPosition);
        }

        /* JADX WARN: Code restructure failed: missing block: B:27:0x0092, code lost:
        
            if (r9 == com.google.android.exoplayer2.C.TIME_UNSET) goto L30;
         */
        /* JADX WARN: Code restructure failed: missing block: B:28:0x0094, code lost:
        
            r4 = r28 + r16;
         */
        /* JADX WARN: Code restructure failed: missing block: B:29:0x009a, code lost:
        
            return com.google.android.exoplayer2.extractor.BinarySearchSeeker.TimestampSearchResult.underestimatedResult(r9, r4);
         */
        /* JADX WARN: Code restructure failed: missing block: B:31:0x009d, code lost:
        
            return com.google.android.exoplayer2.extractor.BinarySearchSeeker.TimestampSearchResult.NO_TIMESTAMP_IN_RANGE_RESULT;
         */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        private com.google.android.exoplayer2.extractor.BinarySearchSeeker.TimestampSearchResult searchForPcrValueInBuffer(com.google.android.exoplayer2.util.ParsableByteArray r25, long r26, long r28) {
            /*
                r24 = this;
                r0 = r24
                r1 = r25
                r2 = r28
                int r4 = r25.limit()
                r5 = -1
                r7 = -1
                r9 = -9223372036854775807(0x8000000000000001, double:-4.9E-324)
            L13:
                int r11 = r25.bytesLeft()
                r12 = 188(0xbc, float:2.63E-43)
                r13 = -9223372036854775807(0x8000000000000001, double:-4.9E-324)
                if (r11 < r12) goto L86
                byte[] r11 = r1.data
                int r12 = r25.getPosition()
                int r11 = com.google.android.exoplayer2.extractor.ts.TsUtil.findSyncBytePosition(r11, r12, r4)
                int r12 = r11 + 188
                if (r12 <= r4) goto L34
                r15 = r4
                r20 = r5
                r16 = r7
                goto L8b
            L34:
                int r15 = r0.pcrPid
                r16 = r7
                long r7 = com.google.android.exoplayer2.extractor.ts.TsUtil.readPcrFromPacket(r1, r11, r15)
                int r15 = (r7 > r13 ? 1 : (r7 == r13 ? 0 : -1))
                if (r15 == 0) goto L7d
                com.google.android.exoplayer2.util.TimestampAdjuster r15 = r0.pcrTimestampAdjuster
                long r13 = r15.adjustTsTimestamp(r7)
                int r15 = (r13 > r26 ? 1 : (r13 == r26 ? 0 : -1))
                if (r15 <= 0) goto L5f
                r18 = -9223372036854775807(0x8000000000000001, double:-4.9E-324)
                int r15 = (r9 > r18 ? 1 : (r9 == r18 ? 0 : -1))
                if (r15 != 0) goto L58
                com.google.android.exoplayer2.extractor.BinarySearchSeeker$TimestampSearchResult r15 = com.google.android.exoplayer2.extractor.BinarySearchSeeker.TimestampSearchResult.overestimatedResult(r13, r2)
                return r15
            L58:
                long r18 = r2 + r5
                com.google.android.exoplayer2.extractor.BinarySearchSeeker$TimestampSearchResult r15 = com.google.android.exoplayer2.extractor.BinarySearchSeeker.TimestampSearchResult.targetFoundResult(r18)
                return r15
            L5f:
                r18 = 100000(0x186a0, double:4.94066E-319)
                long r18 = r13 + r18
                int r15 = (r18 > r26 ? 1 : (r18 == r26 ? 0 : -1))
                if (r15 <= 0) goto L72
                r15 = r4
                r20 = r5
                long r4 = (long) r11
                long r4 = r4 + r2
                com.google.android.exoplayer2.extractor.BinarySearchSeeker$TimestampSearchResult r6 = com.google.android.exoplayer2.extractor.BinarySearchSeeker.TimestampSearchResult.targetFoundResult(r4)
                return r6
            L72:
                r15 = r4
                r20 = r5
                r4 = r13
                long r9 = (long) r11
                r22 = r4
                r5 = r9
                r9 = r22
                goto L80
            L7d:
                r15 = r4
                r20 = r5
            L80:
                r1.setPosition(r12)
                long r7 = (long) r12
                r4 = r15
                goto L13
            L86:
                r15 = r4
                r20 = r5
                r16 = r7
            L8b:
                r4 = -9223372036854775807(0x8000000000000001, double:-4.9E-324)
                int r6 = (r9 > r4 ? 1 : (r9 == r4 ? 0 : -1))
                if (r6 == 0) goto L9b
                long r4 = r2 + r16
                com.google.android.exoplayer2.extractor.BinarySearchSeeker$TimestampSearchResult r6 = com.google.android.exoplayer2.extractor.BinarySearchSeeker.TimestampSearchResult.underestimatedResult(r9, r4)
                return r6
            L9b:
                com.google.android.exoplayer2.extractor.BinarySearchSeeker$TimestampSearchResult r4 = com.google.android.exoplayer2.extractor.BinarySearchSeeker.TimestampSearchResult.NO_TIMESTAMP_IN_RANGE_RESULT
                return r4
            */
            throw new UnsupportedOperationException("Method not decompiled: com.google.android.exoplayer2.extractor.ts.TsBinarySearchSeeker.TsPcrSeeker.searchForPcrValueInBuffer(com.google.android.exoplayer2.util.ParsableByteArray, long, long):com.google.android.exoplayer2.extractor.BinarySearchSeeker$TimestampSearchResult");
        }

        @Override // com.google.android.exoplayer2.extractor.BinarySearchSeeker.TimestampSeeker
        public void onSeekFinished() {
            this.packetBuffer.reset(Util.EMPTY_BYTE_ARRAY);
        }
    }
}
