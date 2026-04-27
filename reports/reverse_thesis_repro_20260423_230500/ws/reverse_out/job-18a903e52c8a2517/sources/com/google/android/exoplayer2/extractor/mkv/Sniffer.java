package com.google.android.exoplayer2.extractor.mkv;

import com.google.android.exoplayer2.extractor.ExtractorInput;
import com.google.android.exoplayer2.util.ParsableByteArray;
import java.io.IOException;
import kotlin.UByte;

/* JADX INFO: loaded from: classes2.dex */
final class Sniffer {
    private static final int ID_EBML = 440786851;
    private static final int SEARCH_LENGTH = 1024;
    private int peekLength;
    private final ParsableByteArray scratch = new ParsableByteArray(8);

    public boolean sniff(ExtractorInput input) throws InterruptedException, IOException {
        ExtractorInput extractorInput = input;
        long inputLength = input.getLength();
        long j = 1024;
        if (inputLength != -1 && inputLength <= 1024) {
            j = inputLength;
        }
        int bytesToSearch = (int) j;
        boolean z = false;
        extractorInput.peekFully(this.scratch.data, 0, 4);
        long tag = this.scratch.readUnsignedInt();
        this.peekLength = 4;
        while (tag != 440786851) {
            int i = this.peekLength + 1;
            this.peekLength = i;
            if (i == bytesToSearch) {
                return false;
            }
            extractorInput.peekFully(this.scratch.data, 0, 1);
            tag = ((tag << 8) & (-256)) | ((long) (this.scratch.data[0] & UByte.MAX_VALUE));
        }
        long headerSize = readUint(input);
        long headerStart = this.peekLength;
        if (headerSize == Long.MIN_VALUE) {
            return false;
        }
        if (inputLength != -1 && headerStart + headerSize >= inputLength) {
            return false;
        }
        while (true) {
            int i2 = this.peekLength;
            if (i2 >= headerStart + headerSize) {
                return ((long) i2) == headerStart + headerSize;
            }
            long id = readUint(input);
            if (id == Long.MIN_VALUE) {
                return z;
            }
            int bytesToSearch2 = bytesToSearch;
            long size = readUint(input);
            if (size < 0 || size > 2147483647L) {
                return false;
            }
            if (size != 0) {
                int sizeInt = (int) size;
                extractorInput.advancePeekPosition(sizeInt);
                this.peekLength += sizeInt;
            }
            extractorInput = input;
            bytesToSearch = bytesToSearch2;
            z = false;
        }
    }

    private long readUint(ExtractorInput input) throws InterruptedException, IOException {
        input.peekFully(this.scratch.data, 0, 1);
        int value = this.scratch.data[0] & UByte.MAX_VALUE;
        if (value == 0) {
            return Long.MIN_VALUE;
        }
        int mask = 128;
        int length = 0;
        while ((value & mask) == 0) {
            mask >>= 1;
            length++;
        }
        int value2 = value & (~mask);
        input.peekFully(this.scratch.data, 1, length);
        for (int i = 0; i < length; i++) {
            value2 = (value2 << 8) + (this.scratch.data[i + 1] & UByte.MAX_VALUE);
        }
        int i2 = this.peekLength;
        this.peekLength = i2 + length + 1;
        return value2;
    }
}
