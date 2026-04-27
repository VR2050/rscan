package com.google.android.exoplayer2.extractor.mp3;

import com.google.android.exoplayer2.extractor.MpegAudioHeader;
import com.google.android.exoplayer2.extractor.SeekMap;
import com.google.android.exoplayer2.extractor.SeekPoint;
import com.google.android.exoplayer2.extractor.mp3.Mp3Extractor;
import com.google.android.exoplayer2.util.Log;
import com.google.android.exoplayer2.util.ParsableByteArray;
import com.google.android.exoplayer2.util.Util;

/* JADX INFO: loaded from: classes2.dex */
final class VbriSeeker implements Mp3Extractor.Seeker {
    private static final String TAG = "VbriSeeker";
    private final long dataEndPosition;
    private final long durationUs;
    private final long[] positions;
    private final long[] timesUs;

    public static VbriSeeker create(long inputLength, long position, MpegAudioHeader mpegAudioHeader, ParsableByteArray frame) {
        int segmentSize;
        frame.skipBytes(10);
        int numFrames = frame.readInt();
        if (numFrames <= 0) {
            return null;
        }
        int sampleRate = mpegAudioHeader.sampleRate;
        long durationUs = Util.scaleLargeTimestamp(numFrames, 1000000 * ((long) (sampleRate >= 32000 ? 1152 : 576)), sampleRate);
        int entryCount = frame.readUnsignedShort();
        int scale = frame.readUnsignedShort();
        int entrySize = frame.readUnsignedShort();
        frame.skipBytes(2);
        long minPosition = position + ((long) mpegAudioHeader.frameSize);
        long[] timesUs = new long[entryCount];
        long[] positions = new long[entryCount];
        long position2 = position;
        int index = 0;
        while (index < entryCount) {
            int sampleRate2 = sampleRate;
            long durationUs2 = durationUs;
            timesUs[index] = (((long) index) * durationUs) / ((long) entryCount);
            long position3 = position2;
            positions[index] = Math.max(position3, minPosition);
            if (entrySize == 1) {
                segmentSize = frame.readUnsignedByte();
            } else if (entrySize == 2) {
                segmentSize = frame.readUnsignedShort();
            } else if (entrySize == 3) {
                segmentSize = frame.readUnsignedInt24();
            } else {
                if (entrySize != 4) {
                    return null;
                }
                segmentSize = frame.readUnsignedIntToInt();
            }
            position2 = position3 + ((long) (segmentSize * scale));
            index++;
            sampleRate = sampleRate2;
            durationUs = durationUs2;
        }
        long durationUs3 = durationUs;
        long position4 = position2;
        if (inputLength != -1 && inputLength != position4) {
            Log.w(TAG, "VBRI data size mismatch: " + inputLength + ", " + position4);
        }
        return new VbriSeeker(timesUs, positions, durationUs3, position4);
    }

    private VbriSeeker(long[] timesUs, long[] positions, long durationUs, long dataEndPosition) {
        this.timesUs = timesUs;
        this.positions = positions;
        this.durationUs = durationUs;
        this.dataEndPosition = dataEndPosition;
    }

    @Override // com.google.android.exoplayer2.extractor.SeekMap
    public boolean isSeekable() {
        return true;
    }

    @Override // com.google.android.exoplayer2.extractor.SeekMap
    public SeekMap.SeekPoints getSeekPoints(long timeUs) {
        int tableIndex = Util.binarySearchFloor(this.timesUs, timeUs, true, true);
        SeekPoint seekPoint = new SeekPoint(this.timesUs[tableIndex], this.positions[tableIndex]);
        if (seekPoint.timeUs < timeUs) {
            long[] jArr = this.timesUs;
            if (tableIndex != jArr.length - 1) {
                SeekPoint nextSeekPoint = new SeekPoint(jArr[tableIndex + 1], this.positions[tableIndex + 1]);
                return new SeekMap.SeekPoints(seekPoint, nextSeekPoint);
            }
        }
        return new SeekMap.SeekPoints(seekPoint);
    }

    @Override // com.google.android.exoplayer2.extractor.mp3.Mp3Extractor.Seeker
    public long getTimeUs(long position) {
        return this.timesUs[Util.binarySearchFloor(this.positions, position, true, true)];
    }

    @Override // com.google.android.exoplayer2.extractor.SeekMap
    public long getDurationUs() {
        return this.durationUs;
    }

    @Override // com.google.android.exoplayer2.extractor.mp3.Mp3Extractor.Seeker
    public long getDataEndPosition() {
        return this.dataEndPosition;
    }
}
