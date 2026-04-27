package com.google.android.exoplayer2.extractor.wav;

import com.google.android.exoplayer2.extractor.SeekMap;
import com.google.android.exoplayer2.extractor.SeekPoint;
import com.google.android.exoplayer2.util.Util;

/* JADX INFO: loaded from: classes2.dex */
final class WavHeader implements SeekMap {
    private final int averageBytesPerSecond;
    private final int bitsPerSample;
    private final int blockAlignment;
    private long dataSize;
    private long dataStartPosition;
    private final int encoding;
    private final int numChannels;
    private final int sampleRateHz;

    public WavHeader(int numChannels, int sampleRateHz, int averageBytesPerSecond, int blockAlignment, int bitsPerSample, int encoding) {
        this.numChannels = numChannels;
        this.sampleRateHz = sampleRateHz;
        this.averageBytesPerSecond = averageBytesPerSecond;
        this.blockAlignment = blockAlignment;
        this.bitsPerSample = bitsPerSample;
        this.encoding = encoding;
    }

    public void setDataBounds(long dataStartPosition, long dataSize) {
        this.dataStartPosition = dataStartPosition;
        this.dataSize = dataSize;
    }

    public long getDataLimit() {
        if (hasDataBounds()) {
            return this.dataStartPosition + this.dataSize;
        }
        return -1L;
    }

    public boolean hasDataBounds() {
        return (this.dataStartPosition == 0 || this.dataSize == 0) ? false : true;
    }

    @Override // com.google.android.exoplayer2.extractor.SeekMap
    public boolean isSeekable() {
        return true;
    }

    @Override // com.google.android.exoplayer2.extractor.SeekMap
    public long getDurationUs() {
        long numFrames = this.dataSize / ((long) this.blockAlignment);
        return (1000000 * numFrames) / ((long) this.sampleRateHz);
    }

    @Override // com.google.android.exoplayer2.extractor.SeekMap
    public SeekMap.SeekPoints getSeekPoints(long timeUs) {
        long positionOffset = (((long) this.averageBytesPerSecond) * timeUs) / 1000000;
        int i = this.blockAlignment;
        long positionOffset2 = (positionOffset / ((long) i)) * ((long) i);
        long positionOffset3 = this.dataSize;
        long positionOffset4 = Util.constrainValue(positionOffset2, 0L, positionOffset3 - ((long) i));
        long seekPosition = this.dataStartPosition + positionOffset4;
        long seekTimeUs = getTimeUs(seekPosition);
        SeekPoint seekPoint = new SeekPoint(seekTimeUs, seekPosition);
        if (seekTimeUs < timeUs) {
            long j = this.dataSize;
            int i2 = this.blockAlignment;
            if (positionOffset4 != j - ((long) i2)) {
                long secondSeekPosition = ((long) i2) + seekPosition;
                long secondSeekTimeUs = getTimeUs(secondSeekPosition);
                SeekPoint secondSeekPoint = new SeekPoint(secondSeekTimeUs, secondSeekPosition);
                return new SeekMap.SeekPoints(seekPoint, secondSeekPoint);
            }
        }
        return new SeekMap.SeekPoints(seekPoint);
    }

    public long getTimeUs(long position) {
        long positionOffset = Math.max(0L, position - this.dataStartPosition);
        return (1000000 * positionOffset) / ((long) this.averageBytesPerSecond);
    }

    public int getBytesPerFrame() {
        return this.blockAlignment;
    }

    public int getBitrate() {
        return this.sampleRateHz * this.bitsPerSample * this.numChannels;
    }

    public int getSampleRateHz() {
        return this.sampleRateHz;
    }

    public int getNumChannels() {
        return this.numChannels;
    }

    public int getEncoding() {
        return this.encoding;
    }
}
