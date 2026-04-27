package com.google.android.exoplayer2.util;

/* JADX INFO: loaded from: classes2.dex */
public final class FlacStreamInfo {
    public final int bitsPerSample;
    public final int channels;
    public final int maxBlockSize;
    public final int maxFrameSize;
    public final int minBlockSize;
    public final int minFrameSize;
    public final int sampleRate;
    public final long totalSamples;

    public FlacStreamInfo(byte[] data, int offset) {
        ParsableBitArray scratch = new ParsableBitArray(data);
        scratch.setPosition(offset * 8);
        this.minBlockSize = scratch.readBits(16);
        this.maxBlockSize = scratch.readBits(16);
        this.minFrameSize = scratch.readBits(24);
        this.maxFrameSize = scratch.readBits(24);
        this.sampleRate = scratch.readBits(20);
        this.channels = scratch.readBits(3) + 1;
        this.bitsPerSample = scratch.readBits(5) + 1;
        this.totalSamples = ((((long) scratch.readBits(4)) & 15) << 32) | (((long) scratch.readBits(32)) & 4294967295L);
    }

    public FlacStreamInfo(int minBlockSize, int maxBlockSize, int minFrameSize, int maxFrameSize, int sampleRate, int channels, int bitsPerSample, long totalSamples) {
        this.minBlockSize = minBlockSize;
        this.maxBlockSize = maxBlockSize;
        this.minFrameSize = minFrameSize;
        this.maxFrameSize = maxFrameSize;
        this.sampleRate = sampleRate;
        this.channels = channels;
        this.bitsPerSample = bitsPerSample;
        this.totalSamples = totalSamples;
    }

    public int maxDecodedFrameSize() {
        return this.maxBlockSize * this.channels * (this.bitsPerSample / 8);
    }

    public int bitRate() {
        return this.bitsPerSample * this.sampleRate;
    }

    public long durationUs() {
        return (this.totalSamples * 1000000) / ((long) this.sampleRate);
    }

    public long getSampleIndex(long timeUs) {
        long sampleIndex = (((long) this.sampleRate) * timeUs) / 1000000;
        return Util.constrainValue(sampleIndex, 0L, this.totalSamples - 1);
    }

    public long getApproxBytesPerFrame() {
        int i = this.maxFrameSize;
        if (i > 0) {
            long approxBytesPerFrame = ((((long) i) + ((long) this.minFrameSize)) / 2) + 1;
            return approxBytesPerFrame;
        }
        int i2 = this.minBlockSize;
        long blockSize = (i2 != this.maxBlockSize || i2 <= 0) ? 4096L : i2;
        long approxBytesPerFrame2 = (((((long) this.channels) * blockSize) * ((long) this.bitsPerSample)) / 8) + 64;
        return approxBytesPerFrame2;
    }
}
