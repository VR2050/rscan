package com.google.android.exoplayer2.audio;

import com.google.android.exoplayer2.audio.AudioProcessor;
import com.google.android.exoplayer2.util.Util;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/* JADX INFO: loaded from: classes2.dex */
final class TrimmingAudioProcessor implements AudioProcessor {
    private static final int OUTPUT_ENCODING = 2;
    private int bytesPerFrame;
    private int endBufferSize;
    private boolean inputEnded;
    private boolean isActive;
    private int pendingTrimStartBytes;
    private boolean receivedInputSinceConfigure;
    private int trimEndFrames;
    private int trimStartFrames;
    private long trimmedFrameCount;
    private ByteBuffer buffer = EMPTY_BUFFER;
    private ByteBuffer outputBuffer = EMPTY_BUFFER;
    private int channelCount = -1;
    private int sampleRateHz = -1;
    private byte[] endBuffer = Util.EMPTY_BYTE_ARRAY;

    public void setTrimFrameCount(int trimStartFrames, int trimEndFrames) {
        this.trimStartFrames = trimStartFrames;
        this.trimEndFrames = trimEndFrames;
    }

    public void resetTrimmedFrameCount() {
        this.trimmedFrameCount = 0L;
    }

    public long getTrimmedFrameCount() {
        return this.trimmedFrameCount;
    }

    @Override // com.google.android.exoplayer2.audio.AudioProcessor
    public boolean configure(int sampleRateHz, int channelCount, int encoding) throws AudioProcessor.UnhandledFormatException {
        if (encoding != 2) {
            throw new AudioProcessor.UnhandledFormatException(sampleRateHz, channelCount, encoding);
        }
        int i = this.endBufferSize;
        if (i > 0) {
            this.trimmedFrameCount += (long) (i / this.bytesPerFrame);
        }
        this.channelCount = channelCount;
        this.sampleRateHz = sampleRateHz;
        int pcmFrameSize = Util.getPcmFrameSize(2, channelCount);
        this.bytesPerFrame = pcmFrameSize;
        int i2 = this.trimEndFrames;
        this.endBuffer = new byte[i2 * pcmFrameSize];
        this.endBufferSize = 0;
        int i3 = this.trimStartFrames;
        this.pendingTrimStartBytes = pcmFrameSize * i3;
        boolean wasActive = this.isActive;
        boolean z = (i3 == 0 && i2 == 0) ? false : true;
        this.isActive = z;
        this.receivedInputSinceConfigure = false;
        return wasActive != z;
    }

    @Override // com.google.android.exoplayer2.audio.AudioProcessor
    public boolean isActive() {
        return this.isActive;
    }

    @Override // com.google.android.exoplayer2.audio.AudioProcessor
    public int getOutputChannelCount() {
        return this.channelCount;
    }

    @Override // com.google.android.exoplayer2.audio.AudioProcessor
    public int getOutputEncoding() {
        return 2;
    }

    @Override // com.google.android.exoplayer2.audio.AudioProcessor
    public int getOutputSampleRateHz() {
        return this.sampleRateHz;
    }

    @Override // com.google.android.exoplayer2.audio.AudioProcessor
    public void queueInput(ByteBuffer inputBuffer) {
        int position = inputBuffer.position();
        int limit = inputBuffer.limit();
        int remaining = limit - position;
        if (remaining == 0) {
            return;
        }
        this.receivedInputSinceConfigure = true;
        int trimBytes = Math.min(remaining, this.pendingTrimStartBytes);
        this.trimmedFrameCount += (long) (trimBytes / this.bytesPerFrame);
        this.pendingTrimStartBytes -= trimBytes;
        inputBuffer.position(position + trimBytes);
        if (this.pendingTrimStartBytes > 0) {
            return;
        }
        int remaining2 = remaining - trimBytes;
        int remainingBytesToOutput = (this.endBufferSize + remaining2) - this.endBuffer.length;
        if (this.buffer.capacity() < remainingBytesToOutput) {
            this.buffer = ByteBuffer.allocateDirect(remainingBytesToOutput).order(ByteOrder.nativeOrder());
        } else {
            this.buffer.clear();
        }
        int endBufferBytesToOutput = Util.constrainValue(remainingBytesToOutput, 0, this.endBufferSize);
        this.buffer.put(this.endBuffer, 0, endBufferBytesToOutput);
        int inputBufferBytesToOutput = Util.constrainValue(remainingBytesToOutput - endBufferBytesToOutput, 0, remaining2);
        inputBuffer.limit(inputBuffer.position() + inputBufferBytesToOutput);
        this.buffer.put(inputBuffer);
        inputBuffer.limit(limit);
        int remaining3 = remaining2 - inputBufferBytesToOutput;
        int i = this.endBufferSize - endBufferBytesToOutput;
        this.endBufferSize = i;
        byte[] bArr = this.endBuffer;
        System.arraycopy(bArr, endBufferBytesToOutput, bArr, 0, i);
        inputBuffer.get(this.endBuffer, this.endBufferSize, remaining3);
        this.endBufferSize += remaining3;
        this.buffer.flip();
        this.outputBuffer = this.buffer;
    }

    @Override // com.google.android.exoplayer2.audio.AudioProcessor
    public void queueEndOfStream() {
        this.inputEnded = true;
    }

    @Override // com.google.android.exoplayer2.audio.AudioProcessor
    public ByteBuffer getOutput() {
        ByteBuffer outputBuffer = this.outputBuffer;
        if (this.inputEnded && this.endBufferSize > 0 && outputBuffer == EMPTY_BUFFER) {
            int iCapacity = this.buffer.capacity();
            int i = this.endBufferSize;
            if (iCapacity < i) {
                this.buffer = ByteBuffer.allocateDirect(i).order(ByteOrder.nativeOrder());
            } else {
                this.buffer.clear();
            }
            this.buffer.put(this.endBuffer, 0, this.endBufferSize);
            this.endBufferSize = 0;
            this.buffer.flip();
            outputBuffer = this.buffer;
        }
        this.outputBuffer = EMPTY_BUFFER;
        return outputBuffer;
    }

    @Override // com.google.android.exoplayer2.audio.AudioProcessor
    public boolean isEnded() {
        return this.inputEnded && this.endBufferSize == 0 && this.outputBuffer == EMPTY_BUFFER;
    }

    @Override // com.google.android.exoplayer2.audio.AudioProcessor
    public void flush() {
        this.outputBuffer = EMPTY_BUFFER;
        this.inputEnded = false;
        if (this.receivedInputSinceConfigure) {
            this.pendingTrimStartBytes = 0;
        }
        this.endBufferSize = 0;
    }

    @Override // com.google.android.exoplayer2.audio.AudioProcessor
    public void reset() {
        flush();
        this.buffer = EMPTY_BUFFER;
        this.channelCount = -1;
        this.sampleRateHz = -1;
        this.endBuffer = Util.EMPTY_BYTE_ARRAY;
    }
}
