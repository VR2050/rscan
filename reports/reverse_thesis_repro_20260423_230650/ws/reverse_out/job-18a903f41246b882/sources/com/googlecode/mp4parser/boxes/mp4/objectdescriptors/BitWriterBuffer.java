package com.googlecode.mp4parser.boxes.mp4.objectdescriptors;

import androidx.core.view.InputDeviceCompat;
import java.nio.ByteBuffer;

/* JADX INFO: loaded from: classes.dex */
public class BitWriterBuffer {
    static final /* synthetic */ boolean $assertionsDisabled = false;
    private ByteBuffer buffer;
    int initialPos;
    int position = 0;

    public BitWriterBuffer(ByteBuffer buffer) {
        this.buffer = buffer;
        this.initialPos = buffer.position();
    }

    public void writeBits(int i, int numBits) {
        int i2 = this.position;
        int left = 8 - (i2 % 8);
        if (numBits <= left) {
            int current = this.buffer.get(this.initialPos + (i2 / 8));
            int current2 = (current < 0 ? current + 256 : current) + (i << (left - numBits));
            this.buffer.put(this.initialPos + (this.position / 8), (byte) (current2 > 127 ? current2 + InputDeviceCompat.SOURCE_ANY : current2));
            this.position += numBits;
        } else {
            int bitsSecondWrite = numBits - left;
            writeBits(i >> bitsSecondWrite, left);
            writeBits(((1 << bitsSecondWrite) - 1) & i, bitsSecondWrite);
        }
        ByteBuffer byteBuffer = this.buffer;
        int i3 = this.initialPos;
        int i4 = this.position;
        byteBuffer.position(i3 + (i4 / 8) + (i4 % 8 <= 0 ? 0 : 1));
    }
}
