package com.shuyu.gsyvideoplayer.utils;

import androidx.core.app.FrameMetricsAggregator;
import androidx.media.AudioAttributesCompat;
import java.io.OutputStream;

/* loaded from: classes2.dex */
public class LZWEncoder {
    public static final int BITS = 12;
    private static final int EOF = -1;
    public static final int HSIZE = 5003;
    public int ClearCode;
    public int EOFCode;
    public int a_count;
    private int curPixel;
    public int g_init_bits;
    private int imgH;
    private int imgW;
    private int initCodeSize;
    public int maxcode;
    public int n_bits;
    private byte[] pixAry;
    private int remaining;
    public int maxbits = 12;
    public int maxmaxcode = 4096;
    public int[] htab = new int[HSIZE];
    public int[] codetab = new int[HSIZE];
    public int hsize = HSIZE;
    public int free_ent = 0;
    public boolean clear_flg = false;
    public int cur_accum = 0;
    public int cur_bits = 0;
    public int[] masks = {0, 1, 3, 7, 15, 31, 63, 127, 255, FrameMetricsAggregator.EVERY_DURATION, AudioAttributesCompat.FLAG_ALL, 2047, 4095, 8191, 16383, 32767, 65535};
    public byte[] accum = new byte[256];

    public LZWEncoder(int i2, int i3, byte[] bArr, int i4) {
        this.imgW = i2;
        this.imgH = i3;
        this.pixAry = bArr;
        this.initCodeSize = Math.max(2, i4);
    }

    private int nextPixel() {
        int i2 = this.remaining;
        if (i2 == 0) {
            return -1;
        }
        this.remaining = i2 - 1;
        byte[] bArr = this.pixAry;
        int i3 = this.curPixel;
        this.curPixel = i3 + 1;
        return bArr[i3] & 255;
    }

    public final int MAXCODE(int i2) {
        return (1 << i2) - 1;
    }

    public void char_out(byte b2, OutputStream outputStream) {
        byte[] bArr = this.accum;
        int i2 = this.a_count;
        int i3 = i2 + 1;
        this.a_count = i3;
        bArr[i2] = b2;
        if (i3 >= 254) {
            flush_char(outputStream);
        }
    }

    public void cl_block(OutputStream outputStream) {
        cl_hash(this.hsize);
        int i2 = this.ClearCode;
        this.free_ent = i2 + 2;
        this.clear_flg = true;
        output(i2, outputStream);
    }

    public void cl_hash(int i2) {
        for (int i3 = 0; i3 < i2; i3++) {
            this.htab[i3] = -1;
        }
    }

    public void compress(int i2, OutputStream outputStream) {
        int[] iArr;
        this.g_init_bits = i2;
        int i3 = 0;
        this.clear_flg = false;
        this.n_bits = i2;
        this.maxcode = MAXCODE(i2);
        int i4 = 1 << (i2 - 1);
        this.ClearCode = i4;
        this.EOFCode = i4 + 1;
        this.free_ent = i4 + 2;
        this.a_count = 0;
        int nextPixel = nextPixel();
        for (int i5 = this.hsize; i5 < 65536; i5 *= 2) {
            i3++;
        }
        int i6 = 8 - i3;
        int i7 = this.hsize;
        cl_hash(i7);
        output(this.ClearCode, outputStream);
        while (true) {
            int nextPixel2 = nextPixel();
            if (nextPixel2 == -1) {
                output(nextPixel, outputStream);
                output(this.EOFCode, outputStream);
                return;
            }
            int i8 = (nextPixel2 << this.maxbits) + nextPixel;
            int i9 = (nextPixel2 << i6) ^ nextPixel;
            int[] iArr2 = this.htab;
            if (iArr2[i9] == i8) {
                nextPixel = this.codetab[i9];
            } else {
                if (iArr2[i9] >= 0) {
                    int i10 = i7 - i9;
                    if (i9 == 0) {
                        i10 = 1;
                    }
                    do {
                        i9 -= i10;
                        if (i9 < 0) {
                            i9 += i7;
                        }
                        iArr = this.htab;
                        if (iArr[i9] == i8) {
                            nextPixel = this.codetab[i9];
                            break;
                        }
                    } while (iArr[i9] >= 0);
                }
                output(nextPixel, outputStream);
                int i11 = this.free_ent;
                if (i11 < this.maxmaxcode) {
                    int[] iArr3 = this.codetab;
                    this.free_ent = i11 + 1;
                    iArr3[i9] = i11;
                    this.htab[i9] = i8;
                } else {
                    cl_block(outputStream);
                }
                nextPixel = nextPixel2;
            }
        }
    }

    public void encode(OutputStream outputStream) {
        outputStream.write(this.initCodeSize);
        this.remaining = this.imgW * this.imgH;
        this.curPixel = 0;
        compress(this.initCodeSize + 1, outputStream);
        outputStream.write(0);
    }

    public void flush_char(OutputStream outputStream) {
        int i2 = this.a_count;
        if (i2 > 0) {
            outputStream.write(i2);
            outputStream.write(this.accum, 0, this.a_count);
            this.a_count = 0;
        }
    }

    public void output(int i2, OutputStream outputStream) {
        int i3 = this.cur_accum;
        int[] iArr = this.masks;
        int i4 = this.cur_bits;
        int i5 = i3 & iArr[i4];
        this.cur_accum = i5;
        if (i4 > 0) {
            this.cur_accum = i5 | (i2 << i4);
        } else {
            this.cur_accum = i2;
        }
        this.cur_bits = i4 + this.n_bits;
        while (this.cur_bits >= 8) {
            char_out((byte) (this.cur_accum & 255), outputStream);
            this.cur_accum >>= 8;
            this.cur_bits -= 8;
        }
        if (this.free_ent > this.maxcode || this.clear_flg) {
            if (this.clear_flg) {
                int i6 = this.g_init_bits;
                this.n_bits = i6;
                this.maxcode = MAXCODE(i6);
                this.clear_flg = false;
            } else {
                int i7 = this.n_bits + 1;
                this.n_bits = i7;
                if (i7 == this.maxbits) {
                    this.maxcode = this.maxmaxcode;
                } else {
                    this.maxcode = MAXCODE(i7);
                }
            }
        }
        if (i2 == this.EOFCode) {
            while (this.cur_bits > 0) {
                char_out((byte) (this.cur_accum & 255), outputStream);
                this.cur_accum >>= 8;
                this.cur_bits -= 8;
            }
            flush_char(outputStream);
        }
    }
}
