package com.shuyu.gsyvideoplayer.utils;

import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Paint;
import java.io.IOException;
import java.io.OutputStream;

/* loaded from: classes2.dex */
public class AnimatedGifEncoder {
    public int colorDepth;
    public byte[] colorTab;
    public int height;
    public Bitmap image;
    public byte[] indexedPixels;
    public OutputStream out;
    public byte[] pixels;
    public int transIndex;
    public int width;

    /* renamed from: x */
    public int f10789x = 0;

    /* renamed from: y */
    public int f10790y = 0;
    public int transparent = -1;
    public int repeat = -1;
    public int delay = 0;
    public boolean started = false;
    public boolean[] usedEntry = new boolean[256];
    public int palSize = 7;
    public int dispose = -1;
    public boolean closeStream = false;
    public boolean firstFrame = true;
    public boolean sizeSet = false;
    public int sample = 10;

    public boolean addFrame(Bitmap bitmap) {
        if (bitmap == null || !this.started) {
            return false;
        }
        try {
            if (!this.sizeSet) {
                setSize(bitmap.getWidth(), bitmap.getHeight());
            }
            this.image = bitmap;
            getImagePixels();
            analyzePixels();
            if (this.firstFrame) {
                writeLSD();
                writePalette();
                if (this.repeat >= 0) {
                    writeNetscapeExt();
                }
            }
            writeGraphicCtrlExt();
            writeImageDesc();
            if (!this.firstFrame) {
                writePalette();
            }
            writePixels();
            this.firstFrame = false;
            return true;
        } catch (IOException unused) {
            return false;
        }
    }

    public void analyzePixels() {
        byte[] bArr = this.pixels;
        int length = bArr.length;
        int i2 = length / 3;
        this.indexedPixels = new byte[i2];
        NeuQuant neuQuant = new NeuQuant(bArr, length, this.sample);
        this.colorTab = neuQuant.process();
        int i3 = 0;
        int i4 = 0;
        while (true) {
            byte[] bArr2 = this.colorTab;
            if (i4 >= bArr2.length) {
                break;
            }
            byte b2 = bArr2[i4];
            int i5 = i4 + 2;
            bArr2[i4] = bArr2[i5];
            bArr2[i5] = b2;
            this.usedEntry[i4 / 3] = false;
            i4 += 3;
        }
        int i6 = 0;
        while (i3 < i2) {
            byte[] bArr3 = this.pixels;
            int i7 = i6 + 1;
            int i8 = i7 + 1;
            int map = neuQuant.map(bArr3[i6] & 255, bArr3[i7] & 255, bArr3[i8] & 255);
            this.usedEntry[map] = true;
            this.indexedPixels[i3] = (byte) map;
            i3++;
            i6 = i8 + 1;
        }
        this.pixels = null;
        this.colorDepth = 8;
        this.palSize = 7;
        int i9 = this.transparent;
        if (i9 != -1) {
            this.transIndex = findClosest(i9);
        }
    }

    public int findClosest(int i2) {
        byte[] bArr = this.colorTab;
        if (bArr == null) {
            return -1;
        }
        int i3 = (i2 >> 16) & 255;
        int i4 = (i2 >> 8) & 255;
        int i5 = 0;
        int i6 = (i2 >> 0) & 255;
        int length = bArr.length;
        int i7 = 0;
        int i8 = 16777216;
        while (i5 < length) {
            byte[] bArr2 = this.colorTab;
            int i9 = i5 + 1;
            int i10 = i3 - (bArr2[i5] & 255);
            int i11 = i9 + 1;
            int i12 = i4 - (bArr2[i9] & 255);
            int i13 = i6 - (bArr2[i11] & 255);
            int i14 = i13 * i13;
            int i15 = i14 + (i12 * i12) + (i10 * i10);
            int i16 = i11 / 3;
            if (this.usedEntry[i16] && i15 < i8) {
                i7 = i16;
                i8 = i15;
            }
            i5 = i11 + 1;
        }
        return i7;
    }

    public boolean finish() {
        boolean z;
        if (!this.started) {
            return false;
        }
        this.started = false;
        try {
            this.out.write(59);
            this.out.flush();
            if (this.closeStream) {
                this.out.close();
            }
            z = true;
        } catch (IOException unused) {
            z = false;
        }
        this.transIndex = 0;
        this.out = null;
        this.image = null;
        this.pixels = null;
        this.indexedPixels = null;
        this.colorTab = null;
        this.closeStream = false;
        this.firstFrame = true;
        return z;
    }

    public int[] getImageData(Bitmap bitmap) {
        int width = bitmap.getWidth();
        int height = bitmap.getHeight();
        int[] iArr = new int[width * height];
        bitmap.getPixels(iArr, 0, width, 0, 0, width, height);
        return iArr;
    }

    public void getImagePixels() {
        int width = this.image.getWidth();
        int height = this.image.getHeight();
        int i2 = this.width;
        if (width != i2 || height != this.height) {
            Bitmap createBitmap = Bitmap.createBitmap(i2, this.height, Bitmap.Config.RGB_565);
            new Canvas(createBitmap).drawBitmap(this.image, 0.0f, 0.0f, new Paint());
            this.image = createBitmap;
        }
        int[] imageData = getImageData(this.image);
        this.pixels = new byte[imageData.length * 3];
        for (int i3 = 0; i3 < imageData.length; i3++) {
            int i4 = imageData[i3];
            int i5 = i3 * 3;
            byte[] bArr = this.pixels;
            int i6 = i5 + 1;
            bArr[i5] = (byte) ((i4 >> 0) & 255);
            bArr[i6] = (byte) ((i4 >> 8) & 255);
            bArr[i6 + 1] = (byte) ((i4 >> 16) & 255);
        }
    }

    public void setDelay(int i2) {
        this.delay = i2 / 10;
    }

    public void setDispose(int i2) {
        if (i2 >= 0) {
            this.dispose = i2;
        }
    }

    public void setFrameRate(float f2) {
        if (f2 != 0.0f) {
            this.delay = (int) (100.0f / f2);
        }
    }

    public void setPosition(int i2, int i3) {
        this.f10789x = i2;
        this.f10790y = i3;
    }

    public void setQuality(int i2) {
        if (i2 < 1) {
            i2 = 1;
        }
        this.sample = i2;
    }

    public void setRepeat(int i2) {
        if (i2 >= 0) {
            this.repeat = i2;
        }
    }

    public void setSize(int i2, int i3) {
        this.width = i2;
        this.height = i3;
        if (i2 < 1) {
            this.width = 320;
        }
        if (i3 < 1) {
            this.height = 240;
        }
        this.sizeSet = true;
    }

    public void setTransparent(int i2) {
        this.transparent = i2;
    }

    public boolean start(OutputStream outputStream) {
        boolean z = false;
        if (outputStream == null) {
            return false;
        }
        this.closeStream = false;
        this.out = outputStream;
        try {
            writeString("GIF89a");
            z = true;
        } catch (IOException unused) {
        }
        this.started = z;
        return z;
    }

    public void writeGraphicCtrlExt() {
        int i2;
        int i3;
        this.out.write(33);
        this.out.write(249);
        this.out.write(4);
        if (this.transparent == -1) {
            i2 = 0;
            i3 = 0;
        } else {
            i2 = 1;
            i3 = 2;
        }
        int i4 = this.dispose;
        if (i4 >= 0) {
            i3 = i4 & 7;
        }
        this.out.write(i2 | (i3 << 2) | 0 | 0);
        writeShort(this.delay);
        this.out.write(this.transIndex);
        this.out.write(0);
    }

    public void writeImageDesc() {
        this.out.write(44);
        writeShort(this.f10789x);
        writeShort(this.f10790y);
        writeShort(this.width);
        writeShort(this.height);
        if (this.firstFrame) {
            this.out.write(0);
        } else {
            this.out.write(this.palSize | 128);
        }
    }

    public void writeLSD() {
        writeShort(this.width);
        writeShort(this.height);
        this.out.write(this.palSize | 240);
        this.out.write(0);
        this.out.write(0);
    }

    public void writeNetscapeExt() {
        this.out.write(33);
        this.out.write(255);
        this.out.write(11);
        writeString("NETSCAPE2.0");
        this.out.write(3);
        this.out.write(1);
        writeShort(this.repeat);
        this.out.write(0);
    }

    public void writePalette() {
        OutputStream outputStream = this.out;
        byte[] bArr = this.colorTab;
        outputStream.write(bArr, 0, bArr.length);
        int length = 768 - this.colorTab.length;
        for (int i2 = 0; i2 < length; i2++) {
            this.out.write(0);
        }
    }

    public void writePixels() {
        new LZWEncoder(this.width, this.height, this.indexedPixels, this.colorDepth).encode(this.out);
    }

    public void writeShort(int i2) {
        this.out.write(i2 & 255);
        this.out.write((i2 >> 8) & 255);
    }

    public void writeString(String str) {
        for (int i2 = 0; i2 < str.length(); i2++) {
            this.out.write((byte) str.charAt(i2));
        }
    }
}
