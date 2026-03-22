package p005b.p143g.p144a.p147m.p148s;

import androidx.annotation.NonNull;
import androidx.exifinterface.media.ExifInterface;
import java.io.FilterInputStream;
import java.io.InputStream;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: b.g.a.m.s.g */
/* loaded from: classes.dex */
public final class C1593g extends FilterInputStream {

    /* renamed from: c */
    public static final byte[] f2009c;

    /* renamed from: e */
    public static final int f2010e;

    /* renamed from: f */
    public static final int f2011f;

    /* renamed from: g */
    public final byte f2012g;

    /* renamed from: h */
    public int f2013h;

    static {
        byte[] bArr = {-1, ExifInterface.MARKER_APP1, 0, 28, 69, 120, 105, 102, 0, 0, 77, 77, 0, 0, 0, 0, 0, 8, 0, 1, 1, 18, 0, 2, 0, 0, 0, 1, 0};
        f2009c = bArr;
        int length = bArr.length;
        f2010e = length;
        f2011f = length + 2;
    }

    public C1593g(InputStream inputStream, int i2) {
        super(inputStream);
        if (i2 < -1 || i2 > 8) {
            throw new IllegalArgumentException(C1499a.m626l("Cannot add invalid orientation: ", i2));
        }
        this.f2012g = (byte) i2;
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public void mark(int i2) {
        throw new UnsupportedOperationException();
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public boolean markSupported() {
        return false;
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public int read() {
        int i2;
        int i3 = this.f2013h;
        int read = (i3 < 2 || i3 > (i2 = f2011f)) ? super.read() : i3 == i2 ? this.f2012g : f2009c[i3 - 2] & 255;
        if (read != -1) {
            this.f2013h++;
        }
        return read;
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public void reset() {
        throw new UnsupportedOperationException();
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public long skip(long j2) {
        long skip = super.skip(j2);
        if (skip > 0) {
            this.f2013h = (int) (this.f2013h + skip);
        }
        return skip;
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public int read(@NonNull byte[] bArr, int i2, int i3) {
        int i4;
        int i5 = this.f2013h;
        int i6 = f2011f;
        if (i5 > i6) {
            i4 = super.read(bArr, i2, i3);
        } else if (i5 == i6) {
            bArr[i2] = this.f2012g;
            i4 = 1;
        } else if (i5 < 2) {
            i4 = super.read(bArr, i2, 2 - i5);
        } else {
            int min = Math.min(i6 - i5, i3);
            System.arraycopy(f2009c, this.f2013h - 2, bArr, i2, min);
            i4 = min;
        }
        if (i4 > 0) {
            this.f2013h += i4;
        }
        return i4;
    }
}
