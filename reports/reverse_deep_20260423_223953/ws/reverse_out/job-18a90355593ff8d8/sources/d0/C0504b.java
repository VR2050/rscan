package d0;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

/* JADX INFO: renamed from: d0.b, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0504b extends FilterInputStream {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final byte[] f9148b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private int f9149c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private int f9150d;

    public C0504b(InputStream inputStream, byte[] bArr) {
        super(inputStream);
        inputStream.getClass();
        bArr.getClass();
        this.f9148b = bArr;
    }

    private int b() {
        int i3 = this.f9149c;
        byte[] bArr = this.f9148b;
        if (i3 >= bArr.length) {
            return -1;
        }
        this.f9149c = i3 + 1;
        return bArr[i3] & 255;
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public void mark(int i3) {
        if (((FilterInputStream) this).in.markSupported()) {
            super.mark(i3);
            this.f9150d = this.f9149c;
        }
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public int read() throws IOException {
        int i3 = ((FilterInputStream) this).in.read();
        return i3 != -1 ? i3 : b();
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public void reset() throws IOException {
        if (!((FilterInputStream) this).in.markSupported()) {
            throw new IOException("mark is not supported");
        }
        ((FilterInputStream) this).in.reset();
        this.f9149c = this.f9150d;
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public int read(byte[] bArr) {
        return read(bArr, 0, bArr.length);
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public int read(byte[] bArr, int i3, int i4) throws IOException {
        int i5 = ((FilterInputStream) this).in.read(bArr, i3, i4);
        if (i5 != -1) {
            return i5;
        }
        int i6 = 0;
        if (i4 == 0) {
            return 0;
        }
        while (i6 < i4) {
            int iB = b();
            if (iB == -1) {
                break;
            }
            bArr[i3 + i6] = (byte) iB;
            i6++;
        }
        if (i6 > 0) {
            return i6;
        }
        return -1;
    }
}
