package a0;

import java.io.InputStream;

/* JADX INFO: loaded from: classes.dex */
public class j extends InputStream {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    final InterfaceC0222h f2923b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    int f2924c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    int f2925d;

    public j(InterfaceC0222h interfaceC0222h) {
        X.k.b(Boolean.valueOf(!interfaceC0222h.a()));
        this.f2923b = (InterfaceC0222h) X.k.g(interfaceC0222h);
        this.f2924c = 0;
        this.f2925d = 0;
    }

    @Override // java.io.InputStream
    public int available() {
        return this.f2923b.size() - this.f2924c;
    }

    @Override // java.io.InputStream
    public void mark(int i3) {
        this.f2925d = this.f2924c;
    }

    @Override // java.io.InputStream
    public boolean markSupported() {
        return true;
    }

    @Override // java.io.InputStream
    public int read() {
        if (available() <= 0) {
            return -1;
        }
        InterfaceC0222h interfaceC0222h = this.f2923b;
        int i3 = this.f2924c;
        this.f2924c = i3 + 1;
        return interfaceC0222h.g(i3) & 255;
    }

    @Override // java.io.InputStream
    public void reset() {
        this.f2924c = this.f2925d;
    }

    @Override // java.io.InputStream
    public long skip(long j3) {
        X.k.b(Boolean.valueOf(j3 >= 0));
        int iMin = Math.min((int) j3, available());
        this.f2924c += iMin;
        return iMin;
    }

    @Override // java.io.InputStream
    public int read(byte[] bArr) {
        return read(bArr, 0, bArr.length);
    }

    @Override // java.io.InputStream
    public int read(byte[] bArr, int i3, int i4) {
        if (i3 >= 0 && i4 >= 0 && i3 + i4 <= bArr.length) {
            int iAvailable = available();
            if (iAvailable <= 0) {
                return -1;
            }
            if (i4 <= 0) {
                return 0;
            }
            int iMin = Math.min(iAvailable, i4);
            this.f2923b.c(this.f2924c, bArr, i3, iMin);
            this.f2924c += iMin;
            return iMin;
        }
        throw new ArrayIndexOutOfBoundsException("length=" + bArr.length + "; regionStart=" + i3 + "; regionLength=" + i4);
    }
}
