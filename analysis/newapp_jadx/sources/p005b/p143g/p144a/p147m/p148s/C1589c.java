package p005b.p143g.p144a.p147m.p148s;

import androidx.annotation.NonNull;
import java.io.OutputStream;
import p005b.p143g.p144a.p147m.p150t.p151c0.InterfaceC1612b;

/* renamed from: b.g.a.m.s.c */
/* loaded from: classes.dex */
public final class C1589c extends OutputStream {

    /* renamed from: c */
    @NonNull
    public final OutputStream f2002c;

    /* renamed from: e */
    public byte[] f2003e;

    /* renamed from: f */
    public InterfaceC1612b f2004f;

    /* renamed from: g */
    public int f2005g;

    public C1589c(@NonNull OutputStream outputStream, @NonNull InterfaceC1612b interfaceC1612b) {
        this.f2002c = outputStream;
        this.f2004f = interfaceC1612b;
        this.f2003e = (byte[]) interfaceC1612b.mo863d(65536, byte[].class);
    }

    @Override // java.io.OutputStream, java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        try {
            flush();
            this.f2002c.close();
            byte[] bArr = this.f2003e;
            if (bArr != null) {
                this.f2004f.put(bArr);
                this.f2003e = null;
            }
        } catch (Throwable th) {
            this.f2002c.close();
            throw th;
        }
    }

    @Override // java.io.OutputStream, java.io.Flushable
    public void flush() {
        int i2 = this.f2005g;
        if (i2 > 0) {
            this.f2002c.write(this.f2003e, 0, i2);
            this.f2005g = 0;
        }
        this.f2002c.flush();
    }

    @Override // java.io.OutputStream
    public void write(int i2) {
        byte[] bArr = this.f2003e;
        int i3 = this.f2005g;
        int i4 = i3 + 1;
        this.f2005g = i4;
        bArr[i3] = (byte) i2;
        if (i4 != bArr.length || i4 <= 0) {
            return;
        }
        this.f2002c.write(bArr, 0, i4);
        this.f2005g = 0;
    }

    @Override // java.io.OutputStream
    public void write(@NonNull byte[] bArr) {
        write(bArr, 0, bArr.length);
    }

    @Override // java.io.OutputStream
    public void write(@NonNull byte[] bArr, int i2, int i3) {
        int i4 = 0;
        do {
            int i5 = i3 - i4;
            int i6 = i2 + i4;
            int i7 = this.f2005g;
            if (i7 == 0 && i5 >= this.f2003e.length) {
                this.f2002c.write(bArr, i6, i5);
                return;
            }
            int min = Math.min(i5, this.f2003e.length - i7);
            System.arraycopy(bArr, i6, this.f2003e, this.f2005g, min);
            int i8 = this.f2005g + min;
            this.f2005g = i8;
            i4 += min;
            byte[] bArr2 = this.f2003e;
            if (i8 == bArr2.length && i8 > 0) {
                this.f2002c.write(bArr2, 0, i8);
                this.f2005g = 0;
            }
        } while (i4 < i3);
    }
}
