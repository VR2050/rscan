package p005b.p199l.p200a.p201a.p208f1;

import java.io.EOFException;
import java.util.Arrays;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* renamed from: b.l.a.a.f1.e */
/* loaded from: classes.dex */
public final class C2003e {

    /* renamed from: b */
    public final InterfaceC2321m f3787b;

    /* renamed from: c */
    public final long f3788c;

    /* renamed from: d */
    public long f3789d;

    /* renamed from: f */
    public int f3791f;

    /* renamed from: g */
    public int f3792g;

    /* renamed from: e */
    public byte[] f3790e = new byte[65536];

    /* renamed from: a */
    public final byte[] f3786a = new byte[4096];

    public C2003e(InterfaceC2321m interfaceC2321m, long j2, long j3) {
        this.f3787b = interfaceC2321m;
        this.f3789d = j2;
        this.f3788c = j3;
    }

    /* renamed from: a */
    public boolean m1561a(int i2, boolean z) {
        m1563c(i2);
        int i3 = this.f3792g - this.f3791f;
        while (i3 < i2) {
            i3 = m1567g(this.f3790e, this.f3791f, i2, i3, z);
            if (i3 == -1) {
                return false;
            }
            this.f3792g = this.f3791f + i3;
        }
        this.f3791f += i2;
        return true;
    }

    /* renamed from: b */
    public final void m1562b(int i2) {
        if (i2 != -1) {
            this.f3789d += i2;
        }
    }

    /* renamed from: c */
    public final void m1563c(int i2) {
        int i3 = this.f3791f + i2;
        byte[] bArr = this.f3790e;
        if (i3 > bArr.length) {
            this.f3790e = Arrays.copyOf(this.f3790e, C2344d0.m2329g(bArr.length * 2, 65536 + i3, i3 + 524288));
        }
    }

    /* renamed from: d */
    public long m1564d() {
        return this.f3789d + this.f3791f;
    }

    /* renamed from: e */
    public boolean m1565e(byte[] bArr, int i2, int i3, boolean z) {
        if (!m1561a(i3, z)) {
            return false;
        }
        System.arraycopy(this.f3790e, this.f3791f - i3, bArr, i2, i3);
        return true;
    }

    /* renamed from: f */
    public int m1566f(byte[] bArr, int i2, int i3) {
        int i4 = this.f3792g;
        int i5 = 0;
        if (i4 != 0) {
            int min = Math.min(i4, i3);
            System.arraycopy(this.f3790e, 0, bArr, i2, min);
            m1570j(min);
            i5 = min;
        }
        if (i5 == 0) {
            i5 = m1567g(bArr, i2, i3, 0, true);
        }
        m1562b(i5);
        return i5;
    }

    /* renamed from: g */
    public final int m1567g(byte[] bArr, int i2, int i3, int i4, boolean z) {
        if (Thread.interrupted()) {
            throw new InterruptedException();
        }
        int read = this.f3787b.read(bArr, i2 + i4, i3 - i4);
        if (read != -1) {
            return i4 + read;
        }
        if (i4 == 0 && z) {
            return -1;
        }
        throw new EOFException();
    }

    /* renamed from: h */
    public boolean m1568h(byte[] bArr, int i2, int i3, boolean z) {
        int min;
        int i4 = this.f3792g;
        if (i4 == 0) {
            min = 0;
        } else {
            min = Math.min(i4, i3);
            System.arraycopy(this.f3790e, 0, bArr, i2, min);
            m1570j(min);
        }
        int i5 = min;
        while (i5 < i3 && i5 != -1) {
            i5 = m1567g(bArr, i2, i3, i5, z);
        }
        m1562b(i5);
        return i5 != -1;
    }

    /* renamed from: i */
    public void m1569i(int i2) {
        int min = Math.min(this.f3792g, i2);
        m1570j(min);
        int i3 = min;
        while (i3 < i2 && i3 != -1) {
            i3 = m1567g(this.f3786a, -i3, Math.min(i2, this.f3786a.length + i3), i3, false);
        }
        m1562b(i3);
    }

    /* renamed from: j */
    public final void m1570j(int i2) {
        int i3 = this.f3792g - i2;
        this.f3792g = i3;
        this.f3791f = 0;
        byte[] bArr = this.f3790e;
        byte[] bArr2 = i3 < bArr.length - 524288 ? new byte[65536 + i3] : bArr;
        System.arraycopy(bArr, i2, bArr2, 0, i3);
        this.f3790e = bArr2;
    }
}
