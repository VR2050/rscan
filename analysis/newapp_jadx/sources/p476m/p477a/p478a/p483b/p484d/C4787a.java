package p476m.p477a.p478a.p483b.p484d;

import java.io.OutputStream;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: m.a.a.b.d.a */
/* loaded from: classes3.dex */
public class C4787a extends OutputStream {

    /* renamed from: c */
    public static final byte[] f12263c = new byte[0];

    /* renamed from: e */
    public final List<byte[]> f12264e = new ArrayList();

    /* renamed from: f */
    public int f12265f;

    /* renamed from: g */
    public int f12266g;

    /* renamed from: h */
    public byte[] f12267h;

    /* renamed from: i */
    public int f12268i;

    public C4787a(int i2) {
        if (i2 < 0) {
            throw new IllegalArgumentException(C1499a.m626l("Negative initial size: ", i2));
        }
        synchronized (this) {
            m5465b(i2);
        }
    }

    /* renamed from: b */
    public final void m5465b(int i2) {
        if (this.f12265f < this.f12264e.size() - 1) {
            this.f12266g += this.f12267h.length;
            int i3 = this.f12265f + 1;
            this.f12265f = i3;
            this.f12267h = this.f12264e.get(i3);
            return;
        }
        byte[] bArr = this.f12267h;
        if (bArr == null) {
            this.f12266g = 0;
        } else {
            i2 = Math.max(bArr.length << 1, i2 - this.f12266g);
            this.f12266g += this.f12267h.length;
        }
        this.f12265f++;
        byte[] bArr2 = new byte[i2];
        this.f12267h = bArr2;
        this.f12264e.add(bArr2);
    }

    @Override // java.io.OutputStream, java.io.Closeable, java.lang.AutoCloseable
    public void close() {
    }

    /* renamed from: d */
    public synchronized byte[] m5466d() {
        int i2 = this.f12268i;
        if (i2 == 0) {
            return f12263c;
        }
        byte[] bArr = new byte[i2];
        int i3 = 0;
        for (byte[] bArr2 : this.f12264e) {
            int min = Math.min(bArr2.length, i2);
            System.arraycopy(bArr2, 0, bArr, i3, min);
            i3 += min;
            i2 -= min;
            if (i2 == 0) {
                break;
            }
        }
        return bArr;
    }

    @Deprecated
    public String toString() {
        return new String(m5466d(), Charset.defaultCharset());
    }

    @Override // java.io.OutputStream
    public void write(byte[] bArr, int i2, int i3) {
        int i4;
        if (i2 < 0 || i2 > bArr.length || i3 < 0 || (i4 = i2 + i3) > bArr.length || i4 < 0) {
            throw new IndexOutOfBoundsException();
        }
        if (i3 == 0) {
            return;
        }
        synchronized (this) {
            int i5 = this.f12268i;
            int i6 = i5 + i3;
            int i7 = i5 - this.f12266g;
            while (i3 > 0) {
                int min = Math.min(i3, this.f12267h.length - i7);
                System.arraycopy(bArr, i4 - i3, this.f12267h, i7, min);
                i3 -= min;
                if (i3 > 0) {
                    m5465b(i6);
                    i7 = 0;
                }
            }
            this.f12268i = i6;
        }
    }

    @Override // java.io.OutputStream
    public synchronized void write(int i2) {
        int i3 = this.f12268i;
        int i4 = i3 - this.f12266g;
        if (i4 == this.f12267h.length) {
            m5465b(i3 + 1);
            i4 = 0;
        }
        this.f12267h[i4] = (byte) i2;
        this.f12268i++;
    }
}
