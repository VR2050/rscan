package p005b.p143g.p144a.p146l;

import android.util.Log;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.view.ViewCompat;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.Objects;

/* renamed from: b.g.a.l.d */
/* loaded from: classes.dex */
public class C1567d {

    /* renamed from: b */
    public ByteBuffer f1946b;

    /* renamed from: c */
    public C1566c f1947c;

    /* renamed from: a */
    public final byte[] f1945a = new byte[256];

    /* renamed from: d */
    public int f1948d = 0;

    /* renamed from: a */
    public final boolean m812a() {
        return this.f1947c.f1934b != 0;
    }

    @NonNull
    /* renamed from: b */
    public C1566c m813b() {
        if (this.f1946b == null) {
            throw new IllegalStateException("You must call setData() before parseHeader()");
        }
        if (m812a()) {
            return this.f1947c;
        }
        StringBuilder sb = new StringBuilder();
        for (int i2 = 0; i2 < 6; i2++) {
            sb.append((char) m814c());
        }
        if (sb.toString().startsWith("GIF")) {
            this.f1947c.f1938f = m817f();
            this.f1947c.f1939g = m817f();
            int m814c = m814c();
            C1566c c1566c = this.f1947c;
            c1566c.f1940h = (m814c & 128) != 0;
            c1566c.f1941i = (int) Math.pow(2.0d, (m814c & 7) + 1);
            this.f1947c.f1942j = m814c();
            C1566c c1566c2 = this.f1947c;
            m814c();
            Objects.requireNonNull(c1566c2);
            if (this.f1947c.f1940h && !m812a()) {
                C1566c c1566c3 = this.f1947c;
                c1566c3.f1933a = m816e(c1566c3.f1941i);
                C1566c c1566c4 = this.f1947c;
                c1566c4.f1943k = c1566c4.f1933a[c1566c4.f1942j];
            }
        } else {
            this.f1947c.f1934b = 1;
        }
        if (!m812a()) {
            boolean z = false;
            while (!z && !m812a() && this.f1947c.f1935c <= Integer.MAX_VALUE) {
                int m814c2 = m814c();
                if (m814c2 == 33) {
                    int m814c3 = m814c();
                    if (m814c3 == 1) {
                        m818g();
                    } else if (m814c3 == 249) {
                        this.f1947c.f1936d = new C1565b();
                        m814c();
                        int m814c4 = m814c();
                        C1565b c1565b = this.f1947c.f1936d;
                        int i3 = (m814c4 & 28) >> 2;
                        c1565b.f1928g = i3;
                        if (i3 == 0) {
                            c1565b.f1928g = 1;
                        }
                        c1565b.f1927f = (m814c4 & 1) != 0;
                        int m817f = m817f();
                        if (m817f < 2) {
                            m817f = 10;
                        }
                        C1565b c1565b2 = this.f1947c.f1936d;
                        c1565b2.f1930i = m817f * 10;
                        c1565b2.f1929h = m814c();
                        m814c();
                    } else if (m814c3 == 254) {
                        m818g();
                    } else if (m814c3 != 255) {
                        m818g();
                    } else {
                        m815d();
                        StringBuilder sb2 = new StringBuilder();
                        for (int i4 = 0; i4 < 11; i4++) {
                            sb2.append((char) this.f1945a[i4]);
                        }
                        if (sb2.toString().equals("NETSCAPE2.0")) {
                            do {
                                m815d();
                                byte[] bArr = this.f1945a;
                                if (bArr[0] == 1) {
                                    this.f1947c.f1944l = ((bArr[2] & 255) << 8) | (bArr[1] & 255);
                                }
                                if (this.f1948d > 0) {
                                }
                            } while (!m812a());
                        } else {
                            m818g();
                        }
                    }
                } else if (m814c2 == 44) {
                    C1566c c1566c5 = this.f1947c;
                    if (c1566c5.f1936d == null) {
                        c1566c5.f1936d = new C1565b();
                    }
                    c1566c5.f1936d.f1922a = m817f();
                    this.f1947c.f1936d.f1923b = m817f();
                    this.f1947c.f1936d.f1924c = m817f();
                    this.f1947c.f1936d.f1925d = m817f();
                    int m814c5 = m814c();
                    boolean z2 = (m814c5 & 128) != 0;
                    int pow = (int) Math.pow(2.0d, (m814c5 & 7) + 1);
                    C1565b c1565b3 = this.f1947c.f1936d;
                    c1565b3.f1926e = (m814c5 & 64) != 0;
                    if (z2) {
                        c1565b3.f1932k = m816e(pow);
                    } else {
                        c1565b3.f1932k = null;
                    }
                    this.f1947c.f1936d.f1931j = this.f1946b.position();
                    m814c();
                    m818g();
                    if (!m812a()) {
                        C1566c c1566c6 = this.f1947c;
                        c1566c6.f1935c++;
                        c1566c6.f1937e.add(c1566c6.f1936d);
                    }
                } else if (m814c2 != 59) {
                    this.f1947c.f1934b = 1;
                } else {
                    z = true;
                }
            }
            C1566c c1566c7 = this.f1947c;
            if (c1566c7.f1935c < 0) {
                c1566c7.f1934b = 1;
            }
        }
        return this.f1947c;
    }

    /* renamed from: c */
    public final int m814c() {
        try {
            return this.f1946b.get() & 255;
        } catch (Exception unused) {
            this.f1947c.f1934b = 1;
            return 0;
        }
    }

    /* renamed from: d */
    public final void m815d() {
        int m814c = m814c();
        this.f1948d = m814c;
        if (m814c <= 0) {
            return;
        }
        int i2 = 0;
        while (true) {
            try {
                int i3 = this.f1948d;
                if (i2 >= i3) {
                    return;
                }
                int i4 = i3 - i2;
                this.f1946b.get(this.f1945a, i2, i4);
                i2 += i4;
            } catch (Exception unused) {
                Log.isLoggable("GifHeaderParser", 3);
                this.f1947c.f1934b = 1;
                return;
            }
        }
    }

    @Nullable
    /* renamed from: e */
    public final int[] m816e(int i2) {
        byte[] bArr = new byte[i2 * 3];
        int[] iArr = null;
        try {
            this.f1946b.get(bArr);
            iArr = new int[256];
            int i3 = 0;
            int i4 = 0;
            while (i3 < i2) {
                int i5 = i4 + 1;
                int i6 = bArr[i4] & 255;
                int i7 = i5 + 1;
                int i8 = bArr[i5] & 255;
                int i9 = i7 + 1;
                int i10 = i3 + 1;
                iArr[i3] = (i6 << 16) | ViewCompat.MEASURED_STATE_MASK | (i8 << 8) | (bArr[i7] & 255);
                i4 = i9;
                i3 = i10;
            }
        } catch (BufferUnderflowException unused) {
            Log.isLoggable("GifHeaderParser", 3);
            this.f1947c.f1934b = 1;
        }
        return iArr;
    }

    /* renamed from: f */
    public final int m817f() {
        return this.f1946b.getShort();
    }

    /* renamed from: g */
    public final void m818g() {
        int m814c;
        do {
            m814c = m814c();
            this.f1946b.position(Math.min(this.f1946b.position() + m814c, this.f1946b.limit()));
        } while (m814c > 0);
    }
}
