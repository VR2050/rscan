package p005b.p143g.p144a.p146l;

import android.graphics.Bitmap;
import android.util.Log;
import androidx.annotation.ColorInt;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Iterator;
import p005b.p143g.p144a.p146l.InterfaceC1564a;
import p005b.p143g.p144a.p147m.p150t.p151c0.InterfaceC1612b;
import p005b.p143g.p144a.p147m.p156v.p161g.C1732b;

/* renamed from: b.g.a.l.e */
/* loaded from: classes.dex */
public class C1568e implements InterfaceC1564a {

    /* renamed from: a */
    public static final String f1949a = "e";

    /* renamed from: b */
    @ColorInt
    public int[] f1950b;

    /* renamed from: d */
    public final InterfaceC1564a.a f1952d;

    /* renamed from: e */
    public ByteBuffer f1953e;

    /* renamed from: f */
    public byte[] f1954f;

    /* renamed from: g */
    public short[] f1955g;

    /* renamed from: h */
    public byte[] f1956h;

    /* renamed from: i */
    public byte[] f1957i;

    /* renamed from: j */
    public byte[] f1958j;

    /* renamed from: k */
    @ColorInt
    public int[] f1959k;

    /* renamed from: l */
    public int f1960l;

    /* renamed from: m */
    public C1566c f1961m;

    /* renamed from: n */
    public Bitmap f1962n;

    /* renamed from: o */
    public boolean f1963o;

    /* renamed from: p */
    public int f1964p;

    /* renamed from: q */
    public int f1965q;

    /* renamed from: r */
    public int f1966r;

    /* renamed from: s */
    public int f1967s;

    /* renamed from: t */
    @Nullable
    public Boolean f1968t;

    /* renamed from: c */
    @ColorInt
    public final int[] f1951c = new int[256];

    /* renamed from: u */
    @NonNull
    public Bitmap.Config f1969u = Bitmap.Config.ARGB_8888;

    public C1568e(@NonNull InterfaceC1564a.a aVar, C1566c c1566c, ByteBuffer byteBuffer, int i2) {
        this.f1952d = aVar;
        this.f1961m = new C1566c();
        synchronized (this) {
            if (i2 <= 0) {
                throw new IllegalArgumentException("Sample size must be >=0, not: " + i2);
            }
            int highestOneBit = Integer.highestOneBit(i2);
            this.f1964p = 0;
            this.f1961m = c1566c;
            this.f1960l = -1;
            ByteBuffer asReadOnlyBuffer = byteBuffer.asReadOnlyBuffer();
            this.f1953e = asReadOnlyBuffer;
            asReadOnlyBuffer.position(0);
            this.f1953e.order(ByteOrder.LITTLE_ENDIAN);
            this.f1963o = false;
            Iterator<C1565b> it = c1566c.f1937e.iterator();
            while (true) {
                if (!it.hasNext()) {
                    break;
                } else if (it.next().f1928g == 3) {
                    this.f1963o = true;
                    break;
                }
            }
            this.f1965q = highestOneBit;
            int i3 = c1566c.f1938f;
            this.f1967s = i3 / highestOneBit;
            int i4 = c1566c.f1939g;
            this.f1966r = i4 / highestOneBit;
            this.f1958j = ((C1732b) this.f1952d).m1031a(i3 * i4);
            InterfaceC1564a.a aVar2 = this.f1952d;
            int i5 = this.f1967s * this.f1966r;
            InterfaceC1612b interfaceC1612b = ((C1732b) aVar2).f2565b;
            this.f1959k = interfaceC1612b == null ? new int[i5] : (int[]) interfaceC1612b.mo863d(i5, int[].class);
        }
    }

    @Override // p005b.p143g.p144a.p146l.InterfaceC1564a
    @Nullable
    /* renamed from: a */
    public synchronized Bitmap mo804a() {
        if (this.f1961m.f1935c <= 0 || this.f1960l < 0) {
            if (Log.isLoggable(f1949a, 3)) {
                int i2 = this.f1961m.f1935c;
            }
            this.f1964p = 1;
        }
        int i3 = this.f1964p;
        if (i3 != 1 && i3 != 2) {
            this.f1964p = 0;
            if (this.f1954f == null) {
                this.f1954f = ((C1732b) this.f1952d).m1031a(255);
            }
            C1565b c1565b = this.f1961m.f1937e.get(this.f1960l);
            int i4 = this.f1960l - 1;
            C1565b c1565b2 = i4 >= 0 ? this.f1961m.f1937e.get(i4) : null;
            int[] iArr = c1565b.f1932k;
            if (iArr == null) {
                iArr = this.f1961m.f1933a;
            }
            this.f1950b = iArr;
            if (iArr == null) {
                Log.isLoggable(f1949a, 3);
                this.f1964p = 1;
                return null;
            }
            if (c1565b.f1927f) {
                System.arraycopy(iArr, 0, this.f1951c, 0, iArr.length);
                int[] iArr2 = this.f1951c;
                this.f1950b = iArr2;
                iArr2[c1565b.f1929h] = 0;
                if (c1565b.f1928g == 2 && this.f1960l == 0) {
                    this.f1968t = Boolean.TRUE;
                }
            }
            return m821k(c1565b, c1565b2);
        }
        Log.isLoggable(f1949a, 3);
        return null;
    }

    @Override // p005b.p143g.p144a.p146l.InterfaceC1564a
    /* renamed from: b */
    public void mo805b() {
        this.f1960l = (this.f1960l + 1) % this.f1961m.f1935c;
    }

    @Override // p005b.p143g.p144a.p146l.InterfaceC1564a
    /* renamed from: c */
    public int mo806c() {
        return this.f1961m.f1935c;
    }

    @Override // p005b.p143g.p144a.p146l.InterfaceC1564a
    public void clear() {
        InterfaceC1612b interfaceC1612b;
        InterfaceC1612b interfaceC1612b2;
        InterfaceC1612b interfaceC1612b3;
        this.f1961m = null;
        byte[] bArr = this.f1958j;
        if (bArr != null && (interfaceC1612b3 = ((C1732b) this.f1952d).f2565b) != null) {
            interfaceC1612b3.put(bArr);
        }
        int[] iArr = this.f1959k;
        if (iArr != null && (interfaceC1612b2 = ((C1732b) this.f1952d).f2565b) != null) {
            interfaceC1612b2.put(iArr);
        }
        Bitmap bitmap = this.f1962n;
        if (bitmap != null) {
            ((C1732b) this.f1952d).f2564a.mo870d(bitmap);
        }
        this.f1962n = null;
        this.f1953e = null;
        this.f1968t = null;
        byte[] bArr2 = this.f1954f;
        if (bArr2 == null || (interfaceC1612b = ((C1732b) this.f1952d).f2565b) == null) {
            return;
        }
        interfaceC1612b.put(bArr2);
    }

    @Override // p005b.p143g.p144a.p146l.InterfaceC1564a
    /* renamed from: d */
    public int mo807d() {
        int i2;
        C1566c c1566c = this.f1961m;
        int i3 = c1566c.f1935c;
        if (i3 <= 0 || (i2 = this.f1960l) < 0) {
            return 0;
        }
        if (i2 < 0 || i2 >= i3) {
            return -1;
        }
        return c1566c.f1937e.get(i2).f1930i;
    }

    @Override // p005b.p143g.p144a.p146l.InterfaceC1564a
    @NonNull
    /* renamed from: e */
    public ByteBuffer mo808e() {
        return this.f1953e;
    }

    @Override // p005b.p143g.p144a.p146l.InterfaceC1564a
    /* renamed from: f */
    public int mo809f() {
        return this.f1960l;
    }

    @Override // p005b.p143g.p144a.p146l.InterfaceC1564a
    /* renamed from: g */
    public int mo810g() {
        return (this.f1959k.length * 4) + this.f1953e.limit() + this.f1958j.length;
    }

    @Override // p005b.p143g.p144a.p146l.InterfaceC1564a
    /* renamed from: h */
    public int mo811h() {
        int i2 = this.f1961m.f1944l;
        if (i2 == -1) {
            return 1;
        }
        if (i2 == 0) {
            return 0;
        }
        return i2 + 1;
    }

    /* renamed from: i */
    public final Bitmap m819i() {
        Boolean bool = this.f1968t;
        Bitmap.Config config = (bool == null || bool.booleanValue()) ? Bitmap.Config.ARGB_8888 : this.f1969u;
        Bitmap mo869c = ((C1732b) this.f1952d).f2564a.mo869c(this.f1967s, this.f1966r, config);
        mo869c.setHasAlpha(true);
        return mo869c;
    }

    /* renamed from: j */
    public void m820j(@NonNull Bitmap.Config config) {
        if (config == Bitmap.Config.ARGB_8888 || config == Bitmap.Config.RGB_565) {
            this.f1969u = config;
            return;
        }
        throw new IllegalArgumentException("Unsupported format: " + config + ", must be one of " + Bitmap.Config.ARGB_8888 + " or " + Bitmap.Config.RGB_565);
    }

    /* JADX WARN: Code restructure failed: missing block: B:24:0x0045, code lost:
    
        if (r3.f1942j == r34.f1929h) goto L26;
     */
    /* JADX WARN: Removed duplicated region for block: B:143:0x0406  */
    /* JADX WARN: Removed duplicated region for block: B:27:0x0060  */
    /* renamed from: k */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final android.graphics.Bitmap m821k(p005b.p143g.p144a.p146l.C1565b r34, p005b.p143g.p144a.p146l.C1565b r35) {
        /*
            Method dump skipped, instructions count: 1070
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p143g.p144a.p146l.C1568e.m821k(b.g.a.l.b, b.g.a.l.b):android.graphics.Bitmap");
    }
}
