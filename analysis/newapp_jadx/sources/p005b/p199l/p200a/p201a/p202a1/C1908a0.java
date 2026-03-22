package p005b.p199l.p200a.p201a.p202a1;

import androidx.annotation.Nullable;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.ShortBuffer;
import java.util.Objects;
import p005b.p199l.p200a.p201a.p202a1.InterfaceC1920l;

/* renamed from: b.l.a.a.a1.a0 */
/* loaded from: classes.dex */
public final class C1908a0 implements InterfaceC1920l {

    /* renamed from: b */
    public int f3020b;

    /* renamed from: c */
    public float f3021c = 1.0f;

    /* renamed from: d */
    public float f3022d = 1.0f;

    /* renamed from: e */
    public InterfaceC1920l.a f3023e;

    /* renamed from: f */
    public InterfaceC1920l.a f3024f;

    /* renamed from: g */
    public InterfaceC1920l.a f3025g;

    /* renamed from: h */
    public InterfaceC1920l.a f3026h;

    /* renamed from: i */
    public boolean f3027i;

    /* renamed from: j */
    @Nullable
    public C1934z f3028j;

    /* renamed from: k */
    public ByteBuffer f3029k;

    /* renamed from: l */
    public ShortBuffer f3030l;

    /* renamed from: m */
    public ByteBuffer f3031m;

    /* renamed from: n */
    public long f3032n;

    /* renamed from: o */
    public long f3033o;

    /* renamed from: p */
    public boolean f3034p;

    public C1908a0() {
        InterfaceC1920l.a aVar = InterfaceC1920l.a.f3077a;
        this.f3023e = aVar;
        this.f3024f = aVar;
        this.f3025g = aVar;
        this.f3026h = aVar;
        ByteBuffer byteBuffer = InterfaceC1920l.f3076a;
        this.f3029k = byteBuffer;
        this.f3030l = byteBuffer.asShortBuffer();
        this.f3031m = byteBuffer;
        this.f3020b = -1;
    }

    @Override // p005b.p199l.p200a.p201a.p202a1.InterfaceC1920l
    /* renamed from: b */
    public boolean mo1253b() {
        return this.f3024f.f3078b != -1 && (Math.abs(this.f3021c - 1.0f) >= 0.01f || Math.abs(this.f3022d - 1.0f) >= 0.01f || this.f3024f.f3078b != this.f3023e.f3078b);
    }

    @Override // p005b.p199l.p200a.p201a.p202a1.InterfaceC1920l
    /* renamed from: c */
    public boolean mo1254c() {
        C1934z c1934z;
        return this.f3034p && ((c1934z = this.f3028j) == null || (c1934z.f3234m * c1934z.f3223b) * 2 == 0);
    }

    @Override // p005b.p199l.p200a.p201a.p202a1.InterfaceC1920l
    /* renamed from: d */
    public ByteBuffer mo1255d() {
        ByteBuffer byteBuffer = this.f3031m;
        this.f3031m = InterfaceC1920l.f3076a;
        return byteBuffer;
    }

    @Override // p005b.p199l.p200a.p201a.p202a1.InterfaceC1920l
    /* renamed from: e */
    public void mo1256e(ByteBuffer byteBuffer) {
        C1934z c1934z = this.f3028j;
        Objects.requireNonNull(c1934z);
        if (byteBuffer.hasRemaining()) {
            ShortBuffer asShortBuffer = byteBuffer.asShortBuffer();
            int remaining = byteBuffer.remaining();
            this.f3032n += remaining;
            int remaining2 = asShortBuffer.remaining();
            int i2 = c1934z.f3223b;
            int i3 = remaining2 / i2;
            short[] m1335c = c1934z.m1335c(c1934z.f3231j, c1934z.f3232k, i3);
            c1934z.f3231j = m1335c;
            asShortBuffer.get(m1335c, c1934z.f3232k * c1934z.f3223b, ((i2 * i3) * 2) / 2);
            c1934z.f3232k += i3;
            c1934z.m1337f();
            byteBuffer.position(byteBuffer.position() + remaining);
        }
        int i4 = c1934z.f3234m * c1934z.f3223b * 2;
        if (i4 > 0) {
            if (this.f3029k.capacity() < i4) {
                ByteBuffer order = ByteBuffer.allocateDirect(i4).order(ByteOrder.nativeOrder());
                this.f3029k = order;
                this.f3030l = order.asShortBuffer();
            } else {
                this.f3029k.clear();
                this.f3030l.clear();
            }
            ShortBuffer shortBuffer = this.f3030l;
            int min = Math.min(shortBuffer.remaining() / c1934z.f3223b, c1934z.f3234m);
            shortBuffer.put(c1934z.f3233l, 0, c1934z.f3223b * min);
            int i5 = c1934z.f3234m - min;
            c1934z.f3234m = i5;
            short[] sArr = c1934z.f3233l;
            int i6 = c1934z.f3223b;
            System.arraycopy(sArr, min * i6, sArr, 0, i5 * i6);
            this.f3033o += i4;
            this.f3029k.limit(i4);
            this.f3031m = this.f3029k;
        }
    }

    @Override // p005b.p199l.p200a.p201a.p202a1.InterfaceC1920l
    /* renamed from: f */
    public InterfaceC1920l.a mo1257f(InterfaceC1920l.a aVar) {
        if (aVar.f3080d != 2) {
            throw new InterfaceC1920l.b(aVar);
        }
        int i2 = this.f3020b;
        if (i2 == -1) {
            i2 = aVar.f3078b;
        }
        this.f3023e = aVar;
        InterfaceC1920l.a aVar2 = new InterfaceC1920l.a(i2, aVar.f3079c, 2);
        this.f3024f = aVar2;
        this.f3027i = true;
        return aVar2;
    }

    @Override // p005b.p199l.p200a.p201a.p202a1.InterfaceC1920l
    public void flush() {
        if (mo1253b()) {
            InterfaceC1920l.a aVar = this.f3023e;
            this.f3025g = aVar;
            InterfaceC1920l.a aVar2 = this.f3024f;
            this.f3026h = aVar2;
            if (this.f3027i) {
                this.f3028j = new C1934z(aVar.f3078b, aVar.f3079c, this.f3021c, this.f3022d, aVar2.f3078b);
            } else {
                C1934z c1934z = this.f3028j;
                if (c1934z != null) {
                    c1934z.f3232k = 0;
                    c1934z.f3234m = 0;
                    c1934z.f3236o = 0;
                    c1934z.f3237p = 0;
                    c1934z.f3238q = 0;
                    c1934z.f3239r = 0;
                    c1934z.f3240s = 0;
                    c1934z.f3241t = 0;
                    c1934z.f3242u = 0;
                    c1934z.f3243v = 0;
                }
            }
        }
        this.f3031m = InterfaceC1920l.f3076a;
        this.f3032n = 0L;
        this.f3033o = 0L;
        this.f3034p = false;
    }

    @Override // p005b.p199l.p200a.p201a.p202a1.InterfaceC1920l
    /* renamed from: g */
    public void mo1258g() {
        int i2;
        C1934z c1934z = this.f3028j;
        if (c1934z != null) {
            int i3 = c1934z.f3232k;
            float f2 = c1934z.f3224c;
            float f3 = c1934z.f3225d;
            int i4 = c1934z.f3234m + ((int) ((((i3 / (f2 / f3)) + c1934z.f3236o) / (c1934z.f3226e * f3)) + 0.5f));
            c1934z.f3231j = c1934z.m1335c(c1934z.f3231j, i3, (c1934z.f3229h * 2) + i3);
            int i5 = 0;
            while (true) {
                i2 = c1934z.f3229h * 2;
                int i6 = c1934z.f3223b;
                if (i5 >= i2 * i6) {
                    break;
                }
                c1934z.f3231j[(i6 * i3) + i5] = 0;
                i5++;
            }
            c1934z.f3232k = i2 + c1934z.f3232k;
            c1934z.m1337f();
            if (c1934z.f3234m > i4) {
                c1934z.f3234m = i4;
            }
            c1934z.f3232k = 0;
            c1934z.f3239r = 0;
            c1934z.f3236o = 0;
        }
        this.f3034p = true;
    }

    @Override // p005b.p199l.p200a.p201a.p202a1.InterfaceC1920l
    public void reset() {
        this.f3021c = 1.0f;
        this.f3022d = 1.0f;
        InterfaceC1920l.a aVar = InterfaceC1920l.a.f3077a;
        this.f3023e = aVar;
        this.f3024f = aVar;
        this.f3025g = aVar;
        this.f3026h = aVar;
        ByteBuffer byteBuffer = InterfaceC1920l.f3076a;
        this.f3029k = byteBuffer;
        this.f3030l = byteBuffer.asShortBuffer();
        this.f3031m = byteBuffer;
        this.f3020b = -1;
        this.f3027i = false;
        this.f3028j = null;
        this.f3032n = 0L;
        this.f3033o = 0L;
        this.f3034p = false;
    }
}
