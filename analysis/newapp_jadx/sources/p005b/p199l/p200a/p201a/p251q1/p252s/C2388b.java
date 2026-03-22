package p005b.p199l.p200a.p201a.p251q1.p252s;

import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;
import java.nio.ByteBuffer;
import p005b.p199l.p200a.p201a.AbstractC2397u;
import p005b.p199l.p200a.p201a.p204c1.C1945e;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p005b.p199l.p200a.p201a.p250p1.C2360t;

/* renamed from: b.l.a.a.q1.s.b */
/* loaded from: classes.dex */
public class C2388b extends AbstractC2397u {

    /* renamed from: o */
    public final C1945e f6270o;

    /* renamed from: p */
    public final C2360t f6271p;

    /* renamed from: q */
    public long f6272q;

    /* renamed from: r */
    @Nullable
    public InterfaceC2387a f6273r;

    /* renamed from: s */
    public long f6274s;

    public C2388b() {
        super(5);
        this.f6270o = new C1945e(1);
        this.f6271p = new C2360t();
    }

    @Override // p005b.p199l.p200a.p201a.AbstractC2397u
    /* renamed from: C */
    public void mo1303C(Format[] formatArr, long j2) {
        this.f6272q = j2;
    }

    @Override // p005b.p199l.p200a.p201a.AbstractC2397u
    /* renamed from: E */
    public int mo1661E(Format format) {
        return "application/x-camera-motion".equals(format.f9245l) ? 4 : 0;
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2396t0
    /* renamed from: c */
    public boolean mo1314c() {
        return mo2654e();
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2396t0
    public boolean isReady() {
        return true;
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2396t0
    /* renamed from: j */
    public void mo1680j(long j2, long j3) {
        float[] fArr;
        while (!mo2654e() && this.f6274s < 100000 + j2) {
            this.f6270o.clear();
            if (m2665D(m2667v(), this.f6270o, false) != -4 || this.f6270o.isEndOfStream()) {
                return;
            }
            this.f6270o.m1382g();
            C1945e c1945e = this.f6270o;
            this.f6274s = c1945e.f3307f;
            if (this.f6273r != null) {
                ByteBuffer byteBuffer = c1945e.f3306e;
                int i2 = C2344d0.f6035a;
                if (byteBuffer.remaining() != 16) {
                    fArr = null;
                } else {
                    this.f6271p.m2565A(byteBuffer.array(), byteBuffer.limit());
                    this.f6271p.m2567C(byteBuffer.arrayOffset() + 4);
                    float[] fArr2 = new float[3];
                    for (int i3 = 0; i3 < 3; i3++) {
                        fArr2[i3] = Float.intBitsToFloat(this.f6271p.m2575g());
                    }
                    fArr = fArr2;
                }
                if (fArr != null) {
                    this.f6273r.mo2174a(this.f6274s - this.f6272q, fArr);
                }
            }
        }
    }

    @Override // p005b.p199l.p200a.p201a.AbstractC2397u, p005b.p199l.p200a.p201a.C2392r0.b
    /* renamed from: k */
    public void mo1318k(int i2, @Nullable Object obj) {
        if (i2 == 7) {
            this.f6273r = (InterfaceC2387a) obj;
        }
    }

    @Override // p005b.p199l.p200a.p201a.AbstractC2397u
    /* renamed from: w */
    public void mo1325w() {
        this.f6274s = 0L;
        InterfaceC2387a interfaceC2387a = this.f6273r;
        if (interfaceC2387a != null) {
            interfaceC2387a.mo2175b();
        }
    }

    @Override // p005b.p199l.p200a.p201a.AbstractC2397u
    /* renamed from: y */
    public void mo1327y(long j2, boolean z) {
        this.f6274s = 0L;
        InterfaceC2387a interfaceC2387a = this.f6273r;
        if (interfaceC2387a != null) {
            interfaceC2387a.mo2175b();
        }
    }
}
