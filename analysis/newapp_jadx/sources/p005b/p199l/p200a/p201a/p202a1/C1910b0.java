package p005b.p199l.p200a.p201a.p202a1;

import java.nio.ByteBuffer;
import p005b.p199l.p200a.p201a.p202a1.InterfaceC1920l;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* renamed from: b.l.a.a.a1.b0 */
/* loaded from: classes.dex */
public final class C1910b0 extends AbstractC1926r {

    /* renamed from: i */
    public int f3039i;

    /* renamed from: j */
    public int f3040j;

    /* renamed from: k */
    public boolean f3041k;

    /* renamed from: l */
    public int f3042l;

    /* renamed from: m */
    public byte[] f3043m = C2344d0.f6040f;

    /* renamed from: n */
    public int f3044n;

    /* renamed from: o */
    public long f3045o;

    @Override // p005b.p199l.p200a.p201a.p202a1.AbstractC1926r
    /* renamed from: a */
    public InterfaceC1920l.a mo1259a(InterfaceC1920l.a aVar) {
        if (aVar.f3080d != 2) {
            throw new InterfaceC1920l.b(aVar);
        }
        this.f3041k = true;
        return (this.f3039i == 0 && this.f3040j == 0) ? InterfaceC1920l.a.f3077a : aVar;
    }

    @Override // p005b.p199l.p200a.p201a.p202a1.AbstractC1926r, p005b.p199l.p200a.p201a.p202a1.InterfaceC1920l
    /* renamed from: c */
    public boolean mo1254c() {
        return super.mo1254c() && this.f3044n == 0;
    }

    @Override // p005b.p199l.p200a.p201a.p202a1.AbstractC1926r, p005b.p199l.p200a.p201a.p202a1.InterfaceC1920l
    /* renamed from: d */
    public ByteBuffer mo1255d() {
        int i2;
        if (super.mo1254c() && (i2 = this.f3044n) > 0) {
            m1278k(i2).put(this.f3043m, 0, this.f3044n).flip();
            this.f3044n = 0;
        }
        return super.mo1255d();
    }

    @Override // p005b.p199l.p200a.p201a.p202a1.InterfaceC1920l
    /* renamed from: e */
    public void mo1256e(ByteBuffer byteBuffer) {
        int position = byteBuffer.position();
        int limit = byteBuffer.limit();
        int i2 = limit - position;
        if (i2 == 0) {
            return;
        }
        int min = Math.min(i2, this.f3042l);
        this.f3045o += min / this.f3122b.f3081e;
        this.f3042l -= min;
        byteBuffer.position(position + min);
        if (this.f3042l > 0) {
            return;
        }
        int i3 = i2 - min;
        int length = (this.f3044n + i3) - this.f3043m.length;
        ByteBuffer m1278k = m1278k(length);
        int m2329g = C2344d0.m2329g(length, 0, this.f3044n);
        m1278k.put(this.f3043m, 0, m2329g);
        int m2329g2 = C2344d0.m2329g(length - m2329g, 0, i3);
        byteBuffer.limit(byteBuffer.position() + m2329g2);
        m1278k.put(byteBuffer);
        byteBuffer.limit(limit);
        int i4 = i3 - m2329g2;
        int i5 = this.f3044n - m2329g;
        this.f3044n = i5;
        byte[] bArr = this.f3043m;
        System.arraycopy(bArr, m2329g, bArr, 0, i5);
        byteBuffer.get(this.f3043m, this.f3044n, i4);
        this.f3044n += i4;
        m1278k.flip();
    }

    @Override // p005b.p199l.p200a.p201a.p202a1.AbstractC1926r
    /* renamed from: h */
    public void mo1260h() {
        if (this.f3041k) {
            this.f3041k = false;
            int i2 = this.f3040j;
            int i3 = this.f3122b.f3081e;
            this.f3043m = new byte[i2 * i3];
            this.f3042l = this.f3039i * i3;
        } else {
            this.f3042l = 0;
        }
        this.f3044n = 0;
    }

    @Override // p005b.p199l.p200a.p201a.p202a1.AbstractC1926r
    /* renamed from: i */
    public void mo1261i() {
        if (this.f3041k) {
            if (this.f3044n > 0) {
                this.f3045o += r0 / this.f3122b.f3081e;
            }
            this.f3044n = 0;
        }
    }

    @Override // p005b.p199l.p200a.p201a.p202a1.AbstractC1926r
    /* renamed from: j */
    public void mo1262j() {
        this.f3043m = C2344d0.f6040f;
    }
}
