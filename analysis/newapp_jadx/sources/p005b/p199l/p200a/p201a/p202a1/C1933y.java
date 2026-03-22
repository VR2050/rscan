package p005b.p199l.p200a.p201a.p202a1;

import java.nio.ByteBuffer;
import p005b.p199l.p200a.p201a.p202a1.InterfaceC1920l;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* renamed from: b.l.a.a.a1.y */
/* loaded from: classes.dex */
public final class C1933y extends AbstractC1926r {

    /* renamed from: i */
    public int f3213i;

    /* renamed from: j */
    public boolean f3214j;

    /* renamed from: k */
    public byte[] f3215k;

    /* renamed from: l */
    public byte[] f3216l;

    /* renamed from: m */
    public int f3217m;

    /* renamed from: n */
    public int f3218n;

    /* renamed from: o */
    public int f3219o;

    /* renamed from: p */
    public boolean f3220p;

    /* renamed from: q */
    public long f3221q;

    public C1933y() {
        byte[] bArr = C2344d0.f6040f;
        this.f3215k = bArr;
        this.f3216l = bArr;
    }

    @Override // p005b.p199l.p200a.p201a.p202a1.AbstractC1926r
    /* renamed from: a */
    public InterfaceC1920l.a mo1259a(InterfaceC1920l.a aVar) {
        if (aVar.f3080d == 2) {
            return this.f3214j ? aVar : InterfaceC1920l.a.f3077a;
        }
        throw new InterfaceC1920l.b(aVar);
    }

    @Override // p005b.p199l.p200a.p201a.p202a1.AbstractC1926r, p005b.p199l.p200a.p201a.p202a1.InterfaceC1920l
    /* renamed from: b */
    public boolean mo1253b() {
        return this.f3214j;
    }

    @Override // p005b.p199l.p200a.p201a.p202a1.InterfaceC1920l
    /* renamed from: e */
    public void mo1256e(ByteBuffer byteBuffer) {
        int position;
        while (byteBuffer.hasRemaining() && !this.f3127g.hasRemaining()) {
            int i2 = this.f3217m;
            if (i2 == 0) {
                int limit = byteBuffer.limit();
                byteBuffer.limit(Math.min(limit, byteBuffer.position() + this.f3215k.length));
                int limit2 = byteBuffer.limit() - 1;
                while (true) {
                    if (limit2 < byteBuffer.position()) {
                        position = byteBuffer.position();
                        break;
                    } else {
                        if (Math.abs((int) byteBuffer.get(limit2)) > 4) {
                            int i3 = this.f3213i;
                            position = ((limit2 / i3) * i3) + i3;
                            break;
                        }
                        limit2 -= 2;
                    }
                }
                if (position == byteBuffer.position()) {
                    this.f3217m = 1;
                } else {
                    byteBuffer.limit(position);
                    int remaining = byteBuffer.remaining();
                    m1278k(remaining).put(byteBuffer).flip();
                    if (remaining > 0) {
                        this.f3220p = true;
                    }
                }
                byteBuffer.limit(limit);
            } else if (i2 == 1) {
                int limit3 = byteBuffer.limit();
                int m1329l = m1329l(byteBuffer);
                int position2 = m1329l - byteBuffer.position();
                byte[] bArr = this.f3215k;
                int length = bArr.length;
                int i4 = this.f3218n;
                int i5 = length - i4;
                if (m1329l >= limit3 || position2 >= i5) {
                    int min = Math.min(position2, i5);
                    byteBuffer.limit(byteBuffer.position() + min);
                    byteBuffer.get(this.f3215k, this.f3218n, min);
                    int i6 = this.f3218n + min;
                    this.f3218n = i6;
                    byte[] bArr2 = this.f3215k;
                    if (i6 == bArr2.length) {
                        if (this.f3220p) {
                            m1330m(bArr2, this.f3219o);
                            this.f3221q += (this.f3218n - (this.f3219o * 2)) / this.f3213i;
                        } else {
                            this.f3221q += (i6 - this.f3219o) / this.f3213i;
                        }
                        m1331n(byteBuffer, this.f3215k, this.f3218n);
                        this.f3218n = 0;
                        this.f3217m = 2;
                    }
                    byteBuffer.limit(limit3);
                } else {
                    m1330m(bArr, i4);
                    this.f3218n = 0;
                    this.f3217m = 0;
                }
            } else {
                if (i2 != 2) {
                    throw new IllegalStateException();
                }
                int limit4 = byteBuffer.limit();
                int m1329l2 = m1329l(byteBuffer);
                byteBuffer.limit(m1329l2);
                this.f3221q += byteBuffer.remaining() / this.f3213i;
                m1331n(byteBuffer, this.f3216l, this.f3219o);
                if (m1329l2 < limit4) {
                    m1330m(this.f3216l, this.f3219o);
                    this.f3217m = 0;
                    byteBuffer.limit(limit4);
                }
            }
        }
    }

    @Override // p005b.p199l.p200a.p201a.p202a1.AbstractC1926r
    /* renamed from: h */
    public void mo1260h() {
        if (this.f3214j) {
            InterfaceC1920l.a aVar = this.f3122b;
            int i2 = aVar.f3081e;
            this.f3213i = i2;
            long j2 = aVar.f3078b;
            int i3 = ((int) ((150000 * j2) / 1000000)) * i2;
            if (this.f3215k.length != i3) {
                this.f3215k = new byte[i3];
            }
            int i4 = ((int) ((j2 * 20000) / 1000000)) * i2;
            this.f3219o = i4;
            if (this.f3216l.length != i4) {
                this.f3216l = new byte[i4];
            }
        }
        this.f3217m = 0;
        this.f3221q = 0L;
        this.f3218n = 0;
        this.f3220p = false;
    }

    @Override // p005b.p199l.p200a.p201a.p202a1.AbstractC1926r
    /* renamed from: i */
    public void mo1261i() {
        int i2 = this.f3218n;
        if (i2 > 0) {
            m1330m(this.f3215k, i2);
        }
        if (this.f3220p) {
            return;
        }
        this.f3221q += this.f3219o / this.f3213i;
    }

    @Override // p005b.p199l.p200a.p201a.p202a1.AbstractC1926r
    /* renamed from: j */
    public void mo1262j() {
        this.f3214j = false;
        this.f3219o = 0;
        byte[] bArr = C2344d0.f6040f;
        this.f3215k = bArr;
        this.f3216l = bArr;
    }

    /* renamed from: l */
    public final int m1329l(ByteBuffer byteBuffer) {
        for (int position = byteBuffer.position() + 1; position < byteBuffer.limit(); position += 2) {
            if (Math.abs((int) byteBuffer.get(position)) > 4) {
                int i2 = this.f3213i;
                return (position / i2) * i2;
            }
        }
        return byteBuffer.limit();
    }

    /* renamed from: m */
    public final void m1330m(byte[] bArr, int i2) {
        m1278k(i2).put(bArr, 0, i2).flip();
        if (i2 > 0) {
            this.f3220p = true;
        }
    }

    /* renamed from: n */
    public final void m1331n(ByteBuffer byteBuffer, byte[] bArr, int i2) {
        int min = Math.min(byteBuffer.remaining(), this.f3219o);
        int i3 = this.f3219o - min;
        System.arraycopy(bArr, i2 - i3, this.f3216l, 0, i3);
        byteBuffer.position(byteBuffer.limit() - min);
        byteBuffer.get(this.f3216l, i3, min);
    }
}
