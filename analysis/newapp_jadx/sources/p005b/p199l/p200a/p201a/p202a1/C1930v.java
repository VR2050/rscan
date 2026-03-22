package p005b.p199l.p200a.p201a.p202a1;

import java.nio.ByteBuffer;
import p005b.p199l.p200a.p201a.p202a1.InterfaceC1920l;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.a1.v */
/* loaded from: classes.dex */
public final class C1930v extends AbstractC1926r {

    /* renamed from: i */
    public static final int f3196i = Float.floatToIntBits(Float.NaN);

    /* renamed from: l */
    public static void m1300l(int i2, ByteBuffer byteBuffer) {
        int floatToIntBits = Float.floatToIntBits((float) (i2 * 4.656612875245797E-10d));
        if (floatToIntBits == f3196i) {
            floatToIntBits = Float.floatToIntBits(0.0f);
        }
        byteBuffer.putInt(floatToIntBits);
    }

    @Override // p005b.p199l.p200a.p201a.p202a1.AbstractC1926r
    /* renamed from: a */
    public InterfaceC1920l.a mo1259a(InterfaceC1920l.a aVar) {
        if (C2344d0.m2345w(aVar.f3080d)) {
            return C2344d0.m2345w(aVar.f3080d) ? new InterfaceC1920l.a(aVar.f3078b, aVar.f3079c, 4) : InterfaceC1920l.a.f3077a;
        }
        throw new InterfaceC1920l.b(aVar);
    }

    @Override // p005b.p199l.p200a.p201a.p202a1.InterfaceC1920l
    /* renamed from: e */
    public void mo1256e(ByteBuffer byteBuffer) {
        C4195m.m4771I(C2344d0.m2345w(this.f3122b.f3080d));
        boolean z = this.f3122b.f3080d == 805306368;
        int position = byteBuffer.position();
        int limit = byteBuffer.limit();
        int i2 = limit - position;
        if (!z) {
            i2 = (i2 / 3) * 4;
        }
        ByteBuffer m1278k = m1278k(i2);
        if (z) {
            while (position < limit) {
                m1300l((byteBuffer.get(position) & 255) | ((byteBuffer.get(position + 1) & 255) << 8) | ((byteBuffer.get(position + 2) & 255) << 16) | ((byteBuffer.get(position + 3) & 255) << 24), m1278k);
                position += 4;
            }
        } else {
            while (position < limit) {
                m1300l(((byteBuffer.get(position) & 255) << 8) | ((byteBuffer.get(position + 1) & 255) << 16) | ((byteBuffer.get(position + 2) & 255) << 24), m1278k);
                position += 3;
            }
        }
        byteBuffer.position(byteBuffer.limit());
        m1278k.flip();
    }
}
