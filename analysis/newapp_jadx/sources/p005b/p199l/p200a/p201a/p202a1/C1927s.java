package p005b.p199l.p200a.p201a.p202a1;

import androidx.annotation.Nullable;
import java.nio.ByteBuffer;
import java.util.Objects;
import p005b.p199l.p200a.p201a.p202a1.InterfaceC1920l;

/* renamed from: b.l.a.a.a1.s */
/* loaded from: classes.dex */
public final class C1927s extends AbstractC1926r {

    /* renamed from: i */
    @Nullable
    public int[] f3129i;

    /* renamed from: j */
    @Nullable
    public int[] f3130j;

    @Override // p005b.p199l.p200a.p201a.p202a1.AbstractC1926r
    /* renamed from: a */
    public InterfaceC1920l.a mo1259a(InterfaceC1920l.a aVar) {
        int[] iArr = this.f3129i;
        if (iArr == null) {
            return InterfaceC1920l.a.f3077a;
        }
        if (aVar.f3080d != 2) {
            throw new InterfaceC1920l.b(aVar);
        }
        boolean z = aVar.f3079c != iArr.length;
        int i2 = 0;
        while (i2 < iArr.length) {
            int i3 = iArr[i2];
            if (i3 >= aVar.f3079c) {
                throw new InterfaceC1920l.b(aVar);
            }
            z |= i3 != i2;
            i2++;
        }
        return z ? new InterfaceC1920l.a(aVar.f3078b, iArr.length, 2) : InterfaceC1920l.a.f3077a;
    }

    @Override // p005b.p199l.p200a.p201a.p202a1.InterfaceC1920l
    /* renamed from: e */
    public void mo1256e(ByteBuffer byteBuffer) {
        int[] iArr = this.f3130j;
        Objects.requireNonNull(iArr);
        int position = byteBuffer.position();
        int limit = byteBuffer.limit();
        ByteBuffer m1278k = m1278k(((limit - position) / this.f3122b.f3081e) * this.f3123c.f3081e);
        while (position < limit) {
            for (int i2 : iArr) {
                m1278k.putShort(byteBuffer.getShort((i2 * 2) + position));
            }
            position += this.f3122b.f3081e;
        }
        byteBuffer.position(limit);
        m1278k.flip();
    }

    @Override // p005b.p199l.p200a.p201a.p202a1.AbstractC1926r
    /* renamed from: h */
    public void mo1260h() {
        this.f3130j = this.f3129i;
    }

    @Override // p005b.p199l.p200a.p201a.p202a1.AbstractC1926r
    /* renamed from: j */
    public void mo1262j() {
        this.f3130j = null;
        this.f3129i = null;
    }
}
