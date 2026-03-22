package p005b.p199l.p200a.p201a.p236l1;

import androidx.annotation.Nullable;
import java.nio.ByteBuffer;
import java.util.Objects;
import p005b.p199l.p200a.p201a.p204c1.AbstractC1947g;
import p005b.p199l.p200a.p201a.p204c1.C1945e;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.l1.c */
/* loaded from: classes.dex */
public abstract class AbstractC2208c extends AbstractC1947g<C2214i, AbstractC2215j, C2212g> implements InterfaceC2211f {
    public AbstractC2208c(String str) {
        super(new C2214i[2], new AbstractC2215j[2]);
        C4195m.m4771I(this.f3316g == this.f3314e.length);
        for (C1945e c1945e : this.f3314e) {
            c1945e.m1381f(1024);
        }
    }

    @Override // p005b.p199l.p200a.p201a.p236l1.InterfaceC2211f
    /* renamed from: a */
    public void mo2046a(long j2) {
    }

    @Override // p005b.p199l.p200a.p201a.p204c1.AbstractC1947g
    @Nullable
    /* renamed from: e */
    public C2212g mo1383e(C2214i c2214i, AbstractC2215j abstractC2215j, boolean z) {
        C2214i c2214i2 = c2214i;
        AbstractC2215j abstractC2215j2 = abstractC2215j;
        try {
            ByteBuffer byteBuffer = c2214i2.f3306e;
            Objects.requireNonNull(byteBuffer);
            InterfaceC2210e mo2047j = mo2047j(byteBuffer.array(), byteBuffer.limit(), z);
            long j2 = c2214i2.f3307f;
            long j3 = c2214i2.f5291i;
            abstractC2215j2.timeUs = j2;
            abstractC2215j2.f5292c = mo2047j;
            if (j3 != Long.MAX_VALUE) {
                j2 = j3;
            }
            abstractC2215j2.f5293e = j2;
            abstractC2215j2.clearFlag(Integer.MIN_VALUE);
            return null;
        } catch (C2212g e2) {
            return e2;
        }
    }

    /* renamed from: j */
    public abstract InterfaceC2210e mo2047j(byte[] bArr, int i2, boolean z);
}
