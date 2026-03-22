package p005b.p199l.p200a.p201a.p236l1;

import androidx.annotation.Nullable;
import java.util.List;
import java.util.Objects;
import p005b.p199l.p200a.p201a.p204c1.AbstractC1946f;

/* renamed from: b.l.a.a.l1.j */
/* loaded from: classes.dex */
public abstract class AbstractC2215j extends AbstractC1946f implements InterfaceC2210e {

    /* renamed from: c */
    @Nullable
    public InterfaceC2210e f5292c;

    /* renamed from: e */
    public long f5293e;

    @Override // p005b.p199l.p200a.p201a.p236l1.InterfaceC2210e
    /* renamed from: a */
    public int mo2048a(long j2) {
        InterfaceC2210e interfaceC2210e = this.f5292c;
        Objects.requireNonNull(interfaceC2210e);
        return interfaceC2210e.mo2048a(j2 - this.f5293e);
    }

    @Override // p005b.p199l.p200a.p201a.p236l1.InterfaceC2210e
    /* renamed from: b */
    public long mo2049b(int i2) {
        InterfaceC2210e interfaceC2210e = this.f5292c;
        Objects.requireNonNull(interfaceC2210e);
        return interfaceC2210e.mo2049b(i2) + this.f5293e;
    }

    @Override // p005b.p199l.p200a.p201a.p236l1.InterfaceC2210e
    /* renamed from: c */
    public List<C2207b> mo2050c(long j2) {
        InterfaceC2210e interfaceC2210e = this.f5292c;
        Objects.requireNonNull(interfaceC2210e);
        return interfaceC2210e.mo2050c(j2 - this.f5293e);
    }

    @Override // p005b.p199l.p200a.p201a.p204c1.AbstractC1941a
    public void clear() {
        super.clear();
        this.f5292c = null;
    }

    @Override // p005b.p199l.p200a.p201a.p236l1.InterfaceC2210e
    /* renamed from: d */
    public int mo2051d() {
        InterfaceC2210e interfaceC2210e = this.f5292c;
        Objects.requireNonNull(interfaceC2210e);
        return interfaceC2210e.mo2051d();
    }
}
