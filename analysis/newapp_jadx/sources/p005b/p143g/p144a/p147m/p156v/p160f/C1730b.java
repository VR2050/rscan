package p005b.p143g.p144a.p147m.p156v.p160f;

import java.io.File;
import java.util.Objects;
import p005b.p143g.p144a.p147m.p150t.InterfaceC1655w;

/* renamed from: b.g.a.m.v.f.b */
/* loaded from: classes.dex */
public class C1730b implements InterfaceC1655w {

    /* renamed from: c */
    public final T f2555c;

    /* JADX WARN: Multi-variable type inference failed */
    public C1730b(File file) {
        Objects.requireNonNull(file, "Argument must not be null");
        this.f2555c = file;
    }

    @Override // p005b.p143g.p144a.p147m.p150t.InterfaceC1655w
    /* renamed from: a */
    public Class mo947a() {
        return this.f2555c.getClass();
    }

    @Override // p005b.p143g.p144a.p147m.p150t.InterfaceC1655w
    public final Object get() {
        return this.f2555c;
    }

    @Override // p005b.p143g.p144a.p147m.p150t.InterfaceC1655w
    public final /* bridge */ /* synthetic */ int getSize() {
        return 1;
    }

    @Override // p005b.p143g.p144a.p147m.p150t.InterfaceC1655w
    public void recycle() {
    }
}
