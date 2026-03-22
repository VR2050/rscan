package p005b.p143g.p144a.p147m.p148s;

import androidx.annotation.NonNull;
import java.io.InputStream;
import p005b.p143g.p144a.p147m.p148s.InterfaceC1591e;
import p005b.p143g.p144a.p147m.p150t.p151c0.InterfaceC1612b;
import p005b.p143g.p144a.p147m.p156v.p157c.C1719x;

/* renamed from: b.g.a.m.s.k */
/* loaded from: classes.dex */
public final class C1597k implements InterfaceC1591e<InputStream> {

    /* renamed from: a */
    public final C1719x f2020a;

    /* renamed from: b.g.a.m.s.k$a */
    public static final class a implements InterfaceC1591e.a<InputStream> {

        /* renamed from: a */
        public final InterfaceC1612b f2021a;

        public a(InterfaceC1612b interfaceC1612b) {
            this.f2021a = interfaceC1612b;
        }

        @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1591e.a
        @NonNull
        /* renamed from: a */
        public Class<InputStream> mo843a() {
            return InputStream.class;
        }

        @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1591e.a
        @NonNull
        /* renamed from: b */
        public InterfaceC1591e<InputStream> mo844b(InputStream inputStream) {
            return new C1597k(inputStream, this.f2021a);
        }
    }

    public C1597k(InputStream inputStream, InterfaceC1612b interfaceC1612b) {
        C1719x c1719x = new C1719x(inputStream, interfaceC1612b);
        this.f2020a = c1719x;
        c1719x.mark(5242880);
    }

    @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1591e
    /* renamed from: b */
    public void mo842b() {
        this.f2020a.m1026d();
    }

    @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1591e
    @NonNull
    /* renamed from: c, reason: merged with bridge method [inline-methods] */
    public InputStream mo841a() {
        this.f2020a.reset();
        return this.f2020a;
    }
}
