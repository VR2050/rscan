package p005b.p143g.p144a.p147m.p154u;

import androidx.annotation.NonNull;
import p005b.p143g.p144a.EnumC1556f;
import p005b.p143g.p144a.p147m.C1582n;
import p005b.p143g.p144a.p147m.EnumC1569a;
import p005b.p143g.p144a.p147m.p148s.InterfaceC1590d;
import p005b.p143g.p144a.p147m.p154u.InterfaceC1672n;
import p005b.p143g.p144a.p169r.C1798d;

/* renamed from: b.g.a.m.u.v */
/* loaded from: classes.dex */
public class C1680v<Model> implements InterfaceC1672n<Model, Model> {

    /* renamed from: a */
    public static final C1680v<?> f2414a = new C1680v<>();

    /* renamed from: b.g.a.m.u.v$a */
    public static class a<Model> implements InterfaceC1673o<Model, Model> {

        /* renamed from: a */
        public static final a<?> f2415a = new a<>();

        @Deprecated
        public a() {
        }

        @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1673o
        @NonNull
        /* renamed from: b */
        public InterfaceC1672n<Model, Model> mo963b(C1676r c1676r) {
            return C1680v.f2414a;
        }
    }

    /* renamed from: b.g.a.m.u.v$b */
    public static class b<Model> implements InterfaceC1590d<Model> {

        /* renamed from: c */
        public final Model f2416c;

        public b(Model model) {
            this.f2416c = model;
        }

        @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
        @NonNull
        /* renamed from: a */
        public Class<Model> mo832a() {
            return (Class<Model>) this.f2416c.getClass();
        }

        @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
        /* renamed from: b */
        public void mo835b() {
        }

        @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
        public void cancel() {
        }

        @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
        /* renamed from: d */
        public void mo837d(@NonNull EnumC1556f enumC1556f, @NonNull InterfaceC1590d.a<? super Model> aVar) {
            aVar.mo840e(this.f2416c);
        }

        @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
        @NonNull
        public EnumC1569a getDataSource() {
            return EnumC1569a.LOCAL;
        }
    }

    @Deprecated
    public C1680v() {
    }

    @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1672n
    /* renamed from: a */
    public boolean mo960a(@NonNull Model model) {
        return true;
    }

    @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1672n
    /* renamed from: b */
    public InterfaceC1672n.a<Model> mo961b(@NonNull Model model, int i2, int i3, @NonNull C1582n c1582n) {
        return new InterfaceC1672n.a<>(new C1798d(model), new b(model));
    }
}
