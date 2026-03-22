package p005b.p143g.p144a.p147m.p154u.p155y;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import java.io.InputStream;
import java.util.Objects;
import java.util.Queue;
import p005b.p143g.p144a.p147m.C1581m;
import p005b.p143g.p144a.p147m.C1582n;
import p005b.p143g.p144a.p147m.p148s.C1596j;
import p005b.p143g.p144a.p147m.p154u.C1665g;
import p005b.p143g.p144a.p147m.p154u.C1671m;
import p005b.p143g.p144a.p147m.p154u.C1676r;
import p005b.p143g.p144a.p147m.p154u.InterfaceC1672n;
import p005b.p143g.p144a.p147m.p154u.InterfaceC1673o;

/* renamed from: b.g.a.m.u.y.a */
/* loaded from: classes.dex */
public class C1683a implements InterfaceC1672n<C1665g, InputStream> {

    /* renamed from: a */
    public static final C1581m<Integer> f2424a = C1581m.m825a("com.bumptech.glide.load.model.stream.HttpGlideUrlLoader.Timeout", 2500);

    /* renamed from: b */
    @Nullable
    public final C1671m<C1665g, C1665g> f2425b;

    /* renamed from: b.g.a.m.u.y.a$a */
    public static class a implements InterfaceC1673o<C1665g, InputStream> {

        /* renamed from: a */
        public final C1671m<C1665g, C1665g> f2426a = new C1671m<>(500);

        @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1673o
        @NonNull
        /* renamed from: b */
        public InterfaceC1672n<C1665g, InputStream> mo963b(C1676r c1676r) {
            return new C1683a(this.f2426a);
        }
    }

    public C1683a(@Nullable C1671m<C1665g, C1665g> c1671m) {
        this.f2425b = c1671m;
    }

    @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1672n
    /* renamed from: a */
    public /* bridge */ /* synthetic */ boolean mo960a(@NonNull C1665g c1665g) {
        return true;
    }

    @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1672n
    /* renamed from: b */
    public InterfaceC1672n.a<InputStream> mo961b(@NonNull C1665g c1665g, int i2, int i3, @NonNull C1582n c1582n) {
        C1665g c1665g2 = c1665g;
        C1671m<C1665g, C1665g> c1671m = this.f2425b;
        if (c1671m != null) {
            C1671m.b<C1665g> m976a = C1671m.b.m976a(c1665g2, 0, 0);
            C1665g m1139a = c1671m.f2376a.m1139a(m976a);
            Queue<C1671m.b<?>> queue = C1671m.b.f2377a;
            synchronized (queue) {
                queue.offer(m976a);
            }
            C1665g c1665g3 = m1139a;
            if (c1665g3 == null) {
                C1671m<C1665g, C1665g> c1671m2 = this.f2425b;
                Objects.requireNonNull(c1671m2);
                c1671m2.f2376a.m1140d(C1671m.b.m976a(c1665g2, 0, 0), c1665g2);
            } else {
                c1665g2 = c1665g3;
            }
        }
        return new InterfaceC1672n.a<>(c1665g2, new C1596j(c1665g2, ((Integer) c1582n.m827a(f2424a)).intValue()));
    }
}
