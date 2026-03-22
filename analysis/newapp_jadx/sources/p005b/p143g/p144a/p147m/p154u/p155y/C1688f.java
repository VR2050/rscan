package p005b.p143g.p144a.p147m.p154u.p155y;

import androidx.annotation.NonNull;
import java.io.InputStream;
import java.net.URL;
import p005b.p143g.p144a.p147m.C1582n;
import p005b.p143g.p144a.p147m.p154u.C1665g;
import p005b.p143g.p144a.p147m.p154u.C1676r;
import p005b.p143g.p144a.p147m.p154u.InterfaceC1672n;
import p005b.p143g.p144a.p147m.p154u.InterfaceC1673o;

/* renamed from: b.g.a.m.u.y.f */
/* loaded from: classes.dex */
public class C1688f implements InterfaceC1672n<URL, InputStream> {

    /* renamed from: a */
    public final InterfaceC1672n<C1665g, InputStream> f2450a;

    /* renamed from: b.g.a.m.u.y.f$a */
    public static class a implements InterfaceC1673o<URL, InputStream> {
        @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1673o
        @NonNull
        /* renamed from: b */
        public InterfaceC1672n<URL, InputStream> mo963b(C1676r c1676r) {
            return new C1688f(c1676r.m979b(C1665g.class, InputStream.class));
        }
    }

    public C1688f(InterfaceC1672n<C1665g, InputStream> interfaceC1672n) {
        this.f2450a = interfaceC1672n;
    }

    @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1672n
    /* renamed from: a */
    public /* bridge */ /* synthetic */ boolean mo960a(@NonNull URL url) {
        return true;
    }

    @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1672n
    /* renamed from: b */
    public InterfaceC1672n.a<InputStream> mo961b(@NonNull URL url, int i2, int i3, @NonNull C1582n c1582n) {
        return this.f2450a.mo961b(new C1665g(url), i2, i3, c1582n);
    }
}
