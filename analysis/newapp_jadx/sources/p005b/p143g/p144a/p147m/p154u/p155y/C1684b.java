package p005b.p143g.p144a.p147m.p154u.p155y;

import android.net.Uri;
import androidx.annotation.NonNull;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import p005b.p143g.p144a.p147m.C1582n;
import p005b.p143g.p144a.p147m.p154u.C1665g;
import p005b.p143g.p144a.p147m.p154u.C1676r;
import p005b.p143g.p144a.p147m.p154u.InterfaceC1672n;
import p005b.p143g.p144a.p147m.p154u.InterfaceC1673o;

/* renamed from: b.g.a.m.u.y.b */
/* loaded from: classes.dex */
public class C1684b implements InterfaceC1672n<Uri, InputStream> {

    /* renamed from: a */
    public static final Set<String> f2427a = Collections.unmodifiableSet(new HashSet(Arrays.asList("http", "https")));

    /* renamed from: b */
    public final InterfaceC1672n<C1665g, InputStream> f2428b;

    /* renamed from: b.g.a.m.u.y.b$a */
    public static class a implements InterfaceC1673o<Uri, InputStream> {
        @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1673o
        @NonNull
        /* renamed from: b */
        public InterfaceC1672n<Uri, InputStream> mo963b(C1676r c1676r) {
            return new C1684b(c1676r.m979b(C1665g.class, InputStream.class));
        }
    }

    public C1684b(InterfaceC1672n<C1665g, InputStream> interfaceC1672n) {
        this.f2428b = interfaceC1672n;
    }

    @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1672n
    /* renamed from: a */
    public boolean mo960a(@NonNull Uri uri) {
        return f2427a.contains(uri.getScheme());
    }

    @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1672n
    /* renamed from: b */
    public InterfaceC1672n.a<InputStream> mo961b(@NonNull Uri uri, int i2, int i3, @NonNull C1582n c1582n) {
        return this.f2428b.mo961b(new C1665g(uri.toString()), i2, i3, c1582n);
    }
}
