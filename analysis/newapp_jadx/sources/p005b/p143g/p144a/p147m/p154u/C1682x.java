package p005b.p143g.p144a.p147m.p154u;

import android.net.Uri;
import androidx.annotation.NonNull;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import p005b.p143g.p144a.p147m.C1582n;
import p005b.p143g.p144a.p147m.p154u.InterfaceC1672n;

/* renamed from: b.g.a.m.u.x */
/* loaded from: classes.dex */
public class C1682x<Data> implements InterfaceC1672n<Uri, Data> {

    /* renamed from: a */
    public static final Set<String> f2422a = Collections.unmodifiableSet(new HashSet(Arrays.asList("http", "https")));

    /* renamed from: b */
    public final InterfaceC1672n<C1665g, Data> f2423b;

    /* renamed from: b.g.a.m.u.x$a */
    public static class a implements InterfaceC1673o<Uri, InputStream> {
        @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1673o
        @NonNull
        /* renamed from: b */
        public InterfaceC1672n<Uri, InputStream> mo963b(C1676r c1676r) {
            return new C1682x(c1676r.m979b(C1665g.class, InputStream.class));
        }
    }

    public C1682x(InterfaceC1672n<C1665g, Data> interfaceC1672n) {
        this.f2423b = interfaceC1672n;
    }

    @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1672n
    /* renamed from: a */
    public boolean mo960a(@NonNull Uri uri) {
        return f2422a.contains(uri.getScheme());
    }

    @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1672n
    /* renamed from: b */
    public InterfaceC1672n.a mo961b(@NonNull Uri uri, int i2, int i3, @NonNull C1582n c1582n) {
        return this.f2423b.mo961b(new C1665g(uri.toString()), i2, i3, c1582n);
    }
}
