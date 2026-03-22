package p005b.p143g.p144a.p147m.p154u.p155y;

import android.content.Context;
import android.net.Uri;
import androidx.annotation.NonNull;
import java.io.InputStream;
import p005b.p143g.p144a.p147m.C1582n;
import p005b.p143g.p144a.p147m.p148s.p149p.C1603b;
import p005b.p143g.p144a.p147m.p154u.C1676r;
import p005b.p143g.p144a.p147m.p154u.InterfaceC1672n;
import p005b.p143g.p144a.p147m.p154u.InterfaceC1673o;
import p005b.p143g.p144a.p169r.C1798d;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.g.a.m.u.y.c */
/* loaded from: classes.dex */
public class C1685c implements InterfaceC1672n<Uri, InputStream> {

    /* renamed from: a */
    public final Context f2429a;

    /* renamed from: b.g.a.m.u.y.c$a */
    public static class a implements InterfaceC1673o<Uri, InputStream> {

        /* renamed from: a */
        public final Context f2430a;

        public a(Context context) {
            this.f2430a = context;
        }

        @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1673o
        @NonNull
        /* renamed from: b */
        public InterfaceC1672n<Uri, InputStream> mo963b(C1676r c1676r) {
            return new C1685c(this.f2430a);
        }
    }

    public C1685c(Context context) {
        this.f2429a = context.getApplicationContext();
    }

    @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1672n
    /* renamed from: a */
    public boolean mo960a(@NonNull Uri uri) {
        Uri uri2 = uri;
        return C4195m.m4831s0(uri2) && !uri2.getPathSegments().contains("video");
    }

    @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1672n
    /* renamed from: b */
    public InterfaceC1672n.a<InputStream> mo961b(@NonNull Uri uri, int i2, int i3, @NonNull C1582n c1582n) {
        Uri uri2 = uri;
        if (!C4195m.m4833t0(i2, i3)) {
            return null;
        }
        C1798d c1798d = new C1798d(uri2);
        Context context = this.f2429a;
        return new InterfaceC1672n.a<>(c1798d, C1603b.m848c(context, uri2, new C1603b.a(context.getContentResolver())));
    }
}
