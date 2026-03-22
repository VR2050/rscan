package p005b.p143g.p144a.p147m.p154u.p155y;

import android.content.Context;
import android.net.Uri;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import java.io.InputStream;
import p005b.p143g.p144a.p147m.C1582n;
import p005b.p143g.p144a.p147m.p148s.p149p.C1603b;
import p005b.p143g.p144a.p147m.p154u.C1676r;
import p005b.p143g.p144a.p147m.p154u.InterfaceC1672n;
import p005b.p143g.p144a.p147m.p154u.InterfaceC1673o;
import p005b.p143g.p144a.p147m.p156v.p157c.C1698d0;
import p005b.p143g.p144a.p169r.C1798d;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.g.a.m.u.y.d */
/* loaded from: classes.dex */
public class C1686d implements InterfaceC1672n<Uri, InputStream> {

    /* renamed from: a */
    public final Context f2431a;

    /* renamed from: b.g.a.m.u.y.d$a */
    public static class a implements InterfaceC1673o<Uri, InputStream> {

        /* renamed from: a */
        public final Context f2432a;

        public a(Context context) {
            this.f2432a = context;
        }

        @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1673o
        @NonNull
        /* renamed from: b */
        public InterfaceC1672n<Uri, InputStream> mo963b(C1676r c1676r) {
            return new C1686d(this.f2432a);
        }
    }

    public C1686d(Context context) {
        this.f2431a = context.getApplicationContext();
    }

    @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1672n
    /* renamed from: a */
    public boolean mo960a(@NonNull Uri uri) {
        Uri uri2 = uri;
        return C4195m.m4831s0(uri2) && uri2.getPathSegments().contains("video");
    }

    @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1672n
    @Nullable
    /* renamed from: b */
    public InterfaceC1672n.a<InputStream> mo961b(@NonNull Uri uri, int i2, int i3, @NonNull C1582n c1582n) {
        Uri uri2 = uri;
        if (C4195m.m4833t0(i2, i3)) {
            Long l2 = (Long) c1582n.m827a(C1698d0.f2478a);
            if (l2 != null && l2.longValue() == -1) {
                C1798d c1798d = new C1798d(uri2);
                Context context = this.f2431a;
                return new InterfaceC1672n.a<>(c1798d, C1603b.m848c(context, uri2, new C1603b.b(context.getContentResolver())));
            }
        }
        return null;
    }
}
