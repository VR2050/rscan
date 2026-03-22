package p005b.p143g.p144a.p147m.p156v.p159e;

import android.content.Context;
import android.content.pm.PackageManager;
import android.content.res.Resources;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import java.util.List;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p143g.p144a.p147m.C1582n;
import p005b.p143g.p144a.p147m.InterfaceC1584p;
import p005b.p143g.p144a.p147m.p150t.InterfaceC1655w;

/* renamed from: b.g.a.m.v.e.d */
/* loaded from: classes.dex */
public class C1727d implements InterfaceC1584p<Uri, Drawable> {

    /* renamed from: a */
    public final Context f2554a;

    public C1727d(Context context) {
        this.f2554a = context.getApplicationContext();
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1584p
    /* renamed from: a */
    public boolean mo829a(@NonNull Uri uri, @NonNull C1582n c1582n) {
        return uri.getScheme().equals("android.resource");
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1584p
    @Nullable
    /* renamed from: b */
    public /* bridge */ /* synthetic */ InterfaceC1655w<Drawable> mo830b(@NonNull Uri uri, int i2, int i3, @NonNull C1582n c1582n) {
        return m1028c(uri);
    }

    @Nullable
    /* renamed from: c */
    public InterfaceC1655w m1028c(@NonNull Uri uri) {
        Context context;
        int parseInt;
        String authority = uri.getAuthority();
        if (authority.equals(this.f2554a.getPackageName())) {
            context = this.f2554a;
        } else {
            try {
                context = this.f2554a.createPackageContext(authority, 0);
            } catch (PackageManager.NameNotFoundException e2) {
                if (!authority.contains(this.f2554a.getPackageName())) {
                    throw new IllegalArgumentException(C1499a.m632r("Failed to obtain context or unrecognized Uri format for: ", uri), e2);
                }
                context = this.f2554a;
            }
        }
        List<String> pathSegments = uri.getPathSegments();
        if (pathSegments.size() == 2) {
            List<String> pathSegments2 = uri.getPathSegments();
            String authority2 = uri.getAuthority();
            String str = pathSegments2.get(0);
            String str2 = pathSegments2.get(1);
            parseInt = context.getResources().getIdentifier(str2, str, authority2);
            if (parseInt == 0) {
                parseInt = Resources.getSystem().getIdentifier(str2, str, "android");
            }
            if (parseInt == 0) {
                throw new IllegalArgumentException(C1499a.m632r("Failed to find resource id for: ", uri));
            }
        } else {
            if (pathSegments.size() != 1) {
                throw new IllegalArgumentException(C1499a.m632r("Unrecognized Uri format: ", uri));
            }
            try {
                parseInt = Integer.parseInt(uri.getPathSegments().get(0));
            } catch (NumberFormatException e3) {
                throw new IllegalArgumentException(C1499a.m632r("Unrecognized Uri format: ", uri), e3);
            }
        }
        Drawable m1027a = C1724a.m1027a(this.f2554a, context, parseInt, null);
        if (m1027a != null) {
            return new C1726c(m1027a);
        }
        return null;
    }
}
