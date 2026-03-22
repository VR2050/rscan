package p005b.p143g.p144a.p147m.p156v.p157c;

import android.graphics.Bitmap;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import p005b.p143g.p144a.p147m.C1582n;
import p005b.p143g.p144a.p147m.InterfaceC1584p;
import p005b.p143g.p144a.p147m.p150t.InterfaceC1655w;
import p005b.p143g.p144a.p147m.p150t.p151c0.InterfaceC1614d;
import p005b.p143g.p144a.p147m.p156v.p159e.AbstractC1725b;
import p005b.p143g.p144a.p147m.p156v.p159e.C1727d;

/* renamed from: b.g.a.m.v.c.y */
/* loaded from: classes.dex */
public class C1720y implements InterfaceC1584p<Uri, Bitmap> {

    /* renamed from: a */
    public final C1727d f2546a;

    /* renamed from: b */
    public final InterfaceC1614d f2547b;

    public C1720y(C1727d c1727d, InterfaceC1614d interfaceC1614d) {
        this.f2546a = c1727d;
        this.f2547b = interfaceC1614d;
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1584p
    /* renamed from: a */
    public boolean mo829a(@NonNull Uri uri, @NonNull C1582n c1582n) {
        return "android.resource".equals(uri.getScheme());
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1584p
    @Nullable
    /* renamed from: b */
    public InterfaceC1655w<Bitmap> mo830b(@NonNull Uri uri, int i2, int i3, @NonNull C1582n c1582n) {
        InterfaceC1655w m1028c = this.f2546a.m1028c(uri);
        if (m1028c == null) {
            return null;
        }
        return C1710o.m1016a(this.f2547b, (Drawable) ((AbstractC1725b) m1028c).get(), i2, i3);
    }
}
