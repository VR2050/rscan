package p005b.p143g.p144a.p147m.p156v.p159e;

import android.graphics.drawable.Drawable;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import p005b.p143g.p144a.p147m.C1582n;
import p005b.p143g.p144a.p147m.InterfaceC1584p;
import p005b.p143g.p144a.p147m.p150t.InterfaceC1655w;

/* renamed from: b.g.a.m.v.e.e */
/* loaded from: classes.dex */
public class C1728e implements InterfaceC1584p<Drawable, Drawable> {
    @Override // p005b.p143g.p144a.p147m.InterfaceC1584p
    /* renamed from: a */
    public /* bridge */ /* synthetic */ boolean mo829a(@NonNull Drawable drawable, @NonNull C1582n c1582n) {
        return true;
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1584p
    @Nullable
    /* renamed from: b */
    public InterfaceC1655w<Drawable> mo830b(@NonNull Drawable drawable, int i2, int i3, @NonNull C1582n c1582n) {
        Drawable drawable2 = drawable;
        if (drawable2 != null) {
            return new C1726c(drawable2);
        }
        return null;
    }
}
