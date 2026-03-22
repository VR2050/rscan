package p005b.p143g.p144a.p147m.p156v.p157c;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.drawable.Drawable;
import androidx.annotation.NonNull;
import java.security.MessageDigest;
import p005b.p143g.p144a.ComponentCallbacks2C1553c;
import p005b.p143g.p144a.p147m.InterfaceC1586r;
import p005b.p143g.p144a.p147m.p150t.InterfaceC1655w;
import p005b.p143g.p144a.p147m.p150t.p151c0.InterfaceC1614d;

/* renamed from: b.g.a.m.v.c.p */
/* loaded from: classes.dex */
public class C1711p implements InterfaceC1586r<Drawable> {

    /* renamed from: b */
    public final InterfaceC1586r<Bitmap> f2520b;

    /* renamed from: c */
    public final boolean f2521c;

    public C1711p(InterfaceC1586r<Bitmap> interfaceC1586r, boolean z) {
        this.f2520b = interfaceC1586r;
        this.f2521c = z;
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1579k
    public boolean equals(Object obj) {
        if (obj instanceof C1711p) {
            return this.f2520b.equals(((C1711p) obj).f2520b);
        }
        return false;
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1579k
    public int hashCode() {
        return this.f2520b.hashCode();
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1586r
    @NonNull
    public InterfaceC1655w<Drawable> transform(@NonNull Context context, @NonNull InterfaceC1655w<Drawable> interfaceC1655w, int i2, int i3) {
        InterfaceC1614d interfaceC1614d = ComponentCallbacks2C1553c.m735d(context).f1811g;
        Drawable drawable = interfaceC1655w.get();
        InterfaceC1655w<Bitmap> m1016a = C1710o.m1016a(interfaceC1614d, drawable, i2, i3);
        if (m1016a != null) {
            InterfaceC1655w<Bitmap> transform = this.f2520b.transform(context, m1016a, i2, i3);
            if (!transform.equals(m1016a)) {
                return C1717v.m1023b(context.getResources(), transform);
            }
            transform.recycle();
            return interfaceC1655w;
        }
        if (!this.f2521c) {
            return interfaceC1655w;
        }
        throw new IllegalArgumentException("Unable to convert " + drawable + " to a Bitmap");
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1579k
    public void updateDiskCacheKey(@NonNull MessageDigest messageDigest) {
        this.f2520b.updateDiskCacheKey(messageDigest);
    }
}
