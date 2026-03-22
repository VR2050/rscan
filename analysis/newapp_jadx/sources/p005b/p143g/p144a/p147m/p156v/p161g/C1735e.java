package p005b.p143g.p144a.p147m.p156v.p161g;

import android.content.Context;
import android.graphics.Bitmap;
import androidx.annotation.NonNull;
import com.bumptech.glide.load.resource.gif.GifDrawable;
import java.security.MessageDigest;
import java.util.Objects;
import p005b.p143g.p144a.ComponentCallbacks2C1553c;
import p005b.p143g.p144a.p147m.InterfaceC1586r;
import p005b.p143g.p144a.p147m.p150t.InterfaceC1655w;
import p005b.p143g.p144a.p147m.p156v.p157c.C1699e;

/* renamed from: b.g.a.m.v.g.e */
/* loaded from: classes.dex */
public class C1735e implements InterfaceC1586r<GifDrawable> {

    /* renamed from: b */
    public final InterfaceC1586r<Bitmap> f2566b;

    public C1735e(InterfaceC1586r<Bitmap> interfaceC1586r) {
        Objects.requireNonNull(interfaceC1586r, "Argument must not be null");
        this.f2566b = interfaceC1586r;
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1579k
    public boolean equals(Object obj) {
        if (obj instanceof C1735e) {
            return this.f2566b.equals(((C1735e) obj).f2566b);
        }
        return false;
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1579k
    public int hashCode() {
        return this.f2566b.hashCode();
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1586r
    @NonNull
    public InterfaceC1655w<GifDrawable> transform(@NonNull Context context, @NonNull InterfaceC1655w<GifDrawable> interfaceC1655w, int i2, int i3) {
        GifDrawable gifDrawable = interfaceC1655w.get();
        InterfaceC1655w<Bitmap> c1699e = new C1699e(gifDrawable.m3892b(), ComponentCallbacks2C1553c.m735d(context).f1811g);
        InterfaceC1655w<Bitmap> transform = this.f2566b.transform(context, c1699e, i2, i3);
        if (!c1699e.equals(transform)) {
            c1699e.recycle();
        }
        Bitmap bitmap = transform.get();
        gifDrawable.f8843c.f8854a.m1034c(this.f2566b, bitmap);
        return interfaceC1655w;
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1579k
    public void updateDiskCacheKey(@NonNull MessageDigest messageDigest) {
        this.f2566b.updateDiskCacheKey(messageDigest);
    }
}
