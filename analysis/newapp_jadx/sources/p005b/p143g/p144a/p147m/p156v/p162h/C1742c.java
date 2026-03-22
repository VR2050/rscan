package p005b.p143g.p144a.p147m.p156v.p162h;

import android.graphics.Bitmap;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.Drawable;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import com.bumptech.glide.load.resource.gif.GifDrawable;
import p005b.p143g.p144a.p147m.C1582n;
import p005b.p143g.p144a.p147m.p150t.InterfaceC1655w;
import p005b.p143g.p144a.p147m.p150t.p151c0.InterfaceC1614d;
import p005b.p143g.p144a.p147m.p156v.p157c.C1699e;

/* renamed from: b.g.a.m.v.h.c */
/* loaded from: classes.dex */
public final class C1742c implements InterfaceC1744e<Drawable, byte[]> {

    /* renamed from: a */
    public final InterfaceC1614d f2599a;

    /* renamed from: b */
    public final InterfaceC1744e<Bitmap, byte[]> f2600b;

    /* renamed from: c */
    public final InterfaceC1744e<GifDrawable, byte[]> f2601c;

    public C1742c(@NonNull InterfaceC1614d interfaceC1614d, @NonNull InterfaceC1744e<Bitmap, byte[]> interfaceC1744e, @NonNull InterfaceC1744e<GifDrawable, byte[]> interfaceC1744e2) {
        this.f2599a = interfaceC1614d;
        this.f2600b = interfaceC1744e;
        this.f2601c = interfaceC1744e2;
    }

    @Override // p005b.p143g.p144a.p147m.p156v.p162h.InterfaceC1744e
    @Nullable
    /* renamed from: a */
    public InterfaceC1655w<byte[]> mo1037a(@NonNull InterfaceC1655w<Drawable> interfaceC1655w, @NonNull C1582n c1582n) {
        Drawable drawable = interfaceC1655w.get();
        if (drawable instanceof BitmapDrawable) {
            return this.f2600b.mo1037a(C1699e.m995b(((BitmapDrawable) drawable).getBitmap(), this.f2599a), c1582n);
        }
        if (drawable instanceof GifDrawable) {
            return this.f2601c.mo1037a(interfaceC1655w, c1582n);
        }
        return null;
    }
}
