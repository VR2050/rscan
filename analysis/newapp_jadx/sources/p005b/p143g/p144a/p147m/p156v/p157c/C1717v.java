package p005b.p143g.p144a.p147m.p156v.p157c;

import android.content.res.Resources;
import android.graphics.Bitmap;
import android.graphics.drawable.BitmapDrawable;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import java.util.Objects;
import p005b.p143g.p144a.p147m.p150t.InterfaceC1651s;
import p005b.p143g.p144a.p147m.p150t.InterfaceC1655w;

/* renamed from: b.g.a.m.v.c.v */
/* loaded from: classes.dex */
public final class C1717v implements InterfaceC1655w<BitmapDrawable>, InterfaceC1651s {

    /* renamed from: c */
    public final Resources f2537c;

    /* renamed from: e */
    public final InterfaceC1655w<Bitmap> f2538e;

    public C1717v(@NonNull Resources resources, @NonNull InterfaceC1655w<Bitmap> interfaceC1655w) {
        Objects.requireNonNull(resources, "Argument must not be null");
        this.f2537c = resources;
        this.f2538e = interfaceC1655w;
    }

    @Nullable
    /* renamed from: b */
    public static InterfaceC1655w<BitmapDrawable> m1023b(@NonNull Resources resources, @Nullable InterfaceC1655w<Bitmap> interfaceC1655w) {
        if (interfaceC1655w == null) {
            return null;
        }
        return new C1717v(resources, interfaceC1655w);
    }

    @Override // p005b.p143g.p144a.p147m.p150t.InterfaceC1655w
    @NonNull
    /* renamed from: a */
    public Class<BitmapDrawable> mo947a() {
        return BitmapDrawable.class;
    }

    @Override // p005b.p143g.p144a.p147m.p150t.InterfaceC1655w
    @NonNull
    public BitmapDrawable get() {
        return new BitmapDrawable(this.f2537c, this.f2538e.get());
    }

    @Override // p005b.p143g.p144a.p147m.p150t.InterfaceC1655w
    public int getSize() {
        return this.f2538e.getSize();
    }

    @Override // p005b.p143g.p144a.p147m.p150t.InterfaceC1651s
    public void initialize() {
        InterfaceC1655w<Bitmap> interfaceC1655w = this.f2538e;
        if (interfaceC1655w instanceof InterfaceC1651s) {
            ((InterfaceC1651s) interfaceC1655w).initialize();
        }
    }

    @Override // p005b.p143g.p144a.p147m.p150t.InterfaceC1655w
    public void recycle() {
        this.f2538e.recycle();
    }
}
