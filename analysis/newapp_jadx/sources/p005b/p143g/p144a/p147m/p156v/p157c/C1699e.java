package p005b.p143g.p144a.p147m.p156v.p157c;

import android.graphics.Bitmap;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import java.util.Objects;
import p005b.p143g.p144a.p147m.p150t.InterfaceC1651s;
import p005b.p143g.p144a.p147m.p150t.InterfaceC1655w;
import p005b.p143g.p144a.p147m.p150t.p151c0.InterfaceC1614d;
import p005b.p143g.p144a.p170s.C1807i;

/* renamed from: b.g.a.m.v.c.e */
/* loaded from: classes.dex */
public class C1699e implements InterfaceC1655w<Bitmap>, InterfaceC1651s {

    /* renamed from: c */
    public final Bitmap f2486c;

    /* renamed from: e */
    public final InterfaceC1614d f2487e;

    public C1699e(@NonNull Bitmap bitmap, @NonNull InterfaceC1614d interfaceC1614d) {
        Objects.requireNonNull(bitmap, "Bitmap must not be null");
        this.f2486c = bitmap;
        Objects.requireNonNull(interfaceC1614d, "BitmapPool must not be null");
        this.f2487e = interfaceC1614d;
    }

    @Nullable
    /* renamed from: b */
    public static C1699e m995b(@Nullable Bitmap bitmap, @NonNull InterfaceC1614d interfaceC1614d) {
        if (bitmap == null) {
            return null;
        }
        return new C1699e(bitmap, interfaceC1614d);
    }

    @Override // p005b.p143g.p144a.p147m.p150t.InterfaceC1655w
    @NonNull
    /* renamed from: a */
    public Class<Bitmap> mo947a() {
        return Bitmap.class;
    }

    @Override // p005b.p143g.p144a.p147m.p150t.InterfaceC1655w
    @NonNull
    public Bitmap get() {
        return this.f2486c;
    }

    @Override // p005b.p143g.p144a.p147m.p150t.InterfaceC1655w
    public int getSize() {
        return C1807i.m1147d(this.f2486c);
    }

    @Override // p005b.p143g.p144a.p147m.p150t.InterfaceC1651s
    public void initialize() {
        this.f2486c.prepareToDraw();
    }

    @Override // p005b.p143g.p144a.p147m.p150t.InterfaceC1655w
    public void recycle() {
        this.f2487e.mo870d(this.f2486c);
    }
}
