package p005b.p143g.p144a.p147m.p156v.p157c;

import android.graphics.Bitmap;
import androidx.annotation.NonNull;
import java.security.MessageDigest;
import p005b.p143g.p144a.p147m.InterfaceC1579k;
import p005b.p143g.p144a.p147m.p150t.p151c0.InterfaceC1614d;

/* renamed from: b.g.a.m.v.c.r */
/* loaded from: classes.dex */
public class C1713r extends AbstractC1701f {

    /* renamed from: b */
    public static final byte[] f2522b = "com.bumptech.glide.load.resource.bitmap.FitCenter".getBytes(InterfaceC1579k.f1988a);

    @Override // p005b.p143g.p144a.p147m.InterfaceC1579k
    public boolean equals(Object obj) {
        return obj instanceof C1713r;
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1579k
    public int hashCode() {
        return 1572326941;
    }

    @Override // p005b.p143g.p144a.p147m.p156v.p157c.AbstractC1701f
    public Bitmap transform(@NonNull InterfaceC1614d interfaceC1614d, @NonNull Bitmap bitmap, int i2, int i3) {
        return C1694b0.m989c(interfaceC1614d, bitmap, i2, i3);
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1579k
    public void updateDiskCacheKey(@NonNull MessageDigest messageDigest) {
        messageDigest.update(f2522b);
    }
}
