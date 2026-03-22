package p005b.p143g.p144a.p147m.p156v.p157c;

import android.content.Context;
import android.graphics.Bitmap;
import androidx.annotation.NonNull;
import p005b.p143g.p144a.ComponentCallbacks2C1553c;
import p005b.p143g.p144a.p147m.InterfaceC1586r;
import p005b.p143g.p144a.p147m.p150t.InterfaceC1655w;
import p005b.p143g.p144a.p147m.p150t.p151c0.InterfaceC1614d;
import p005b.p143g.p144a.p170s.C1807i;

/* renamed from: b.g.a.m.v.c.f */
/* loaded from: classes.dex */
public abstract class AbstractC1701f implements InterfaceC1586r<Bitmap> {
    public abstract Bitmap transform(@NonNull InterfaceC1614d interfaceC1614d, @NonNull Bitmap bitmap, int i2, int i3);

    @Override // p005b.p143g.p144a.p147m.InterfaceC1586r
    @NonNull
    public final InterfaceC1655w<Bitmap> transform(@NonNull Context context, @NonNull InterfaceC1655w<Bitmap> interfaceC1655w, int i2, int i3) {
        if (!C1807i.m1152i(i2, i3)) {
            throw new IllegalArgumentException("Cannot apply transformation on width: " + i2 + " or height: " + i3 + " less than or equal to zero and not Target.SIZE_ORIGINAL");
        }
        InterfaceC1614d interfaceC1614d = ComponentCallbacks2C1553c.m735d(context).f1811g;
        Bitmap bitmap = interfaceC1655w.get();
        if (i2 == Integer.MIN_VALUE) {
            i2 = bitmap.getWidth();
        }
        if (i3 == Integer.MIN_VALUE) {
            i3 = bitmap.getHeight();
        }
        Bitmap transform = transform(interfaceC1614d, bitmap, i2, i3);
        return bitmap.equals(transform) ? interfaceC1655w : C1699e.m995b(transform, interfaceC1614d);
    }
}
