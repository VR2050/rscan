package p005b.p143g.p144a.p147m.p156v.p162h;

import android.graphics.Bitmap;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import java.io.ByteArrayOutputStream;
import p005b.p143g.p144a.p147m.C1582n;
import p005b.p143g.p144a.p147m.p150t.InterfaceC1655w;
import p005b.p143g.p144a.p147m.p156v.p158d.C1723b;

/* renamed from: b.g.a.m.v.h.a */
/* loaded from: classes.dex */
public class C1740a implements InterfaceC1744e<Bitmap, byte[]> {

    /* renamed from: a */
    public final Bitmap.CompressFormat f2596a = Bitmap.CompressFormat.JPEG;

    /* renamed from: b */
    public final int f2597b = 100;

    @Override // p005b.p143g.p144a.p147m.p156v.p162h.InterfaceC1744e
    @Nullable
    /* renamed from: a */
    public InterfaceC1655w<byte[]> mo1037a(@NonNull InterfaceC1655w<Bitmap> interfaceC1655w, @NonNull C1582n c1582n) {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        interfaceC1655w.get().compress(this.f2596a, this.f2597b, byteArrayOutputStream);
        interfaceC1655w.recycle();
        return new C1723b(byteArrayOutputStream.toByteArray());
    }
}
