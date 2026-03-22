package p005b.p143g.p144a.p147m.p156v.p157c;

import android.graphics.Bitmap;
import android.graphics.ImageDecoder;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;
import java.nio.ByteBuffer;
import p005b.p143g.p144a.p147m.C1582n;
import p005b.p143g.p144a.p147m.InterfaceC1584p;
import p005b.p143g.p144a.p147m.p150t.InterfaceC1655w;

@RequiresApi(api = 28)
/* renamed from: b.g.a.m.v.c.h */
/* loaded from: classes.dex */
public final class C1703h implements InterfaceC1584p<ByteBuffer, Bitmap> {

    /* renamed from: a */
    public final C1697d f2490a = new C1697d();

    @Override // p005b.p143g.p144a.p147m.InterfaceC1584p
    /* renamed from: a */
    public /* bridge */ /* synthetic */ boolean mo829a(@NonNull ByteBuffer byteBuffer, @NonNull C1582n c1582n) {
        return true;
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1584p
    @Nullable
    /* renamed from: b */
    public InterfaceC1655w<Bitmap> mo830b(@NonNull ByteBuffer byteBuffer, int i2, int i3, @NonNull C1582n c1582n) {
        return this.f2490a.mo830b(ImageDecoder.createSource(byteBuffer), i2, i3, c1582n);
    }
}
