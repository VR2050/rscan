package p005b.p143g.p144a.p147m.p156v.p157c;

import android.content.res.Resources;
import android.graphics.Bitmap;
import android.graphics.drawable.BitmapDrawable;
import androidx.annotation.NonNull;
import p005b.p143g.p144a.p147m.C1582n;
import p005b.p143g.p144a.p147m.InterfaceC1584p;
import p005b.p143g.p144a.p147m.p150t.InterfaceC1655w;

/* renamed from: b.g.a.m.v.c.a */
/* loaded from: classes.dex */
public class C1691a<DataType> implements InterfaceC1584p<DataType, BitmapDrawable> {

    /* renamed from: a */
    public final InterfaceC1584p<DataType, Bitmap> f2460a;

    /* renamed from: b */
    public final Resources f2461b;

    public C1691a(@NonNull Resources resources, @NonNull InterfaceC1584p<DataType, Bitmap> interfaceC1584p) {
        this.f2461b = resources;
        this.f2460a = interfaceC1584p;
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1584p
    /* renamed from: a */
    public boolean mo829a(@NonNull DataType datatype, @NonNull C1582n c1582n) {
        return this.f2460a.mo829a(datatype, c1582n);
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1584p
    /* renamed from: b */
    public InterfaceC1655w<BitmapDrawable> mo830b(@NonNull DataType datatype, int i2, int i3, @NonNull C1582n c1582n) {
        return C1717v.m1023b(this.f2461b, this.f2460a.mo830b(datatype, i2, i3, c1582n));
    }
}
