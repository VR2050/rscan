package p005b.p143g.p144a.p147m.p156v.p157c;

import android.graphics.Bitmap;
import android.os.ParcelFileDescriptor;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;
import java.util.Objects;
import p005b.p143g.p144a.p147m.C1582n;
import p005b.p143g.p144a.p147m.InterfaceC1584p;
import p005b.p143g.p144a.p147m.p150t.InterfaceC1655w;
import p005b.p143g.p144a.p147m.p156v.p157c.InterfaceC1715t;

@RequiresApi(21)
/* renamed from: b.g.a.m.v.c.w */
/* loaded from: classes.dex */
public final class C1718w implements InterfaceC1584p<ParcelFileDescriptor, Bitmap> {

    /* renamed from: a */
    public final C1709n f2539a;

    public C1718w(C1709n c1709n) {
        this.f2539a = c1709n;
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1584p
    /* renamed from: a */
    public boolean mo829a(@NonNull ParcelFileDescriptor parcelFileDescriptor, @NonNull C1582n c1582n) {
        Objects.requireNonNull(this.f2539a);
        return true;
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1584p
    @Nullable
    /* renamed from: b */
    public InterfaceC1655w<Bitmap> mo830b(@NonNull ParcelFileDescriptor parcelFileDescriptor, int i2, int i3, @NonNull C1582n c1582n) {
        C1709n c1709n = this.f2539a;
        return c1709n.m1013a(new InterfaceC1715t.b(parcelFileDescriptor, c1709n.f2517l, c1709n.f2516k), i2, i3, c1582n, C1709n.f2511f);
    }
}
