package p005b.p143g.p144a.p147m.p156v.p157c;

import android.graphics.Bitmap;
import android.graphics.drawable.BitmapDrawable;
import androidx.annotation.NonNull;
import java.io.File;
import p005b.p143g.p144a.p147m.C1582n;
import p005b.p143g.p144a.p147m.EnumC1571c;
import p005b.p143g.p144a.p147m.InterfaceC1585q;
import p005b.p143g.p144a.p147m.p150t.InterfaceC1655w;
import p005b.p143g.p144a.p147m.p150t.p151c0.InterfaceC1614d;

/* renamed from: b.g.a.m.v.c.b */
/* loaded from: classes.dex */
public class C1693b implements InterfaceC1585q<BitmapDrawable> {

    /* renamed from: a */
    public final InterfaceC1614d f2466a;

    /* renamed from: b */
    public final InterfaceC1585q<Bitmap> f2467b;

    public C1693b(InterfaceC1614d interfaceC1614d, InterfaceC1585q<Bitmap> interfaceC1585q) {
        this.f2466a = interfaceC1614d;
        this.f2467b = interfaceC1585q;
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1572d
    /* renamed from: a */
    public boolean mo822a(@NonNull Object obj, @NonNull File file, @NonNull C1582n c1582n) {
        return this.f2467b.mo822a(new C1699e(((BitmapDrawable) ((InterfaceC1655w) obj).get()).getBitmap(), this.f2466a), file, c1582n);
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1585q
    @NonNull
    /* renamed from: b */
    public EnumC1571c mo831b(@NonNull C1582n c1582n) {
        return this.f2467b.mo831b(c1582n);
    }
}
