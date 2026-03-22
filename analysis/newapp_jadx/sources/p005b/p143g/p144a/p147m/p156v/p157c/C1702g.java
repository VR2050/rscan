package p005b.p143g.p144a.p147m.p156v.p157c;

import android.graphics.Bitmap;
import androidx.annotation.NonNull;
import java.nio.ByteBuffer;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;
import p005b.p143g.p144a.p147m.C1582n;
import p005b.p143g.p144a.p147m.InterfaceC1584p;
import p005b.p143g.p144a.p147m.p150t.InterfaceC1655w;
import p005b.p143g.p144a.p170s.C1799a;

/* renamed from: b.g.a.m.v.c.g */
/* loaded from: classes.dex */
public class C1702g implements InterfaceC1584p<ByteBuffer, Bitmap> {

    /* renamed from: a */
    public final C1709n f2489a;

    public C1702g(C1709n c1709n) {
        this.f2489a = c1709n;
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1584p
    /* renamed from: a */
    public boolean mo829a(@NonNull ByteBuffer byteBuffer, @NonNull C1582n c1582n) {
        Objects.requireNonNull(this.f2489a);
        return true;
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1584p
    /* renamed from: b */
    public InterfaceC1655w<Bitmap> mo830b(@NonNull ByteBuffer byteBuffer, int i2, int i3, @NonNull C1582n c1582n) {
        AtomicReference<byte[]> atomicReference = C1799a.f2744a;
        return this.f2489a.m1014b(new C1799a.a(byteBuffer), i2, i3, c1582n, C1709n.f2511f);
    }
}
