package p005b.p143g.p144a.p147m.p156v.p162h;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import com.bumptech.glide.load.resource.gif.GifDrawable;
import java.nio.ByteBuffer;
import java.util.concurrent.atomic.AtomicReference;
import p005b.p143g.p144a.p147m.C1582n;
import p005b.p143g.p144a.p147m.p150t.InterfaceC1655w;
import p005b.p143g.p144a.p147m.p156v.p158d.C1723b;
import p005b.p143g.p144a.p170s.C1799a;

/* renamed from: b.g.a.m.v.h.d */
/* loaded from: classes.dex */
public class C1743d implements InterfaceC1744e<GifDrawable, byte[]> {
    @Override // p005b.p143g.p144a.p147m.p156v.p162h.InterfaceC1744e
    @Nullable
    /* renamed from: a */
    public InterfaceC1655w<byte[]> mo1037a(@NonNull InterfaceC1655w<GifDrawable> interfaceC1655w, @NonNull C1582n c1582n) {
        byte[] bArr;
        ByteBuffer asReadOnlyBuffer = interfaceC1655w.get().f8843c.f8854a.f2567a.mo808e().asReadOnlyBuffer();
        AtomicReference<byte[]> atomicReference = C1799a.f2744a;
        C1799a.b bVar = (asReadOnlyBuffer.isReadOnly() || !asReadOnlyBuffer.hasArray()) ? null : new C1799a.b(asReadOnlyBuffer.array(), asReadOnlyBuffer.arrayOffset(), asReadOnlyBuffer.limit());
        if (bVar != null && bVar.f2747a == 0 && bVar.f2748b == bVar.f2749c.length) {
            bArr = asReadOnlyBuffer.array();
        } else {
            ByteBuffer asReadOnlyBuffer2 = asReadOnlyBuffer.asReadOnlyBuffer();
            byte[] bArr2 = new byte[asReadOnlyBuffer2.limit()];
            asReadOnlyBuffer2.position(0);
            asReadOnlyBuffer2.get(bArr2);
            bArr = bArr2;
        }
        return new C1723b(bArr);
    }
}
