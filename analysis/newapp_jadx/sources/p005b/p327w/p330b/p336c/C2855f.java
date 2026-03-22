package p005b.p327w.p330b.p336c;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import java.nio.ByteBuffer;
import p005b.p143g.p144a.p147m.C1582n;
import p005b.p143g.p144a.p147m.p154u.InterfaceC1672n;
import p005b.p143g.p144a.p169r.C1798d;

/* renamed from: b.w.b.c.f */
/* loaded from: classes2.dex */
public class C2855f implements InterfaceC1672n<String, ByteBuffer> {
    @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1672n
    /* renamed from: a */
    public boolean mo960a(@NonNull String str) {
        String str2 = str;
        return str2.contains(".safe.txt?ext=") || str2.contains(".enc") || str2.contains(".bnc");
    }

    @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1672n
    @Nullable
    /* renamed from: b */
    public InterfaceC1672n.a<ByteBuffer> mo961b(@NonNull String str, int i2, int i3, @NonNull C1582n c1582n) {
        String str2 = str;
        return new InterfaceC1672n.a<>(new C1798d(str2), new C2854e(str2));
    }
}
