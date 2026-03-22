package p005b.p143g.p144a.p147m.p156v.p161g;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import p005b.p143g.p144a.p146l.InterfaceC1564a;
import p005b.p143g.p144a.p147m.p150t.p151c0.InterfaceC1612b;
import p005b.p143g.p144a.p147m.p150t.p151c0.InterfaceC1614d;

/* renamed from: b.g.a.m.v.g.b */
/* loaded from: classes.dex */
public final class C1732b implements InterfaceC1564a.a {

    /* renamed from: a */
    public final InterfaceC1614d f2564a;

    /* renamed from: b */
    @Nullable
    public final InterfaceC1612b f2565b;

    public C1732b(InterfaceC1614d interfaceC1614d, @Nullable InterfaceC1612b interfaceC1612b) {
        this.f2564a = interfaceC1614d;
        this.f2565b = interfaceC1612b;
    }

    @NonNull
    /* renamed from: a */
    public byte[] m1031a(int i2) {
        InterfaceC1612b interfaceC1612b = this.f2565b;
        return interfaceC1612b == null ? new byte[i2] : (byte[]) interfaceC1612b.mo863d(i2, byte[].class);
    }
}
