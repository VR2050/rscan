package p005b.p199l.p200a.p201a.p248o1;

import android.content.Context;
import androidx.annotation.Nullable;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m;

/* renamed from: b.l.a.a.o1.t */
/* loaded from: classes.dex */
public final class C2328t implements InterfaceC2321m.a {

    /* renamed from: a */
    public final Context f5987a;

    /* renamed from: b */
    @Nullable
    public final InterfaceC2291f0 f5988b;

    /* renamed from: c */
    public final InterfaceC2321m.a f5989c;

    public C2328t(Context context, @Nullable InterfaceC2291f0 interfaceC2291f0, InterfaceC2321m.a aVar) {
        this.f5987a = context.getApplicationContext();
        this.f5988b = interfaceC2291f0;
        this.f5989c = aVar;
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m.a
    public InterfaceC2321m createDataSource() {
        C2327s c2327s = new C2327s(this.f5987a, this.f5989c.createDataSource());
        InterfaceC2291f0 interfaceC2291f0 = this.f5988b;
        if (interfaceC2291f0 != null) {
            c2327s.addTransferListener(interfaceC2291f0);
        }
        return c2327s;
    }
}
