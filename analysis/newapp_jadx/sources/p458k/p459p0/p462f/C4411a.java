package p458k.p459p0.p462f;

import java.io.IOException;
import java.util.Objects;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p458k.AbstractC4485v;
import p458k.C4375d0;
import p458k.C4381g0;
import p458k.C4389k0;
import p458k.InterfaceC4369a0;
import p458k.InterfaceC4378f;
import p458k.p459p0.p463g.C4430g;
import p458k.p459p0.p463g.InterfaceC4427d;

/* renamed from: k.p0.f.a */
/* loaded from: classes3.dex */
public final class C4411a implements InterfaceC4369a0 {

    /* renamed from: a */
    public static final C4411a f11638a = new C4411a();

    @Override // p458k.InterfaceC4369a0
    @NotNull
    /* renamed from: a */
    public C4389k0 mo280a(@NotNull InterfaceC4369a0.a chain) {
        Intrinsics.checkParameterIsNotNull(chain, "chain");
        C4430g c4430g = (C4430g) chain;
        C4381g0 c4381g0 = c4430g.f11739f;
        C4423m c4423m = c4430g.f11736c;
        boolean z = true;
        boolean z2 = !Intrinsics.areEqual(c4381g0.f11441c, "GET");
        Objects.requireNonNull(c4423m);
        Intrinsics.checkParameterIsNotNull(chain, "chain");
        synchronized (c4423m.f11712a) {
            if (!(!c4423m.f11724m)) {
                throw new IllegalStateException("released".toString());
            }
            if (c4423m.f11719h != null) {
                z = false;
            }
            if (!z) {
                throw new IllegalStateException("cannot make a new request because the previous response is still open: please call response.close()".toString());
            }
            Unit unit = Unit.INSTANCE;
        }
        C4414d c4414d = c4423m.f11717f;
        if (c4414d == null) {
            Intrinsics.throwNpe();
        }
        C4375d0 client = c4423m.f11725n;
        Objects.requireNonNull(c4414d);
        Intrinsics.checkParameterIsNotNull(client, "client");
        Intrinsics.checkParameterIsNotNull(chain, "chain");
        int i2 = c4430g.f11741h;
        int i3 = c4430g.f11742i;
        int i4 = c4430g.f11743j;
        Objects.requireNonNull(client);
        try {
            InterfaceC4427d m5103g = c4414d.m5093b(i2, i3, i4, 0, client.f11372l, z2).m5103g(client, chain);
            InterfaceC4378f interfaceC4378f = c4423m.f11726o;
            AbstractC4485v abstractC4485v = c4423m.f11713b;
            C4414d c4414d2 = c4423m.f11717f;
            if (c4414d2 == null) {
                Intrinsics.throwNpe();
            }
            C4413c c4413c = new C4413c(c4423m, interfaceC4378f, abstractC4485v, c4414d2, m5103g);
            synchronized (c4423m.f11712a) {
                c4423m.f11719h = c4413c;
                c4423m.f11720i = false;
                c4423m.f11721j = false;
            }
            return c4430g.m5140e(c4381g0, c4423m, c4413c);
        } catch (IOException e2) {
            c4414d.m5096e();
            throw new C4421k(e2);
        } catch (C4421k e3) {
            c4414d.m5096e();
            throw e3;
        }
    }
}
