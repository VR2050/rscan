package p005b.p113c0.p114a.p116h.p123m;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import p005b.p113c0.p114a.p116h.InterfaceC1425a;
import p005b.p113c0.p114a.p116h.InterfaceC1428d;
import p005b.p113c0.p114a.p116h.p120j.InterfaceC1437a;
import p005b.p113c0.p114a.p116h.p120j.InterfaceC1442f;
import p005b.p113c0.p114a.p116h.p122l.C1447a;
import p005b.p113c0.p114a.p116h.p122l.InterfaceC1449c;
import p005b.p113c0.p114a.p124i.InterfaceC1457c;
import p005b.p113c0.p114a.p124i.InterfaceC1458d;
import p005b.p113c0.p114a.p124i.InterfaceC1463i;

/* renamed from: b.c0.a.h.m.d */
/* loaded from: classes2.dex */
public abstract class AbstractC1454d implements InterfaceC1437a, InterfaceC1425a, InterfaceC1428d {

    /* renamed from: b.c0.a.h.m.d$a */
    public class a implements InterfaceC1442f {
        public a() {
        }

        @Override // p005b.p113c0.p114a.p116h.InterfaceC1428d
        /* renamed from: d */
        public long mo493d(@NonNull InterfaceC1457c interfaceC1457c) {
            return AbstractC1454d.this.mo493d(interfaceC1457c);
        }

        @Override // p005b.p113c0.p114a.p116h.InterfaceC1425a
        @Nullable
        /* renamed from: e */
        public String mo490e(@NonNull InterfaceC1457c interfaceC1457c) {
            return AbstractC1454d.this.mo490e(interfaceC1457c);
        }

        @Override // p005b.p113c0.p114a.p116h.p120j.InterfaceC1442f
        /* renamed from: f */
        public InterfaceC1449c mo506f(@NonNull InterfaceC1457c interfaceC1457c, @NonNull InterfaceC1458d interfaceC1458d) {
            return new C1447a(AbstractC1454d.this.mo515g(interfaceC1457c, interfaceC1458d));
        }
    }

    @Override // p005b.p113c0.p114a.p116h.p120j.InterfaceC1437a
    @Nullable
    /* renamed from: a */
    public InterfaceC1442f mo498a(@NonNull InterfaceC1457c interfaceC1457c) {
        return new a();
    }

    /* renamed from: d */
    public long mo493d(@NonNull InterfaceC1457c interfaceC1457c) {
        return 0L;
    }

    @Nullable
    /* renamed from: e */
    public String mo490e(@NonNull InterfaceC1457c interfaceC1457c) {
        return null;
    }

    @NonNull
    /* renamed from: g */
    public abstract InterfaceC1463i mo515g(@NonNull InterfaceC1457c interfaceC1457c, @NonNull InterfaceC1458d interfaceC1458d);
}
