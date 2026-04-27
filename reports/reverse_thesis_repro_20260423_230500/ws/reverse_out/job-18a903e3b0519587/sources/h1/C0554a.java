package h1;

import B2.InterfaceC0167e;
import B2.p;
import B2.z;
import t2.j;

/* JADX INFO: renamed from: h1.a, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0554a {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final C0554a f9267a = new C0554a();

    private C0554a() {
    }

    public static final void a(z zVar, Object obj) {
        j.f(zVar, "client");
        j.f(obj, "tag");
        p pVarC = zVar.c();
        for (InterfaceC0167e interfaceC0167e : pVarC.j()) {
            if (j.b(obj, interfaceC0167e.i().j())) {
                interfaceC0167e.cancel();
                return;
            }
        }
        for (InterfaceC0167e interfaceC0167e2 : pVarC.k()) {
            if (j.b(obj, interfaceC0167e2.i().j())) {
                interfaceC0167e2.cancel();
                return;
            }
        }
    }
}
