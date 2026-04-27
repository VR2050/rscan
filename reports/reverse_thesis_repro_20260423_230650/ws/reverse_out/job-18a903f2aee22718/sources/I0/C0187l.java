package I0;

import S.g;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

/* JADX INFO: renamed from: I0.l, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0187l implements InterfaceC0192q {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private InterfaceC0188m f1223a;

    public C0187l(InterfaceC0188m interfaceC0188m) {
        this.f1223a = interfaceC0188m;
    }

    private static S.g b(S.d dVar, S.f fVar) {
        return c(dVar, fVar, Executors.newSingleThreadExecutor());
    }

    private static S.g c(S.d dVar, S.f fVar, Executor executor) {
        return new S.g(fVar, dVar.h(), new g.c(dVar.k(), dVar.j(), dVar.f()), dVar.e(), dVar.d(), dVar.g(), executor, dVar.i());
    }

    @Override // I0.InterfaceC0192q
    public S.k a(S.d dVar) {
        return b(dVar, this.f1223a.a(dVar));
    }
}
