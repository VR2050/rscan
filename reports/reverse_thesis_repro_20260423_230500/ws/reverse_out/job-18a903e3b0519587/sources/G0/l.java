package G0;

import G0.n;
import G0.x;
import a0.InterfaceC0218d;

/* JADX INFO: loaded from: classes.dex */
public class l implements InterfaceC0172a {

    class a implements D {
        a() {
        }

        @Override // G0.D
        /* JADX INFO: renamed from: b, reason: merged with bridge method [inline-methods] */
        public int a(N0.d dVar) {
            return dVar.b0();
        }
    }

    @Override // G0.InterfaceC0172a
    public n a(X.n nVar, InterfaceC0218d interfaceC0218d, x.a aVar, boolean z3, boolean z4, n.b bVar) {
        w wVar = new w(new a(), aVar, nVar, bVar, z3, z4);
        interfaceC0218d.a(wVar);
        return wVar;
    }
}
