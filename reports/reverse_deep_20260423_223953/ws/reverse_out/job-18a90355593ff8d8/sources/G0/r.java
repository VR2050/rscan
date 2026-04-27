package G0;

import G0.x;
import a0.InterfaceC0218d;
import a0.InterfaceC0222h;

/* JADX INFO: loaded from: classes.dex */
public abstract class r {

    class a implements D {
        a() {
        }

        @Override // G0.D
        /* JADX INFO: renamed from: b, reason: merged with bridge method [inline-methods] */
        public int a(InterfaceC0222h interfaceC0222h) {
            return interfaceC0222h.size();
        }
    }

    public static n a(X.n nVar, InterfaceC0218d interfaceC0218d, x.a aVar) {
        w wVar = new w(new a(), aVar, nVar, null, false, false);
        interfaceC0218d.a(wVar);
        return wVar;
    }
}
