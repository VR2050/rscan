package b2;

import com.facebook.soloader.C;
import com.facebook.soloader.C0497c;
import com.facebook.soloader.E;
import com.facebook.soloader.G;
import com.facebook.soloader.p;

/* JADX INFO: renamed from: b2.d, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0316d implements InterfaceC0320h {
    @Override // b2.InterfaceC0320h
    public boolean a(UnsatisfiedLinkError unsatisfiedLinkError, E[] eArr) {
        if (!(unsatisfiedLinkError instanceof C)) {
            return false;
        }
        p.b("SoLoader", "Checking /data/data missing libraries.");
        boolean z3 = false;
        for (E e3 : eArr) {
            if ((e3 instanceof G) && !(e3 instanceof C0497c)) {
                G g3 = (G) e3;
                try {
                    G.c[] cVarArrO = g3.o();
                    int length = cVarArrO.length;
                    int i3 = 0;
                    while (true) {
                        if (i3 < length) {
                            G.c cVar = cVarArrO[i3];
                            if (g3.f(cVar.f8323b) == null) {
                                p.b("SoLoader", "Missing " + cVar.f8323b + " from " + g3.c() + ", will force prepare.");
                                g3.e(2);
                                z3 = true;
                                break;
                            }
                            i3++;
                        }
                    }
                } catch (Exception e4) {
                    p.c("SoLoader", "Encountered an exception while recovering from /data/data failure ", e4);
                    return false;
                }
            }
        }
        if (z3) {
            p.b("SoLoader", "Successfully recovered from /data/data disk failure.");
            return true;
        }
        p.b("SoLoader", "No libraries missing from unpacking so paths while recovering /data/data failure");
        return false;
    }
}
