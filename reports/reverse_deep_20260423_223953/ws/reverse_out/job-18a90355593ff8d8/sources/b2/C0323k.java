package b2;

import com.facebook.soloader.B;
import com.facebook.soloader.C;
import com.facebook.soloader.C0497c;
import com.facebook.soloader.E;
import com.facebook.soloader.G;
import com.facebook.soloader.p;

/* JADX INFO: renamed from: b2.k, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0323k implements InterfaceC0320h {
    @Override // b2.InterfaceC0320h
    public boolean a(UnsatisfiedLinkError unsatisfiedLinkError, E[] eArr) {
        if (!(unsatisfiedLinkError instanceof C) || (unsatisfiedLinkError instanceof B)) {
            return false;
        }
        String strA = ((C) unsatisfiedLinkError).a();
        StringBuilder sb = new StringBuilder();
        sb.append("Reunpacking NonApk UnpackingSoSources due to ");
        sb.append(unsatisfiedLinkError);
        sb.append(strA == null ? "" : ", retrying for specific library " + strA);
        p.b("SoLoader", sb.toString());
        for (E e3 : eArr) {
            if (e3 instanceof G) {
                G g3 = (G) e3;
                if (g3 instanceof C0497c) {
                    continue;
                } else {
                    try {
                        p.b("SoLoader", "Runpacking " + g3.c());
                        g3.e(2);
                    } catch (Exception e4) {
                        p.c("SoLoader", "Encountered an exception while reunpacking " + g3.c() + " for library " + strA + ": ", e4);
                        return false;
                    }
                }
            }
        }
        return true;
    }
}
