package H2;

import B2.B;
import B2.u;
import java.net.Proxy;

/* JADX INFO: loaded from: classes.dex */
public final class i {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final i f1091a = new i();

    private i() {
    }

    private final boolean b(B b3, Proxy.Type type) {
        return !b3.g() && type == Proxy.Type.HTTP;
    }

    public final String a(B b3, Proxy.Type type) {
        t2.j.f(b3, "request");
        t2.j.f(type, "proxyType");
        StringBuilder sb = new StringBuilder();
        sb.append(b3.h());
        sb.append(' ');
        i iVar = f1091a;
        if (iVar.b(b3, type)) {
            sb.append(b3.l());
        } else {
            sb.append(iVar.c(b3.l()));
        }
        sb.append(" HTTP/1.1");
        String string = sb.toString();
        t2.j.e(string, "StringBuilder().apply(builderAction).toString()");
        return string;
    }

    public final String c(u uVar) {
        t2.j.f(uVar, "url");
        String strD = uVar.d();
        String strF = uVar.f();
        if (strF == null) {
            return strD;
        }
        return strD + '?' + strF;
    }
}
