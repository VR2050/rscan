package b2;

import com.facebook.soloader.E;
import com.facebook.soloader.InterfaceC0496b;
import com.facebook.soloader.m;
import com.facebook.soloader.p;

/* JADX INFO: renamed from: b2.l, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0324l implements InterfaceC0320h {
    /* JADX WARN: Multi-variable type inference failed */
    @Override // b2.InterfaceC0320h
    public boolean a(UnsatisfiedLinkError unsatisfiedLinkError, E[] eArr) {
        for (m mVar : eArr) {
            if (mVar instanceof InterfaceC0496b) {
                p.b("SoLoader", "Waiting on SoSource " + mVar.c());
                mVar.b();
            }
        }
        return true;
    }
}
