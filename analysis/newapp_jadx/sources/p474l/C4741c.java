package p474l;

import java.io.IOException;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

/* renamed from: l.c */
/* loaded from: classes3.dex */
public final class C4741c implements InterfaceC4762x {

    /* renamed from: c */
    public final /* synthetic */ C4738b f12128c;

    /* renamed from: e */
    public final /* synthetic */ InterfaceC4762x f12129e;

    public C4741c(C4738b c4738b, InterfaceC4762x interfaceC4762x) {
        this.f12128c = c4738b;
        this.f12129e = interfaceC4762x;
    }

    @Override // p474l.InterfaceC4762x
    /* renamed from: c */
    public C4737a0 mo5151c() {
        return this.f12128c;
    }

    @Override // p474l.InterfaceC4762x, java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        C4738b c4738b = this.f12128c;
        c4738b.m5344h();
        try {
            this.f12129e.close();
            Unit unit = Unit.INSTANCE;
            if (c4738b.m5345i()) {
                throw c4738b.mo5205j(null);
            }
        } catch (IOException e2) {
            if (!c4738b.m5345i()) {
                throw e2;
            }
            throw c4738b.mo5205j(e2);
        } finally {
            c4738b.m5345i();
        }
    }

    @Override // p474l.InterfaceC4762x, java.io.Flushable
    public void flush() {
        C4738b c4738b = this.f12128c;
        c4738b.m5344h();
        try {
            this.f12129e.flush();
            Unit unit = Unit.INSTANCE;
            if (c4738b.m5345i()) {
                throw c4738b.mo5205j(null);
            }
        } catch (IOException e2) {
            if (!c4738b.m5345i()) {
                throw e2;
            }
            throw c4738b.mo5205j(e2);
        } finally {
            c4738b.m5345i();
        }
    }

    @NotNull
    public String toString() {
        StringBuilder m586H = C1499a.m586H("AsyncTimeout.sink(");
        m586H.append(this.f12129e);
        m586H.append(')');
        return m586H.toString();
    }

    @Override // p474l.InterfaceC4762x
    /* renamed from: x */
    public void mo4923x(@NotNull C4744f source, long j2) {
        Intrinsics.checkNotNullParameter(source, "source");
        C2354n.m2530y(source.f12133e, 0L, j2);
        while (true) {
            long j3 = 0;
            if (j2 <= 0) {
                return;
            }
            C4759u c4759u = source.f12132c;
            Intrinsics.checkNotNull(c4759u);
            while (true) {
                if (j3 >= 65536) {
                    break;
                }
                j3 += c4759u.f12169c - c4759u.f12168b;
                if (j3 >= j2) {
                    j3 = j2;
                    break;
                } else {
                    c4759u = c4759u.f12172f;
                    Intrinsics.checkNotNull(c4759u);
                }
            }
            C4738b c4738b = this.f12128c;
            c4738b.m5344h();
            try {
                this.f12129e.mo4923x(source, j3);
                Unit unit = Unit.INSTANCE;
                if (c4738b.m5345i()) {
                    throw c4738b.mo5205j(null);
                }
                j2 -= j3;
            } catch (IOException e2) {
                if (!c4738b.m5345i()) {
                    throw e2;
                }
                throw c4738b.mo5205j(e2);
            } finally {
                c4738b.m5345i();
            }
        }
    }
}
