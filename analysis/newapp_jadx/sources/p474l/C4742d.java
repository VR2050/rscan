package p474l;

import java.io.IOException;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: l.d */
/* loaded from: classes3.dex */
public final class C4742d implements InterfaceC4764z {

    /* renamed from: c */
    public final /* synthetic */ C4738b f12130c;

    /* renamed from: e */
    public final /* synthetic */ InterfaceC4764z f12131e;

    public C4742d(C4738b c4738b, InterfaceC4764z interfaceC4764z) {
        this.f12130c = c4738b;
        this.f12131e = interfaceC4764z;
    }

    @Override // p474l.InterfaceC4764z
    /* renamed from: J */
    public long mo4924J(@NotNull C4744f sink, long j2) {
        Intrinsics.checkNotNullParameter(sink, "sink");
        C4738b c4738b = this.f12130c;
        c4738b.m5344h();
        try {
            long mo4924J = this.f12131e.mo4924J(sink, j2);
            if (c4738b.m5345i()) {
                throw c4738b.mo5205j(null);
            }
            return mo4924J;
        } catch (IOException e2) {
            if (c4738b.m5345i()) {
                throw c4738b.mo5205j(e2);
            }
            throw e2;
        } finally {
            c4738b.m5345i();
        }
    }

    @Override // p474l.InterfaceC4764z
    /* renamed from: c */
    public C4737a0 mo5044c() {
        return this.f12130c;
    }

    @Override // p474l.InterfaceC4764z, java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        C4738b c4738b = this.f12130c;
        c4738b.m5344h();
        try {
            this.f12131e.close();
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
        StringBuilder m586H = C1499a.m586H("AsyncTimeout.source(");
        m586H.append(this.f12131e);
        m586H.append(')');
        return m586H.toString();
    }
}
