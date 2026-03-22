package p458k.p459p0.p460d;

import java.io.IOException;
import java.util.concurrent.TimeUnit;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p458k.p459p0.C4401c;
import p474l.C4737a0;
import p474l.C4744f;
import p474l.InterfaceC4745g;
import p474l.InterfaceC4746h;
import p474l.InterfaceC4764z;

/* renamed from: k.p0.d.b */
/* loaded from: classes3.dex */
public final class C4403b implements InterfaceC4764z {

    /* renamed from: c */
    public boolean f11564c;

    /* renamed from: e */
    public final /* synthetic */ InterfaceC4746h f11565e;

    /* renamed from: f */
    public final /* synthetic */ InterfaceC4404c f11566f;

    /* renamed from: g */
    public final /* synthetic */ InterfaceC4745g f11567g;

    public C4403b(InterfaceC4746h interfaceC4746h, InterfaceC4404c interfaceC4404c, InterfaceC4745g interfaceC4745g) {
        this.f11565e = interfaceC4746h;
        this.f11566f = interfaceC4404c;
        this.f11567g = interfaceC4745g;
    }

    @Override // p474l.InterfaceC4764z
    /* renamed from: J */
    public long mo4924J(@NotNull C4744f sink, long j2) {
        Intrinsics.checkParameterIsNotNull(sink, "sink");
        try {
            long mo4924J = this.f11565e.mo4924J(sink, j2);
            if (mo4924J != -1) {
                sink.m5392t(this.f11567g.getBuffer(), sink.f12133e - mo4924J, mo4924J);
                this.f11567g.mo5389p();
                return mo4924J;
            }
            if (!this.f11564c) {
                this.f11564c = true;
                this.f11567g.close();
            }
            return -1L;
        } catch (IOException e2) {
            if (!this.f11564c) {
                this.f11564c = true;
                this.f11566f.mo4954a();
            }
            throw e2;
        }
    }

    @Override // p474l.InterfaceC4764z
    @NotNull
    /* renamed from: c */
    public C4737a0 mo5044c() {
        return this.f11565e.mo5044c();
    }

    @Override // p474l.InterfaceC4764z, java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        if (!this.f11564c && !C4401c.m5023h(this, 100, TimeUnit.MILLISECONDS)) {
            this.f11564c = true;
            this.f11566f.mo4954a();
        }
        this.f11565e.close();
    }
}
