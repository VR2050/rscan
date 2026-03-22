package p474l;

import java.io.OutputStream;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

/* renamed from: l.r */
/* loaded from: classes3.dex */
public final class C4756r implements InterfaceC4762x {

    /* renamed from: c */
    public final OutputStream f12158c;

    /* renamed from: e */
    public final C4737a0 f12159e;

    public C4756r(@NotNull OutputStream out, @NotNull C4737a0 timeout) {
        Intrinsics.checkNotNullParameter(out, "out");
        Intrinsics.checkNotNullParameter(timeout, "timeout");
        this.f12158c = out;
        this.f12159e = timeout;
    }

    @Override // p474l.InterfaceC4762x
    @NotNull
    /* renamed from: c */
    public C4737a0 mo5151c() {
        return this.f12159e;
    }

    @Override // p474l.InterfaceC4762x, java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        this.f12158c.close();
    }

    @Override // p474l.InterfaceC4762x, java.io.Flushable
    public void flush() {
        this.f12158c.flush();
    }

    @NotNull
    public String toString() {
        StringBuilder m586H = C1499a.m586H("sink(");
        m586H.append(this.f12158c);
        m586H.append(')');
        return m586H.toString();
    }

    @Override // p474l.InterfaceC4762x
    /* renamed from: x */
    public void mo4923x(@NotNull C4744f source, long j2) {
        Intrinsics.checkNotNullParameter(source, "source");
        C2354n.m2530y(source.f12133e, 0L, j2);
        while (j2 > 0) {
            this.f12159e.mo5342f();
            C4759u c4759u = source.f12132c;
            Intrinsics.checkNotNull(c4759u);
            int min = (int) Math.min(j2, c4759u.f12169c - c4759u.f12168b);
            this.f12158c.write(c4759u.f12167a, c4759u.f12168b, min);
            int i2 = c4759u.f12168b + min;
            c4759u.f12168b = i2;
            long j3 = min;
            j2 -= j3;
            source.f12133e -= j3;
            if (i2 == c4759u.f12169c) {
                source.f12132c = c4759u.m5420a();
                C4760v.m5424a(c4759u);
            }
        }
    }
}
