package p474l;

import java.io.IOException;
import java.io.InputStream;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

/* renamed from: l.o */
/* loaded from: classes3.dex */
public final class C4753o implements InterfaceC4764z {

    /* renamed from: c */
    public final InputStream f12152c;

    /* renamed from: e */
    public final C4737a0 f12153e;

    public C4753o(@NotNull InputStream input, @NotNull C4737a0 timeout) {
        Intrinsics.checkNotNullParameter(input, "input");
        Intrinsics.checkNotNullParameter(timeout, "timeout");
        this.f12152c = input;
        this.f12153e = timeout;
    }

    @Override // p474l.InterfaceC4764z
    /* renamed from: J */
    public long mo4924J(@NotNull C4744f sink, long j2) {
        Intrinsics.checkNotNullParameter(sink, "sink");
        if (j2 == 0) {
            return 0L;
        }
        if (!(j2 >= 0)) {
            throw new IllegalArgumentException(C1499a.m630p("byteCount < 0: ", j2).toString());
        }
        try {
            this.f12153e.mo5342f();
            C4759u m5369W = sink.m5369W(1);
            int read = this.f12152c.read(m5369W.f12167a, m5369W.f12169c, (int) Math.min(j2, 8192 - m5369W.f12169c));
            if (read != -1) {
                m5369W.f12169c += read;
                long j3 = read;
                sink.f12133e += j3;
                return j3;
            }
            if (m5369W.f12168b != m5369W.f12169c) {
                return -1L;
            }
            sink.f12132c = m5369W.m5420a();
            C4760v.m5424a(m5369W);
            return -1L;
        } catch (AssertionError e2) {
            if (C2354n.m2399I0(e2)) {
                throw new IOException(e2);
            }
            throw e2;
        }
    }

    @Override // p474l.InterfaceC4764z
    @NotNull
    /* renamed from: c */
    public C4737a0 mo5044c() {
        return this.f12153e;
    }

    @Override // p474l.InterfaceC4764z, java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        this.f12152c.close();
    }

    @NotNull
    public String toString() {
        StringBuilder m586H = C1499a.m586H("source(");
        m586H.append(this.f12152c);
        m586H.append(')');
        return m586H.toString();
    }
}
