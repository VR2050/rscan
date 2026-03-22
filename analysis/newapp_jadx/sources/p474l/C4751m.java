package p474l;

import java.io.EOFException;
import java.io.IOException;
import java.util.Arrays;
import java.util.zip.CRC32;
import java.util.zip.Inflater;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: l.m */
/* loaded from: classes3.dex */
public final class C4751m implements InterfaceC4764z {

    /* renamed from: c */
    public byte f12143c;

    /* renamed from: e */
    public final C4758t f12144e;

    /* renamed from: f */
    public final Inflater f12145f;

    /* renamed from: g */
    public final C4752n f12146g;

    /* renamed from: h */
    public final CRC32 f12147h;

    public C4751m(@NotNull InterfaceC4764z source) {
        Intrinsics.checkNotNullParameter(source, "source");
        C4758t c4758t = new C4758t(source);
        this.f12144e = c4758t;
        Inflater inflater = new Inflater(true);
        this.f12145f = inflater;
        this.f12146g = new C4752n(c4758t, inflater);
        this.f12147h = new CRC32();
    }

    @Override // p474l.InterfaceC4764z
    /* renamed from: J */
    public long mo4924J(@NotNull C4744f sink, long j2) {
        long j3;
        Intrinsics.checkNotNullParameter(sink, "sink");
        if (!(j2 >= 0)) {
            throw new IllegalArgumentException(C1499a.m630p("byteCount < 0: ", j2).toString());
        }
        if (j2 == 0) {
            return 0L;
        }
        if (this.f12143c == 0) {
            this.f12144e.mo5360M(10L);
            byte m5394v = this.f12144e.f12163c.m5394v(3L);
            boolean z = ((m5394v >> 1) & 1) == 1;
            if (z) {
                m5414d(this.f12144e.f12163c, 0L, 10L);
            }
            C4758t c4758t = this.f12144e;
            c4758t.mo5360M(2L);
            m5413b("ID1ID2", 8075, c4758t.f12163c.readShort());
            this.f12144e.skip(8L);
            if (((m5394v >> 2) & 1) == 1) {
                this.f12144e.mo5360M(2L);
                if (z) {
                    m5414d(this.f12144e.f12163c, 0L, 2L);
                }
                long m5358I = this.f12144e.f12163c.m5358I();
                this.f12144e.mo5360M(m5358I);
                if (z) {
                    j3 = m5358I;
                    m5414d(this.f12144e.f12163c, 0L, m5358I);
                } else {
                    j3 = m5358I;
                }
                this.f12144e.skip(j3);
            }
            if (((m5394v >> 3) & 1) == 1) {
                long m5417b = this.f12144e.m5417b((byte) 0, 0L, Long.MAX_VALUE);
                if (m5417b == -1) {
                    throw new EOFException();
                }
                if (z) {
                    m5414d(this.f12144e.f12163c, 0L, m5417b + 1);
                }
                this.f12144e.skip(m5417b + 1);
            }
            if (((m5394v >> 4) & 1) == 1) {
                long m5417b2 = this.f12144e.m5417b((byte) 0, 0L, Long.MAX_VALUE);
                if (m5417b2 == -1) {
                    throw new EOFException();
                }
                if (z) {
                    m5414d(this.f12144e.f12163c, 0L, m5417b2 + 1);
                }
                this.f12144e.skip(m5417b2 + 1);
            }
            if (z) {
                C4758t c4758t2 = this.f12144e;
                c4758t2.mo5360M(2L);
                m5413b("FHCRC", c4758t2.f12163c.m5358I(), (short) this.f12147h.getValue());
                this.f12147h.reset();
            }
            this.f12143c = (byte) 1;
        }
        if (this.f12143c == 1) {
            long j4 = sink.f12133e;
            long mo4924J = this.f12146g.mo4924J(sink, j2);
            if (mo4924J != -1) {
                m5414d(sink, j4, mo4924J);
                return mo4924J;
            }
            this.f12143c = (byte) 2;
        }
        if (this.f12143c == 2) {
            m5413b("CRC", this.f12144e.m5419e(), (int) this.f12147h.getValue());
            m5413b("ISIZE", this.f12144e.m5419e(), (int) this.f12145f.getBytesWritten());
            this.f12143c = (byte) 3;
            if (!this.f12144e.mo5387m()) {
                throw new IOException("gzip finished without exhausting source");
            }
        }
        return -1L;
    }

    /* renamed from: b */
    public final void m5413b(String str, int i2, int i3) {
        if (i3 == i2) {
            return;
        }
        String format = String.format("%s: actual 0x%08x != expected 0x%08x", Arrays.copyOf(new Object[]{str, Integer.valueOf(i3), Integer.valueOf(i2)}, 3));
        Intrinsics.checkNotNullExpressionValue(format, "java.lang.String.format(this, *args)");
        throw new IOException(format);
    }

    @Override // p474l.InterfaceC4764z
    @NotNull
    /* renamed from: c */
    public C4737a0 mo5044c() {
        return this.f12144e.mo5044c();
    }

    @Override // p474l.InterfaceC4764z, java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        this.f12146g.close();
    }

    /* renamed from: d */
    public final void m5414d(C4744f c4744f, long j2, long j3) {
        C4759u c4759u = c4744f.f12132c;
        Intrinsics.checkNotNull(c4759u);
        while (true) {
            int i2 = c4759u.f12169c;
            int i3 = c4759u.f12168b;
            if (j2 < i2 - i3) {
                break;
            }
            j2 -= i2 - i3;
            c4759u = c4759u.f12172f;
            Intrinsics.checkNotNull(c4759u);
        }
        while (j3 > 0) {
            int min = (int) Math.min(c4759u.f12169c - r7, j3);
            this.f12147h.update(c4759u.f12167a, (int) (c4759u.f12168b + j2), min);
            j3 -= min;
            c4759u = c4759u.f12172f;
            Intrinsics.checkNotNull(c4759u);
            j2 = 0;
        }
    }
}
