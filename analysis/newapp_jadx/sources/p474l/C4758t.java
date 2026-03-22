package p474l;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import kotlin.jvm.JvmField;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.CharsKt__CharJVMKt;
import org.jetbrains.annotations.NotNull;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p474l.p475b0.C4739a;

/* renamed from: l.t */
/* loaded from: classes3.dex */
public final class C4758t implements InterfaceC4746h {

    /* renamed from: c */
    @JvmField
    @NotNull
    public final C4744f f12163c;

    /* renamed from: e */
    @JvmField
    public boolean f12164e;

    /* renamed from: f */
    @JvmField
    @NotNull
    public final InterfaceC4764z f12165f;

    public C4758t(@NotNull InterfaceC4764z source) {
        Intrinsics.checkNotNullParameter(source, "source");
        this.f12165f = source;
        this.f12163c = new C4744f();
    }

    @Override // p474l.InterfaceC4746h
    /* renamed from: A */
    public boolean mo5350A(long j2) {
        C4744f c4744f;
        if (!(j2 >= 0)) {
            throw new IllegalArgumentException(C1499a.m630p("byteCount < 0: ", j2).toString());
        }
        if (!(!this.f12164e)) {
            throw new IllegalStateException("closed".toString());
        }
        do {
            c4744f = this.f12163c;
            if (c4744f.f12133e >= j2) {
                return true;
            }
        } while (this.f12165f.mo4924J(c4744f, 8192) != -1);
        return false;
    }

    @Override // p474l.InterfaceC4746h
    @NotNull
    /* renamed from: B */
    public String mo5351B() {
        return mo5390r(Long.MAX_VALUE);
    }

    @Override // p474l.InterfaceC4746h
    @NotNull
    /* renamed from: F */
    public byte[] mo5355F(long j2) {
        if (mo5350A(j2)) {
            return this.f12163c.mo5355F(j2);
        }
        throw new EOFException();
    }

    @Override // p474l.InterfaceC4764z
    /* renamed from: J */
    public long mo4924J(@NotNull C4744f sink, long j2) {
        Intrinsics.checkNotNullParameter(sink, "sink");
        if (!(j2 >= 0)) {
            throw new IllegalArgumentException(C1499a.m630p("byteCount < 0: ", j2).toString());
        }
        if (!(!this.f12164e)) {
            throw new IllegalStateException("closed".toString());
        }
        C4744f c4744f = this.f12163c;
        if (c4744f.f12133e == 0 && this.f12165f.mo4924J(c4744f, 8192) == -1) {
            return -1L;
        }
        return this.f12163c.mo4924J(sink, Math.min(j2, this.f12163c.f12133e));
    }

    @Override // p474l.InterfaceC4746h
    /* renamed from: K */
    public long mo5359K(@NotNull InterfaceC4762x sink) {
        Intrinsics.checkNotNullParameter(sink, "sink");
        long j2 = 0;
        while (this.f12165f.mo4924J(this.f12163c, 8192) != -1) {
            long m5391s = this.f12163c.m5391s();
            if (m5391s > 0) {
                j2 += m5391s;
                ((C4744f) sink).mo4923x(this.f12163c, m5391s);
            }
        }
        C4744f c4744f = this.f12163c;
        long j3 = c4744f.f12133e;
        if (j3 <= 0) {
            return j2;
        }
        long j4 = j2 + j3;
        ((C4744f) sink).mo4923x(c4744f, j3);
        return j4;
    }

    @Override // p474l.InterfaceC4746h
    /* renamed from: M */
    public void mo5360M(long j2) {
        if (!mo5350A(j2)) {
            throw new EOFException();
        }
    }

    @Override // p474l.InterfaceC4746h
    /* renamed from: Q */
    public long mo5363Q() {
        byte m5394v;
        mo5360M(1L);
        int i2 = 0;
        while (true) {
            int i3 = i2 + 1;
            if (!mo5350A(i3)) {
                break;
            }
            m5394v = this.f12163c.m5394v(i2);
            if ((m5394v < ((byte) 48) || m5394v > ((byte) 57)) && ((m5394v < ((byte) 97) || m5394v > ((byte) 102)) && (m5394v < ((byte) 65) || m5394v > ((byte) 70)))) {
                break;
            }
            i2 = i3;
        }
        if (i2 == 0) {
            StringBuilder m586H = C1499a.m586H("Expected leading [0-9a-fA-F] character but was 0x");
            String num = Integer.toString(m5394v, CharsKt__CharJVMKt.checkRadix(CharsKt__CharJVMKt.checkRadix(16)));
            Intrinsics.checkNotNullExpressionValue(num, "java.lang.Integer.toStri…(this, checkRadix(radix))");
            m586H.append(num);
            throw new NumberFormatException(m586H.toString());
        }
        return this.f12163c.mo5363Q();
    }

    @Override // p474l.InterfaceC4746h
    @NotNull
    /* renamed from: R */
    public InputStream mo5364R() {
        return new a();
    }

    @Override // p474l.InterfaceC4746h
    /* renamed from: T */
    public int mo5366T(@NotNull C4755q options) {
        Intrinsics.checkNotNullParameter(options, "options");
        if (!(!this.f12164e)) {
            throw new IllegalStateException("closed".toString());
        }
        while (true) {
            int m5348b = C4739a.m5348b(this.f12163c, options, true);
            if (m5348b != -2) {
                if (m5348b != -1) {
                    this.f12163c.skip(options.f12156e[m5348b].mo5400c());
                    return m5348b;
                }
            } else if (this.f12165f.mo4924J(this.f12163c, 8192) == -1) {
                break;
            }
        }
        return -1;
    }

    /* renamed from: b */
    public long m5417b(byte b2, long j2, long j3) {
        if (!(!this.f12164e)) {
            throw new IllegalStateException("closed".toString());
        }
        if (!(0 <= j2 && j3 >= j2)) {
            throw new IllegalArgumentException(("fromIndex=" + j2 + " toIndex=" + j3).toString());
        }
        while (j2 < j3) {
            long m5352C = this.f12163c.m5352C(b2, j2, j3);
            if (m5352C != -1) {
                return m5352C;
            }
            C4744f c4744f = this.f12163c;
            long j4 = c4744f.f12133e;
            if (j4 >= j3 || this.f12165f.mo4924J(c4744f, 8192) == -1) {
                return -1L;
            }
            j2 = Math.max(j2, j4);
        }
        return -1L;
    }

    @Override // p474l.InterfaceC4764z
    @NotNull
    /* renamed from: c */
    public C4737a0 mo5044c() {
        return this.f12165f.mo5044c();
    }

    @Override // p474l.InterfaceC4764z, java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        if (this.f12164e) {
            return;
        }
        this.f12164e = true;
        this.f12165f.close();
        C4744f c4744f = this.f12163c;
        c4744f.skip(c4744f.f12133e);
    }

    /* JADX WARN: Code restructure failed: missing block: B:15:0x002c, code lost:
    
        if (r4 == 0) goto L17;
     */
    /* JADX WARN: Code restructure failed: missing block: B:16:0x002f, code lost:
    
        r1 = p005b.p131d.p132a.p133a.C1499a.m586H("Expected leading [0-9] or '-' character but was 0x");
        r2 = java.lang.Integer.toString(r8, kotlin.text.CharsKt__CharJVMKt.checkRadix(kotlin.text.CharsKt__CharJVMKt.checkRadix(16)));
        kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r2, "java.lang.Integer.toStri…(this, checkRadix(radix))");
        r1.append(r2);
     */
    /* JADX WARN: Code restructure failed: missing block: B:17:0x0054, code lost:
    
        throw new java.lang.NumberFormatException(r1.toString());
     */
    /* renamed from: d */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public long m5418d() {
        /*
            r10 = this;
            r0 = 1
            r10.mo5360M(r0)
            r2 = 0
            r4 = r2
        L8:
            long r6 = r4 + r0
            boolean r8 = r10.mo5350A(r6)
            if (r8 == 0) goto L55
            l.f r8 = r10.f12163c
            byte r8 = r8.m5394v(r4)
            r9 = 48
            byte r9 = (byte) r9
            if (r8 < r9) goto L20
            r9 = 57
            byte r9 = (byte) r9
            if (r8 <= r9) goto L2a
        L20:
            int r9 = (r4 > r2 ? 1 : (r4 == r2 ? 0 : -1))
            if (r9 != 0) goto L2c
            r4 = 45
            byte r4 = (byte) r4
            if (r8 == r4) goto L2a
            goto L2c
        L2a:
            r4 = r6
            goto L8
        L2c:
            if (r9 == 0) goto L2f
            goto L55
        L2f:
            java.lang.NumberFormatException r0 = new java.lang.NumberFormatException
            java.lang.String r1 = "Expected leading [0-9] or '-' character but was 0x"
            java.lang.StringBuilder r1 = p005b.p131d.p132a.p133a.C1499a.m586H(r1)
            r2 = 16
            int r2 = kotlin.text.CharsKt__CharJVMKt.checkRadix(r2)
            int r2 = kotlin.text.CharsKt__CharJVMKt.checkRadix(r2)
            java.lang.String r2 = java.lang.Integer.toString(r8, r2)
            java.lang.String r3 = "java.lang.Integer.toStri…(this, checkRadix(radix))"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r2, r3)
            r1.append(r2)
            java.lang.String r1 = r1.toString()
            r0.<init>(r1)
            throw r0
        L55:
            l.f r0 = r10.f12163c
            long r0 = r0.m5354E()
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: p474l.C4758t.m5418d():long");
    }

    /* renamed from: e */
    public int m5419e() {
        mo5360M(4L);
        int readInt = this.f12163c.readInt();
        return ((readInt & 255) << 24) | (((-16777216) & readInt) >>> 24) | ((16711680 & readInt) >>> 8) | ((65280 & readInt) << 8);
    }

    @Override // p474l.InterfaceC4746h
    @NotNull
    /* renamed from: f */
    public C4747i mo5380f(long j2) {
        if (mo5350A(j2)) {
            return this.f12163c.mo5380f(j2);
        }
        throw new EOFException();
    }

    @Override // p474l.InterfaceC4746h, p474l.InterfaceC4745g
    @NotNull
    public C4744f getBuffer() {
        return this.f12163c;
    }

    @Override // java.nio.channels.Channel
    public boolean isOpen() {
        return !this.f12164e;
    }

    @Override // p474l.InterfaceC4746h
    @NotNull
    /* renamed from: l */
    public byte[] mo5386l() {
        this.f12163c.mo5396y(this.f12165f);
        return this.f12163c.mo5386l();
    }

    @Override // p474l.InterfaceC4746h
    /* renamed from: m */
    public boolean mo5387m() {
        if (!this.f12164e) {
            return this.f12163c.mo5387m() && this.f12165f.mo4924J(this.f12163c, (long) 8192) == -1;
        }
        throw new IllegalStateException("closed".toString());
    }

    @Override // p474l.InterfaceC4746h
    @NotNull
    /* renamed from: r */
    public String mo5390r(long j2) {
        if (!(j2 >= 0)) {
            throw new IllegalArgumentException(C1499a.m630p("limit < 0: ", j2).toString());
        }
        long j3 = j2 == Long.MAX_VALUE ? Long.MAX_VALUE : j2 + 1;
        byte b2 = (byte) 10;
        long m5417b = m5417b(b2, 0L, j3);
        if (m5417b != -1) {
            return C4739a.m5347a(this.f12163c, m5417b);
        }
        if (j3 < Long.MAX_VALUE && mo5350A(j3) && this.f12163c.m5394v(j3 - 1) == ((byte) 13) && mo5350A(1 + j3) && this.f12163c.m5394v(j3) == b2) {
            return C4739a.m5347a(this.f12163c, j3);
        }
        C4744f c4744f = new C4744f();
        C4744f c4744f2 = this.f12163c;
        c4744f2.m5392t(c4744f, 0L, Math.min(32, c4744f2.f12133e));
        StringBuilder m586H = C1499a.m586H("\\n not found: limit=");
        m586H.append(Math.min(this.f12163c.f12133e, j2));
        m586H.append(" content=");
        m586H.append(c4744f.m5353D().mo5401d());
        m586H.append("…");
        throw new EOFException(m586H.toString());
    }

    @Override // java.nio.channels.ReadableByteChannel
    public int read(@NotNull ByteBuffer sink) {
        Intrinsics.checkNotNullParameter(sink, "sink");
        C4744f c4744f = this.f12163c;
        if (c4744f.f12133e == 0 && this.f12165f.mo4924J(c4744f, 8192) == -1) {
            return -1;
        }
        return this.f12163c.read(sink);
    }

    @Override // p474l.InterfaceC4746h
    public byte readByte() {
        mo5360M(1L);
        return this.f12163c.readByte();
    }

    @Override // p474l.InterfaceC4746h
    public int readInt() {
        mo5360M(4L);
        return this.f12163c.readInt();
    }

    @Override // p474l.InterfaceC4746h
    public short readShort() {
        mo5360M(2L);
        return this.f12163c.readShort();
    }

    @Override // p474l.InterfaceC4746h
    public void skip(long j2) {
        if (!(!this.f12164e)) {
            throw new IllegalStateException("closed".toString());
        }
        while (j2 > 0) {
            C4744f c4744f = this.f12163c;
            if (c4744f.f12133e == 0 && this.f12165f.mo4924J(c4744f, 8192) == -1) {
                throw new EOFException();
            }
            long min = Math.min(j2, this.f12163c.f12133e);
            this.f12163c.skip(min);
            j2 -= min;
        }
    }

    @NotNull
    public String toString() {
        StringBuilder m586H = C1499a.m586H("buffer(");
        m586H.append(this.f12165f);
        m586H.append(')');
        return m586H.toString();
    }

    @Override // p474l.InterfaceC4746h
    @NotNull
    /* renamed from: w */
    public String mo5395w(@NotNull Charset charset) {
        Intrinsics.checkNotNullParameter(charset, "charset");
        this.f12163c.mo5396y(this.f12165f);
        return this.f12163c.mo5395w(charset);
    }

    /* renamed from: l.t$a */
    public static final class a extends InputStream {
        public a() {
        }

        @Override // java.io.InputStream
        public int available() {
            C4758t c4758t = C4758t.this;
            if (c4758t.f12164e) {
                throw new IOException("closed");
            }
            return (int) Math.min(c4758t.f12163c.f12133e, Integer.MAX_VALUE);
        }

        @Override // java.io.InputStream, java.io.Closeable, java.lang.AutoCloseable
        public void close() {
            C4758t.this.close();
        }

        @Override // java.io.InputStream
        public int read() {
            C4758t c4758t = C4758t.this;
            if (c4758t.f12164e) {
                throw new IOException("closed");
            }
            C4744f c4744f = c4758t.f12163c;
            if (c4744f.f12133e == 0 && c4758t.f12165f.mo4924J(c4744f, 8192) == -1) {
                return -1;
            }
            return C4758t.this.f12163c.readByte() & 255;
        }

        @NotNull
        public String toString() {
            return C4758t.this + ".inputStream()";
        }

        @Override // java.io.InputStream
        public int read(@NotNull byte[] data, int i2, int i3) {
            Intrinsics.checkNotNullParameter(data, "data");
            if (!C4758t.this.f12164e) {
                C2354n.m2530y(data.length, i2, i3);
                C4758t c4758t = C4758t.this;
                C4744f c4744f = c4758t.f12163c;
                if (c4744f.f12133e == 0 && c4758t.f12165f.mo4924J(c4744f, 8192) == -1) {
                    return -1;
                }
                return C4758t.this.f12163c.read(data, i2, i3);
            }
            throw new IOException("closed");
        }
    }
}
