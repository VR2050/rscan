package p474l;

import java.nio.ByteBuffer;
import kotlin.jvm.JvmField;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: l.s */
/* loaded from: classes3.dex */
public final class C4757s implements InterfaceC4745g {

    /* renamed from: c */
    @JvmField
    @NotNull
    public final C4744f f12160c;

    /* renamed from: e */
    @JvmField
    public boolean f12161e;

    /* renamed from: f */
    @JvmField
    @NotNull
    public final InterfaceC4762x f12162f;

    public C4757s(@NotNull InterfaceC4762x sink) {
        Intrinsics.checkNotNullParameter(sink, "sink");
        this.f12162f = sink;
        this.f12160c = new C4744f();
    }

    @Override // p474l.InterfaceC4745g
    @NotNull
    /* renamed from: G */
    public InterfaceC4745g mo5356G(@NotNull byte[] source) {
        Intrinsics.checkNotNullParameter(source, "source");
        if (!(!this.f12161e)) {
            throw new IllegalStateException("closed".toString());
        }
        this.f12160c.m5371Y(source);
        return mo5389p();
    }

    @Override // p474l.InterfaceC4745g
    @NotNull
    /* renamed from: H */
    public InterfaceC4745g mo5357H(@NotNull C4747i byteString) {
        Intrinsics.checkNotNullParameter(byteString, "byteString");
        if (!(!this.f12161e)) {
            throw new IllegalStateException("closed".toString());
        }
        this.f12160c.m5370X(byteString);
        return mo5389p();
    }

    @Override // p474l.InterfaceC4745g
    @NotNull
    /* renamed from: N */
    public InterfaceC4745g mo5361N(long j2) {
        if (!(!this.f12161e)) {
            throw new IllegalStateException("closed".toString());
        }
        this.f12160c.mo5361N(j2);
        return mo5389p();
    }

    @Override // p474l.InterfaceC4745g
    @NotNull
    /* renamed from: a */
    public InterfaceC4745g mo5373a(@NotNull byte[] source, int i2, int i3) {
        Intrinsics.checkNotNullParameter(source, "source");
        if (!(!this.f12161e)) {
            throw new IllegalStateException("closed".toString());
        }
        this.f12160c.m5372Z(source, i2, i3);
        return mo5389p();
    }

    @Override // p474l.InterfaceC4762x
    @NotNull
    /* renamed from: c */
    public C4737a0 mo5151c() {
        return this.f12162f.mo5151c();
    }

    @Override // p474l.InterfaceC4762x, java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        if (this.f12161e) {
            return;
        }
        Throwable th = null;
        try {
            C4744f c4744f = this.f12160c;
            long j2 = c4744f.f12133e;
            if (j2 > 0) {
                this.f12162f.mo4923x(c4744f, j2);
            }
        } catch (Throwable th2) {
            th = th2;
        }
        try {
            this.f12162f.close();
        } catch (Throwable th3) {
            if (th == null) {
                th = th3;
            }
        }
        this.f12161e = true;
        if (th != null) {
            throw th;
        }
    }

    @Override // p474l.InterfaceC4745g, p474l.InterfaceC4762x, java.io.Flushable
    public void flush() {
        if (!(!this.f12161e)) {
            throw new IllegalStateException("closed".toString());
        }
        C4744f c4744f = this.f12160c;
        long j2 = c4744f.f12133e;
        if (j2 > 0) {
            this.f12162f.mo4923x(c4744f, j2);
        }
        this.f12162f.flush();
    }

    @Override // p474l.InterfaceC4745g
    @NotNull
    public C4744f getBuffer() {
        return this.f12160c;
    }

    @Override // p474l.InterfaceC4745g
    @NotNull
    /* renamed from: h */
    public InterfaceC4745g mo5383h(int i2) {
        if (!(!this.f12161e)) {
            throw new IllegalStateException("closed".toString());
        }
        this.f12160c.m5379e0(i2);
        mo5389p();
        return this;
    }

    @Override // java.nio.channels.Channel
    public boolean isOpen() {
        return !this.f12161e;
    }

    @Override // p474l.InterfaceC4745g
    @NotNull
    /* renamed from: j */
    public InterfaceC4745g mo5385j(int i2) {
        if (!(!this.f12161e)) {
            throw new IllegalStateException("closed".toString());
        }
        this.f12160c.m5378d0(i2);
        return mo5389p();
    }

    @Override // p474l.InterfaceC4745g
    @NotNull
    /* renamed from: n */
    public InterfaceC4745g mo5388n(int i2) {
        if (!(!this.f12161e)) {
            throw new IllegalStateException("closed".toString());
        }
        this.f12160c.m5374a0(i2);
        mo5389p();
        return this;
    }

    @Override // p474l.InterfaceC4745g
    @NotNull
    /* renamed from: p */
    public InterfaceC4745g mo5389p() {
        if (!(!this.f12161e)) {
            throw new IllegalStateException("closed".toString());
        }
        long m5391s = this.f12160c.m5391s();
        if (m5391s > 0) {
            this.f12162f.mo4923x(this.f12160c, m5391s);
        }
        return this;
    }

    @NotNull
    public String toString() {
        StringBuilder m586H = C1499a.m586H("buffer(");
        m586H.append(this.f12162f);
        m586H.append(')');
        return m586H.toString();
    }

    @Override // p474l.InterfaceC4745g
    @NotNull
    /* renamed from: u */
    public InterfaceC4745g mo5393u(@NotNull String string) {
        Intrinsics.checkNotNullParameter(string, "string");
        if (!(!this.f12161e)) {
            throw new IllegalStateException("closed".toString());
        }
        this.f12160c.m5381f0(string);
        return mo5389p();
    }

    @Override // java.nio.channels.WritableByteChannel
    public int write(@NotNull ByteBuffer source) {
        Intrinsics.checkNotNullParameter(source, "source");
        if (!(!this.f12161e)) {
            throw new IllegalStateException("closed".toString());
        }
        int write = this.f12160c.write(source);
        mo5389p();
        return write;
    }

    @Override // p474l.InterfaceC4762x
    /* renamed from: x */
    public void mo4923x(@NotNull C4744f source, long j2) {
        Intrinsics.checkNotNullParameter(source, "source");
        if (!(!this.f12161e)) {
            throw new IllegalStateException("closed".toString());
        }
        this.f12160c.mo4923x(source, j2);
        mo5389p();
    }

    @Override // p474l.InterfaceC4745g
    /* renamed from: y */
    public long mo5396y(@NotNull InterfaceC4764z source) {
        Intrinsics.checkNotNullParameter(source, "source");
        long j2 = 0;
        while (true) {
            long mo4924J = source.mo4924J(this.f12160c, 8192);
            if (mo4924J == -1) {
                return j2;
            }
            j2 += mo4924J;
            mo5389p();
        }
    }

    @Override // p474l.InterfaceC4745g
    @NotNull
    /* renamed from: z */
    public InterfaceC4745g mo5397z(long j2) {
        if (!(!this.f12161e)) {
            throw new IllegalStateException("closed".toString());
        }
        this.f12160c.mo5397z(j2);
        return mo5389p();
    }
}
