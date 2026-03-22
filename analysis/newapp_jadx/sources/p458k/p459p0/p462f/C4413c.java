package p458k.p459p0.p462f;

import java.io.IOException;
import java.net.ProtocolException;
import java.util.Objects;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p458k.AbstractC4387j0;
import p458k.AbstractC4485v;
import p458k.C4381g0;
import p458k.C4389k0;
import p458k.InterfaceC4378f;
import p458k.p459p0.C4401c;
import p458k.p459p0.p463g.InterfaceC4427d;
import p458k.p459p0.p465i.C4435a;
import p458k.p459p0.p465i.C4455u;
import p474l.AbstractC4748j;
import p474l.AbstractC4749k;
import p474l.C4744f;
import p474l.InterfaceC4762x;
import p474l.InterfaceC4764z;

/* renamed from: k.p0.f.c */
/* loaded from: classes3.dex */
public final class C4413c {

    /* renamed from: a */
    public boolean f11643a;

    /* renamed from: b */
    @NotNull
    public final C4423m f11644b;

    /* renamed from: c */
    @NotNull
    public final InterfaceC4378f f11645c;

    /* renamed from: d */
    @NotNull
    public final AbstractC4485v f11646d;

    /* renamed from: e */
    public final C4414d f11647e;

    /* renamed from: f */
    public final InterfaceC4427d f11648f;

    /* renamed from: k.p0.f.c$a */
    public final class a extends AbstractC4748j {

        /* renamed from: e */
        public boolean f11649e;

        /* renamed from: f */
        public long f11650f;

        /* renamed from: g */
        public boolean f11651g;

        /* renamed from: h */
        public final long f11652h;

        /* renamed from: i */
        public final /* synthetic */ C4413c f11653i;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public a(@NotNull C4413c c4413c, InterfaceC4762x delegate, long j2) {
            super(delegate);
            Intrinsics.checkParameterIsNotNull(delegate, "delegate");
            this.f11653i = c4413c;
            this.f11652h = j2;
        }

        /* renamed from: b */
        public final <E extends IOException> E m5090b(E e2) {
            if (this.f11649e) {
                return e2;
            }
            this.f11649e = true;
            return (E) this.f11653i.m5083a(this.f11650f, false, true, e2);
        }

        @Override // p474l.AbstractC4748j, p474l.InterfaceC4762x, java.io.Closeable, java.lang.AutoCloseable
        public void close() {
            if (this.f11651g) {
                return;
            }
            this.f11651g = true;
            long j2 = this.f11652h;
            if (j2 != -1 && this.f11650f != j2) {
                throw new ProtocolException("unexpected end of stream");
            }
            try {
                super.close();
                m5090b(null);
            } catch (IOException e2) {
                throw m5090b(e2);
            }
        }

        @Override // p474l.AbstractC4748j, p474l.InterfaceC4762x, java.io.Flushable
        public void flush() {
            try {
                super.flush();
            } catch (IOException e2) {
                throw m5090b(e2);
            }
        }

        @Override // p474l.AbstractC4748j, p474l.InterfaceC4762x
        /* renamed from: x */
        public void mo4923x(@NotNull C4744f source, long j2) {
            Intrinsics.checkParameterIsNotNull(source, "source");
            if (!(!this.f11651g)) {
                throw new IllegalStateException("closed".toString());
            }
            long j3 = this.f11652h;
            if (j3 == -1 || this.f11650f + j2 <= j3) {
                try {
                    super.mo4923x(source, j2);
                    this.f11650f += j2;
                    return;
                } catch (IOException e2) {
                    throw m5090b(e2);
                }
            }
            StringBuilder m586H = C1499a.m586H("expected ");
            m586H.append(this.f11652h);
            m586H.append(" bytes but received ");
            m586H.append(this.f11650f + j2);
            throw new ProtocolException(m586H.toString());
        }
    }

    /* renamed from: k.p0.f.c$b */
    public final class b extends AbstractC4749k {

        /* renamed from: e */
        public long f11654e;

        /* renamed from: f */
        public boolean f11655f;

        /* renamed from: g */
        public boolean f11656g;

        /* renamed from: h */
        public boolean f11657h;

        /* renamed from: i */
        public final long f11658i;

        /* renamed from: j */
        public final /* synthetic */ C4413c f11659j;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public b(@NotNull C4413c c4413c, InterfaceC4764z delegate, long j2) {
            super(delegate);
            Intrinsics.checkParameterIsNotNull(delegate, "delegate");
            this.f11659j = c4413c;
            this.f11658i = j2;
            this.f11655f = true;
            if (j2 == 0) {
                m5091b(null);
            }
        }

        @Override // p474l.AbstractC4749k, p474l.InterfaceC4764z
        /* renamed from: J */
        public long mo4924J(@NotNull C4744f sink, long j2) {
            Intrinsics.checkParameterIsNotNull(sink, "sink");
            if (!(!this.f11657h)) {
                throw new IllegalStateException("closed".toString());
            }
            try {
                long mo4924J = this.f12141c.mo4924J(sink, j2);
                if (this.f11655f) {
                    this.f11655f = false;
                    C4413c c4413c = this.f11659j;
                    AbstractC4485v abstractC4485v = c4413c.f11646d;
                    InterfaceC4378f call = c4413c.f11645c;
                    Objects.requireNonNull(abstractC4485v);
                    Intrinsics.checkParameterIsNotNull(call, "call");
                }
                if (mo4924J == -1) {
                    m5091b(null);
                    return -1L;
                }
                long j3 = this.f11654e + mo4924J;
                long j4 = this.f11658i;
                if (j4 != -1 && j3 > j4) {
                    throw new ProtocolException("expected " + this.f11658i + " bytes but received " + j3);
                }
                this.f11654e = j3;
                if (j3 == j4) {
                    m5091b(null);
                }
                return mo4924J;
            } catch (IOException e2) {
                throw m5091b(e2);
            }
        }

        /* renamed from: b */
        public final <E extends IOException> E m5091b(E e2) {
            if (this.f11656g) {
                return e2;
            }
            this.f11656g = true;
            if (e2 == null && this.f11655f) {
                this.f11655f = false;
                C4413c c4413c = this.f11659j;
                AbstractC4485v abstractC4485v = c4413c.f11646d;
                InterfaceC4378f call = c4413c.f11645c;
                Objects.requireNonNull(abstractC4485v);
                Intrinsics.checkParameterIsNotNull(call, "call");
            }
            return (E) this.f11659j.m5083a(this.f11654e, true, false, e2);
        }

        @Override // p474l.AbstractC4749k, p474l.InterfaceC4764z, java.io.Closeable, java.lang.AutoCloseable
        public void close() {
            if (this.f11657h) {
                return;
            }
            this.f11657h = true;
            try {
                super.close();
                m5091b(null);
            } catch (IOException e2) {
                throw m5091b(e2);
            }
        }
    }

    public C4413c(@NotNull C4423m transmitter, @NotNull InterfaceC4378f call, @NotNull AbstractC4485v eventListener, @NotNull C4414d finder, @NotNull InterfaceC4427d codec) {
        Intrinsics.checkParameterIsNotNull(transmitter, "transmitter");
        Intrinsics.checkParameterIsNotNull(call, "call");
        Intrinsics.checkParameterIsNotNull(eventListener, "eventListener");
        Intrinsics.checkParameterIsNotNull(finder, "finder");
        Intrinsics.checkParameterIsNotNull(codec, "codec");
        this.f11644b = transmitter;
        this.f11645c = call;
        this.f11646d = eventListener;
        this.f11647e = finder;
        this.f11648f = codec;
    }

    /* renamed from: a */
    public final <E extends IOException> E m5083a(long j2, boolean z, boolean z2, E ioe) {
        if (ioe != null) {
            m5089g(ioe);
        }
        if (z2) {
            if (ioe != null) {
                AbstractC4485v abstractC4485v = this.f11646d;
                InterfaceC4378f call = this.f11645c;
                Objects.requireNonNull(abstractC4485v);
                Intrinsics.checkParameterIsNotNull(call, "call");
                Intrinsics.checkParameterIsNotNull(ioe, "ioe");
            } else {
                AbstractC4485v abstractC4485v2 = this.f11646d;
                InterfaceC4378f call2 = this.f11645c;
                Objects.requireNonNull(abstractC4485v2);
                Intrinsics.checkParameterIsNotNull(call2, "call");
            }
        }
        if (z) {
            if (ioe != null) {
                AbstractC4485v abstractC4485v3 = this.f11646d;
                InterfaceC4378f call3 = this.f11645c;
                Objects.requireNonNull(abstractC4485v3);
                Intrinsics.checkParameterIsNotNull(call3, "call");
                Intrinsics.checkParameterIsNotNull(ioe, "ioe");
            } else {
                AbstractC4485v abstractC4485v4 = this.f11646d;
                InterfaceC4378f call4 = this.f11645c;
                Objects.requireNonNull(abstractC4485v4);
                Intrinsics.checkParameterIsNotNull(call4, "call");
            }
        }
        return (E) this.f11644b.m5120e(this, z2, z, ioe);
    }

    @Nullable
    /* renamed from: b */
    public final C4418h m5084b() {
        return this.f11648f.mo5131e();
    }

    @NotNull
    /* renamed from: c */
    public final InterfaceC4762x m5085c(@NotNull C4381g0 request, boolean z) {
        Intrinsics.checkParameterIsNotNull(request, "request");
        this.f11643a = z;
        AbstractC4387j0 abstractC4387j0 = request.f11443e;
        if (abstractC4387j0 == null) {
            Intrinsics.throwNpe();
        }
        long mo4920a = abstractC4387j0.mo4920a();
        AbstractC4485v abstractC4485v = this.f11646d;
        InterfaceC4378f call = this.f11645c;
        Objects.requireNonNull(abstractC4485v);
        Intrinsics.checkParameterIsNotNull(call, "call");
        return new a(this, this.f11648f.mo5134h(request, mo4920a), mo4920a);
    }

    /* renamed from: d */
    public final void m5086d() {
        try {
            this.f11648f.mo5132f();
        } catch (IOException ioe) {
            AbstractC4485v abstractC4485v = this.f11646d;
            InterfaceC4378f call = this.f11645c;
            Objects.requireNonNull(abstractC4485v);
            Intrinsics.checkParameterIsNotNull(call, "call");
            Intrinsics.checkParameterIsNotNull(ioe, "ioe");
            m5089g(ioe);
            throw ioe;
        }
    }

    @Nullable
    /* renamed from: e */
    public final C4389k0.a m5087e(boolean z) {
        try {
            C4389k0.a mo5130d = this.f11648f.mo5130d(z);
            if (mo5130d != null) {
                Intrinsics.checkParameterIsNotNull(this, "deferredTrailers");
                mo5130d.f11510m = this;
            }
            return mo5130d;
        } catch (IOException ioe) {
            AbstractC4485v abstractC4485v = this.f11646d;
            InterfaceC4378f call = this.f11645c;
            Objects.requireNonNull(abstractC4485v);
            Intrinsics.checkParameterIsNotNull(call, "call");
            Intrinsics.checkParameterIsNotNull(ioe, "ioe");
            m5089g(ioe);
            throw ioe;
        }
    }

    /* renamed from: f */
    public final void m5088f() {
        AbstractC4485v abstractC4485v = this.f11646d;
        InterfaceC4378f call = this.f11645c;
        Objects.requireNonNull(abstractC4485v);
        Intrinsics.checkParameterIsNotNull(call, "call");
    }

    /* renamed from: g */
    public final void m5089g(IOException iOException) {
        this.f11647e.m5096e();
        C4418h mo5131e = this.f11648f.mo5131e();
        if (mo5131e == null) {
            Intrinsics.throwNpe();
        }
        C4419i c4419i = mo5131e.f11690p;
        byte[] bArr = C4401c.f11556a;
        synchronized (c4419i) {
            if (iOException instanceof C4455u) {
                int ordinal = ((C4455u) iOException).f11957c.ordinal();
                if (ordinal == 7) {
                    int i2 = mo5131e.f11686l + 1;
                    mo5131e.f11686l = i2;
                    if (i2 > 1) {
                        mo5131e.f11683i = true;
                        mo5131e.f11684j++;
                    }
                } else if (ordinal != 8) {
                    mo5131e.f11683i = true;
                    mo5131e.f11684j++;
                }
            } else if (!mo5131e.m5102f() || (iOException instanceof C4435a)) {
                mo5131e.f11683i = true;
                if (mo5131e.f11685k == 0) {
                    mo5131e.f11690p.m5109a(mo5131e.f11691q, iOException);
                    mo5131e.f11684j++;
                }
            }
            Unit unit = Unit.INSTANCE;
        }
    }
}
