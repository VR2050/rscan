package p458k.p459p0.p465i;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.SocketTimeoutException;
import java.util.ArrayDeque;
import java.util.Objects;
import kotlin.TypeCastException;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p458k.C4488y;
import p458k.p459p0.C4401c;
import p458k.p459p0.p461e.C4409b;
import p474l.C4737a0;
import p474l.C4738b;
import p474l.C4744f;
import p474l.InterfaceC4762x;
import p474l.InterfaceC4764z;
import tv.danmaku.ijk.media.player.IjkMediaMeta;

/* renamed from: k.p0.i.o */
/* loaded from: classes3.dex */
public final class C4449o {

    /* renamed from: a */
    public long f11915a;

    /* renamed from: b */
    public long f11916b;

    /* renamed from: c */
    public long f11917c;

    /* renamed from: d */
    public long f11918d;

    /* renamed from: e */
    public final ArrayDeque<C4488y> f11919e;

    /* renamed from: f */
    public boolean f11920f;

    /* renamed from: g */
    @NotNull
    public final b f11921g;

    /* renamed from: h */
    @NotNull
    public final a f11922h;

    /* renamed from: i */
    @NotNull
    public final c f11923i;

    /* renamed from: j */
    @NotNull
    public final c f11924j;

    /* renamed from: k */
    @Nullable
    public EnumC4436b f11925k;

    /* renamed from: l */
    @Nullable
    public IOException f11926l;

    /* renamed from: m */
    public final int f11927m;

    /* renamed from: n */
    @NotNull
    public final C4440f f11928n;

    /* renamed from: k.p0.i.o$a */
    public final class a implements InterfaceC4762x {

        /* renamed from: c */
        public final C4744f f11929c = new C4744f();

        /* renamed from: e */
        public boolean f11930e;

        /* renamed from: f */
        public boolean f11931f;

        public a(boolean z) {
            this.f11931f = z;
        }

        /* renamed from: b */
        public final void m5203b(boolean z) {
            long min;
            boolean z2;
            synchronized (C4449o.this) {
                C4449o.this.f11924j.m5344h();
                while (true) {
                    try {
                        C4449o c4449o = C4449o.this;
                        if (c4449o.f11917c < c4449o.f11918d || this.f11931f || this.f11930e || c4449o.m5196f() != null) {
                            break;
                        } else {
                            C4449o.this.m5202l();
                        }
                    } finally {
                    }
                }
                C4449o.this.f11924j.m5206l();
                C4449o.this.m5192b();
                C4449o c4449o2 = C4449o.this;
                min = Math.min(c4449o2.f11918d - c4449o2.f11917c, this.f11929c.f12133e);
                C4449o c4449o3 = C4449o.this;
                c4449o3.f11917c += min;
                z2 = z && min == this.f11929c.f12133e && c4449o3.m5196f() == null;
                Unit unit = Unit.INSTANCE;
            }
            C4449o.this.f11924j.m5344h();
            try {
                C4449o c4449o4 = C4449o.this;
                c4449o4.f11928n.m5174s(c4449o4.f11927m, z2, this.f11929c, min);
            } finally {
            }
        }

        @Override // p474l.InterfaceC4762x
        @NotNull
        /* renamed from: c */
        public C4737a0 mo5151c() {
            return C4449o.this.f11924j;
        }

        @Override // p474l.InterfaceC4762x, java.io.Closeable, java.lang.AutoCloseable
        public void close() {
            C4449o c4449o = C4449o.this;
            byte[] bArr = C4401c.f11556a;
            synchronized (c4449o) {
                if (this.f11930e) {
                    return;
                }
                boolean z = C4449o.this.m5196f() == null;
                Unit unit = Unit.INSTANCE;
                C4449o c4449o2 = C4449o.this;
                if (!c4449o2.f11922h.f11931f) {
                    if (this.f11929c.f12133e > 0) {
                        while (this.f11929c.f12133e > 0) {
                            m5203b(true);
                        }
                    } else if (z) {
                        c4449o2.f11928n.m5174s(c4449o2.f11927m, true, null, 0L);
                    }
                }
                synchronized (C4449o.this) {
                    this.f11930e = true;
                    Unit unit2 = Unit.INSTANCE;
                }
                C4449o.this.f11928n.f11824E.flush();
                C4449o.this.m5191a();
            }
        }

        @Override // p474l.InterfaceC4762x, java.io.Flushable
        public void flush() {
            C4449o c4449o = C4449o.this;
            byte[] bArr = C4401c.f11556a;
            synchronized (c4449o) {
                C4449o.this.m5192b();
                Unit unit = Unit.INSTANCE;
            }
            while (this.f11929c.f12133e > 0) {
                m5203b(false);
                C4449o.this.f11928n.f11824E.flush();
            }
        }

        @Override // p474l.InterfaceC4762x
        /* renamed from: x */
        public void mo4923x(@NotNull C4744f source, long j2) {
            Intrinsics.checkParameterIsNotNull(source, "source");
            byte[] bArr = C4401c.f11556a;
            this.f11929c.mo4923x(source, j2);
            while (this.f11929c.f12133e >= IjkMediaMeta.AV_CH_TOP_FRONT_RIGHT) {
                m5203b(false);
            }
        }
    }

    /* renamed from: k.p0.i.o$b */
    public final class b implements InterfaceC4764z {

        /* renamed from: c */
        @NotNull
        public final C4744f f11933c = new C4744f();

        /* renamed from: e */
        @NotNull
        public final C4744f f11934e = new C4744f();

        /* renamed from: f */
        public boolean f11935f;

        /* renamed from: g */
        public final long f11936g;

        /* renamed from: h */
        public boolean f11937h;

        public b(long j2, boolean z) {
            this.f11936g = j2;
            this.f11937h = z;
        }

        @Override // p474l.InterfaceC4764z
        /* renamed from: J */
        public long mo4924J(@NotNull C4744f sink, long j2) {
            long j3;
            boolean z;
            long j4;
            Intrinsics.checkParameterIsNotNull(sink, "sink");
            long j5 = 0;
            if (!(j2 >= 0)) {
                throw new IllegalArgumentException(C1499a.m630p("byteCount < 0: ", j2).toString());
            }
            while (true) {
                Throwable th = null;
                synchronized (C4449o.this) {
                    C4449o.this.f11923i.m5344h();
                    try {
                        if (C4449o.this.m5196f() != null && (th = C4449o.this.f11926l) == null) {
                            EnumC4436b m5196f = C4449o.this.m5196f();
                            if (m5196f == null) {
                                Intrinsics.throwNpe();
                            }
                            th = new C4455u(m5196f);
                        }
                        if (this.f11935f) {
                            throw new IOException("stream closed");
                        }
                        C4744f c4744f = this.f11934e;
                        long j6 = c4744f.f12133e;
                        if (j6 > j5) {
                            j3 = c4744f.mo4924J(sink, Math.min(j2, j6));
                            C4449o c4449o = C4449o.this;
                            long j7 = c4449o.f11915a + j3;
                            c4449o.f11915a = j7;
                            long j8 = j7 - c4449o.f11916b;
                            if (th == null && j8 >= c4449o.f11928n.f11845x.m5221a() / 2) {
                                C4449o c4449o2 = C4449o.this;
                                c4449o2.f11928n.m5167C(c4449o2.f11927m, j8);
                                C4449o c4449o3 = C4449o.this;
                                c4449o3.f11916b = c4449o3.f11915a;
                            }
                        } else if (this.f11937h || th != null) {
                            j3 = -1;
                        } else {
                            C4449o.this.m5202l();
                            z = true;
                            j4 = -1;
                            C4449o.this.f11923i.m5206l();
                            Unit unit = Unit.INSTANCE;
                        }
                        j4 = j3;
                        z = false;
                        C4449o.this.f11923i.m5206l();
                        Unit unit2 = Unit.INSTANCE;
                    } finally {
                    }
                }
                if (!z) {
                    if (j4 != -1) {
                        m5204b(j4);
                        return j4;
                    }
                    if (th == null) {
                        return -1L;
                    }
                    throw th;
                }
                j5 = 0;
            }
        }

        /* renamed from: b */
        public final void m5204b(long j2) {
            C4449o c4449o = C4449o.this;
            byte[] bArr = C4401c.f11556a;
            c4449o.f11928n.m5173q(j2);
        }

        @Override // p474l.InterfaceC4764z
        @NotNull
        /* renamed from: c */
        public C4737a0 mo5044c() {
            return C4449o.this.f11923i;
        }

        @Override // p474l.InterfaceC4764z, java.io.Closeable, java.lang.AutoCloseable
        public void close() {
            long j2;
            synchronized (C4449o.this) {
                this.f11935f = true;
                C4744f c4744f = this.f11934e;
                j2 = c4744f.f12133e;
                c4744f.skip(j2);
                C4449o c4449o = C4449o.this;
                if (c4449o == null) {
                    throw new TypeCastException("null cannot be cast to non-null type java.lang.Object");
                }
                c4449o.notifyAll();
                Unit unit = Unit.INSTANCE;
            }
            if (j2 > 0) {
                m5204b(j2);
            }
            C4449o.this.m5191a();
        }
    }

    /* renamed from: k.p0.i.o$c */
    public final class c extends C4738b {
        public c() {
        }

        @Override // p474l.C4738b
        @NotNull
        /* renamed from: j */
        public IOException mo5205j(@Nullable IOException iOException) {
            SocketTimeoutException socketTimeoutException = new SocketTimeoutException("timeout");
            if (iOException != null) {
                socketTimeoutException.initCause(iOException);
            }
            return socketTimeoutException;
        }

        @Override // p474l.C4738b
        /* renamed from: k */
        public void mo5125k() {
            C4449o.this.m5195e(EnumC4436b.CANCEL);
            C4440f c4440f = C4449o.this.f11928n;
            synchronized (c4440f) {
                long j2 = c4440f.f11842u;
                long j3 = c4440f.f11841t;
                if (j2 < j3) {
                    return;
                }
                c4440f.f11841t = j3 + 1;
                c4440f.f11844w = System.nanoTime() + 1000000000;
                Unit unit = Unit.INSTANCE;
                C4409b c4409b = c4440f.f11835n;
                String m582D = C1499a.m582D(new StringBuilder(), c4440f.f11830i, " ping");
                c4409b.m5070c(new C4446l(m582D, true, m582D, true, c4440f), 0L);
            }
        }

        /* renamed from: l */
        public final void m5206l() {
            if (m5345i()) {
                throw new SocketTimeoutException("timeout");
            }
        }
    }

    public C4449o(int i2, @NotNull C4440f connection, boolean z, boolean z2, @Nullable C4488y c4488y) {
        Intrinsics.checkParameterIsNotNull(connection, "connection");
        this.f11927m = i2;
        this.f11928n = connection;
        this.f11918d = connection.f11846y.m5221a();
        ArrayDeque<C4488y> arrayDeque = new ArrayDeque<>();
        this.f11919e = arrayDeque;
        this.f11921g = new b(connection.f11845x.m5221a(), z2);
        this.f11922h = new a(z);
        this.f11923i = new c();
        this.f11924j = new c();
        if (c4488y == null) {
            if (!m5198h()) {
                throw new IllegalStateException("remotely-initiated streams should have headers".toString());
            }
        } else {
            if (!(!m5198h())) {
                throw new IllegalStateException("locally-initiated streams shouldn't have headers yet".toString());
            }
            arrayDeque.add(c4488y);
        }
    }

    /* renamed from: a */
    public final void m5191a() {
        boolean z;
        boolean m5199i;
        byte[] bArr = C4401c.f11556a;
        synchronized (this) {
            b bVar = this.f11921g;
            if (!bVar.f11937h && bVar.f11935f) {
                a aVar = this.f11922h;
                if (aVar.f11931f || aVar.f11930e) {
                    z = true;
                    m5199i = m5199i();
                    Unit unit = Unit.INSTANCE;
                }
            }
            z = false;
            m5199i = m5199i();
            Unit unit2 = Unit.INSTANCE;
        }
        if (z) {
            m5193c(EnumC4436b.CANCEL, null);
        } else {
            if (m5199i) {
                return;
            }
            this.f11928n.m5171k(this.f11927m);
        }
    }

    /* renamed from: b */
    public final void m5192b() {
        a aVar = this.f11922h;
        if (aVar.f11930e) {
            throw new IOException("stream closed");
        }
        if (aVar.f11931f) {
            throw new IOException("stream finished");
        }
        if (this.f11925k != null) {
            IOException iOException = this.f11926l;
            if (iOException != null) {
                throw iOException;
            }
            EnumC4436b enumC4436b = this.f11925k;
            if (enumC4436b == null) {
                Intrinsics.throwNpe();
            }
            throw new C4455u(enumC4436b);
        }
    }

    /* renamed from: c */
    public final void m5193c(@NotNull EnumC4436b statusCode, @Nullable IOException iOException) {
        Intrinsics.checkParameterIsNotNull(statusCode, "rstStatusCode");
        if (m5194d(statusCode, iOException)) {
            C4440f c4440f = this.f11928n;
            int i2 = this.f11927m;
            Objects.requireNonNull(c4440f);
            Intrinsics.checkParameterIsNotNull(statusCode, "statusCode");
            c4440f.f11824E.m5213s(i2, statusCode);
        }
    }

    /* renamed from: d */
    public final boolean m5194d(EnumC4436b enumC4436b, IOException iOException) {
        byte[] bArr = C4401c.f11556a;
        synchronized (this) {
            if (this.f11925k != null) {
                return false;
            }
            if (this.f11921g.f11937h && this.f11922h.f11931f) {
                return false;
            }
            this.f11925k = enumC4436b;
            this.f11926l = iOException;
            notifyAll();
            Unit unit = Unit.INSTANCE;
            this.f11928n.m5171k(this.f11927m);
            return true;
        }
    }

    /* renamed from: e */
    public final void m5195e(@NotNull EnumC4436b errorCode) {
        Intrinsics.checkParameterIsNotNull(errorCode, "errorCode");
        if (m5194d(errorCode, null)) {
            this.f11928n.m5176v(this.f11927m, errorCode);
        }
    }

    @Nullable
    /* renamed from: f */
    public final synchronized EnumC4436b m5196f() {
        return this.f11925k;
    }

    /* JADX WARN: Removed duplicated region for block: B:10:0x0011 A[Catch: all -> 0x0023, TRY_LEAVE, TryCatch #0 {, blocks: (B:3:0x0001, B:5:0x0005, B:10:0x0011, B:15:0x0017, B:16:0x0022), top: B:2:0x0001 }] */
    /* JADX WARN: Removed duplicated region for block: B:15:0x0017 A[Catch: all -> 0x0023, TRY_ENTER, TryCatch #0 {, blocks: (B:3:0x0001, B:5:0x0005, B:10:0x0011, B:15:0x0017, B:16:0x0022), top: B:2:0x0001 }] */
    @org.jetbrains.annotations.NotNull
    /* renamed from: g */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final p474l.InterfaceC4762x m5197g() {
        /*
            r2 = this;
            monitor-enter(r2)
            boolean r0 = r2.f11920f     // Catch: java.lang.Throwable -> L23
            if (r0 != 0) goto Le
            boolean r0 = r2.m5198h()     // Catch: java.lang.Throwable -> L23
            if (r0 == 0) goto Lc
            goto Le
        Lc:
            r0 = 0
            goto Lf
        Le:
            r0 = 1
        Lf:
            if (r0 == 0) goto L17
            kotlin.Unit r0 = kotlin.Unit.INSTANCE     // Catch: java.lang.Throwable -> L23
            monitor-exit(r2)
            k.p0.i.o$a r0 = r2.f11922h
            return r0
        L17:
            java.lang.String r0 = "reply before requesting the sink"
            java.lang.IllegalStateException r1 = new java.lang.IllegalStateException     // Catch: java.lang.Throwable -> L23
            java.lang.String r0 = r0.toString()     // Catch: java.lang.Throwable -> L23
            r1.<init>(r0)     // Catch: java.lang.Throwable -> L23
            throw r1     // Catch: java.lang.Throwable -> L23
        L23:
            r0 = move-exception
            monitor-exit(r2)
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: p458k.p459p0.p465i.C4449o.m5197g():l.x");
    }

    /* renamed from: h */
    public final boolean m5198h() {
        return this.f11928n.f11827f == ((this.f11927m & 1) == 1);
    }

    /* renamed from: i */
    public final synchronized boolean m5199i() {
        if (this.f11925k != null) {
            return false;
        }
        b bVar = this.f11921g;
        if (bVar.f11937h || bVar.f11935f) {
            a aVar = this.f11922h;
            if (aVar.f11931f || aVar.f11930e) {
                if (this.f11920f) {
                    return false;
                }
            }
        }
        return true;
    }

    /* JADX WARN: Removed duplicated region for block: B:10:0x001f A[Catch: all -> 0x0037, TryCatch #0 {, blocks: (B:4:0x0008, B:8:0x0010, B:10:0x001f, B:11:0x0023, B:19:0x0016), top: B:3:0x0008 }] */
    /* renamed from: j */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void m5200j(@org.jetbrains.annotations.NotNull p458k.C4488y r3, boolean r4) {
        /*
            r2 = this;
            java.lang.String r0 = "headers"
            kotlin.jvm.internal.Intrinsics.checkParameterIsNotNull(r3, r0)
            byte[] r0 = p458k.p459p0.C4401c.f11556a
            monitor-enter(r2)
            boolean r0 = r2.f11920f     // Catch: java.lang.Throwable -> L37
            r1 = 1
            if (r0 == 0) goto L16
            if (r4 != 0) goto L10
            goto L16
        L10:
            k.p0.i.o$b r3 = r2.f11921g     // Catch: java.lang.Throwable -> L37
            java.util.Objects.requireNonNull(r3)     // Catch: java.lang.Throwable -> L37
            goto L1d
        L16:
            r2.f11920f = r1     // Catch: java.lang.Throwable -> L37
            java.util.ArrayDeque<k.y> r0 = r2.f11919e     // Catch: java.lang.Throwable -> L37
            r0.add(r3)     // Catch: java.lang.Throwable -> L37
        L1d:
            if (r4 == 0) goto L23
            k.p0.i.o$b r3 = r2.f11921g     // Catch: java.lang.Throwable -> L37
            r3.f11937h = r1     // Catch: java.lang.Throwable -> L37
        L23:
            boolean r3 = r2.m5199i()     // Catch: java.lang.Throwable -> L37
            r2.notifyAll()     // Catch: java.lang.Throwable -> L37
            kotlin.Unit r4 = kotlin.Unit.INSTANCE     // Catch: java.lang.Throwable -> L37
            monitor-exit(r2)
            if (r3 != 0) goto L36
            k.p0.i.f r3 = r2.f11928n
            int r4 = r2.f11927m
            r3.m5171k(r4)
        L36:
            return
        L37:
            r3 = move-exception
            monitor-exit(r2)
            throw r3
        */
        throw new UnsupportedOperationException("Method not decompiled: p458k.p459p0.p465i.C4449o.m5200j(k.y, boolean):void");
    }

    /* renamed from: k */
    public final synchronized void m5201k(@NotNull EnumC4436b errorCode) {
        Intrinsics.checkParameterIsNotNull(errorCode, "errorCode");
        if (this.f11925k == null) {
            this.f11925k = errorCode;
            notifyAll();
        }
    }

    /* renamed from: l */
    public final void m5202l() {
        try {
            wait();
        } catch (InterruptedException unused) {
            Thread.currentThread().interrupt();
            throw new InterruptedIOException();
        }
    }
}
