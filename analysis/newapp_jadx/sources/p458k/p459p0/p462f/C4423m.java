package p458k.p459p0.p462f;

import java.io.IOException;
import java.lang.ref.Reference;
import java.lang.ref.WeakReference;
import java.net.Socket;
import java.util.Iterator;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p458k.AbstractC4485v;
import p458k.C4375d0;
import p458k.C4381g0;
import p458k.InterfaceC4378f;
import p458k.p459p0.C4401c;
import p458k.p459p0.p461e.C4409b;
import p458k.p459p0.p467k.C4463g;
import p474l.C4738b;

/* renamed from: k.p0.f.m */
/* loaded from: classes3.dex */
public final class C4423m {

    /* renamed from: a */
    public final C4419i f11712a;

    /* renamed from: b */
    public final AbstractC4485v f11713b;

    /* renamed from: c */
    public final b f11714c;

    /* renamed from: d */
    public Object f11715d;

    /* renamed from: e */
    public C4381g0 f11716e;

    /* renamed from: f */
    public C4414d f11717f;

    /* renamed from: g */
    @Nullable
    public C4418h f11718g;

    /* renamed from: h */
    public C4413c f11719h;

    /* renamed from: i */
    public boolean f11720i;

    /* renamed from: j */
    public boolean f11721j;

    /* renamed from: k */
    public boolean f11722k;

    /* renamed from: l */
    public boolean f11723l;

    /* renamed from: m */
    public boolean f11724m;

    /* renamed from: n */
    public final C4375d0 f11725n;

    /* renamed from: o */
    public final InterfaceC4378f f11726o;

    /* renamed from: k.p0.f.m$a */
    public static final class a extends WeakReference<C4423m> {

        /* renamed from: a */
        @Nullable
        public final Object f11727a;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public a(@NotNull C4423m referent, @Nullable Object obj) {
            super(referent);
            Intrinsics.checkParameterIsNotNull(referent, "referent");
            this.f11727a = obj;
        }
    }

    /* renamed from: k.p0.f.m$b */
    public static final class b extends C4738b {
        public b() {
        }

        @Override // p474l.C4738b
        /* renamed from: k */
        public void mo5125k() {
            C4423m.this.m5118c();
        }
    }

    public C4423m(@NotNull C4375d0 client, @NotNull InterfaceC4378f call) {
        Intrinsics.checkParameterIsNotNull(client, "client");
        Intrinsics.checkParameterIsNotNull(call, "call");
        this.f11725n = client;
        this.f11726o = call;
        this.f11712a = client.f11368h.f11511a;
        this.f11713b = client.f11371k.mo5015a(call);
        b bVar = new b();
        bVar.mo5343g(0, TimeUnit.MILLISECONDS);
        this.f11714c = bVar;
    }

    /* renamed from: a */
    public final void m5116a(@NotNull C4418h connection) {
        Intrinsics.checkParameterIsNotNull(connection, "connection");
        byte[] bArr = C4401c.f11556a;
        if (!(this.f11718g == null)) {
            throw new IllegalStateException("Check failed.".toString());
        }
        this.f11718g = connection;
        connection.f11688n.add(new a(this, this.f11715d));
    }

    /* renamed from: b */
    public final void m5117b() {
        C4463g.a aVar = C4463g.f11988c;
        this.f11715d = C4463g.f11986a.mo5239i("response.body().close()");
        AbstractC4485v abstractC4485v = this.f11713b;
        InterfaceC4378f call = this.f11726o;
        Objects.requireNonNull(abstractC4485v);
        Intrinsics.checkParameterIsNotNull(call, "call");
    }

    /* renamed from: c */
    public final void m5118c() {
        C4413c c4413c;
        C4418h c4418h;
        Socket socket;
        synchronized (this.f11712a) {
            this.f11722k = true;
            c4413c = this.f11719h;
            C4414d c4414d = this.f11717f;
            if (c4414d != null) {
                byte[] bArr = C4401c.f11556a;
                c4418h = c4414d.f11662c;
                if (c4418h != null) {
                    Unit unit = Unit.INSTANCE;
                }
            }
            c4418h = this.f11718g;
            Unit unit2 = Unit.INSTANCE;
        }
        if (c4413c != null) {
            c4413c.f11648f.cancel();
        } else {
            if (c4418h == null || (socket = c4418h.f11676b) == null) {
                return;
            }
            C4401c.m5020e(socket);
        }
    }

    /* renamed from: d */
    public final void m5119d() {
        synchronized (this.f11712a) {
            C4413c c4413c = this.f11719h;
            if (c4413c != null) {
                c4413c.f11648f.cancel();
                c4413c.f11644b.m5120e(c4413c, true, true, null);
            }
            if (!(!this.f11724m)) {
                throw new IllegalStateException("Check failed.".toString());
            }
            this.f11719h = null;
            Unit unit = Unit.INSTANCE;
        }
    }

    /* renamed from: e */
    public final <E extends IOException> E m5120e(@NotNull C4413c exchange, boolean z, boolean z2, E e2) {
        boolean z3;
        Intrinsics.checkParameterIsNotNull(exchange, "exchange");
        synchronized (this.f11712a) {
            boolean z4 = true;
            if (!Intrinsics.areEqual(exchange, this.f11719h)) {
                return e2;
            }
            if (z) {
                z3 = !this.f11720i;
                this.f11720i = true;
            } else {
                z3 = false;
            }
            if (z2) {
                if (!this.f11721j) {
                    z3 = true;
                }
                this.f11721j = true;
            }
            if (this.f11720i && this.f11721j && z3) {
                C4413c c4413c = this.f11719h;
                if (c4413c == null) {
                    Intrinsics.throwNpe();
                }
                C4418h m5084b = c4413c.m5084b();
                if (m5084b == null) {
                    Intrinsics.throwNpe();
                }
                m5084b.f11685k++;
                this.f11719h = null;
            } else {
                z4 = false;
            }
            Unit unit = Unit.INSTANCE;
            return z4 ? (E) m5122g(e2, false) : e2;
        }
    }

    /* renamed from: f */
    public final boolean m5121f() {
        boolean z;
        synchronized (this.f11712a) {
            z = this.f11722k;
        }
        return z;
    }

    /* JADX WARN: Removed duplicated region for block: B:54:0x00ac A[Catch: all -> 0x0013, TRY_ENTER, TryCatch #0 {all -> 0x0013, blocks: (B:57:0x000c, B:7:0x0019, B:9:0x0020, B:12:0x0026, B:14:0x002a, B:15:0x0030, B:17:0x0034, B:18:0x0036, B:20:0x003a, B:23:0x0041, B:54:0x00ac, B:55:0x00b7), top: B:56:0x000c }] */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0019 A[Catch: all -> 0x0013, TryCatch #0 {all -> 0x0013, blocks: (B:57:0x000c, B:7:0x0019, B:9:0x0020, B:12:0x0026, B:14:0x002a, B:15:0x0030, B:17:0x0034, B:18:0x0036, B:20:0x003a, B:23:0x0041, B:54:0x00ac, B:55:0x00b7), top: B:56:0x000c }] */
    /* JADX WARN: Type inference failed for: r4v3, types: [T, k.p0.f.h] */
    /* renamed from: g */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final <E extends java.io.IOException> E m5122g(E r7, boolean r8) {
        /*
            r6 = this;
            kotlin.jvm.internal.Ref$ObjectRef r0 = new kotlin.jvm.internal.Ref$ObjectRef
            r0.<init>()
            k.p0.f.i r1 = r6.f11712a
            monitor-enter(r1)
            r2 = 1
            r3 = 0
            if (r8 == 0) goto L16
            k.p0.f.c r4 = r6.f11719h     // Catch: java.lang.Throwable -> L13
            if (r4 != 0) goto L11
            goto L16
        L11:
            r4 = 0
            goto L17
        L13:
            r7 = move-exception
            goto Lb8
        L16:
            r4 = 1
        L17:
            if (r4 == 0) goto Lac
            k.p0.f.h r4 = r6.f11718g     // Catch: java.lang.Throwable -> L13
            r0.element = r4     // Catch: java.lang.Throwable -> L13
            r5 = 0
            if (r4 == 0) goto L2f
            k.p0.f.c r4 = r6.f11719h     // Catch: java.lang.Throwable -> L13
            if (r4 != 0) goto L2f
            if (r8 != 0) goto L2a
            boolean r8 = r6.f11724m     // Catch: java.lang.Throwable -> L13
            if (r8 == 0) goto L2f
        L2a:
            java.net.Socket r8 = r6.m5124i()     // Catch: java.lang.Throwable -> L13
            goto L30
        L2f:
            r8 = r5
        L30:
            k.p0.f.h r4 = r6.f11718g     // Catch: java.lang.Throwable -> L13
            if (r4 == 0) goto L36
            r0.element = r5     // Catch: java.lang.Throwable -> L13
        L36:
            boolean r4 = r6.f11724m     // Catch: java.lang.Throwable -> L13
            if (r4 == 0) goto L40
            k.p0.f.c r4 = r6.f11719h     // Catch: java.lang.Throwable -> L13
            if (r4 != 0) goto L40
            r4 = 1
            goto L41
        L40:
            r4 = 0
        L41:
            kotlin.Unit r5 = kotlin.Unit.INSTANCE     // Catch: java.lang.Throwable -> L13
            monitor-exit(r1)
            if (r8 == 0) goto L49
            p458k.p459p0.C4401c.m5020e(r8)
        L49:
            T r8 = r0.element
            k.k r8 = (p458k.InterfaceC4388k) r8
            if (r8 == 0) goto L65
            k.v r0 = r6.f11713b
            k.f r1 = r6.f11726o
            if (r8 != 0) goto L58
            kotlin.jvm.internal.Intrinsics.throwNpe()
        L58:
            java.util.Objects.requireNonNull(r0)
            java.lang.String r0 = "call"
            kotlin.jvm.internal.Intrinsics.checkParameterIsNotNull(r1, r0)
            java.lang.String r0 = "connection"
            kotlin.jvm.internal.Intrinsics.checkParameterIsNotNull(r8, r0)
        L65:
            if (r4 == 0) goto Lab
            if (r7 == 0) goto L6a
            goto L6b
        L6a:
            r2 = 0
        L6b:
            boolean r8 = r6.f11723l
            if (r8 == 0) goto L70
            goto L86
        L70:
            k.p0.f.m$b r8 = r6.f11714c
            boolean r8 = r8.m5345i()
            if (r8 != 0) goto L79
            goto L86
        L79:
            java.io.InterruptedIOException r8 = new java.io.InterruptedIOException
            java.lang.String r0 = "timeout"
            r8.<init>(r0)
            if (r7 == 0) goto L85
            r8.initCause(r7)
        L85:
            r7 = r8
        L86:
            if (r2 == 0) goto L9f
            k.v r8 = r6.f11713b
            k.f r0 = r6.f11726o
            if (r7 != 0) goto L91
            kotlin.jvm.internal.Intrinsics.throwNpe()
        L91:
            java.util.Objects.requireNonNull(r8)
            java.lang.String r8 = "call"
            kotlin.jvm.internal.Intrinsics.checkParameterIsNotNull(r0, r8)
            java.lang.String r8 = "ioe"
            kotlin.jvm.internal.Intrinsics.checkParameterIsNotNull(r7, r8)
            goto Lab
        L9f:
            k.v r8 = r6.f11713b
            k.f r0 = r6.f11726o
            java.util.Objects.requireNonNull(r8)
            java.lang.String r8 = "call"
            kotlin.jvm.internal.Intrinsics.checkParameterIsNotNull(r0, r8)
        Lab:
            return r7
        Lac:
            java.lang.String r7 = "cannot release connection while it is in use"
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException     // Catch: java.lang.Throwable -> L13
            java.lang.String r7 = r7.toString()     // Catch: java.lang.Throwable -> L13
            r8.<init>(r7)     // Catch: java.lang.Throwable -> L13
            throw r8     // Catch: java.lang.Throwable -> L13
        Lb8:
            monitor-exit(r1)
            throw r7
        */
        throw new UnsupportedOperationException("Method not decompiled: p458k.p459p0.p462f.C4423m.m5122g(java.io.IOException, boolean):java.io.IOException");
    }

    @Nullable
    /* renamed from: h */
    public final IOException m5123h(@Nullable IOException iOException) {
        synchronized (this.f11712a) {
            this.f11724m = true;
            Unit unit = Unit.INSTANCE;
        }
        return m5122g(iOException, false);
    }

    @Nullable
    /* renamed from: i */
    public final Socket m5124i() {
        byte[] bArr = C4401c.f11556a;
        C4418h c4418h = this.f11718g;
        if (c4418h == null) {
            Intrinsics.throwNpe();
        }
        Iterator<Reference<C4423m>> it = c4418h.f11688n.iterator();
        boolean z = false;
        int i2 = 0;
        while (true) {
            if (!it.hasNext()) {
                i2 = -1;
                break;
            }
            if (Intrinsics.areEqual(it.next().get(), this)) {
                break;
            }
            i2++;
        }
        if (!(i2 != -1)) {
            throw new IllegalStateException("Check failed.".toString());
        }
        C4418h connection = this.f11718g;
        if (connection == null) {
            Intrinsics.throwNpe();
        }
        connection.f11688n.remove(i2);
        this.f11718g = null;
        if (connection.f11688n.isEmpty()) {
            connection.f11689o = System.nanoTime();
            C4419i c4419i = this.f11712a;
            Objects.requireNonNull(c4419i);
            Intrinsics.checkParameterIsNotNull(connection, "connection");
            byte[] bArr2 = C4401c.f11556a;
            if (connection.f11683i || c4419i.f11697f == 0) {
                c4419i.f11695d.remove(connection);
                if (c4419i.f11695d.isEmpty()) {
                    c4419i.f11693b.m5068a();
                }
                z = true;
            } else {
                C4409b.m5067d(c4419i.f11693b, c4419i.f11694c, 0L, 2);
            }
            if (z) {
                return connection.m5106j();
            }
        }
        return null;
    }
}
