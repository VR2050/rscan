package p458k.p459p0.p462f;

import java.io.IOException;
import java.lang.ref.Reference;
import java.net.Proxy;
import java.security.cert.Certificate;
import java.util.ArrayDeque;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLPeerUnverifiedException;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p458k.C4368a;
import p458k.C4382h;
import p458k.C4384i;
import p458k.C4395n0;
import p458k.C4487x;
import p458k.p459p0.C4401c;
import p458k.p459p0.p461e.AbstractC4408a;
import p458k.p459p0.p461e.C4409b;
import p458k.p459p0.p461e.C4410c;
import p458k.p459p0.p462f.C4423m;
import p458k.p459p0.p467k.C4463g;
import p458k.p459p0.p470m.C4477d;

/* renamed from: k.p0.f.i */
/* loaded from: classes3.dex */
public final class C4419i {

    /* renamed from: a */
    public final long f11692a;

    /* renamed from: b */
    public final C4409b f11693b;

    /* renamed from: c */
    public final a f11694c;

    /* renamed from: d */
    public final ArrayDeque<C4418h> f11695d;

    /* renamed from: e */
    @NotNull
    public final C4420j f11696e;

    /* renamed from: f */
    public final int f11697f;

    /* renamed from: k.p0.f.i$a */
    public static final class a extends AbstractC4408a {
        public a(String str) {
            super(str, true);
        }

        @Override // p458k.p459p0.p461e.AbstractC4408a
        /* renamed from: a */
        public long mo5066a() {
            C4419i c4419i = C4419i.this;
            long nanoTime = System.nanoTime();
            synchronized (c4419i) {
                Iterator<C4418h> it = c4419i.f11695d.iterator();
                C4418h c4418h = null;
                long j2 = Long.MIN_VALUE;
                int i2 = 0;
                int i3 = 0;
                while (it.hasNext()) {
                    C4418h connection = it.next();
                    Intrinsics.checkExpressionValueIsNotNull(connection, "connection");
                    if (c4419i.m5110b(connection, nanoTime) > 0) {
                        i3++;
                    } else {
                        i2++;
                        long j3 = nanoTime - connection.f11689o;
                        if (j3 > j2) {
                            c4418h = connection;
                            j2 = j3;
                        }
                    }
                }
                long j4 = c4419i.f11692a;
                if (j2 < j4 && i2 <= c4419i.f11697f) {
                    if (i2 > 0) {
                        return j4 - j2;
                    }
                    if (i3 > 0) {
                        return j4;
                    }
                    return -1L;
                }
                c4419i.f11695d.remove(c4418h);
                if (c4419i.f11695d.isEmpty()) {
                    c4419i.f11693b.m5068a();
                }
                Unit unit = Unit.INSTANCE;
                if (c4418h == null) {
                    Intrinsics.throwNpe();
                }
                C4401c.m5020e(c4418h.m5106j());
                return 0L;
            }
        }
    }

    public C4419i(@NotNull C4410c taskRunner, int i2, long j2, @NotNull TimeUnit timeUnit) {
        Intrinsics.checkParameterIsNotNull(taskRunner, "taskRunner");
        Intrinsics.checkParameterIsNotNull(timeUnit, "timeUnit");
        this.f11697f = i2;
        this.f11692a = timeUnit.toNanos(j2);
        this.f11693b = taskRunner.m5078f();
        this.f11694c = new a("OkHttp ConnectionPool");
        this.f11695d = new ArrayDeque<>();
        this.f11696e = new C4420j();
        if (!(j2 > 0)) {
            throw new IllegalArgumentException(C1499a.m630p("keepAliveDuration <= 0: ", j2).toString());
        }
    }

    /* renamed from: a */
    public final void m5109a(@NotNull C4395n0 failedRoute, @NotNull IOException failure) {
        Intrinsics.checkParameterIsNotNull(failedRoute, "failedRoute");
        Intrinsics.checkParameterIsNotNull(failure, "failure");
        if (failedRoute.f11529b.type() != Proxy.Type.DIRECT) {
            C4368a c4368a = failedRoute.f11528a;
            c4368a.f11306k.connectFailed(c4368a.f11296a.m5298h(), failedRoute.f11529b.address(), failure);
        }
        C4420j c4420j = this.f11696e;
        synchronized (c4420j) {
            Intrinsics.checkParameterIsNotNull(failedRoute, "failedRoute");
            c4420j.f11699a.add(failedRoute);
        }
    }

    /* renamed from: b */
    public final int m5110b(C4418h c4418h, long j2) {
        List<Reference<C4423m>> list = c4418h.f11688n;
        int i2 = 0;
        while (i2 < list.size()) {
            Reference<C4423m> reference = list.get(i2);
            if (reference.get() != null) {
                i2++;
            } else {
                StringBuilder m586H = C1499a.m586H("A connection to ");
                m586H.append(c4418h.f11691q.f11528a.f11296a);
                m586H.append(" was leaked. ");
                m586H.append("Did you forget to close a response body?");
                String sb = m586H.toString();
                C4463g.a aVar = C4463g.f11988c;
                C4463g.f11986a.mo5240m(sb, ((C4423m.a) reference).f11727a);
                list.remove(i2);
                c4418h.f11683i = true;
                if (list.isEmpty()) {
                    c4418h.f11689o = j2 - this.f11692a;
                    return 0;
                }
            }
        }
        return list.size();
    }

    /* renamed from: c */
    public final boolean m5111c(@NotNull C4368a address, @NotNull C4423m transmitter, @Nullable List<C4395n0> list, boolean z) {
        boolean z2;
        Intrinsics.checkParameterIsNotNull(address, "address");
        Intrinsics.checkParameterIsNotNull(transmitter, "transmitter");
        byte[] bArr = C4401c.f11556a;
        Iterator<C4418h> it = this.f11695d.iterator();
        while (true) {
            boolean z3 = false;
            if (!it.hasNext()) {
                return false;
            }
            C4418h connection = it.next();
            if (!z || connection.m5102f()) {
                Objects.requireNonNull(connection);
                Intrinsics.checkParameterIsNotNull(address, "address");
                if (connection.f11688n.size() < connection.f11687m && !connection.f11683i && connection.f11691q.f11528a.m4940a(address)) {
                    if (!Intrinsics.areEqual(address.f11296a.f12049g, connection.f11691q.f11528a.f11296a.f12049g)) {
                        if (connection.f11680f != null && list != null) {
                            if (!list.isEmpty()) {
                                for (C4395n0 c4395n0 : list) {
                                    if (c4395n0.f11529b.type() == Proxy.Type.DIRECT && connection.f11691q.f11529b.type() == Proxy.Type.DIRECT && Intrinsics.areEqual(connection.f11691q.f11530c, c4395n0.f11530c)) {
                                        z2 = true;
                                        break;
                                    }
                                }
                            }
                            z2 = false;
                            if (z2 && address.f11302g == C4477d.f12010a && connection.m5108l(address.f11296a)) {
                                try {
                                    C4382h c4382h = address.f11303h;
                                    if (c4382h == null) {
                                        Intrinsics.throwNpe();
                                    }
                                    String hostname = address.f11296a.f12049g;
                                    C4487x c4487x = connection.f11678d;
                                    if (c4487x == null) {
                                        Intrinsics.throwNpe();
                                    }
                                    List<Certificate> peerCertificates = c4487x.m5273b();
                                    Objects.requireNonNull(c4382h);
                                    Intrinsics.checkParameterIsNotNull(hostname, "hostname");
                                    Intrinsics.checkParameterIsNotNull(peerCertificates, "peerCertificates");
                                    c4382h.m4980a(hostname, new C4384i(c4382h, peerCertificates, hostname));
                                } catch (SSLPeerUnverifiedException unused) {
                                }
                            }
                        }
                    }
                    z3 = true;
                }
                if (z3) {
                    Intrinsics.checkExpressionValueIsNotNull(connection, "connection");
                    transmitter.m5116a(connection);
                    return true;
                }
            }
        }
    }
}
