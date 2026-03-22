package p458k.p459p0.p462f;

import java.io.IOException;
import java.net.Socket;
import java.net.SocketTimeoutException;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p458k.AbstractC4485v;
import p458k.C4368a;
import p458k.C4395n0;
import p458k.InterfaceC4378f;
import p458k.p459p0.C4401c;
import p458k.p459p0.p462f.C4422l;
import p458k.p459p0.p465i.C4440f;
import p474l.InterfaceC4746h;

/* renamed from: k.p0.f.d */
/* loaded from: classes3.dex */
public final class C4414d {

    /* renamed from: a */
    public C4422l.a f11660a;

    /* renamed from: b */
    public final C4422l f11661b;

    /* renamed from: c */
    public C4418h f11662c;

    /* renamed from: d */
    public boolean f11663d;

    /* renamed from: e */
    public C4395n0 f11664e;

    /* renamed from: f */
    public final C4423m f11665f;

    /* renamed from: g */
    public final C4419i f11666g;

    /* renamed from: h */
    public final C4368a f11667h;

    /* renamed from: i */
    public final InterfaceC4378f f11668i;

    /* renamed from: j */
    public final AbstractC4485v f11669j;

    public C4414d(@NotNull C4423m transmitter, @NotNull C4419i connectionPool, @NotNull C4368a address, @NotNull InterfaceC4378f call, @NotNull AbstractC4485v eventListener) {
        Intrinsics.checkParameterIsNotNull(transmitter, "transmitter");
        Intrinsics.checkParameterIsNotNull(connectionPool, "connectionPool");
        Intrinsics.checkParameterIsNotNull(address, "address");
        Intrinsics.checkParameterIsNotNull(call, "call");
        Intrinsics.checkParameterIsNotNull(eventListener, "eventListener");
        this.f11665f = transmitter;
        this.f11666g = connectionPool;
        this.f11667h = address;
        this.f11668i = call;
        this.f11669j = eventListener;
        this.f11661b = new C4422l(address, connectionPool.f11696e, call, eventListener);
    }

    /* JADX WARN: Code restructure failed: missing block: B:157:0x03a1, code lost:
    
        if (r4.f11691q.m5010a() == false) goto L195;
     */
    /* JADX WARN: Code restructure failed: missing block: B:159:0x03a5, code lost:
    
        if (r4.f11676b == null) goto L193;
     */
    /* JADX WARN: Code restructure failed: missing block: B:161:0x03b4, code lost:
    
        throw new p458k.p459p0.p462f.C4421k(new java.net.ProtocolException("Too many tunnel connections attempted: 21"));
     */
    /* JADX WARN: Code restructure failed: missing block: B:162:0x03b5, code lost:
    
        r1.f11666g.f11696e.m5112a(r4.f11691q);
        r2 = r1.f11666g;
     */
    /* JADX WARN: Code restructure failed: missing block: B:163:0x03c0, code lost:
    
        monitor-enter(r2);
     */
    /* JADX WARN: Code restructure failed: missing block: B:166:0x03c2, code lost:
    
        r1.f11662c = null;
     */
    /* JADX WARN: Code restructure failed: missing block: B:167:0x03cf, code lost:
    
        if (r1.f11666g.m5111c(r1.f11667h, r1.f11665f, r3, true) == false) goto L201;
     */
    /* JADX WARN: Code restructure failed: missing block: B:168:0x03d1, code lost:
    
        r4.f11683i = true;
        r0 = r4.m5106j();
        r4 = r1.f11665f.f11718g;
        r1.f11664e = r17;
     */
    /* JADX WARN: Code restructure failed: missing block: B:169:0x0401, code lost:
    
        r3 = kotlin.Unit.INSTANCE;
     */
    /* JADX WARN: Code restructure failed: missing block: B:170:0x0403, code lost:
    
        monitor-exit(r2);
     */
    /* JADX WARN: Code restructure failed: missing block: B:171:0x0404, code lost:
    
        if (r0 == null) goto L206;
     */
    /* JADX WARN: Code restructure failed: missing block: B:172:0x0406, code lost:
    
        p458k.p459p0.C4401c.m5020e(r0);
     */
    /* JADX WARN: Code restructure failed: missing block: B:173:0x0409, code lost:
    
        r0 = r1.f11669j;
        r2 = r1.f11668i;
     */
    /* JADX WARN: Code restructure failed: missing block: B:174:0x040d, code lost:
    
        if (r4 != null) goto L209;
     */
    /* JADX WARN: Code restructure failed: missing block: B:175:0x040f, code lost:
    
        kotlin.jvm.internal.Intrinsics.throwNpe();
     */
    /* JADX WARN: Code restructure failed: missing block: B:176:0x0412, code lost:
    
        r0.m5269a(r2, r4);
     */
    /* JADX WARN: Code restructure failed: missing block: B:177:0x0415, code lost:
    
        if (r4 != null) goto L212;
     */
    /* JADX WARN: Code restructure failed: missing block: B:178:0x0417, code lost:
    
        kotlin.jvm.internal.Intrinsics.throwNpe();
     */
    /* JADX WARN: Code restructure failed: missing block: B:179:0x041a, code lost:
    
        return r4;
     */
    /* JADX WARN: Code restructure failed: missing block: B:181:0x03e0, code lost:
    
        r0 = r1.f11666g;
        java.util.Objects.requireNonNull(r0);
        kotlin.jvm.internal.Intrinsics.checkParameterIsNotNull(r4, "connection");
        r3 = p458k.p459p0.C4401c.f11556a;
        r0.f11695d.add(r4);
        p458k.p459p0.p461e.C4409b.m5067d(r0.f11693b, r0.f11694c, 0, 2);
        r1.f11665f.m5116a(r4);
        r0 = null;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:105:0x0286  */
    /* JADX WARN: Removed duplicated region for block: B:188:0x0435  */
    /* JADX WARN: Removed duplicated region for block: B:191:0x043c  */
    /* JADX WARN: Removed duplicated region for block: B:194:0x046e  */
    /* JADX WARN: Removed duplicated region for block: B:196:0x0480  */
    /* JADX WARN: Removed duplicated region for block: B:216:0x04b7 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:218:0x0474  */
    /* JADX WARN: Type inference failed for: r5v0, types: [T, k.p0.f.h] */
    /* renamed from: a */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final p458k.p459p0.p462f.C4418h m5092a(int r20, int r21, int r22, int r23, boolean r24) {
        /*
            Method dump skipped, instructions count: 1255
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p458k.p459p0.p462f.C4414d.m5092a(int, int, int, int, boolean):k.p0.f.h");
    }

    /* renamed from: b */
    public final C4418h m5093b(int i2, int i3, int i4, int i5, boolean z, boolean z2) {
        while (true) {
            C4418h m5092a = m5092a(i2, i3, i4, i5, z);
            synchronized (this.f11666g) {
                if (m5092a.f11685k == 0) {
                    return m5092a;
                }
                Unit unit = Unit.INSTANCE;
                Socket socket = m5092a.f11677c;
                if (socket == null) {
                    Intrinsics.throwNpe();
                }
                InterfaceC4746h interfaceC4746h = m5092a.f11681g;
                if (interfaceC4746h == null) {
                    Intrinsics.throwNpe();
                }
                boolean z3 = false;
                if (!socket.isClosed() && !socket.isInputShutdown() && !socket.isOutputShutdown()) {
                    C4440f c4440f = m5092a.f11680f;
                    if (c4440f != null) {
                        long nanoTime = System.nanoTime();
                        synchronized (c4440f) {
                            if (!c4440f.f11833l) {
                                if (c4440f.f11842u >= c4440f.f11841t || nanoTime < c4440f.f11844w) {
                                    z3 = true;
                                }
                            }
                        }
                    } else {
                        if (z2) {
                            try {
                                int soTimeout = socket.getSoTimeout();
                                try {
                                    socket.setSoTimeout(1);
                                    boolean z4 = !interfaceC4746h.mo5387m();
                                    socket.setSoTimeout(soTimeout);
                                    z3 = z4;
                                } catch (Throwable th) {
                                    socket.setSoTimeout(soTimeout);
                                    throw th;
                                }
                            } catch (SocketTimeoutException unused) {
                            } catch (IOException unused2) {
                            }
                        }
                        z3 = true;
                    }
                }
                if (z3) {
                    return m5092a;
                }
                m5092a.m5104h();
            }
        }
    }

    /* renamed from: c */
    public final boolean m5094c() {
        synchronized (this.f11666g) {
            boolean z = true;
            if (this.f11664e != null) {
                return true;
            }
            if (m5095d()) {
                C4418h c4418h = this.f11665f.f11718g;
                if (c4418h == null) {
                    Intrinsics.throwNpe();
                }
                this.f11664e = c4418h.f11691q;
                return true;
            }
            C4422l.a aVar = this.f11660a;
            if (!(aVar != null ? aVar.m5115a() : false) && !this.f11661b.m5113a()) {
                z = false;
            }
            return z;
        }
    }

    /* renamed from: d */
    public final boolean m5095d() {
        C4418h c4418h = this.f11665f.f11718g;
        if (c4418h != null) {
            if (c4418h == null) {
                Intrinsics.throwNpe();
            }
            if (c4418h.f11684j == 0) {
                C4418h c4418h2 = this.f11665f.f11718g;
                if (c4418h2 == null) {
                    Intrinsics.throwNpe();
                }
                if (C4401c.m5016a(c4418h2.f11691q.f11528a.f11296a, this.f11667h.f11296a)) {
                    return true;
                }
            }
        }
        return false;
    }

    /* renamed from: e */
    public final void m5096e() {
        C4419i c4419i = this.f11666g;
        byte[] bArr = C4401c.f11556a;
        synchronized (c4419i) {
            this.f11663d = true;
            Unit unit = Unit.INSTANCE;
        }
    }
}
