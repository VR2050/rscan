package p458k;

import androidx.core.app.NotificationCompat;
import java.io.IOException;
import java.util.Iterator;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;
import kotlin.Unit;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p005b.p131d.p132a.p133a.C1499a;
import p458k.p459p0.p462f.C4423m;
import p458k.p459p0.p467k.C4463g;

/* renamed from: k.f0 */
/* loaded from: classes3.dex */
public final class C4379f0 implements InterfaceC4378f {

    /* renamed from: c */
    public C4423m f11431c;

    /* renamed from: e */
    public boolean f11432e;

    /* renamed from: f */
    @NotNull
    public final C4375d0 f11433f;

    /* renamed from: g */
    @NotNull
    public final C4381g0 f11434g;

    /* renamed from: h */
    public final boolean f11435h;

    /* renamed from: k.f0$a */
    public final class a implements Runnable {

        /* renamed from: c */
        public volatile AtomicInteger f11436c;

        /* renamed from: e */
        public final InterfaceC4380g f11437e;

        /* renamed from: f */
        public final /* synthetic */ C4379f0 f11438f;

        public a(@NotNull C4379f0 c4379f0, InterfaceC4380g responseCallback) {
            Intrinsics.checkParameterIsNotNull(responseCallback, "responseCallback");
            this.f11438f = c4379f0;
            this.f11437e = responseCallback;
            this.f11436c = new AtomicInteger(0);
        }

        @NotNull
        /* renamed from: a */
        public final String m4968a() {
            return this.f11438f.f11434g.f11440b.f12049g;
        }

        @Override // java.lang.Runnable
        public void run() {
            C4379f0 c4379f0;
            StringBuilder m586H = C1499a.m586H("OkHttp ");
            m586H.append(this.f11438f.f11434g.f11440b.m5297g());
            String sb = m586H.toString();
            Thread currentThread = Thread.currentThread();
            Intrinsics.checkExpressionValueIsNotNull(currentThread, "currentThread");
            String name = currentThread.getName();
            currentThread.setName(sb);
            try {
                C4423m c4423m = this.f11438f.f11431c;
                if (c4423m == null) {
                    Intrinsics.throwUninitializedPropertyAccessException("transmitter");
                }
                c4423m.f11714c.m5344h();
                boolean z = false;
                try {
                    try {
                    } catch (Throwable th) {
                        this.f11438f.f11433f.f11367g.m5266b(this);
                        throw th;
                    }
                } catch (IOException e2) {
                    e = e2;
                } catch (Throwable th2) {
                    th = th2;
                }
                try {
                    this.f11437e.mo195a(this.f11438f, this.f11438f.m4966c());
                    c4379f0 = this.f11438f;
                } catch (IOException e3) {
                    e = e3;
                    z = true;
                    if (z) {
                        C4463g.a aVar = C4463g.f11988c;
                        C4463g.f11986a.mo5236k("Callback failure for " + this.f11438f.m4967d(), 4, e);
                    } else {
                        this.f11437e.mo196b(this.f11438f, e);
                    }
                    c4379f0 = this.f11438f;
                    c4379f0.f11433f.f11367g.m5266b(this);
                } catch (Throwable th3) {
                    th = th3;
                    z = true;
                    this.f11438f.cancel();
                    if (!z) {
                        IOException iOException = new IOException("canceled due to " + th);
                        iOException.addSuppressed(th);
                        this.f11437e.mo196b(this.f11438f, iOException);
                    }
                    throw th;
                }
                c4379f0.f11433f.f11367g.m5266b(this);
            } finally {
                currentThread.setName(name);
            }
        }
    }

    public C4379f0(C4375d0 c4375d0, C4381g0 c4381g0, boolean z, DefaultConstructorMarker defaultConstructorMarker) {
        this.f11433f = c4375d0;
        this.f11434g = c4381g0;
        this.f11435h = z;
    }

    @NotNull
    /* renamed from: a */
    public C4389k0 m4965a() {
        synchronized (this) {
            if (!(!this.f11432e)) {
                throw new IllegalStateException("Already Executed".toString());
            }
            this.f11432e = true;
            Unit unit = Unit.INSTANCE;
        }
        C4423m c4423m = this.f11431c;
        if (c4423m == null) {
            Intrinsics.throwUninitializedPropertyAccessException("transmitter");
        }
        c4423m.f11714c.m5344h();
        C4423m c4423m2 = this.f11431c;
        if (c4423m2 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("transmitter");
        }
        c4423m2.m5117b();
        try {
            C4482s c4482s = this.f11433f.f11367g;
            synchronized (c4482s) {
                Intrinsics.checkParameterIsNotNull(this, "call");
                c4482s.f12023d.add(this);
            }
            return m4966c();
        } finally {
            C4482s c4482s2 = this.f11433f.f11367g;
            Objects.requireNonNull(c4482s2);
            Intrinsics.checkParameterIsNotNull(this, NotificationCompat.CATEGORY_CALL);
            c4482s2.m5265a(c4482s2.f12023d, this);
        }
    }

    @Override // p458k.InterfaceC4378f
    /* renamed from: b */
    public boolean mo4962b() {
        C4423m c4423m = this.f11431c;
        if (c4423m == null) {
            Intrinsics.throwUninitializedPropertyAccessException("transmitter");
        }
        return c4423m.m5121f();
    }

    /* JADX WARN: Removed duplicated region for block: B:42:0x00b4  */
    @org.jetbrains.annotations.NotNull
    /* renamed from: c */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final p458k.C4389k0 m4966c() {
        /*
            r12 = this;
            java.util.ArrayList r1 = new java.util.ArrayList
            r1.<init>()
            k.d0 r0 = r12.f11433f
            java.util.List<k.a0> r0 = r0.f11369i
            kotlin.collections.CollectionsKt__MutableCollectionsKt.addAll(r1, r0)
            k.p0.g.i r0 = new k.p0.g.i
            k.d0 r2 = r12.f11433f
            r0.<init>(r2)
            r1.add(r0)
            k.p0.g.a r0 = new k.p0.g.a
            k.d0 r2 = r12.f11433f
            k.r r2 = r2.f11376p
            r0.<init>(r2)
            r1.add(r0)
            k.p0.d.a r0 = new k.p0.d.a
            k.d0 r2 = r12.f11433f
            k.d r2 = r2.f11377q
            r0.<init>(r2)
            r1.add(r0)
            k.p0.f.a r0 = p458k.p459p0.p462f.C4411a.f11638a
            r1.add(r0)
            boolean r0 = r12.f11435h
            if (r0 != 0) goto L3e
            k.d0 r0 = r12.f11433f
            java.util.List<k.a0> r0 = r0.f11370j
            kotlin.collections.CollectionsKt__MutableCollectionsKt.addAll(r1, r0)
        L3e:
            k.p0.g.b r0 = new k.p0.g.b
            boolean r2 = r12.f11435h
            r0.<init>(r2)
            r1.add(r0)
            k.p0.g.g r10 = new k.p0.g.g
            k.p0.f.m r2 = r12.f11431c
            java.lang.String r11 = "transmitter"
            if (r2 != 0) goto L53
            kotlin.jvm.internal.Intrinsics.throwUninitializedPropertyAccessException(r11)
        L53:
            r3 = 0
            r4 = 0
            k.g0 r5 = r12.f11434g
            k.d0 r0 = r12.f11433f
            int r7 = r0.f11364C
            int r8 = r0.f11365D
            int r9 = r0.f11366E
            r0 = r10
            r6 = r12
            r0.<init>(r1, r2, r3, r4, r5, r6, r7, r8, r9)
            r0 = 0
            r1 = 0
            k.g0 r2 = r12.f11434g     // Catch: java.lang.Throwable -> L96 java.io.IOException -> L98
            k.k0 r2 = r10.m5139d(r2)     // Catch: java.lang.Throwable -> L96 java.io.IOException -> L98
            k.p0.f.m r3 = r12.f11431c     // Catch: java.lang.Throwable -> L96 java.io.IOException -> L98
            if (r3 != 0) goto L73
            kotlin.jvm.internal.Intrinsics.throwUninitializedPropertyAccessException(r11)     // Catch: java.lang.Throwable -> L96 java.io.IOException -> L98
        L73:
            boolean r3 = r3.m5121f()     // Catch: java.lang.Throwable -> L96 java.io.IOException -> L98
            if (r3 != 0) goto L84
            k.p0.f.m r0 = r12.f11431c
            if (r0 != 0) goto L80
            kotlin.jvm.internal.Intrinsics.throwUninitializedPropertyAccessException(r11)
        L80:
            r0.m5123h(r1)
            return r2
        L84:
            java.lang.String r3 = "$this$closeQuietly"
            kotlin.jvm.internal.Intrinsics.checkParameterIsNotNull(r2, r3)     // Catch: java.lang.Throwable -> L96 java.io.IOException -> L98
            r2.close()     // Catch: java.lang.Exception -> L8c java.lang.RuntimeException -> L94 java.lang.Throwable -> L96
        L8c:
            java.io.IOException r2 = new java.io.IOException     // Catch: java.lang.Throwable -> L96 java.io.IOException -> L98
            java.lang.String r3 = "Canceled"
            r2.<init>(r3)     // Catch: java.lang.Throwable -> L96 java.io.IOException -> L98
            throw r2     // Catch: java.lang.Throwable -> L96 java.io.IOException -> L98
        L94:
            r2 = move-exception
            throw r2     // Catch: java.lang.Throwable -> L96 java.io.IOException -> L98
        L96:
            r2 = move-exception
            goto Lb2
        L98:
            r0 = move-exception
            k.p0.f.m r2 = r12.f11431c     // Catch: java.lang.Throwable -> Laf
            if (r2 != 0) goto La0
            kotlin.jvm.internal.Intrinsics.throwUninitializedPropertyAccessException(r11)     // Catch: java.lang.Throwable -> Laf
        La0:
            java.io.IOException r0 = r2.m5123h(r0)     // Catch: java.lang.Throwable -> Laf
            if (r0 != 0) goto Lae
            kotlin.TypeCastException r0 = new kotlin.TypeCastException     // Catch: java.lang.Throwable -> Laf
            java.lang.String r2 = "null cannot be cast to non-null type kotlin.Throwable"
            r0.<init>(r2)     // Catch: java.lang.Throwable -> Laf
            throw r0     // Catch: java.lang.Throwable -> Laf
        Lae:
            throw r0     // Catch: java.lang.Throwable -> Laf
        Laf:
            r0 = move-exception
            r2 = r0
            r0 = 1
        Lb2:
            if (r0 != 0) goto Lbe
            k.p0.f.m r0 = r12.f11431c
            if (r0 != 0) goto Lbb
            kotlin.jvm.internal.Intrinsics.throwUninitializedPropertyAccessException(r11)
        Lbb:
            r0.m5123h(r1)
        Lbe:
            throw r2
        */
        throw new UnsupportedOperationException("Method not decompiled: p458k.C4379f0.m4966c():k.k0");
    }

    @Override // p458k.InterfaceC4378f
    public void cancel() {
        C4423m c4423m = this.f11431c;
        if (c4423m == null) {
            Intrinsics.throwUninitializedPropertyAccessException("transmitter");
        }
        c4423m.m5118c();
    }

    public Object clone() {
        C4375d0 client = this.f11433f;
        C4381g0 originalRequest = this.f11434g;
        boolean z = this.f11435h;
        Intrinsics.checkParameterIsNotNull(client, "client");
        Intrinsics.checkParameterIsNotNull(originalRequest, "originalRequest");
        C4379f0 c4379f0 = new C4379f0(client, originalRequest, z, null);
        c4379f0.f11431c = new C4423m(client, c4379f0);
        return c4379f0;
    }

    @NotNull
    /* renamed from: d */
    public final String m4967d() {
        StringBuilder sb = new StringBuilder();
        sb.append(mo4962b() ? "canceled " : "");
        sb.append(this.f11435h ? "web socket" : NotificationCompat.CATEGORY_CALL);
        sb.append(" to ");
        sb.append(this.f11434g.f11440b.m5297g());
        return sb.toString();
    }

    @Override // p458k.InterfaceC4378f
    @NotNull
    /* renamed from: e */
    public C4381g0 mo4963e() {
        return this.f11434g;
    }

    @Override // p458k.InterfaceC4378f
    /* renamed from: k */
    public void mo4964k(@NotNull InterfaceC4380g responseCallback) {
        a other;
        Intrinsics.checkParameterIsNotNull(responseCallback, "responseCallback");
        synchronized (this) {
            if (!(!this.f11432e)) {
                throw new IllegalStateException("Already Executed".toString());
            }
            this.f11432e = true;
            Unit unit = Unit.INSTANCE;
        }
        C4423m c4423m = this.f11431c;
        if (c4423m == null) {
            Intrinsics.throwUninitializedPropertyAccessException("transmitter");
        }
        c4423m.m5117b();
        C4482s c4482s = this.f11433f.f11367g;
        a call = new a(this, responseCallback);
        Objects.requireNonNull(c4482s);
        Intrinsics.checkParameterIsNotNull(call, "call");
        synchronized (c4482s) {
            c4482s.f12021b.add(call);
            if (!call.f11438f.f11435h) {
                String m4968a = call.m4968a();
                Iterator<a> it = c4482s.f12022c.iterator();
                while (true) {
                    if (!it.hasNext()) {
                        Iterator<a> it2 = c4482s.f12021b.iterator();
                        while (true) {
                            if (!it2.hasNext()) {
                                other = null;
                                break;
                            } else {
                                other = it2.next();
                                if (Intrinsics.areEqual(other.m4968a(), m4968a)) {
                                    break;
                                }
                            }
                        }
                    } else {
                        other = it.next();
                        if (Intrinsics.areEqual(other.m4968a(), m4968a)) {
                            break;
                        }
                    }
                }
                if (other != null) {
                    Intrinsics.checkParameterIsNotNull(other, "other");
                    call.f11436c = other.f11436c;
                }
            }
            Unit unit2 = Unit.INSTANCE;
        }
        c4482s.m5267c();
    }
}
