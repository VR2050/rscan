package com.facebook.imagepipeline.producers;

import I0.InterfaceC0178c;
import a0.InterfaceC0215a;
import a0.InterfaceC0223i;
import android.net.Uri;
import b0.AbstractC0311a;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Map;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicBoolean;

/* JADX INFO: loaded from: classes.dex */
public class Y implements d0 {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final X.n f6204a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final G0.k f6205b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final InterfaceC0223i f6206c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final InterfaceC0215a f6207d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final d0 f6208e;

    class a implements N.d {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ g0 f6209a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ e0 f6210b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ InterfaceC0369n f6211c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final /* synthetic */ R.d f6212d;

        a(g0 g0Var, e0 e0Var, InterfaceC0369n interfaceC0369n, R.d dVar) {
            this.f6209a = g0Var;
            this.f6210b = e0Var;
            this.f6211c = interfaceC0369n;
            this.f6212d = dVar;
        }

        @Override // N.d
        /* JADX INFO: renamed from: b, reason: merged with bridge method [inline-methods] */
        public Void a(N.f fVar) {
            if (Y.g(fVar)) {
                this.f6209a.f(this.f6210b, "PartialDiskCacheProducer", null);
                this.f6211c.b();
            } else if (fVar.n()) {
                this.f6209a.i(this.f6210b, "PartialDiskCacheProducer", fVar.i(), null);
                Y.this.i(this.f6211c, this.f6210b, this.f6212d, null);
            } else {
                N0.j jVar = (N0.j) fVar.j();
                if (jVar != null) {
                    g0 g0Var = this.f6209a;
                    e0 e0Var = this.f6210b;
                    g0Var.d(e0Var, "PartialDiskCacheProducer", Y.f(g0Var, e0Var, true, jVar.d0()));
                    H0.b bVarG = H0.b.g(jVar.d0() - 1);
                    jVar.B0(bVarG);
                    int iD0 = jVar.d0();
                    T0.b bVarW = this.f6210b.W();
                    if (bVarG.c(bVarW.b())) {
                        this.f6210b.n0("disk", "partial");
                        this.f6209a.e(this.f6210b, "PartialDiskCacheProducer", true);
                        this.f6211c.d(jVar, 9);
                    } else {
                        this.f6211c.d(jVar, 8);
                        Y.this.i(this.f6211c, new l0(T0.c.b(bVarW).z(H0.b.d(iD0 - 1)).a(), this.f6210b), this.f6212d, jVar);
                    }
                } else {
                    g0 g0Var2 = this.f6209a;
                    e0 e0Var2 = this.f6210b;
                    g0Var2.d(e0Var2, "PartialDiskCacheProducer", Y.f(g0Var2, e0Var2, false, 0));
                    Y.this.i(this.f6211c, this.f6210b, this.f6212d, jVar);
                }
            }
            return null;
        }
    }

    class b extends AbstractC0361f {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ AtomicBoolean f6214a;

        b(AtomicBoolean atomicBoolean) {
            this.f6214a = atomicBoolean;
        }

        @Override // com.facebook.imagepipeline.producers.f0
        public void a() {
            this.f6214a.set(true);
        }
    }

    private static class c extends AbstractC0374t {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final X.n f6216c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private final R.d f6217d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private final InterfaceC0223i f6218e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        private final InterfaceC0215a f6219f;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        private final N0.j f6220g;

        /* JADX INFO: renamed from: h, reason: collision with root package name */
        private final boolean f6221h;

        private void q(InputStream inputStream, OutputStream outputStream, int i3) throws IOException {
            byte[] bArr = (byte[]) this.f6219f.get(16384);
            int i4 = i3;
            while (i4 > 0) {
                try {
                    int i5 = inputStream.read(bArr, 0, Math.min(16384, i4));
                    if (i5 < 0) {
                        break;
                    } else if (i5 > 0) {
                        outputStream.write(bArr, 0, i5);
                        i4 -= i5;
                    }
                } finally {
                    this.f6219f.a(bArr);
                }
            }
            if (i4 > 0) {
                throw new IOException(String.format(null, "Failed to read %d bytes - finished %d short", Integer.valueOf(i3), Integer.valueOf(i4)));
            }
        }

        private a0.k r(N0.j jVar, N0.j jVar2) throws IOException {
            int i3 = ((H0.b) X.k.g(jVar2.x())).f987a;
            a0.k kVarE = this.f6218e.e(jVar2.d0() + i3);
            q(jVar.W(), kVarE, i3);
            q(jVar2.W(), kVarE, jVar2.d0());
            return kVarE;
        }

        private void t(a0.k kVar) throws Throwable {
            N0.j jVar;
            Throwable th;
            AbstractC0311a abstractC0311aE0 = AbstractC0311a.e0(kVar.b());
            try {
                jVar = new N0.j(abstractC0311aE0);
                try {
                    jVar.x0();
                    p().d(jVar, 1);
                    N0.j.p(jVar);
                    AbstractC0311a.D(abstractC0311aE0);
                } catch (Throwable th2) {
                    th = th2;
                    N0.j.p(jVar);
                    AbstractC0311a.D(abstractC0311aE0);
                    throw th;
                }
            } catch (Throwable th3) {
                jVar = null;
                th = th3;
            }
        }

        @Override // com.facebook.imagepipeline.producers.AbstractC0358c
        /* JADX INFO: renamed from: s, reason: merged with bridge method [inline-methods] */
        public void i(N0.j jVar, int i3) {
            if (AbstractC0358c.f(i3)) {
                return;
            }
            if (this.f6220g != null && jVar != null && jVar.x() != null) {
                try {
                    try {
                        t(r(this.f6220g, jVar));
                    } catch (IOException e3) {
                        Y.a.n("PartialDiskCacheProducer", "Error while merging image data", e3);
                        p().a(e3);
                    }
                    ((InterfaceC0178c) this.f6216c.get()).a().s(this.f6217d);
                    return;
                } finally {
                    jVar.close();
                    this.f6220g.close();
                }
            }
            if (!this.f6221h || !AbstractC0358c.n(i3, 8) || !AbstractC0358c.e(i3) || jVar == null || jVar.D() == C0.c.f565d) {
                p().d(jVar, i3);
            } else {
                ((InterfaceC0178c) this.f6216c.get()).a().p(this.f6217d, jVar);
                p().d(jVar, i3);
            }
        }

        private c(InterfaceC0369n interfaceC0369n, X.n nVar, R.d dVar, InterfaceC0223i interfaceC0223i, InterfaceC0215a interfaceC0215a, N0.j jVar, boolean z3) {
            super(interfaceC0369n);
            this.f6216c = nVar;
            this.f6217d = dVar;
            this.f6218e = interfaceC0223i;
            this.f6219f = interfaceC0215a;
            this.f6220g = jVar;
            this.f6221h = z3;
        }
    }

    public Y(X.n nVar, G0.k kVar, InterfaceC0223i interfaceC0223i, InterfaceC0215a interfaceC0215a, d0 d0Var) {
        this.f6204a = nVar;
        this.f6205b = kVar;
        this.f6206c = interfaceC0223i;
        this.f6207d = interfaceC0215a;
        this.f6208e = d0Var;
    }

    private static Uri e(T0.b bVar) {
        return bVar.v().buildUpon().appendQueryParameter("fresco_partial", "true").build();
    }

    static Map f(g0 g0Var, e0 e0Var, boolean z3, int i3) {
        if (g0Var.j(e0Var, "PartialDiskCacheProducer")) {
            return z3 ? X.g.of("cached_value_found", String.valueOf(z3), "encodedImageSize", String.valueOf(i3)) : X.g.of("cached_value_found", String.valueOf(z3));
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static boolean g(N.f fVar) {
        return fVar.l() || (fVar.n() && (fVar.i() instanceof CancellationException));
    }

    private N.d h(InterfaceC0369n interfaceC0369n, e0 e0Var, R.d dVar) {
        return new a(e0Var.P(), e0Var, interfaceC0369n, dVar);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void i(InterfaceC0369n interfaceC0369n, e0 e0Var, R.d dVar, N0.j jVar) {
        this.f6208e.a(new c(interfaceC0369n, this.f6204a, dVar, this.f6206c, this.f6207d, jVar, e0Var.W().y(32)), e0Var);
    }

    private void j(AtomicBoolean atomicBoolean, e0 e0Var) {
        e0Var.Z(new b(atomicBoolean));
    }

    @Override // com.facebook.imagepipeline.producers.d0
    public void a(InterfaceC0369n interfaceC0369n, e0 e0Var) {
        T0.b bVarW = e0Var.W();
        boolean zY = e0Var.W().y(16);
        boolean zY2 = e0Var.W().y(32);
        if (!zY && !zY2) {
            this.f6208e.a(interfaceC0369n, e0Var);
            return;
        }
        g0 g0VarP = e0Var.P();
        g0VarP.g(e0Var, "PartialDiskCacheProducer");
        R.d dVarD = this.f6205b.d(bVarW, e(bVarW), e0Var.i());
        if (!zY) {
            g0VarP.d(e0Var, "PartialDiskCacheProducer", f(g0VarP, e0Var, false, 0));
            i(interfaceC0369n, e0Var, dVarD, null);
        } else {
            AtomicBoolean atomicBoolean = new AtomicBoolean(false);
            ((InterfaceC0178c) this.f6204a.get()).a().m(dVarD, atomicBoolean).e(h(interfaceC0369n, e0Var, dVarD));
            j(atomicBoolean, e0Var);
        }
    }
}
