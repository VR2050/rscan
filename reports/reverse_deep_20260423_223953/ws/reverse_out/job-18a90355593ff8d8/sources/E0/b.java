package E0;

import B2.B;
import B2.C0166d;
import B2.D;
import B2.E;
import B2.InterfaceC0167e;
import B2.InterfaceC0168f;
import B2.z;
import E0.b;
import android.net.Uri;
import android.os.Looper;
import android.os.SystemClock;
import com.facebook.imagepipeline.producers.AbstractC0359d;
import com.facebook.imagepipeline.producers.AbstractC0361f;
import com.facebook.imagepipeline.producers.C;
import com.facebook.imagepipeline.producers.InterfaceC0369n;
import com.facebook.imagepipeline.producers.X;
import com.facebook.imagepipeline.producers.e0;
import h2.n;
import h2.r;
import java.io.IOException;
import java.util.Map;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import kotlin.jvm.internal.DefaultConstructorMarker;
import q2.AbstractC0663a;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public class b extends AbstractC0359d {

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private static final a f617d = new a(null);

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final InterfaceC0167e.a f618a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final Executor f619b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final C0166d f620c;

    private static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    /* JADX INFO: renamed from: E0.b$b, reason: collision with other inner class name */
    public static final class C0013b extends C {

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        public long f621f;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        public long f622g;

        /* JADX INFO: renamed from: h, reason: collision with root package name */
        public long f623h;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public C0013b(InterfaceC0369n interfaceC0369n, e0 e0Var) {
            super(interfaceC0369n, e0Var);
            j.f(interfaceC0369n, "consumer");
            j.f(e0Var, "producerContext");
        }
    }

    public static final class c extends AbstractC0361f {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ InterfaceC0167e f624a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ b f625b;

        c(InterfaceC0167e interfaceC0167e, b bVar) {
            this.f624a = interfaceC0167e;
            this.f625b = bVar;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final void f(InterfaceC0167e interfaceC0167e) {
            interfaceC0167e.cancel();
        }

        @Override // com.facebook.imagepipeline.producers.f0
        public void a() {
            if (!j.b(Looper.myLooper(), Looper.getMainLooper())) {
                this.f624a.cancel();
                return;
            }
            Executor executor = this.f625b.f619b;
            final InterfaceC0167e interfaceC0167e = this.f624a;
            executor.execute(new Runnable() { // from class: E0.c
                @Override // java.lang.Runnable
                public final void run() {
                    b.c.f(interfaceC0167e);
                }
            });
        }
    }

    public static final class d implements InterfaceC0168f {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ C0013b f626a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ b f627b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ X.a f628c;

        d(C0013b c0013b, b bVar, X.a aVar) {
            this.f626a = c0013b;
            this.f627b = bVar;
            this.f628c = aVar;
        }

        @Override // B2.InterfaceC0168f
        public void a(InterfaceC0167e interfaceC0167e, D d3) throws IOException {
            j.f(interfaceC0167e, "call");
            j.f(d3, "response");
            this.f626a.f622g = SystemClock.elapsedRealtime();
            E eR = d3.r();
            if (eR == null) {
                b bVar = this.f627b;
                bVar.m(interfaceC0167e, bVar.n("Response body null: " + d3, d3), this.f628c);
                return;
            }
            b bVar2 = this.f627b;
            X.a aVar = this.f628c;
            C0013b c0013b = this.f626a;
            try {
                try {
                    if (d3.f0()) {
                        H0.b bVarC = H0.b.f985c.c(d3.W("Content-Range"));
                        if (bVarC != null && (bVarC.f987a != 0 || bVarC.f988b != Integer.MAX_VALUE)) {
                            c0013b.j(bVarC);
                            c0013b.i(8);
                        }
                        aVar.c(eR.b(), eR.r() < 0 ? 0 : (int) eR.r());
                    } else {
                        bVar2.m(interfaceC0167e, bVar2.n("Unexpected HTTP code " + d3, d3), aVar);
                    }
                } catch (Exception e3) {
                    bVar2.m(interfaceC0167e, e3, aVar);
                }
                r rVar = r.f9288a;
                AbstractC0663a.a(eR, null);
            } catch (Throwable th) {
                try {
                    throw th;
                } catch (Throwable th2) {
                    AbstractC0663a.a(eR, th);
                    throw th2;
                }
            }
        }

        @Override // B2.InterfaceC0168f
        public void b(InterfaceC0167e interfaceC0167e, IOException iOException) {
            j.f(interfaceC0167e, "call");
            j.f(iOException, "e");
            this.f627b.m(interfaceC0167e, iOException, this.f628c);
        }
    }

    public /* synthetic */ b(InterfaceC0167e.a aVar, Executor executor, boolean z3, int i3, DefaultConstructorMarker defaultConstructorMarker) {
        this(aVar, executor, (i3 & 4) != 0 ? true : z3);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void m(InterfaceC0167e interfaceC0167e, Exception exc, X.a aVar) {
        if (interfaceC0167e.r()) {
            aVar.b();
        } else {
            aVar.a(exc);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final IOException n(String str, D d3) {
        return new IOException(str, E0.d.f630d.a(d3));
    }

    @Override // com.facebook.imagepipeline.producers.X
    /* JADX INFO: renamed from: i, reason: merged with bridge method [inline-methods] */
    public C0013b c(InterfaceC0369n interfaceC0369n, e0 e0Var) {
        j.f(interfaceC0369n, "consumer");
        j.f(e0Var, "context");
        return new C0013b(interfaceC0369n, e0Var);
    }

    @Override // com.facebook.imagepipeline.producers.X
    /* JADX INFO: renamed from: j, reason: merged with bridge method [inline-methods] */
    public void b(C0013b c0013b, X.a aVar) {
        j.f(c0013b, "fetchState");
        j.f(aVar, "callback");
        c0013b.f621f = SystemClock.elapsedRealtime();
        Uri uriG = c0013b.g();
        j.e(uriG, "getUri(...)");
        try {
            B.a aVarD = new B.a().m(uriG.toString()).d();
            C0166d c0166d = this.f620c;
            if (c0166d != null) {
                aVarD.c(c0166d);
            }
            H0.b bVarB = c0013b.b().W().b();
            if (bVarB != null) {
                aVarD.a("Range", bVarB.f());
            }
            B b3 = aVarD.b();
            j.e(b3, "build(...)");
            k(c0013b, aVar, b3);
        } catch (Exception e3) {
            aVar.a(e3);
        }
    }

    protected void k(C0013b c0013b, X.a aVar, B b3) {
        j.f(c0013b, "fetchState");
        j.f(aVar, "callback");
        j.f(b3, "request");
        InterfaceC0167e interfaceC0167eA = this.f618a.a(b3);
        c0013b.b().Z(new c(interfaceC0167eA, this));
        interfaceC0167eA.p(new d(c0013b, this, aVar));
    }

    @Override // com.facebook.imagepipeline.producers.X
    /* JADX INFO: renamed from: l, reason: merged with bridge method [inline-methods] */
    public Map e(C0013b c0013b, int i3) {
        j.f(c0013b, "fetchState");
        return i2.D.h(n.a("queue_time", String.valueOf(c0013b.f622g - c0013b.f621f)), n.a("fetch_time", String.valueOf(c0013b.f623h - c0013b.f622g)), n.a("total_time", String.valueOf(c0013b.f623h - c0013b.f621f)), n.a("image_size", String.valueOf(i3)));
    }

    @Override // com.facebook.imagepipeline.producers.X
    /* JADX INFO: renamed from: o, reason: merged with bridge method [inline-methods] */
    public void a(C0013b c0013b, int i3) {
        j.f(c0013b, "fetchState");
        c0013b.f623h = SystemClock.elapsedRealtime();
    }

    public b(InterfaceC0167e.a aVar, Executor executor, boolean z3) {
        j.f(aVar, "callFactory");
        j.f(executor, "cancellationExecutor");
        this.f618a = aVar;
        this.f619b = executor;
        this.f620c = z3 ? new C0166d.a().e().a() : null;
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public b(z zVar) {
        j.f(zVar, "okHttpClient");
        ExecutorService executorServiceD = zVar.s().d();
        j.e(executorServiceD, "executorService(...)");
        this(zVar, executorServiceD, false, 4, null);
    }
}
