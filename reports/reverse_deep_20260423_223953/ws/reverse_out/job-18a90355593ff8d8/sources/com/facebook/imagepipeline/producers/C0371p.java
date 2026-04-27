package com.facebook.imagepipeline.producers;

import I0.C0176a;
import I0.EnumC0189n;
import T0.b;
import a0.InterfaceC0215a;
import android.graphics.Bitmap;
import android.net.Uri;
import b0.AbstractC0311a;
import com.facebook.imagepipeline.producers.C0371p;
import com.facebook.imagepipeline.producers.G;
import f0.C0523a;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executor;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: renamed from: com.facebook.imagepipeline.producers.p, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0371p implements d0 {

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    public static final a f6327m = new a(null);

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final InterfaceC0215a f6328a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final Executor f6329b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final L0.c f6330c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final L0.e f6331d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final EnumC0189n f6332e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final boolean f6333f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private final boolean f6334g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private final d0 f6335h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private final int f6336i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private final C0176a f6337j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private final Runnable f6338k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private final X.n f6339l;

    /* JADX INFO: renamed from: com.facebook.imagepipeline.producers.p$a */
    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public final boolean b(N0.j jVar, H0.d dVar) {
            return (((long) jVar.h()) * ((long) jVar.d())) * ((long) Y0.e.h(dVar.f997h)) > 104857600;
        }

        private a() {
        }
    }

    /* JADX INFO: renamed from: com.facebook.imagepipeline.producers.p$b */
    private final class b extends d {

        /* JADX INFO: renamed from: k, reason: collision with root package name */
        final /* synthetic */ C0371p f6340k;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public b(C0371p c0371p, InterfaceC0369n interfaceC0369n, e0 e0Var, boolean z3, int i3) {
            super(c0371p, interfaceC0369n, e0Var, z3, i3);
            t2.j.f(interfaceC0369n, "consumer");
            t2.j.f(e0Var, "producerContext");
            this.f6340k = c0371p;
        }

        @Override // com.facebook.imagepipeline.producers.C0371p.d
        protected synchronized boolean J(N0.j jVar, int i3) {
            return AbstractC0358c.f(i3) ? false : super.J(jVar, i3);
        }

        @Override // com.facebook.imagepipeline.producers.C0371p.d
        protected int x(N0.j jVar) {
            t2.j.f(jVar, "encodedImage");
            return jVar.d0();
        }

        @Override // com.facebook.imagepipeline.producers.C0371p.d
        protected N0.o z() {
            N0.o oVarD = N0.n.d(0, false, false);
            t2.j.e(oVarD, "of(...)");
            return oVarD;
        }
    }

    /* JADX INFO: renamed from: com.facebook.imagepipeline.producers.p$c */
    private final class c extends d {

        /* JADX INFO: renamed from: k, reason: collision with root package name */
        private final L0.f f6341k;

        /* JADX INFO: renamed from: l, reason: collision with root package name */
        private final L0.e f6342l;

        /* JADX INFO: renamed from: m, reason: collision with root package name */
        final /* synthetic */ C0371p f6343m;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public c(C0371p c0371p, InterfaceC0369n interfaceC0369n, e0 e0Var, L0.f fVar, L0.e eVar, boolean z3, int i3) {
            super(c0371p, interfaceC0369n, e0Var, z3, i3);
            t2.j.f(interfaceC0369n, "consumer");
            t2.j.f(e0Var, "producerContext");
            t2.j.f(fVar, "progressiveJpegParser");
            t2.j.f(eVar, "progressiveJpegConfig");
            this.f6343m = c0371p;
            this.f6341k = fVar;
            this.f6342l = eVar;
            I(0);
        }

        @Override // com.facebook.imagepipeline.producers.C0371p.d
        protected synchronized boolean J(N0.j jVar, int i3) {
            if (jVar == null) {
                return false;
            }
            try {
                boolean zJ = super.J(jVar, i3);
                if (AbstractC0358c.f(i3) || AbstractC0358c.n(i3, 8)) {
                    if (!AbstractC0358c.n(i3, 4) && N0.j.w0(jVar) && jVar.D() == C0.b.f549b) {
                        if (!this.f6341k.g(jVar)) {
                            return false;
                        }
                        int iD = this.f6341k.d();
                        if (iD <= y()) {
                            return false;
                        }
                        if (iD < this.f6342l.a(y()) && !this.f6341k.e()) {
                            return false;
                        }
                        I(iD);
                    }
                }
                return zJ;
            } catch (Throwable th) {
                throw th;
            }
        }

        @Override // com.facebook.imagepipeline.producers.C0371p.d
        protected int x(N0.j jVar) {
            t2.j.f(jVar, "encodedImage");
            return this.f6341k.c();
        }

        @Override // com.facebook.imagepipeline.producers.C0371p.d
        protected N0.o z() {
            N0.o oVarB = this.f6342l.b(this.f6341k.d());
            t2.j.e(oVarB, "getQualityInfo(...)");
            return oVarB;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX INFO: renamed from: com.facebook.imagepipeline.producers.p$d */
    abstract class d extends AbstractC0374t {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final e0 f6344c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private final String f6345d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private final g0 f6346e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        private final H0.d f6347f;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        private boolean f6348g;

        /* JADX INFO: renamed from: h, reason: collision with root package name */
        private final G f6349h;

        /* JADX INFO: renamed from: i, reason: collision with root package name */
        private int f6350i;

        /* JADX INFO: renamed from: j, reason: collision with root package name */
        final /* synthetic */ C0371p f6351j;

        /* JADX INFO: renamed from: com.facebook.imagepipeline.producers.p$d$a */
        public static final class a extends AbstractC0361f {

            /* JADX INFO: renamed from: b, reason: collision with root package name */
            final /* synthetic */ boolean f6353b;

            a(boolean z3) {
                this.f6353b = z3;
            }

            @Override // com.facebook.imagepipeline.producers.f0
            public void a() {
                if (this.f6353b) {
                    d.this.A();
                }
            }

            @Override // com.facebook.imagepipeline.producers.AbstractC0361f, com.facebook.imagepipeline.producers.f0
            public void b() {
                if (d.this.f6344c.d0()) {
                    d.this.f6349h.h();
                }
            }
        }

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public d(final C0371p c0371p, InterfaceC0369n interfaceC0369n, e0 e0Var, boolean z3, final int i3) {
            super(interfaceC0369n);
            t2.j.f(interfaceC0369n, "consumer");
            t2.j.f(e0Var, "producerContext");
            this.f6351j = c0371p;
            this.f6344c = e0Var;
            this.f6345d = "ProgressiveDecoder";
            this.f6346e = e0Var.P();
            H0.d dVarH = e0Var.W().h();
            t2.j.e(dVarH, "getImageDecodeOptions(...)");
            this.f6347f = dVarH;
            this.f6349h = new G(c0371p.f(), new G.d() { // from class: com.facebook.imagepipeline.producers.q
                @Override // com.facebook.imagepipeline.producers.G.d
                public final void a(N0.j jVar, int i4) {
                    C0371p.d.r(this.f6354a, c0371p, i3, jVar, i4);
                }
            }, dVarH.f990a);
            e0Var.Z(new a(z3));
        }

        /* JADX INFO: Access modifiers changed from: private */
        public final void A() {
            E(true);
            p().b();
        }

        private final void B(Throwable th) {
            E(true);
            p().a(th);
        }

        private final void C(N0.d dVar, int i3) {
            AbstractC0311a abstractC0311aB = this.f6351j.c().b(dVar);
            try {
                E(AbstractC0358c.e(i3));
                p().d(abstractC0311aB, i3);
            } finally {
                AbstractC0311a.D(abstractC0311aB);
            }
        }

        private final N0.d D(N0.j jVar, int i3, N0.o oVar) {
            boolean z3 = this.f6351j.h() != null && ((Boolean) this.f6351j.i().get()).booleanValue();
            try {
                return this.f6351j.g().a(jVar, i3, oVar, this.f6347f);
            } catch (OutOfMemoryError e3) {
                if (!z3) {
                    throw e3;
                }
                Runnable runnableH = this.f6351j.h();
                if (runnableH != null) {
                    runnableH.run();
                }
                System.gc();
                return this.f6351j.g().a(jVar, i3, oVar, this.f6347f);
            }
        }

        private final void E(boolean z3) {
            synchronized (this) {
                if (z3) {
                    if (!this.f6348g) {
                        p().c(1.0f);
                        this.f6348g = true;
                        h2.r rVar = h2.r.f9288a;
                        this.f6349h.c();
                    }
                }
            }
        }

        private final void F(N0.j jVar) {
            if (jVar.D() != C0.b.f549b) {
                return;
            }
            jVar.G0(V0.a.c(jVar, Y0.e.h(this.f6347f.f997h), 104857600));
        }

        private final void H(N0.j jVar, N0.d dVar, int i3) {
            this.f6344c.A("encoded_width", Integer.valueOf(jVar.h()));
            this.f6344c.A("encoded_height", Integer.valueOf(jVar.d()));
            this.f6344c.A("encoded_size", Integer.valueOf(jVar.d0()));
            this.f6344c.A("image_color_space", jVar.y());
            if (dVar instanceof N0.c) {
                this.f6344c.A("bitmap_config", String.valueOf(((N0.c) dVar).C().getConfig()));
            }
            if (dVar != null) {
                dVar.r(this.f6344c.b());
            }
            this.f6344c.A("last_scan_num", Integer.valueOf(i3));
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final void r(d dVar, C0371p c0371p, int i3, N0.j jVar, int i4) {
            t2.j.f(dVar, "this$0");
            t2.j.f(c0371p, "this$1");
            if (jVar != null) {
                T0.b bVarW = dVar.f6344c.W();
                dVar.f6344c.A("image_format", jVar.D().a());
                Uri uriV = bVarW.v();
                jVar.H0(uriV != null ? uriV.toString() : null);
                EnumC0189n enumC0189nG = bVarW.g();
                if (enumC0189nG == null) {
                    enumC0189nG = c0371p.e();
                }
                boolean zN = AbstractC0358c.n(i4, 16);
                if ((enumC0189nG == EnumC0189n.f1224b || (enumC0189nG == EnumC0189n.f1225c && !zN)) && (c0371p.d() || !f0.f.n(bVarW.v()))) {
                    H0.h hVarT = bVarW.t();
                    t2.j.e(hVarT, "getRotationOptions(...)");
                    jVar.G0(V0.a.b(hVarT, bVarW.r(), jVar, i3));
                }
                if (dVar.f6344c.f0().G().i()) {
                    dVar.F(jVar);
                }
                dVar.v(jVar, i4, dVar.f6350i);
            }
        }

        private final void v(N0.j jVar, int i3, int i4) {
            String str;
            N0.d dVar;
            N0.d dVarD;
            int i5 = i3;
            if ((jVar.D() == C0.b.f549b || !AbstractC0358c.f(i3)) && !this.f6348g && N0.j.w0(jVar)) {
                if (t2.j.b(jVar.D(), C0.b.f551d) && C0371p.f6327m.b(jVar, this.f6347f)) {
                    IllegalStateException illegalStateException = new IllegalStateException("Image is too big to attempt decoding: w = " + jVar.h() + ", h = " + jVar.d() + ", pixel config = " + this.f6347f.f997h + ", max bitmap size = 104857600");
                    this.f6346e.i(this.f6344c, "DecodeProducer", illegalStateException, null);
                    B(illegalStateException);
                    return;
                }
                C0.c cVarD = jVar.D();
                t2.j.e(cVarD, "getImageFormat(...)");
                String strA = cVarD.a();
                String str2 = strA == null ? "unknown" : strA;
                String str3 = jVar.h() + "x" + jVar.d();
                String strValueOf = String.valueOf(jVar.Z());
                boolean zE = AbstractC0358c.e(i3);
                boolean z3 = zE && !AbstractC0358c.n(i5, 8);
                boolean zN = AbstractC0358c.n(i5, 4);
                H0.g gVarR = this.f6344c.W().r();
                if (gVarR != null) {
                    str = gVarR.f1021a + "x" + gVarR.f1022b;
                } else {
                    str = "unknown";
                }
                try {
                    long jF = this.f6349h.f();
                    String string = this.f6344c.W().v().toString();
                    t2.j.e(string, "toString(...)");
                    int iD0 = (z3 || zN) ? jVar.d0() : x(jVar);
                    N0.o oVarZ = (z3 || zN) ? N0.n.f1902d : z();
                    this.f6346e.g(this.f6344c, "DecodeProducer");
                    try {
                        try {
                            t2.j.c(oVarZ);
                            dVarD = D(jVar, iD0, oVarZ);
                        } catch (Exception e3) {
                            e = e3;
                            dVar = null;
                        }
                        try {
                            if (jVar.Z() != 1) {
                                i5 |= 16;
                            }
                            this.f6346e.d(this.f6344c, "DecodeProducer", w(dVarD, jF, oVarZ, zE, str2, str3, str, strValueOf));
                            H(jVar, dVarD, i4);
                            C(dVarD, i5);
                            N0.j.p(jVar);
                        } catch (Exception e4) {
                            e = e4;
                            dVar = dVarD;
                            t2.j.c(oVarZ);
                            this.f6346e.i(this.f6344c, "DecodeProducer", e, w(dVar, jF, oVarZ, zE, str2, str3, str, strValueOf));
                            B(e);
                            N0.j.p(jVar);
                        }
                    } catch (L0.a e5) {
                        N0.j jVarA = e5.a();
                        Y.a.K(this.f6345d, "%s, {uri: %s, firstEncodedBytes: %s, length: %d}", e5.getMessage(), string, jVarA.A(10), Integer.valueOf(jVarA.d0()));
                        throw e5;
                    }
                } catch (Throwable th) {
                    N0.j.p(jVar);
                    throw th;
                }
            }
        }

        private final Map w(N0.d dVar, long j3, N0.o oVar, boolean z3, String str, String str2, String str3, String str4) {
            Map mapB;
            Object obj;
            String string = null;
            if (!this.f6346e.j(this.f6344c, "DecodeProducer")) {
                return null;
            }
            String strValueOf = String.valueOf(j3);
            String strValueOf2 = String.valueOf(oVar.b());
            String strValueOf3 = String.valueOf(z3);
            if (dVar != null && (mapB = dVar.b()) != null && (obj = mapB.get("non_fatal_decode_error")) != null) {
                string = obj.toString();
            }
            String str5 = string;
            if (!(dVar instanceof N0.e)) {
                HashMap map = new HashMap(7);
                map.put("queueTime", strValueOf);
                map.put("hasGoodQuality", strValueOf2);
                map.put("isFinal", strValueOf3);
                map.put("encodedImageSize", str2);
                map.put("imageFormat", str);
                map.put("requestedImageSize", str3);
                map.put("sampleSize", str4);
                if (str5 != null) {
                    map.put("non_fatal_decode_error", str5);
                }
                return X.g.a(map);
            }
            Bitmap bitmapC = ((N0.e) dVar).C();
            t2.j.e(bitmapC, "getUnderlyingBitmap(...)");
            String str6 = bitmapC.getWidth() + "x" + bitmapC.getHeight();
            HashMap map2 = new HashMap(8);
            map2.put("bitmapSize", str6);
            map2.put("queueTime", strValueOf);
            map2.put("hasGoodQuality", strValueOf2);
            map2.put("isFinal", strValueOf3);
            map2.put("encodedImageSize", str2);
            map2.put("imageFormat", str);
            map2.put("requestedImageSize", str3);
            map2.put("sampleSize", str4);
            int byteCount = bitmapC.getByteCount();
            StringBuilder sb = new StringBuilder();
            sb.append(byteCount);
            map2.put("byteCount", sb.toString());
            if (str5 != null) {
                map2.put("non_fatal_decode_error", str5);
            }
            return X.g.a(map2);
        }

        @Override // com.facebook.imagepipeline.producers.AbstractC0358c
        /* JADX INFO: renamed from: G, reason: merged with bridge method [inline-methods] */
        public void i(N0.j jVar, int i3) {
            if (!U0.b.d()) {
                boolean zE = AbstractC0358c.e(i3);
                if (zE) {
                    if (jVar == null) {
                        boolean zB = t2.j.b(this.f6344c.x("cached_value_found"), Boolean.TRUE);
                        if (!this.f6344c.f0().G().h() || this.f6344c.e0() == b.c.FULL_FETCH || zB) {
                            B(new C0523a("Encoded image is null."));
                            return;
                        }
                    } else if (!jVar.v0()) {
                        B(new C0523a("Encoded image is not valid."));
                        return;
                    }
                }
                if (J(jVar, i3)) {
                    boolean zN = AbstractC0358c.n(i3, 4);
                    if (zE || zN || this.f6344c.d0()) {
                        this.f6349h.h();
                        return;
                    }
                    return;
                }
                return;
            }
            U0.b.a("DecodeProducer#onNewResultImpl");
            try {
                boolean zE2 = AbstractC0358c.e(i3);
                if (zE2) {
                    if (jVar == null) {
                        boolean zB2 = t2.j.b(this.f6344c.x("cached_value_found"), Boolean.TRUE);
                        if (this.f6344c.f0().G().h()) {
                            if (this.f6344c.e0() != b.c.FULL_FETCH) {
                                if (zB2) {
                                }
                            }
                        }
                        B(new C0523a("Encoded image is null."));
                        U0.b.b();
                        return;
                    }
                    if (!jVar.v0()) {
                        B(new C0523a("Encoded image is not valid."));
                        U0.b.b();
                        return;
                    }
                }
                if (!J(jVar, i3)) {
                    U0.b.b();
                    return;
                }
                boolean zN2 = AbstractC0358c.n(i3, 4);
                if (zE2 || zN2 || this.f6344c.d0()) {
                    this.f6349h.h();
                }
                h2.r rVar = h2.r.f9288a;
                U0.b.b();
            } catch (Throwable th) {
                U0.b.b();
                throw th;
            }
        }

        protected final void I(int i3) {
            this.f6350i = i3;
        }

        protected boolean J(N0.j jVar, int i3) {
            return this.f6349h.k(jVar, i3);
        }

        @Override // com.facebook.imagepipeline.producers.AbstractC0374t, com.facebook.imagepipeline.producers.AbstractC0358c
        public void g() {
            A();
        }

        @Override // com.facebook.imagepipeline.producers.AbstractC0374t, com.facebook.imagepipeline.producers.AbstractC0358c
        public void h(Throwable th) {
            t2.j.f(th, "t");
            B(th);
        }

        @Override // com.facebook.imagepipeline.producers.AbstractC0374t, com.facebook.imagepipeline.producers.AbstractC0358c
        protected void j(float f3) {
            super.j(f3 * 0.99f);
        }

        protected abstract int x(N0.j jVar);

        protected final int y() {
            return this.f6350i;
        }

        protected abstract N0.o z();
    }

    public C0371p(InterfaceC0215a interfaceC0215a, Executor executor, L0.c cVar, L0.e eVar, EnumC0189n enumC0189n, boolean z3, boolean z4, d0 d0Var, int i3, C0176a c0176a, Runnable runnable, X.n nVar) {
        t2.j.f(interfaceC0215a, "byteArrayPool");
        t2.j.f(executor, "executor");
        t2.j.f(cVar, "imageDecoder");
        t2.j.f(eVar, "progressiveJpegConfig");
        t2.j.f(enumC0189n, "downsampleMode");
        t2.j.f(d0Var, "inputProducer");
        t2.j.f(c0176a, "closeableReferenceFactory");
        t2.j.f(nVar, "recoverFromDecoderOOM");
        this.f6328a = interfaceC0215a;
        this.f6329b = executor;
        this.f6330c = cVar;
        this.f6331d = eVar;
        this.f6332e = enumC0189n;
        this.f6333f = z3;
        this.f6334g = z4;
        this.f6335h = d0Var;
        this.f6336i = i3;
        this.f6337j = c0176a;
        this.f6338k = runnable;
        this.f6339l = nVar;
    }

    @Override // com.facebook.imagepipeline.producers.d0
    public void a(InterfaceC0369n interfaceC0369n, e0 e0Var) {
        t2.j.f(interfaceC0369n, "consumer");
        t2.j.f(e0Var, "context");
        if (!U0.b.d()) {
            T0.b bVarW = e0Var.W();
            this.f6335h.a((f0.f.n(bVarW.v()) || T0.c.s(bVarW.v())) ? new c(this, interfaceC0369n, e0Var, new L0.f(this.f6328a), this.f6331d, this.f6334g, this.f6336i) : new b(this, interfaceC0369n, e0Var, this.f6334g, this.f6336i), e0Var);
            return;
        }
        U0.b.a("DecodeProducer#produceResults");
        try {
            T0.b bVarW2 = e0Var.W();
            this.f6335h.a((f0.f.n(bVarW2.v()) || T0.c.s(bVarW2.v())) ? new c(this, interfaceC0369n, e0Var, new L0.f(this.f6328a), this.f6331d, this.f6334g, this.f6336i) : new b(this, interfaceC0369n, e0Var, this.f6334g, this.f6336i), e0Var);
            h2.r rVar = h2.r.f9288a;
            U0.b.b();
        } catch (Throwable th) {
            U0.b.b();
            throw th;
        }
    }

    public final C0176a c() {
        return this.f6337j;
    }

    public final boolean d() {
        return this.f6333f;
    }

    public final EnumC0189n e() {
        return this.f6332e;
    }

    public final Executor f() {
        return this.f6329b;
    }

    public final L0.c g() {
        return this.f6330c;
    }

    public final Runnable h() {
        return this.f6338k;
    }

    public final X.n i() {
        return this.f6339l;
    }
}
