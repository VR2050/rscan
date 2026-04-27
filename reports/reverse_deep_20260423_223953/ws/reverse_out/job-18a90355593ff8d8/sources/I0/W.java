package I0;

import T0.b;
import android.content.ContentResolver;
import android.net.Uri;
import android.os.Build;
import com.facebook.imagepipeline.producers.C0356a;
import com.facebook.imagepipeline.producers.C0362g;
import com.facebook.imagepipeline.producers.C0363h;
import com.facebook.imagepipeline.producers.C0364i;
import com.facebook.imagepipeline.producers.C0366k;
import com.facebook.imagepipeline.producers.C0367l;
import com.facebook.imagepipeline.producers.C0370o;
import com.facebook.imagepipeline.producers.C0371p;
import com.facebook.imagepipeline.producers.C0373s;
import com.facebook.imagepipeline.producers.C0376v;
import com.facebook.imagepipeline.producers.C0377w;
import com.facebook.imagepipeline.producers.C0379y;
import com.facebook.imagepipeline.producers.X;
import com.facebook.imagepipeline.producers.Y;
import com.facebook.imagepipeline.producers.b0;
import com.facebook.imagepipeline.producers.d0;
import com.facebook.imagepipeline.producers.i0;
import com.facebook.imagepipeline.producers.j0;
import com.facebook.imagepipeline.producers.k0;
import com.facebook.imagepipeline.producers.n0;
import com.facebook.imagepipeline.producers.p0;
import com.facebook.imagepipeline.producers.r0;
import com.facebook.imagepipeline.producers.t0;
import com.facebook.imagepipeline.producers.u0;
import h2.AbstractC0558d;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import kotlin.Lazy;
import kotlin.jvm.internal.DefaultConstructorMarker;
import s2.InterfaceC0688a;

/* JADX INFO: loaded from: classes.dex */
public final class W {

    /* JADX INFO: renamed from: K, reason: collision with root package name */
    public static final a f1151K = new a(null);

    /* JADX INFO: renamed from: A, reason: collision with root package name */
    private final Lazy f1152A;

    /* JADX INFO: renamed from: B, reason: collision with root package name */
    private final Lazy f1153B;

    /* JADX INFO: renamed from: C, reason: collision with root package name */
    private final Lazy f1154C;

    /* JADX INFO: renamed from: D, reason: collision with root package name */
    private final Lazy f1155D;

    /* JADX INFO: renamed from: E, reason: collision with root package name */
    private final Lazy f1156E;

    /* JADX INFO: renamed from: F, reason: collision with root package name */
    private final Lazy f1157F;

    /* JADX INFO: renamed from: G, reason: collision with root package name */
    private final Lazy f1158G;

    /* JADX INFO: renamed from: H, reason: collision with root package name */
    private final Lazy f1159H;

    /* JADX INFO: renamed from: I, reason: collision with root package name */
    private final Lazy f1160I;

    /* JADX INFO: renamed from: J, reason: collision with root package name */
    private final Lazy f1161J;

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final ContentResolver f1162a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final C f1163b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final X f1164c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final boolean f1165d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final boolean f1166e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final p0 f1167f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private final EnumC0189n f1168g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private final boolean f1169h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private final boolean f1170i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private final boolean f1171j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private final V0.d f1172k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private final boolean f1173l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private final boolean f1174m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private final boolean f1175n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private final Set f1176o;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private Map f1177p;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private Map f1178q;

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    private Map f1179r;

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    private final Lazy f1180s;

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    private final Lazy f1181t;

    /* JADX INFO: renamed from: u, reason: collision with root package name */
    private final Lazy f1182u;

    /* JADX INFO: renamed from: v, reason: collision with root package name */
    private final Lazy f1183v;

    /* JADX INFO: renamed from: w, reason: collision with root package name */
    private final Lazy f1184w;

    /* JADX INFO: renamed from: x, reason: collision with root package name */
    private final Lazy f1185x;

    /* JADX INFO: renamed from: y, reason: collision with root package name */
    private final Lazy f1186y;

    /* JADX INFO: renamed from: z, reason: collision with root package name */
    private final Lazy f1187z;

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public final String c(Uri uri) {
            String string = uri.toString();
            t2.j.e(string, "toString(...)");
            if (string.length() <= 30) {
                return string;
            }
            String strSubstring = string.substring(0, 30);
            t2.j.e(strSubstring, "substring(...)");
            return strSubstring + "...";
        }

        /* JADX INFO: Access modifiers changed from: private */
        public final void d(T0.b bVar) {
            X.k.b(Boolean.valueOf(bVar.k().b() <= b.c.ENCODED_MEMORY_CACHE.b()));
        }

        private a() {
        }
    }

    public W(ContentResolver contentResolver, C c3, X x3, boolean z3, boolean z4, p0 p0Var, EnumC0189n enumC0189n, boolean z5, boolean z6, boolean z7, V0.d dVar, boolean z8, boolean z9, boolean z10, Set set) {
        t2.j.f(contentResolver, "contentResolver");
        t2.j.f(c3, "producerFactory");
        t2.j.f(x3, "networkFetcher");
        t2.j.f(p0Var, "threadHandoffProducerQueue");
        t2.j.f(enumC0189n, "downsampleMode");
        t2.j.f(dVar, "imageTranscoderFactory");
        this.f1162a = contentResolver;
        this.f1163b = c3;
        this.f1164c = x3;
        this.f1165d = z3;
        this.f1166e = z4;
        this.f1167f = p0Var;
        this.f1168g = enumC0189n;
        this.f1169h = z5;
        this.f1170i = z6;
        this.f1171j = z7;
        this.f1172k = dVar;
        this.f1173l = z8;
        this.f1174m = z9;
        this.f1175n = z10;
        this.f1176o = set;
        this.f1177p = new LinkedHashMap();
        this.f1178q = new LinkedHashMap();
        this.f1179r = new LinkedHashMap();
        this.f1180s = AbstractC0558d.b(new InterfaceC0688a() { // from class: I0.D
            @Override // s2.InterfaceC0688a
            public final Object a() {
                return W.b0(this.f1133b);
            }
        });
        this.f1181t = AbstractC0558d.b(new InterfaceC0688a() { // from class: I0.V
            @Override // s2.InterfaceC0688a
            public final Object a() {
                return W.V(this.f1150b);
            }
        });
        this.f1182u = AbstractC0558d.b(new InterfaceC0688a() { // from class: I0.E
            @Override // s2.InterfaceC0688a
            public final Object a() {
                return W.T(this.f1134b);
            }
        });
        this.f1183v = AbstractC0558d.b(new InterfaceC0688a() { // from class: I0.F
            @Override // s2.InterfaceC0688a
            public final Object a() {
                return W.c0(this.f1135b);
            }
        });
        this.f1184w = AbstractC0558d.b(new InterfaceC0688a() { // from class: I0.G
            @Override // s2.InterfaceC0688a
            public final Object a() {
                return W.u(this.f1136b);
            }
        });
        this.f1185x = AbstractC0558d.b(new InterfaceC0688a() { // from class: I0.H
            @Override // s2.InterfaceC0688a
            public final Object a() {
                return W.d0(this.f1137b);
            }
        });
        this.f1186y = AbstractC0558d.b(new InterfaceC0688a() { // from class: I0.I
            @Override // s2.InterfaceC0688a
            public final Object a() {
                return W.v(this.f1138b);
            }
        });
        this.f1187z = AbstractC0558d.b(new InterfaceC0688a() { // from class: I0.J
            @Override // s2.InterfaceC0688a
            public final Object a() {
                return W.W(this.f1139b);
            }
        });
        this.f1152A = AbstractC0558d.b(new InterfaceC0688a() { // from class: I0.K
            @Override // s2.InterfaceC0688a
            public final Object a() {
                return W.t(this.f1140b);
            }
        });
        this.f1153B = AbstractC0558d.b(new InterfaceC0688a() { // from class: I0.L
            @Override // s2.InterfaceC0688a
            public final Object a() {
                return W.s(this.f1141b);
            }
        });
        this.f1154C = AbstractC0558d.b(new InterfaceC0688a() { // from class: I0.M
            @Override // s2.InterfaceC0688a
            public final Object a() {
                return W.X(this.f1142b);
            }
        });
        this.f1155D = AbstractC0558d.b(new InterfaceC0688a() { // from class: I0.N
            @Override // s2.InterfaceC0688a
            public final Object a() {
                return W.a0(this.f1143b);
            }
        });
        this.f1156E = AbstractC0558d.b(new InterfaceC0688a() { // from class: I0.O
            @Override // s2.InterfaceC0688a
            public final Object a() {
                return W.U(this.f1144b);
            }
        });
        this.f1157F = AbstractC0558d.b(new InterfaceC0688a() { // from class: I0.P
            @Override // s2.InterfaceC0688a
            public final Object a() {
                return W.Z(this.f1145b);
            }
        });
        this.f1158G = AbstractC0558d.b(new InterfaceC0688a() { // from class: I0.Q
            @Override // s2.InterfaceC0688a
            public final Object a() {
                return W.n0(this.f1146b);
            }
        });
        this.f1159H = AbstractC0558d.b(new InterfaceC0688a() { // from class: I0.S
            @Override // s2.InterfaceC0688a
            public final Object a() {
                return W.Y(this.f1147b);
            }
        });
        this.f1160I = AbstractC0558d.b(new InterfaceC0688a() { // from class: I0.T
            @Override // s2.InterfaceC0688a
            public final Object a() {
                return W.S(this.f1148b);
            }
        });
        this.f1161J = AbstractC0558d.b(new InterfaceC0688a() { // from class: I0.U
            @Override // s2.InterfaceC0688a
            public final Object a() {
                return W.w(this.f1149b);
            }
        });
    }

    private final d0 A(T0.b bVar) {
        d0 d0VarO;
        if (!U0.b.d()) {
            Uri uriV = bVar.v();
            t2.j.e(uriV, "getSourceUri(...)");
            if (uriV == null) {
                throw new IllegalStateException("Uri is null.");
            }
            int iW = bVar.w();
            if (iW == 0) {
                return O();
            }
            switch (iW) {
                case 2:
                    return bVar.i() ? M() : N();
                case 3:
                    return bVar.i() ? M() : K();
                case 4:
                    return bVar.i() ? M() : Z.a.c(this.f1162a.getType(uriV)) ? N() : I();
                case 5:
                    return H();
                case 6:
                    return L();
                case 7:
                    return D();
                case 8:
                    return R();
                default:
                    Set set = this.f1176o;
                    if (set != null) {
                        Iterator it = set.iterator();
                        if (it.hasNext()) {
                            androidx.activity.result.d.a(it.next());
                            throw null;
                        }
                    }
                    throw new IllegalArgumentException("Unsupported uri scheme! Uri is: " + f1151K.c(uriV));
            }
        }
        U0.b.a("ProducerSequenceFactory#getBasicDecodedImageSequence");
        try {
            Uri uriV2 = bVar.v();
            t2.j.e(uriV2, "getSourceUri(...)");
            if (uriV2 == null) {
                throw new IllegalStateException("Uri is null.");
            }
            int iW2 = bVar.w();
            if (iW2 != 0) {
                switch (iW2) {
                    case 2:
                        if (bVar.i()) {
                            d0 d0VarM = M();
                            U0.b.b();
                            return d0VarM;
                        }
                        d0VarO = N();
                        break;
                    case 3:
                        if (bVar.i()) {
                            d0 d0VarM2 = M();
                            U0.b.b();
                            return d0VarM2;
                        }
                        d0VarO = K();
                        break;
                    case 4:
                        if (bVar.i()) {
                            d0 d0VarM3 = M();
                            U0.b.b();
                            return d0VarM3;
                        }
                        if (Z.a.c(this.f1162a.getType(uriV2))) {
                            d0 d0VarN = N();
                            U0.b.b();
                            return d0VarN;
                        }
                        d0VarO = I();
                        break;
                    case 5:
                        d0VarO = H();
                        break;
                    case 6:
                        d0VarO = L();
                        break;
                    case 7:
                        d0VarO = D();
                        break;
                    case 8:
                        d0VarO = R();
                        break;
                    default:
                        Set set2 = this.f1176o;
                        if (set2 != null) {
                            Iterator it2 = set2.iterator();
                            if (it2.hasNext()) {
                                androidx.activity.result.d.a(it2.next());
                                throw null;
                            }
                        }
                        throw new IllegalArgumentException("Unsupported uri scheme! Uri is: " + f1151K.c(uriV2));
                }
            } else {
                d0VarO = O();
            }
            U0.b.b();
            return d0VarO;
        } catch (Throwable th) {
            U0.b.b();
            throw th;
        }
    }

    private final synchronized d0 B(d0 d0Var) {
        d0 d0VarF;
        d0VarF = (d0) this.f1179r.get(d0Var);
        if (d0VarF == null) {
            d0VarF = this.f1163b.f(d0Var);
            this.f1179r.put(d0Var, d0VarF);
        }
        return d0VarF;
    }

    private final synchronized d0 F(d0 d0Var) {
        C0373s c0373sK;
        c0373sK = this.f1163b.k(d0Var);
        t2.j.e(c0373sK, "newDelayProducer(...)");
        return c0373sK;
    }

    private final synchronized d0 Q(d0 d0Var) {
        d0 d0VarA;
        d0VarA = (d0) this.f1177p.get(d0Var);
        if (d0VarA == null) {
            b0 b0VarB = this.f1163b.B(d0Var);
            t2.j.e(b0VarB, "newPostprocessorProducer(...)");
            d0VarA = this.f1163b.A(b0VarB);
            this.f1177p.put(d0Var, d0VarA);
        }
        return d0VarA;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final d0 S(W w3) {
        t2.j.f(w3, "this$0");
        com.facebook.imagepipeline.producers.H hQ = w3.f1163b.q();
        t2.j.e(hQ, "newLocalAssetFetchProducer(...)");
        return w3.g0(hQ);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final j0 T(W w3) {
        t2.j.f(w3, "this$0");
        if (!U0.b.d()) {
            return new j0(w3.x());
        }
        U0.b.a("ProducerSequenceFactory#getLocalContentUriFetchEncodedImageProducerSequence:init");
        try {
            return new j0(w3.x());
        } finally {
            U0.b.b();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final d0 U(W w3) {
        t2.j.f(w3, "this$0");
        com.facebook.imagepipeline.producers.I iR = w3.f1163b.r();
        t2.j.e(iR, "newLocalContentUriFetchProducer(...)");
        return w3.h0(iR, new u0[]{w3.f1163b.s(), w3.f1163b.t()});
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final j0 V(W w3) {
        t2.j.f(w3, "this$0");
        if (!U0.b.d()) {
            return new j0(w3.y());
        }
        U0.b.a("ProducerSequenceFactory#getLocalFileFetchEncodedImageProducerSequence:init");
        try {
            return new j0(w3.y());
        } finally {
            U0.b.b();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final n0 W(W w3) {
        t2.j.f(w3, "this$0");
        if (!U0.b.d()) {
            return w3.f1163b.E(w3.y());
        }
        U0.b.a("ProducerSequenceFactory#getLocalFileFetchToEncodedMemoryPrefetchSequence:init");
        try {
            return w3.f1163b.E(w3.y());
        } finally {
            U0.b.b();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final d0 X(W w3) {
        t2.j.f(w3, "this$0");
        com.facebook.imagepipeline.producers.M mU = w3.f1163b.u();
        t2.j.e(mU, "newLocalFileFetchProducer(...)");
        return w3.g0(mU);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final d0 Y(W w3) {
        t2.j.f(w3, "this$0");
        com.facebook.imagepipeline.producers.N nV = w3.f1163b.v();
        t2.j.e(nV, "newLocalResourceFetchProducer(...)");
        return w3.g0(nV);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final d0 Z(W w3) throws Throwable {
        t2.j.f(w3, "this$0");
        if (Build.VERSION.SDK_INT < 29) {
            throw new Throwable("Unreachable exception. Just to make linter happy for the lazy block.");
        }
        com.facebook.imagepipeline.producers.S sW = w3.f1163b.w();
        t2.j.e(sW, "newLocalThumbnailBitmapSdk29Producer(...)");
        return w3.e0(sW);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final d0 a0(W w3) {
        t2.j.f(w3, "this$0");
        com.facebook.imagepipeline.producers.T tX = w3.f1163b.x();
        t2.j.e(tX, "newLocalVideoThumbnailProducer(...)");
        return w3.e0(tX);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final j0 b0(W w3) {
        t2.j.f(w3, "this$0");
        if (!U0.b.d()) {
            return new j0(w3.z());
        }
        U0.b.a("ProducerSequenceFactory#getNetworkFetchEncodedImageProducerSequence:init");
        try {
            return new j0(w3.z());
        } finally {
            U0.b.b();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final d0 c0(W w3) {
        t2.j.f(w3, "this$0");
        if (!U0.b.d()) {
            return w3.f0(w3.C());
        }
        U0.b.a("ProducerSequenceFactory#getNetworkFetchSequence:init");
        try {
            return w3.f0(w3.C());
        } finally {
            U0.b.b();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final n0 d0(W w3) {
        t2.j.f(w3, "this$0");
        if (!U0.b.d()) {
            return w3.f1163b.E(w3.z());
        }
        U0.b.a("ProducerSequenceFactory#getNetworkFetchToEncodedMemoryPrefetchSequence");
        try {
            return w3.f1163b.E(w3.z());
        } finally {
            U0.b.b();
        }
    }

    private final d0 e0(d0 d0Var) {
        C0364i c0364iE = this.f1163b.e(d0Var);
        t2.j.e(c0364iE, "newBitmapMemoryCacheProducer(...)");
        C0363h c0363hD = this.f1163b.d(c0364iE);
        t2.j.e(c0363hD, "newBitmapMemoryCacheKeyMultiplexProducer(...)");
        d0 d0VarB = this.f1163b.b(c0363hD, this.f1167f);
        t2.j.e(d0VarB, "newBackgroundThreadHandoffProducer(...)");
        if (!this.f1173l && !this.f1174m) {
            C0362g c0362gC = this.f1163b.c(d0VarB);
            t2.j.e(c0362gC, "newBitmapMemoryCacheGetProducer(...)");
            return c0362gC;
        }
        C0362g c0362gC2 = this.f1163b.c(d0VarB);
        t2.j.e(c0362gC2, "newBitmapMemoryCacheGetProducer(...)");
        C0366k c0366kG = this.f1163b.g(c0362gC2);
        t2.j.e(c0366kG, "newBitmapProbeProducer(...)");
        return c0366kG;
    }

    private final d0 g0(d0 d0Var) {
        return h0(d0Var, new u0[]{this.f1163b.t()});
    }

    private final d0 h0(d0 d0Var, u0[] u0VarArr) {
        return f0(m0(k0(d0Var), u0VarArr));
    }

    private final d0 j0(d0 d0Var) {
        C0377w c0377wM;
        C0377w c0377wM2;
        if (!U0.b.d()) {
            if (this.f1170i) {
                Y yZ = this.f1163b.z(d0Var);
                t2.j.e(yZ, "newPartialDiskCacheProducer(...)");
                c0377wM2 = this.f1163b.m(yZ);
            } else {
                c0377wM2 = this.f1163b.m(d0Var);
            }
            t2.j.c(c0377wM2);
            C0376v c0376vL = this.f1163b.l(c0377wM2);
            t2.j.e(c0376vL, "newDiskCacheReadProducer(...)");
            return c0376vL;
        }
        U0.b.a("ProducerSequenceFactory#newDiskCacheSequence");
        try {
            if (this.f1170i) {
                Y yZ2 = this.f1163b.z(d0Var);
                t2.j.e(yZ2, "newPartialDiskCacheProducer(...)");
                c0377wM = this.f1163b.m(yZ2);
            } else {
                c0377wM = this.f1163b.m(d0Var);
            }
            t2.j.c(c0377wM);
            C0376v c0376vL2 = this.f1163b.l(c0377wM);
            t2.j.e(c0376vL2, "newDiskCacheReadProducer(...)");
            U0.b.b();
            return c0376vL2;
        } catch (Throwable th) {
            U0.b.b();
            throw th;
        }
    }

    private final d0 k0(d0 d0Var) {
        if (this.f1171j) {
            d0Var = j0(d0Var);
        }
        d0 d0VarO = this.f1163b.o(d0Var);
        t2.j.e(d0VarO, "newEncodedMemoryCacheProducer(...)");
        if (!this.f1174m) {
            C0379y c0379yN = this.f1163b.n(d0VarO);
            t2.j.e(c0379yN, "newEncodedCacheKeyMultiplexProducer(...)");
            return c0379yN;
        }
        com.facebook.imagepipeline.producers.A aP = this.f1163b.p(d0VarO);
        t2.j.e(aP, "newEncodedProbeProducer(...)");
        C0379y c0379yN2 = this.f1163b.n(aP);
        t2.j.e(c0379yN2, "newEncodedCacheKeyMultiplexProducer(...)");
        return c0379yN2;
    }

    private final d0 l0(u0[] u0VarArr) {
        t0 t0VarG = this.f1163b.G(u0VarArr);
        t2.j.e(t0VarG, "newThumbnailBranchProducer(...)");
        k0 k0VarD = this.f1163b.D(t0VarG, true, this.f1172k);
        t2.j.e(k0VarD, "newResizeAndRotateProducer(...)");
        return k0VarD;
    }

    private final d0 m0(d0 d0Var, u0[] u0VarArr) {
        C0356a c0356aA = C.a(d0Var);
        t2.j.e(c0356aA, "newAddImageTransformMetaDataProducer(...)");
        r0 r0VarF = this.f1163b.F(this.f1163b.D(c0356aA, true, this.f1172k));
        t2.j.e(r0VarF, "newThrottlingProducer(...)");
        C0367l c0367lH = C.h(l0(u0VarArr), r0VarF);
        t2.j.e(c0367lH, "newBranchOnSeparateImagesProducer(...)");
        return c0367lH;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final d0 n0(W w3) {
        t2.j.f(w3, "this$0");
        i0 i0VarC = w3.f1163b.C();
        t2.j.e(i0VarC, "newQualifiedResourceFetchProducer(...)");
        return w3.g0(i0VarC);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final d0 s(W w3) {
        t2.j.f(w3, "this$0");
        if (!U0.b.d()) {
            com.facebook.imagepipeline.producers.I iR = w3.f1163b.r();
            t2.j.e(iR, "newLocalContentUriFetchProducer(...)");
            return w3.f1163b.b(w3.k0(iR), w3.f1167f);
        }
        U0.b.a("ProducerSequenceFactory#getBackgroundLocalContentUriFetchToEncodeMemorySequence:init");
        try {
            com.facebook.imagepipeline.producers.I iR2 = w3.f1163b.r();
            t2.j.e(iR2, "newLocalContentUriFetchProducer(...)");
            return w3.f1163b.b(w3.k0(iR2), w3.f1167f);
        } finally {
            U0.b.b();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final d0 t(W w3) {
        t2.j.f(w3, "this$0");
        if (!U0.b.d()) {
            com.facebook.imagepipeline.producers.M mU = w3.f1163b.u();
            t2.j.e(mU, "newLocalFileFetchProducer(...)");
            return w3.f1163b.b(w3.k0(mU), w3.f1167f);
        }
        U0.b.a("ProducerSequenceFactory#getBackgroundLocalFileFetchToEncodeMemorySequence");
        try {
            com.facebook.imagepipeline.producers.M mU2 = w3.f1163b.u();
            t2.j.e(mU2, "newLocalFileFetchProducer(...)");
            return w3.f1163b.b(w3.k0(mU2), w3.f1167f);
        } finally {
            U0.b.b();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final d0 u(W w3) {
        t2.j.f(w3, "this$0");
        if (!U0.b.d()) {
            return w3.f1163b.b(w3.C(), w3.f1167f);
        }
        U0.b.a("ProducerSequenceFactory#getBackgroundNetworkFetchToEncodedMemorySequence:init");
        try {
            return w3.f1163b.b(w3.C(), w3.f1167f);
        } finally {
            U0.b.b();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final d0 v(W w3) {
        t2.j.f(w3, "this$0");
        if (!U0.b.d()) {
            return w3.i0(w3.f1164c);
        }
        U0.b.a("ProducerSequenceFactory#getCommonNetworkFetchToEncodedMemorySequence");
        try {
            return w3.i0(w3.f1164c);
        } finally {
            U0.b.b();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final d0 w(W w3) {
        t2.j.f(w3, "this$0");
        C0370o c0370oI = w3.f1163b.i();
        t2.j.e(c0370oI, "newDataFetchProducer(...)");
        return w3.f0(w3.f1163b.D(C.a(c0370oI), true, w3.f1172k));
    }

    public final d0 C() {
        return (d0) this.f1186y.getValue();
    }

    public final d0 D() {
        return (d0) this.f1161J.getValue();
    }

    public final d0 E(T0.b bVar) {
        t2.j.f(bVar, "imageRequest");
        if (!U0.b.d()) {
            d0 d0VarA = A(bVar);
            if (bVar.l() != null) {
                d0VarA = Q(d0VarA);
            }
            if (this.f1169h) {
                d0VarA = B(d0VarA);
            }
            return (!this.f1175n || bVar.e() <= 0) ? d0VarA : F(d0VarA);
        }
        U0.b.a("ProducerSequenceFactory#getDecodedImageProducerSequence");
        try {
            d0 d0VarA2 = A(bVar);
            if (bVar.l() != null) {
                d0VarA2 = Q(d0VarA2);
            }
            if (this.f1169h) {
                d0VarA2 = B(d0VarA2);
            }
            if (this.f1175n && bVar.e() > 0) {
                d0VarA2 = F(d0VarA2);
            }
            U0.b.b();
            return d0VarA2;
        } catch (Throwable th) {
            U0.b.b();
            throw th;
        }
    }

    public final d0 G(T0.b bVar) {
        t2.j.f(bVar, "imageRequest");
        a aVar = f1151K;
        aVar.d(bVar);
        int iW = bVar.w();
        if (iW == 0) {
            return P();
        }
        if (iW == 2 || iW == 3) {
            return J();
        }
        Uri uriV = bVar.v();
        t2.j.e(uriV, "getSourceUri(...)");
        throw new IllegalArgumentException("Unsupported uri scheme for encoded image fetch! Uri is: " + aVar.c(uriV));
    }

    public final d0 H() {
        return (d0) this.f1160I.getValue();
    }

    public final d0 I() {
        return (d0) this.f1156E.getValue();
    }

    public final d0 J() {
        Object value = this.f1187z.getValue();
        t2.j.e(value, "getValue(...)");
        return (d0) value;
    }

    public final d0 K() {
        return (d0) this.f1154C.getValue();
    }

    public final d0 L() {
        return (d0) this.f1159H.getValue();
    }

    public final d0 M() {
        return (d0) this.f1157F.getValue();
    }

    public final d0 N() {
        return (d0) this.f1155D.getValue();
    }

    public final d0 O() {
        return (d0) this.f1183v.getValue();
    }

    public final d0 P() {
        Object value = this.f1185x.getValue();
        t2.j.e(value, "getValue(...)");
        return (d0) value;
    }

    public final d0 R() {
        return (d0) this.f1158G.getValue();
    }

    public final d0 f0(d0 d0Var) {
        t2.j.f(d0Var, "inputProducer");
        if (!U0.b.d()) {
            C0371p c0371pJ = this.f1163b.j(d0Var);
            t2.j.e(c0371pJ, "newDecodeProducer(...)");
            return e0(c0371pJ);
        }
        U0.b.a("ProducerSequenceFactory#newBitmapCacheGetToDecodeSequence");
        try {
            C0371p c0371pJ2 = this.f1163b.j(d0Var);
            t2.j.e(c0371pJ2, "newDecodeProducer(...)");
            return e0(c0371pJ2);
        } finally {
            U0.b.b();
        }
    }

    public final synchronized d0 i0(X x3) {
        try {
            t2.j.f(x3, "networkFetcher");
            boolean z3 = false;
            if (!U0.b.d()) {
                d0 d0VarY = this.f1163b.y(x3);
                t2.j.e(d0VarY, "newNetworkFetchProducer(...)");
                C0356a c0356aA = C.a(k0(d0VarY));
                t2.j.e(c0356aA, "newAddImageTransformMetaDataProducer(...)");
                C c3 = this.f1163b;
                if (this.f1165d && this.f1168g != EnumC0189n.f1226d) {
                    z3 = true;
                }
                return c3.D(c0356aA, z3, this.f1172k);
            }
            U0.b.a("ProducerSequenceFactory#createCommonNetworkFetchToEncodedMemorySequence");
            try {
                d0 d0VarY2 = this.f1163b.y(x3);
                t2.j.e(d0VarY2, "newNetworkFetchProducer(...)");
                C0356a c0356aA2 = C.a(k0(d0VarY2));
                t2.j.e(c0356aA2, "newAddImageTransformMetaDataProducer(...)");
                C c4 = this.f1163b;
                if (this.f1165d && this.f1168g != EnumC0189n.f1226d) {
                    z3 = true;
                }
                k0 k0VarD = c4.D(c0356aA2, z3, this.f1172k);
                U0.b.b();
                return k0VarD;
            } catch (Throwable th) {
                U0.b.b();
                throw th;
            }
        } catch (Throwable th2) {
            throw th2;
        }
    }

    public final d0 x() {
        Object value = this.f1153B.getValue();
        t2.j.e(value, "getValue(...)");
        return (d0) value;
    }

    public final d0 y() {
        Object value = this.f1152A.getValue();
        t2.j.e(value, "getValue(...)");
        return (d0) value;
    }

    public final d0 z() {
        Object value = this.f1184w.getValue();
        t2.j.e(value, "getValue(...)");
        return (d0) value;
    }
}
