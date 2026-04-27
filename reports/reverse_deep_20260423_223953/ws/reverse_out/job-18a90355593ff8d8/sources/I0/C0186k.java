package I0;

import I0.C0186k;
import a0.InterfaceC0223i;
import h2.AbstractC0558d;
import h2.EnumC0561g;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.Executor;
import kotlin.Lazy;
import s2.InterfaceC0688a;

/* JADX INFO: renamed from: I0.k, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0186k implements X.n {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final InterfaceC0192q f1208a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final Q0.E f1209b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final InterfaceC0191p f1210c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final G0.t f1211d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final int f1212e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final S.d f1213f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private final S.d f1214g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private final Map f1215h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private final Lazy f1216i;

    /* JADX INFO: renamed from: I0.k$a */
    public static final class a implements InterfaceC0178c {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final Lazy f1217a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final Lazy f1218b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final Lazy f1219c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private final Lazy f1220d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private final Lazy f1221e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        private final Lazy f1222f;

        a(final C0186k c0186k) {
            EnumC0561g enumC0561g = EnumC0561g.f9269b;
            this.f1217a = AbstractC0558d.a(enumC0561g, new InterfaceC0688a() { // from class: I0.e
                @Override // s2.InterfaceC0688a
                public final Object a() {
                    return C0186k.a.p(c0186k);
                }
            });
            this.f1218b = AbstractC0558d.a(enumC0561g, new InterfaceC0688a() { // from class: I0.f
                @Override // s2.InterfaceC0688a
                public final Object a() {
                    return C0186k.a.o(this.f1199b, c0186k);
                }
            });
            this.f1219c = AbstractC0558d.a(enumC0561g, new InterfaceC0688a() { // from class: I0.g
                @Override // s2.InterfaceC0688a
                public final Object a() {
                    return C0186k.a.r(c0186k);
                }
            });
            this.f1220d = AbstractC0558d.a(enumC0561g, new InterfaceC0688a() { // from class: I0.h
                @Override // s2.InterfaceC0688a
                public final Object a() {
                    return C0186k.a.q(this.f1202b, c0186k);
                }
            });
            this.f1221e = AbstractC0558d.a(enumC0561g, new InterfaceC0688a() { // from class: I0.i
                @Override // s2.InterfaceC0688a
                public final Object a() {
                    return C0186k.a.k(c0186k, this);
                }
            });
            this.f1222f = AbstractC0558d.a(enumC0561g, new InterfaceC0688a() { // from class: I0.j
                @Override // s2.InterfaceC0688a
                public final Object a() {
                    return C0186k.a.j(this.f1206b, c0186k);
                }
            });
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final X.g j(a aVar, C0186k c0186k) {
            t2.j.f(aVar, "this$0");
            t2.j.f(c0186k, "this$1");
            Map mapL = aVar.l();
            LinkedHashMap linkedHashMap = new LinkedHashMap(i2.D.c(mapL.size()));
            for (Map.Entry entry : mapL.entrySet()) {
                Object key = entry.getKey();
                S.k kVar = (S.k) entry.getValue();
                InterfaceC0223i interfaceC0223iG = c0186k.f1209b.g(c0186k.f1212e);
                t2.j.e(interfaceC0223iG, "getPooledByteBufferFactory(...)");
                a0.l lVarH = c0186k.f1209b.h();
                t2.j.e(lVarH, "getPooledByteStreams(...)");
                Executor executorC = c0186k.f1210c.c();
                t2.j.e(executorC, "forLocalStorageRead(...)");
                Executor executorF = c0186k.f1210c.f();
                t2.j.e(executorF, "forLocalStorageWrite(...)");
                linkedHashMap.put(key, new G0.j(kVar, interfaceC0223iG, lVarH, executorC, executorF, c0186k.f1211d));
            }
            return X.g.a(linkedHashMap);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final Map k(C0186k c0186k, a aVar) {
            t2.j.f(c0186k, "this$0");
            t2.j.f(aVar, "this$1");
            Map map = c0186k.f1215h;
            if (map == null) {
                return i2.D.f();
            }
            LinkedHashMap linkedHashMap = new LinkedHashMap(i2.D.c(map.size()));
            for (Map.Entry entry : map.entrySet()) {
                linkedHashMap.put(entry.getKey(), c0186k.f1208a.a((S.d) entry.getValue()));
            }
            return linkedHashMap;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final G0.j o(a aVar, C0186k c0186k) {
            t2.j.f(aVar, "this$0");
            t2.j.f(c0186k, "this$1");
            S.k kVarM = aVar.m();
            InterfaceC0223i interfaceC0223iG = c0186k.f1209b.g(c0186k.f1212e);
            t2.j.e(interfaceC0223iG, "getPooledByteBufferFactory(...)");
            a0.l lVarH = c0186k.f1209b.h();
            t2.j.e(lVarH, "getPooledByteStreams(...)");
            Executor executorC = c0186k.f1210c.c();
            t2.j.e(executorC, "forLocalStorageRead(...)");
            Executor executorF = c0186k.f1210c.f();
            t2.j.e(executorF, "forLocalStorageWrite(...)");
            return new G0.j(kVarM, interfaceC0223iG, lVarH, executorC, executorF, c0186k.f1211d);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final S.k p(C0186k c0186k) {
            t2.j.f(c0186k, "this$0");
            return c0186k.f1208a.a(c0186k.f1213f);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final G0.j q(a aVar, C0186k c0186k) {
            t2.j.f(aVar, "this$0");
            t2.j.f(c0186k, "this$1");
            S.k kVarN = aVar.n();
            InterfaceC0223i interfaceC0223iG = c0186k.f1209b.g(c0186k.f1212e);
            t2.j.e(interfaceC0223iG, "getPooledByteBufferFactory(...)");
            a0.l lVarH = c0186k.f1209b.h();
            t2.j.e(lVarH, "getPooledByteStreams(...)");
            Executor executorC = c0186k.f1210c.c();
            t2.j.e(executorC, "forLocalStorageRead(...)");
            Executor executorF = c0186k.f1210c.f();
            t2.j.e(executorF, "forLocalStorageWrite(...)");
            return new G0.j(kVarN, interfaceC0223iG, lVarH, executorC, executorF, c0186k.f1211d);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final S.k r(C0186k c0186k) {
            t2.j.f(c0186k, "this$0");
            return c0186k.f1208a.a(c0186k.f1214g);
        }

        @Override // I0.InterfaceC0178c
        public G0.j a() {
            return (G0.j) this.f1218b.getValue();
        }

        @Override // I0.InterfaceC0178c
        public X.g b() {
            Object value = this.f1222f.getValue();
            t2.j.e(value, "getValue(...)");
            return (X.g) value;
        }

        @Override // I0.InterfaceC0178c
        public G0.j c() {
            return (G0.j) this.f1220d.getValue();
        }

        public Map l() {
            return (Map) this.f1221e.getValue();
        }

        public S.k m() {
            return (S.k) this.f1217a.getValue();
        }

        public S.k n() {
            return (S.k) this.f1219c.getValue();
        }
    }

    public C0186k(InterfaceC0192q interfaceC0192q, Q0.E e3, InterfaceC0191p interfaceC0191p, G0.t tVar, int i3, S.d dVar, S.d dVar2, Map map) {
        t2.j.f(interfaceC0192q, "fileCacheFactory");
        t2.j.f(e3, "poolFactory");
        t2.j.f(interfaceC0191p, "executorSupplier");
        t2.j.f(tVar, "imageCacheStatsTracker");
        t2.j.f(dVar, "mainDiskCacheConfig");
        t2.j.f(dVar2, "smallImageDiskCacheConfig");
        this.f1208a = interfaceC0192q;
        this.f1209b = e3;
        this.f1210c = interfaceC0191p;
        this.f1211d = tVar;
        this.f1212e = i3;
        this.f1213f = dVar;
        this.f1214g = dVar2;
        this.f1215h = map;
        this.f1216i = AbstractC0558d.a(EnumC0561g.f9269b, new InterfaceC0688a() { // from class: I0.d
            @Override // s2.InterfaceC0688a
            public final Object a() {
                return C0186k.j(this.f1197b);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final a j(C0186k c0186k) {
        t2.j.f(c0186k, "this$0");
        return new a(c0186k);
    }

    private final InterfaceC0178c l() {
        return (InterfaceC0178c) this.f1216i.getValue();
    }

    @Override // X.n
    /* JADX INFO: renamed from: k, reason: merged with bridge method [inline-methods] */
    public InterfaceC0178c get() {
        return l();
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public C0186k(InterfaceC0192q interfaceC0192q, InterfaceC0196v interfaceC0196v) {
        this(interfaceC0192q, interfaceC0196v.d(), interfaceC0196v.I(), interfaceC0196v.h(), interfaceC0196v.j(), interfaceC0196v.t(), interfaceC0196v.g(), interfaceC0196v.f());
        t2.j.f(interfaceC0192q, "fileCacheFactory");
        t2.j.f(interfaceC0196v, "config");
    }
}
