package p458k.p459p0.p465i;

import java.io.Closeable;
import java.io.IOException;
import java.net.Socket;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import kotlin.TypeCastException;
import kotlin.Unit;
import kotlin.jvm.JvmField;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p458k.p459p0.C4401c;
import p458k.p459p0.p461e.AbstractC4408a;
import p458k.p459p0.p461e.C4409b;
import p458k.p459p0.p461e.C4410c;
import p458k.p459p0.p465i.C4448n;
import p458k.p459p0.p467k.C4463g;
import p474l.C4747i;
import p474l.InterfaceC4745g;
import p474l.InterfaceC4746h;

/* renamed from: k.p0.i.f */
/* loaded from: classes3.dex */
public final class C4440f implements Closeable {

    /* renamed from: c */
    @NotNull
    public static final C4454t f11818c;

    /* renamed from: e */
    public static final C4440f f11819e = null;

    /* renamed from: A */
    public long f11820A;

    /* renamed from: B */
    public long f11821B;

    /* renamed from: C */
    public long f11822C;

    /* renamed from: D */
    @NotNull
    public final Socket f11823D;

    /* renamed from: E */
    @NotNull
    public final C4450p f11824E;

    /* renamed from: F */
    @NotNull
    public final d f11825F;

    /* renamed from: G */
    public final Set<Integer> f11826G;

    /* renamed from: f */
    public final boolean f11827f;

    /* renamed from: g */
    @NotNull
    public final c f11828g;

    /* renamed from: h */
    @NotNull
    public final Map<Integer, C4449o> f11829h;

    /* renamed from: i */
    @NotNull
    public final String f11830i;

    /* renamed from: j */
    public int f11831j;

    /* renamed from: k */
    public int f11832k;

    /* renamed from: l */
    public boolean f11833l;

    /* renamed from: m */
    public final C4410c f11834m;

    /* renamed from: n */
    public final C4409b f11835n;

    /* renamed from: o */
    public final C4409b f11836o;

    /* renamed from: p */
    public final C4409b f11837p;

    /* renamed from: q */
    public final InterfaceC4453s f11838q;

    /* renamed from: r */
    public long f11839r;

    /* renamed from: s */
    public long f11840s;

    /* renamed from: t */
    public long f11841t;

    /* renamed from: u */
    public long f11842u;

    /* renamed from: v */
    public long f11843v;

    /* renamed from: w */
    public long f11844w;

    /* renamed from: x */
    @NotNull
    public final C4454t f11845x;

    /* renamed from: y */
    @NotNull
    public C4454t f11846y;

    /* renamed from: z */
    public long f11847z;

    /* renamed from: k.p0.i.f$a */
    public static final class a extends AbstractC4408a {

        /* renamed from: e */
        public final /* synthetic */ C4440f f11848e;

        /* renamed from: f */
        public final /* synthetic */ long f11849f;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public a(String str, String str2, C4440f c4440f, long j2) {
            super(str2, true);
            this.f11848e = c4440f;
            this.f11849f = j2;
        }

        @Override // p458k.p459p0.p461e.AbstractC4408a
        /* renamed from: a */
        public long mo5066a() {
            C4440f c4440f;
            boolean z;
            synchronized (this.f11848e) {
                c4440f = this.f11848e;
                long j2 = c4440f.f11840s;
                long j3 = c4440f.f11839r;
                if (j2 < j3) {
                    z = true;
                } else {
                    c4440f.f11839r = j3 + 1;
                    z = false;
                }
            }
            if (!z) {
                c4440f.m5175t(false, 1, 0);
                return this.f11849f;
            }
            EnumC4436b enumC4436b = EnumC4436b.PROTOCOL_ERROR;
            c4440f.m5168b(enumC4436b, enumC4436b, null);
            return -1L;
        }
    }

    /* renamed from: k.p0.i.f$b */
    public static final class b {

        /* renamed from: a */
        @NotNull
        public Socket f11850a;

        /* renamed from: b */
        @NotNull
        public String f11851b;

        /* renamed from: c */
        @NotNull
        public InterfaceC4746h f11852c;

        /* renamed from: d */
        @NotNull
        public InterfaceC4745g f11853d;

        /* renamed from: e */
        @NotNull
        public c f11854e;

        /* renamed from: f */
        @NotNull
        public InterfaceC4453s f11855f;

        /* renamed from: g */
        public int f11856g;

        /* renamed from: h */
        public boolean f11857h;

        /* renamed from: i */
        @NotNull
        public final C4410c f11858i;

        public b(boolean z, @NotNull C4410c taskRunner) {
            Intrinsics.checkParameterIsNotNull(taskRunner, "taskRunner");
            this.f11857h = z;
            this.f11858i = taskRunner;
            this.f11854e = c.f11859a;
            this.f11855f = InterfaceC4453s.f11954a;
        }
    }

    /* renamed from: k.p0.i.f$c */
    public static abstract class c {

        /* renamed from: a */
        @JvmField
        @NotNull
        public static final c f11859a = new a();

        /* renamed from: k.p0.i.f$c$a */
        public static final class a extends c {
            @Override // p458k.p459p0.p465i.C4440f.c
            /* renamed from: b */
            public void mo5098b(@NotNull C4449o stream) {
                Intrinsics.checkParameterIsNotNull(stream, "stream");
                stream.m5193c(EnumC4436b.REFUSED_STREAM, null);
            }
        }

        /* renamed from: a */
        public void mo5097a(@NotNull C4440f connection, @NotNull C4454t settings) {
            Intrinsics.checkParameterIsNotNull(connection, "connection");
            Intrinsics.checkParameterIsNotNull(settings, "settings");
        }

        /* renamed from: b */
        public abstract void mo5098b(@NotNull C4449o c4449o);
    }

    /* renamed from: k.p0.i.f$d */
    public final class d implements Runnable, C4448n.b {

        /* renamed from: c */
        @NotNull
        public final C4448n f11860c;

        /* renamed from: e */
        public final /* synthetic */ C4440f f11861e;

        /* renamed from: k.p0.i.f$d$a */
        public static final class a extends AbstractC4408a {

            /* renamed from: e */
            public final /* synthetic */ C4449o f11862e;

            /* renamed from: f */
            public final /* synthetic */ d f11863f;

            /* renamed from: g */
            public final /* synthetic */ List f11864g;

            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            public a(String str, boolean z, String str2, boolean z2, C4449o c4449o, d dVar, C4449o c4449o2, int i2, List list, boolean z3) {
                super(str2, z2);
                this.f11862e = c4449o;
                this.f11863f = dVar;
                this.f11864g = list;
            }

            @Override // p458k.p459p0.p461e.AbstractC4408a
            /* renamed from: a */
            public long mo5066a() {
                try {
                    this.f11863f.f11861e.f11828g.mo5098b(this.f11862e);
                    return -1L;
                } catch (IOException e2) {
                    C4463g.a aVar = C4463g.f11988c;
                    C4463g c4463g = C4463g.f11986a;
                    StringBuilder m586H = C1499a.m586H("Http2Connection.Listener failure for ");
                    m586H.append(this.f11863f.f11861e.f11830i);
                    c4463g.mo5236k(m586H.toString(), 4, e2);
                    try {
                        this.f11862e.m5193c(EnumC4436b.PROTOCOL_ERROR, e2);
                        return -1L;
                    } catch (IOException unused) {
                        return -1L;
                    }
                }
            }
        }

        /* renamed from: k.p0.i.f$d$b */
        public static final class b extends AbstractC4408a {

            /* renamed from: e */
            public final /* synthetic */ d f11865e;

            /* renamed from: f */
            public final /* synthetic */ int f11866f;

            /* renamed from: g */
            public final /* synthetic */ int f11867g;

            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            public b(String str, boolean z, String str2, boolean z2, d dVar, int i2, int i3) {
                super(str2, z2);
                this.f11865e = dVar;
                this.f11866f = i2;
                this.f11867g = i3;
            }

            @Override // p458k.p459p0.p461e.AbstractC4408a
            /* renamed from: a */
            public long mo5066a() {
                this.f11865e.f11861e.m5175t(true, this.f11866f, this.f11867g);
                return -1L;
            }
        }

        /* renamed from: k.p0.i.f$d$c */
        public static final class c extends AbstractC4408a {

            /* renamed from: e */
            public final /* synthetic */ d f11868e;

            /* renamed from: f */
            public final /* synthetic */ boolean f11869f;

            /* renamed from: g */
            public final /* synthetic */ C4454t f11870g;

            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            public c(String str, boolean z, String str2, boolean z2, d dVar, boolean z3, C4454t c4454t) {
                super(str2, z2);
                this.f11868e = dVar;
                this.f11869f = z3;
                this.f11870g = c4454t;
            }

            /* JADX WARN: Can't wrap try/catch for region: R(17:7|8|(1:10)(1:60)|11|(2:16|(12:18|19|20|21|22|23|24|25|26|27|28|(5:(1:31)|32|(3:34|f9|42)|47|48)(1:49))(2:57|58))|59|19|20|21|22|23|24|25|26|27|28|(0)(0)) */
            /* JADX WARN: Code restructure failed: missing block: B:51:0x00dd, code lost:
            
                r0 = move-exception;
             */
            /* JADX WARN: Code restructure failed: missing block: B:52:0x00de, code lost:
            
                r2 = r13.f11861e;
                r3 = p458k.p459p0.p465i.EnumC4436b.PROTOCOL_ERROR;
                r2.m5168b(r3, r3, r0);
             */
            /* JADX WARN: Multi-variable type inference failed */
            /* JADX WARN: Removed duplicated region for block: B:30:0x00ee  */
            /* JADX WARN: Removed duplicated region for block: B:49:0x0111 A[ORIG_RETURN, RETURN] */
            /* JADX WARN: Type inference failed for: r10v0, types: [T, java.lang.Object, k.p0.i.t] */
            /* JADX WARN: Type inference failed for: r3v0, types: [T, k.p0.i.t] */
            @Override // p458k.p459p0.p461e.AbstractC4408a
            /* renamed from: a */
            /*
                Code decompiled incorrectly, please refer to instructions dump.
                To view partially-correct add '--show-bad-code' argument
            */
            public long mo5066a() {
                /*
                    Method dump skipped, instructions count: 292
                    To view this dump add '--comments-level debug' option
                */
                throw new UnsupportedOperationException("Method not decompiled: p458k.p459p0.p465i.C4440f.d.c.mo5066a():long");
            }
        }

        public d(@NotNull C4440f c4440f, C4448n reader) {
            Intrinsics.checkParameterIsNotNull(reader, "reader");
            this.f11861e = c4440f;
            this.f11860c = reader;
        }

        @Override // p458k.p459p0.p465i.C4448n.b
        /* renamed from: a */
        public void mo5177a() {
        }

        @Override // p458k.p459p0.p465i.C4448n.b
        /* renamed from: b */
        public void mo5178b(boolean z, @NotNull C4454t settings) {
            Intrinsics.checkParameterIsNotNull(settings, "settings");
            C4409b c4409b = this.f11861e.f11835n;
            String m582D = C1499a.m582D(new StringBuilder(), this.f11861e.f11830i, " applyAndAckSettings");
            c4409b.m5070c(new c(m582D, true, m582D, true, this, z, settings), 0L);
        }

        @Override // p458k.p459p0.p465i.C4448n.b
        /* renamed from: c */
        public void mo5179c(boolean z, int i2, int i3, @NotNull List<C4437c> requestHeaders) {
            Intrinsics.checkParameterIsNotNull(requestHeaders, "headerBlock");
            if (this.f11861e.m5170e(i2)) {
                C4440f c4440f = this.f11861e;
                Objects.requireNonNull(c4440f);
                Intrinsics.checkParameterIsNotNull(requestHeaders, "requestHeaders");
                C4409b c4409b = c4440f.f11836o;
                String str = c4440f.f11830i + '[' + i2 + "] onHeaders";
                c4409b.m5070c(new C4443i(str, true, str, true, c4440f, i2, requestHeaders, z), 0L);
                return;
            }
            synchronized (this.f11861e) {
                C4449o m5169d = this.f11861e.m5169d(i2);
                if (m5169d != null) {
                    Unit unit = Unit.INSTANCE;
                    m5169d.m5200j(C4401c.m5036u(requestHeaders), z);
                    return;
                }
                C4440f c4440f2 = this.f11861e;
                if (c4440f2.f11833l) {
                    return;
                }
                if (i2 <= c4440f2.f11831j) {
                    return;
                }
                if (i2 % 2 == c4440f2.f11832k % 2) {
                    return;
                }
                C4449o c4449o = new C4449o(i2, this.f11861e, false, z, C4401c.m5036u(requestHeaders));
                C4440f c4440f3 = this.f11861e;
                c4440f3.f11831j = i2;
                c4440f3.f11829h.put(Integer.valueOf(i2), c4449o);
                C4409b m5078f = this.f11861e.f11834m.m5078f();
                String str2 = this.f11861e.f11830i + '[' + i2 + "] onStream";
                m5078f.m5070c(new a(str2, true, str2, true, c4449o, this, m5169d, i2, requestHeaders, z), 0L);
            }
        }

        @Override // p458k.p459p0.p465i.C4448n.b
        /* renamed from: d */
        public void mo5180d(int i2, long j2) {
            if (i2 == 0) {
                synchronized (this.f11861e) {
                    C4440f c4440f = this.f11861e;
                    c4440f.f11822C += j2;
                    c4440f.notifyAll();
                    Unit unit = Unit.INSTANCE;
                }
                return;
            }
            C4449o m5169d = this.f11861e.m5169d(i2);
            if (m5169d != null) {
                synchronized (m5169d) {
                    m5169d.f11918d += j2;
                    if (j2 > 0) {
                        m5169d.notifyAll();
                    }
                    Unit unit2 = Unit.INSTANCE;
                }
            }
        }

        /* JADX WARN: Code restructure failed: missing block: B:49:0x00f3, code lost:
        
            throw new kotlin.TypeCastException("null cannot be cast to non-null type java.lang.Object");
         */
        @Override // p458k.p459p0.p465i.C4448n.b
        /* renamed from: e */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public void mo5181e(boolean r18, int r19, @org.jetbrains.annotations.NotNull p474l.InterfaceC4746h r20, int r21) {
            /*
                Method dump skipped, instructions count: 274
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: p458k.p459p0.p465i.C4440f.d.mo5181e(boolean, int, l.h, int):void");
        }

        @Override // p458k.p459p0.p465i.C4448n.b
        /* renamed from: f */
        public void mo5182f(boolean z, int i2, int i3) {
            if (!z) {
                C4409b c4409b = this.f11861e.f11835n;
                String m582D = C1499a.m582D(new StringBuilder(), this.f11861e.f11830i, " ping");
                c4409b.m5070c(new b(m582D, true, m582D, true, this, i2, i3), 0L);
                return;
            }
            synchronized (this.f11861e) {
                if (i2 == 1) {
                    this.f11861e.f11840s++;
                } else if (i2 != 2) {
                    if (i2 == 3) {
                        C4440f c4440f = this.f11861e;
                        c4440f.f11843v++;
                        c4440f.notifyAll();
                    }
                    Unit unit = Unit.INSTANCE;
                } else {
                    this.f11861e.f11842u++;
                }
            }
        }

        @Override // p458k.p459p0.p465i.C4448n.b
        /* renamed from: g */
        public void mo5183g(int i2, int i3, int i4, boolean z) {
        }

        @Override // p458k.p459p0.p465i.C4448n.b
        /* renamed from: h */
        public void mo5184h(int i2, @NotNull EnumC4436b errorCode) {
            Intrinsics.checkParameterIsNotNull(errorCode, "errorCode");
            if (!this.f11861e.m5170e(i2)) {
                C4449o m5171k = this.f11861e.m5171k(i2);
                if (m5171k != null) {
                    m5171k.m5201k(errorCode);
                    return;
                }
                return;
            }
            C4440f c4440f = this.f11861e;
            Objects.requireNonNull(c4440f);
            Intrinsics.checkParameterIsNotNull(errorCode, "errorCode");
            C4409b c4409b = c4440f.f11836o;
            String str = c4440f.f11830i + '[' + i2 + "] onReset";
            c4409b.m5070c(new C4445k(str, true, str, true, c4440f, i2, errorCode), 0L);
        }

        @Override // p458k.p459p0.p465i.C4448n.b
        /* renamed from: i */
        public void mo5185i(int i2, int i3, @NotNull List<C4437c> requestHeaders) {
            Intrinsics.checkParameterIsNotNull(requestHeaders, "requestHeaders");
            C4440f c4440f = this.f11861e;
            Objects.requireNonNull(c4440f);
            Intrinsics.checkParameterIsNotNull(requestHeaders, "requestHeaders");
            synchronized (c4440f) {
                if (c4440f.f11826G.contains(Integer.valueOf(i3))) {
                    c4440f.m5176v(i3, EnumC4436b.PROTOCOL_ERROR);
                    return;
                }
                c4440f.f11826G.add(Integer.valueOf(i3));
                C4409b c4409b = c4440f.f11836o;
                String str = c4440f.f11830i + '[' + i3 + "] onRequest";
                c4409b.m5070c(new C4444j(str, true, str, true, c4440f, i3, requestHeaders), 0L);
            }
        }

        @Override // p458k.p459p0.p465i.C4448n.b
        /* renamed from: j */
        public void mo5186j(int i2, @NotNull EnumC4436b errorCode, @NotNull C4747i debugData) {
            int i3;
            C4449o[] c4449oArr;
            Intrinsics.checkParameterIsNotNull(errorCode, "errorCode");
            Intrinsics.checkParameterIsNotNull(debugData, "debugData");
            debugData.mo5400c();
            synchronized (this.f11861e) {
                Object[] array = this.f11861e.f11829h.values().toArray(new C4449o[0]);
                if (array == null) {
                    throw new TypeCastException("null cannot be cast to non-null type kotlin.Array<T>");
                }
                c4449oArr = (C4449o[]) array;
                this.f11861e.f11833l = true;
                Unit unit = Unit.INSTANCE;
            }
            for (C4449o c4449o : c4449oArr) {
                if (c4449o.f11927m > i2 && c4449o.m5198h()) {
                    c4449o.m5201k(EnumC4436b.REFUSED_STREAM);
                    this.f11861e.m5171k(c4449o.f11927m);
                }
            }
        }

        /* JADX WARN: Multi-variable type inference failed */
        /* JADX WARN: Type inference failed for: r0v0, types: [k.p0.i.b] */
        /* JADX WARN: Type inference failed for: r0v3 */
        /* JADX WARN: Type inference failed for: r0v5, types: [java.io.Closeable, k.p0.i.n] */
        @Override // java.lang.Runnable
        public void run() {
            EnumC4436b enumC4436b;
            EnumC4436b enumC4436b2 = EnumC4436b.INTERNAL_ERROR;
            IOException e2 = null;
            try {
                try {
                    this.f11860c.m5188d(this);
                    while (this.f11860c.m5187b(false, this)) {
                    }
                    EnumC4436b enumC4436b3 = EnumC4436b.NO_ERROR;
                    try {
                        this.f11861e.m5168b(enumC4436b3, EnumC4436b.CANCEL, null);
                        enumC4436b = enumC4436b3;
                    } catch (IOException e3) {
                        e2 = e3;
                        EnumC4436b enumC4436b4 = EnumC4436b.PROTOCOL_ERROR;
                        C4440f c4440f = this.f11861e;
                        c4440f.m5168b(enumC4436b4, enumC4436b4, e2);
                        enumC4436b = c4440f;
                        enumC4436b2 = this.f11860c;
                        C4401c.m5019d(enumC4436b2);
                    }
                } catch (Throwable th) {
                    th = th;
                    this.f11861e.m5168b(enumC4436b, enumC4436b2, e2);
                    C4401c.m5019d(this.f11860c);
                    throw th;
                }
            } catch (IOException e4) {
                e2 = e4;
            } catch (Throwable th2) {
                th = th2;
                enumC4436b = enumC4436b2;
                this.f11861e.m5168b(enumC4436b, enumC4436b2, e2);
                C4401c.m5019d(this.f11860c);
                throw th;
            }
            enumC4436b2 = this.f11860c;
            C4401c.m5019d(enumC4436b2);
        }
    }

    /* renamed from: k.p0.i.f$e */
    public static final class e extends AbstractC4408a {

        /* renamed from: e */
        public final /* synthetic */ C4440f f11871e;

        /* renamed from: f */
        public final /* synthetic */ int f11872f;

        /* renamed from: g */
        public final /* synthetic */ EnumC4436b f11873g;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public e(String str, boolean z, String str2, boolean z2, C4440f c4440f, int i2, EnumC4436b enumC4436b) {
            super(str2, z2);
            this.f11871e = c4440f;
            this.f11872f = i2;
            this.f11873g = enumC4436b;
        }

        @Override // p458k.p459p0.p461e.AbstractC4408a
        /* renamed from: a */
        public long mo5066a() {
            try {
                C4440f c4440f = this.f11871e;
                int i2 = this.f11872f;
                EnumC4436b statusCode = this.f11873g;
                Objects.requireNonNull(c4440f);
                Intrinsics.checkParameterIsNotNull(statusCode, "statusCode");
                c4440f.f11824E.m5213s(i2, statusCode);
                return -1L;
            } catch (IOException e2) {
                C4440f c4440f2 = this.f11871e;
                EnumC4436b enumC4436b = EnumC4436b.PROTOCOL_ERROR;
                c4440f2.m5168b(enumC4436b, enumC4436b, e2);
                return -1L;
            }
        }
    }

    /* renamed from: k.p0.i.f$f */
    public static final class f extends AbstractC4408a {

        /* renamed from: e */
        public final /* synthetic */ C4440f f11874e;

        /* renamed from: f */
        public final /* synthetic */ int f11875f;

        /* renamed from: g */
        public final /* synthetic */ long f11876g;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public f(String str, boolean z, String str2, boolean z2, C4440f c4440f, int i2, long j2) {
            super(str2, z2);
            this.f11874e = c4440f;
            this.f11875f = i2;
            this.f11876g = j2;
        }

        @Override // p458k.p459p0.p461e.AbstractC4408a
        /* renamed from: a */
        public long mo5066a() {
            try {
                this.f11874e.f11824E.m5214t(this.f11875f, this.f11876g);
                return -1L;
            } catch (IOException e2) {
                C4440f c4440f = this.f11874e;
                EnumC4436b enumC4436b = EnumC4436b.PROTOCOL_ERROR;
                c4440f.m5168b(enumC4436b, enumC4436b, e2);
                return -1L;
            }
        }
    }

    static {
        C4454t c4454t = new C4454t();
        c4454t.m5223c(7, 65535);
        c4454t.m5223c(5, 16384);
        f11818c = c4454t;
    }

    public C4440f(@NotNull b builder) {
        Intrinsics.checkParameterIsNotNull(builder, "builder");
        boolean z = builder.f11857h;
        this.f11827f = z;
        this.f11828g = builder.f11854e;
        this.f11829h = new LinkedHashMap();
        String str = builder.f11851b;
        if (str == null) {
            Intrinsics.throwUninitializedPropertyAccessException("connectionName");
        }
        this.f11830i = str;
        this.f11832k = builder.f11857h ? 3 : 2;
        C4410c c4410c = builder.f11858i;
        this.f11834m = c4410c;
        C4409b m5078f = c4410c.m5078f();
        this.f11835n = m5078f;
        this.f11836o = c4410c.m5078f();
        this.f11837p = c4410c.m5078f();
        this.f11838q = builder.f11855f;
        C4454t c4454t = new C4454t();
        if (builder.f11857h) {
            c4454t.m5223c(7, 16777216);
        }
        this.f11845x = c4454t;
        this.f11846y = f11818c;
        this.f11822C = r2.m5221a();
        Socket socket = builder.f11850a;
        if (socket == null) {
            Intrinsics.throwUninitializedPropertyAccessException("socket");
        }
        this.f11823D = socket;
        InterfaceC4745g interfaceC4745g = builder.f11853d;
        if (interfaceC4745g == null) {
            Intrinsics.throwUninitializedPropertyAccessException("sink");
        }
        this.f11824E = new C4450p(interfaceC4745g, z);
        InterfaceC4746h interfaceC4746h = builder.f11852c;
        if (interfaceC4746h == null) {
            Intrinsics.throwUninitializedPropertyAccessException("source");
        }
        this.f11825F = new d(this, new C4448n(interfaceC4746h, z));
        this.f11826G = new LinkedHashSet();
        int i2 = builder.f11856g;
        if (i2 != 0) {
            long nanos = TimeUnit.MILLISECONDS.toNanos(i2);
            String m637w = C1499a.m637w(str, " ping");
            m5078f.m5070c(new a(m637w, m637w, this, nanos), nanos);
        }
    }

    /* renamed from: C */
    public final void m5167C(int i2, long j2) {
        C4409b c4409b = this.f11835n;
        String str = this.f11830i + '[' + i2 + "] windowUpdate";
        c4409b.m5070c(new f(str, true, str, true, this, i2, j2), 0L);
    }

    /* renamed from: b */
    public final void m5168b(@NotNull EnumC4436b connectionCode, @NotNull EnumC4436b streamCode, @Nullable IOException iOException) {
        int i2;
        Intrinsics.checkParameterIsNotNull(connectionCode, "connectionCode");
        Intrinsics.checkParameterIsNotNull(streamCode, "streamCode");
        byte[] bArr = C4401c.f11556a;
        try {
            m5172o(connectionCode);
        } catch (IOException unused) {
        }
        C4449o[] c4449oArr = null;
        synchronized (this) {
            if (!this.f11829h.isEmpty()) {
                Object[] array = this.f11829h.values().toArray(new C4449o[0]);
                if (array == null) {
                    throw new TypeCastException("null cannot be cast to non-null type kotlin.Array<T>");
                }
                c4449oArr = (C4449o[]) array;
                this.f11829h.clear();
            }
            Unit unit = Unit.INSTANCE;
        }
        if (c4449oArr != null) {
            for (C4449o c4449o : c4449oArr) {
                try {
                    c4449o.m5193c(streamCode, iOException);
                } catch (IOException unused2) {
                }
            }
        }
        try {
            this.f11824E.close();
        } catch (IOException unused3) {
        }
        try {
            this.f11823D.close();
        } catch (IOException unused4) {
        }
        this.f11835n.m5072f();
        this.f11836o.m5072f();
        this.f11837p.m5072f();
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        m5168b(EnumC4436b.NO_ERROR, EnumC4436b.CANCEL, null);
    }

    @Nullable
    /* renamed from: d */
    public final synchronized C4449o m5169d(int i2) {
        return this.f11829h.get(Integer.valueOf(i2));
    }

    /* renamed from: e */
    public final boolean m5170e(int i2) {
        return i2 != 0 && (i2 & 1) == 0;
    }

    @Nullable
    /* renamed from: k */
    public final synchronized C4449o m5171k(int i2) {
        C4449o remove;
        remove = this.f11829h.remove(Integer.valueOf(i2));
        notifyAll();
        return remove;
    }

    /* renamed from: o */
    public final void m5172o(@NotNull EnumC4436b statusCode) {
        Intrinsics.checkParameterIsNotNull(statusCode, "statusCode");
        synchronized (this.f11824E) {
            synchronized (this) {
                if (this.f11833l) {
                    return;
                }
                this.f11833l = true;
                int i2 = this.f11831j;
                Unit unit = Unit.INSTANCE;
                this.f11824E.m5210k(i2, statusCode, C4401c.f11556a);
            }
        }
    }

    /* renamed from: q */
    public final synchronized void m5173q(long j2) {
        long j3 = this.f11847z + j2;
        this.f11847z = j3;
        long j4 = j3 - this.f11820A;
        if (j4 >= this.f11845x.m5221a() / 2) {
            m5167C(0, j4);
            this.f11820A += j4;
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:22:0x0038, code lost:
    
        r5 = (int) java.lang.Math.min(r13, r6 - r4);
        r3.element = r5;
        r4 = java.lang.Math.min(r5, r9.f11824E.f11942f);
        r3.element = r4;
        r9.f11821B += r4;
        r3 = kotlin.Unit.INSTANCE;
     */
    /* renamed from: s */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void m5174s(int r10, boolean r11, @org.jetbrains.annotations.Nullable p474l.C4744f r12, long r13) {
        /*
            r9 = this;
            r0 = 0
            r1 = 0
            int r3 = (r13 > r1 ? 1 : (r13 == r1 ? 0 : -1))
            if (r3 != 0) goto Ld
            k.p0.i.p r13 = r9.f11824E
            r13.m5208d(r11, r10, r12, r0)
            return
        Ld:
            int r3 = (r13 > r1 ? 1 : (r13 == r1 ? 0 : -1))
            if (r3 <= 0) goto L74
            kotlin.jvm.internal.Ref$IntRef r3 = new kotlin.jvm.internal.Ref$IntRef
            r3.<init>()
            monitor-enter(r9)
        L17:
            long r4 = r9.f11821B     // Catch: java.lang.Throwable -> L63 java.lang.InterruptedException -> L65
            long r6 = r9.f11822C     // Catch: java.lang.Throwable -> L63 java.lang.InterruptedException -> L65
            int r8 = (r4 > r6 ? 1 : (r4 == r6 ? 0 : -1))
            if (r8 < 0) goto L37
            java.util.Map<java.lang.Integer, k.p0.i.o> r4 = r9.f11829h     // Catch: java.lang.Throwable -> L63 java.lang.InterruptedException -> L65
            java.lang.Integer r5 = java.lang.Integer.valueOf(r10)     // Catch: java.lang.Throwable -> L63 java.lang.InterruptedException -> L65
            boolean r4 = r4.containsKey(r5)     // Catch: java.lang.Throwable -> L63 java.lang.InterruptedException -> L65
            if (r4 == 0) goto L2f
            r9.wait()     // Catch: java.lang.Throwable -> L63 java.lang.InterruptedException -> L65
            goto L17
        L2f:
            java.io.IOException r10 = new java.io.IOException     // Catch: java.lang.Throwable -> L63 java.lang.InterruptedException -> L65
            java.lang.String r11 = "stream closed"
            r10.<init>(r11)     // Catch: java.lang.Throwable -> L63 java.lang.InterruptedException -> L65
            throw r10     // Catch: java.lang.Throwable -> L63 java.lang.InterruptedException -> L65
        L37:
            long r6 = r6 - r4
            long r4 = java.lang.Math.min(r13, r6)     // Catch: java.lang.Throwable -> L63
            int r5 = (int) r4     // Catch: java.lang.Throwable -> L63
            r3.element = r5     // Catch: java.lang.Throwable -> L63
            k.p0.i.p r4 = r9.f11824E     // Catch: java.lang.Throwable -> L63
            int r4 = r4.f11942f     // Catch: java.lang.Throwable -> L63
            int r4 = java.lang.Math.min(r5, r4)     // Catch: java.lang.Throwable -> L63
            r3.element = r4     // Catch: java.lang.Throwable -> L63
            long r5 = r9.f11821B     // Catch: java.lang.Throwable -> L63
            long r7 = (long) r4     // Catch: java.lang.Throwable -> L63
            long r5 = r5 + r7
            r9.f11821B = r5     // Catch: java.lang.Throwable -> L63
            kotlin.Unit r3 = kotlin.Unit.INSTANCE     // Catch: java.lang.Throwable -> L63
            monitor-exit(r9)
            long r5 = (long) r4
            long r13 = r13 - r5
            k.p0.i.p r3 = r9.f11824E
            if (r11 == 0) goto L5e
            int r5 = (r13 > r1 ? 1 : (r13 == r1 ? 0 : -1))
            if (r5 != 0) goto L5e
            r5 = 1
            goto L5f
        L5e:
            r5 = 0
        L5f:
            r3.m5208d(r5, r10, r12, r4)
            goto Ld
        L63:
            r10 = move-exception
            goto L72
        L65:
            java.lang.Thread r10 = java.lang.Thread.currentThread()     // Catch: java.lang.Throwable -> L63
            r10.interrupt()     // Catch: java.lang.Throwable -> L63
            java.io.InterruptedIOException r10 = new java.io.InterruptedIOException     // Catch: java.lang.Throwable -> L63
            r10.<init>()     // Catch: java.lang.Throwable -> L63
            throw r10     // Catch: java.lang.Throwable -> L63
        L72:
            monitor-exit(r9)
            throw r10
        L74:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: p458k.p459p0.p465i.C4440f.m5174s(int, boolean, l.f, long):void");
    }

    /* renamed from: t */
    public final void m5175t(boolean z, int i2, int i3) {
        try {
            this.f11824E.m5212q(z, i2, i3);
        } catch (IOException e2) {
            EnumC4436b enumC4436b = EnumC4436b.PROTOCOL_ERROR;
            m5168b(enumC4436b, enumC4436b, e2);
        }
    }

    /* renamed from: v */
    public final void m5176v(int i2, @NotNull EnumC4436b errorCode) {
        Intrinsics.checkParameterIsNotNull(errorCode, "errorCode");
        C4409b c4409b = this.f11835n;
        String str = this.f11830i + '[' + i2 + "] writeSynReset";
        c4409b.m5070c(new e(str, true, str, true, this, i2, errorCode), 0L);
    }
}
