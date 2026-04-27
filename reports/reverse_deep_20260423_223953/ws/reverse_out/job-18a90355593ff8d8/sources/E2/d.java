package E2;

import Q2.D;
import Q2.F;
import Q2.j;
import Q2.o;
import Q2.t;
import h2.C0557c;
import h2.r;
import java.io.Closeable;
import java.io.EOFException;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.Flushable;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import kotlin.jvm.internal.DefaultConstructorMarker;
import q2.AbstractC0663a;
import s2.l;
import t2.k;
import z2.g;

/* JADX INFO: loaded from: classes.dex */
public final class d implements Closeable, Flushable {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private long f679b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final File f680c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final File f681d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final File f682e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private long f683f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private j f684g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private final LinkedHashMap f685h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private int f686i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private boolean f687j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private boolean f688k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private boolean f689l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private boolean f690m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private boolean f691n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private boolean f692o;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private long f693p;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private final F2.d f694q;

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    private final e f695r;

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    private final K2.a f696s;

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    private final File f697t;

    /* JADX INFO: renamed from: u, reason: collision with root package name */
    private final int f698u;

    /* JADX INFO: renamed from: v, reason: collision with root package name */
    private final int f699v;

    /* JADX INFO: renamed from: H, reason: collision with root package name */
    public static final a f674H = new a(null);

    /* JADX INFO: renamed from: w, reason: collision with root package name */
    public static final String f675w = "journal";

    /* JADX INFO: renamed from: x, reason: collision with root package name */
    public static final String f676x = "journal.tmp";

    /* JADX INFO: renamed from: y, reason: collision with root package name */
    public static final String f677y = "journal.bkp";

    /* JADX INFO: renamed from: z, reason: collision with root package name */
    public static final String f678z = "libcore.io.DiskLruCache";

    /* JADX INFO: renamed from: A, reason: collision with root package name */
    public static final String f667A = "1";

    /* JADX INFO: renamed from: B, reason: collision with root package name */
    public static final long f668B = -1;

    /* JADX INFO: renamed from: C, reason: collision with root package name */
    public static final z2.f f669C = new z2.f("[a-z0-9_-]{1,120}");

    /* JADX INFO: renamed from: D, reason: collision with root package name */
    public static final String f670D = "CLEAN";

    /* JADX INFO: renamed from: E, reason: collision with root package name */
    public static final String f671E = "DIRTY";

    /* JADX INFO: renamed from: F, reason: collision with root package name */
    public static final String f672F = "REMOVE";

    /* JADX INFO: renamed from: G, reason: collision with root package name */
    public static final String f673G = "READ";

    public static final class a {
        private a() {
        }

        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    public final class b {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final boolean[] f700a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private boolean f701b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final c f702c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final /* synthetic */ d f703d;

        static final class a extends k implements l {

            /* JADX INFO: renamed from: d, reason: collision with root package name */
            final /* synthetic */ int f705d;

            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            a(int i3) {
                super(1);
                this.f705d = i3;
            }

            @Override // s2.l
            public /* bridge */ /* synthetic */ Object d(Object obj) {
                e((IOException) obj);
                return r.f9288a;
            }

            public final void e(IOException iOException) {
                t2.j.f(iOException, "it");
                synchronized (b.this.f703d) {
                    b.this.c();
                    r rVar = r.f9288a;
                }
            }
        }

        public b(d dVar, c cVar) {
            t2.j.f(cVar, "entry");
            this.f703d = dVar;
            this.f702c = cVar;
            this.f700a = cVar.g() ? null : new boolean[dVar.u0()];
        }

        public final void a() {
            synchronized (this.f703d) {
                try {
                    if (this.f701b) {
                        throw new IllegalStateException("Check failed.");
                    }
                    if (t2.j.b(this.f702c.b(), this)) {
                        this.f703d.P(this, false);
                    }
                    this.f701b = true;
                    r rVar = r.f9288a;
                } catch (Throwable th) {
                    throw th;
                }
            }
        }

        public final void b() {
            synchronized (this.f703d) {
                try {
                    if (this.f701b) {
                        throw new IllegalStateException("Check failed.");
                    }
                    if (t2.j.b(this.f702c.b(), this)) {
                        this.f703d.P(this, true);
                    }
                    this.f701b = true;
                    r rVar = r.f9288a;
                } catch (Throwable th) {
                    throw th;
                }
            }
        }

        public final void c() {
            if (t2.j.b(this.f702c.b(), this)) {
                if (this.f703d.f688k) {
                    this.f703d.P(this, false);
                } else {
                    this.f702c.q(true);
                }
            }
        }

        public final c d() {
            return this.f702c;
        }

        public final boolean[] e() {
            return this.f700a;
        }

        public final D f(int i3) {
            synchronized (this.f703d) {
                if (this.f701b) {
                    throw new IllegalStateException("Check failed.");
                }
                if (!t2.j.b(this.f702c.b(), this)) {
                    return t.b();
                }
                if (!this.f702c.g()) {
                    boolean[] zArr = this.f700a;
                    t2.j.c(zArr);
                    zArr[i3] = true;
                }
                try {
                    return new E2.e(this.f703d.t0().c((File) this.f702c.c().get(i3)), new a(i3));
                } catch (FileNotFoundException unused) {
                    return t.b();
                }
            }
        }
    }

    public final class c {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final long[] f706a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final List f707b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final List f708c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private boolean f709d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private boolean f710e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        private b f711f;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        private int f712g;

        /* JADX INFO: renamed from: h, reason: collision with root package name */
        private long f713h;

        /* JADX INFO: renamed from: i, reason: collision with root package name */
        private final String f714i;

        /* JADX INFO: renamed from: j, reason: collision with root package name */
        final /* synthetic */ d f715j;

        public static final class a extends o {

            /* JADX INFO: renamed from: c, reason: collision with root package name */
            private boolean f716c;

            /* JADX INFO: renamed from: e, reason: collision with root package name */
            final /* synthetic */ F f718e;

            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            a(F f3, F f4) {
                super(f4);
                this.f718e = f3;
            }

            @Override // Q2.o, Q2.F, java.io.Closeable, java.lang.AutoCloseable
            public void close() {
                super.close();
                if (this.f716c) {
                    return;
                }
                this.f716c = true;
                synchronized (c.this.f715j) {
                    try {
                        c.this.n(r1.f() - 1);
                        if (c.this.f() == 0 && c.this.i()) {
                            c cVar = c.this;
                            cVar.f715j.D0(cVar);
                        }
                        r rVar = r.f9288a;
                    } catch (Throwable th) {
                        throw th;
                    }
                }
            }
        }

        public c(d dVar, String str) {
            t2.j.f(str, "key");
            this.f715j = dVar;
            this.f714i = str;
            this.f706a = new long[dVar.u0()];
            this.f707b = new ArrayList();
            this.f708c = new ArrayList();
            StringBuilder sb = new StringBuilder(str);
            sb.append('.');
            int length = sb.length();
            int iU0 = dVar.u0();
            for (int i3 = 0; i3 < iU0; i3++) {
                sb.append(i3);
                this.f707b.add(new File(dVar.n0(), sb.toString()));
                sb.append(".tmp");
                this.f708c.add(new File(dVar.n0(), sb.toString()));
                sb.setLength(length);
            }
        }

        private final Void j(List list) throws IOException {
            throw new IOException("unexpected journal line: " + list);
        }

        private final F k(int i3) {
            F fB = this.f715j.t0().b((File) this.f707b.get(i3));
            if (this.f715j.f688k) {
                return fB;
            }
            this.f712g++;
            return new a(fB, fB);
        }

        public final List a() {
            return this.f707b;
        }

        public final b b() {
            return this.f711f;
        }

        public final List c() {
            return this.f708c;
        }

        public final String d() {
            return this.f714i;
        }

        public final long[] e() {
            return this.f706a;
        }

        public final int f() {
            return this.f712g;
        }

        public final boolean g() {
            return this.f709d;
        }

        public final long h() {
            return this.f713h;
        }

        public final boolean i() {
            return this.f710e;
        }

        public final void l(b bVar) {
            this.f711f = bVar;
        }

        public final void m(List list) throws IOException {
            t2.j.f(list, "strings");
            if (list.size() != this.f715j.u0()) {
                j(list);
                throw new C0557c();
            }
            try {
                int size = list.size();
                for (int i3 = 0; i3 < size; i3++) {
                    this.f706a[i3] = Long.parseLong((String) list.get(i3));
                }
            } catch (NumberFormatException unused) {
                j(list);
                throw new C0557c();
            }
        }

        public final void n(int i3) {
            this.f712g = i3;
        }

        public final void o(boolean z3) {
            this.f709d = z3;
        }

        public final void p(long j3) {
            this.f713h = j3;
        }

        public final void q(boolean z3) {
            this.f710e = z3;
        }

        public final C0015d r() {
            d dVar = this.f715j;
            if (C2.c.f585h && !Thread.holdsLock(dVar)) {
                StringBuilder sb = new StringBuilder();
                sb.append("Thread ");
                Thread threadCurrentThread = Thread.currentThread();
                t2.j.e(threadCurrentThread, "Thread.currentThread()");
                sb.append(threadCurrentThread.getName());
                sb.append(" MUST hold lock on ");
                sb.append(dVar);
                throw new AssertionError(sb.toString());
            }
            if (!this.f709d) {
                return null;
            }
            if (!this.f715j.f688k && (this.f711f != null || this.f710e)) {
                return null;
            }
            ArrayList arrayList = new ArrayList();
            long[] jArr = (long[]) this.f706a.clone();
            try {
                int iU0 = this.f715j.u0();
                for (int i3 = 0; i3 < iU0; i3++) {
                    arrayList.add(k(i3));
                }
                return new C0015d(this.f715j, this.f714i, this.f713h, arrayList, jArr);
            } catch (FileNotFoundException unused) {
                Iterator it = arrayList.iterator();
                while (it.hasNext()) {
                    C2.c.j((F) it.next());
                }
                try {
                    this.f715j.D0(this);
                } catch (IOException unused2) {
                }
                return null;
            }
        }

        public final void s(j jVar) {
            t2.j.f(jVar, "writer");
            for (long j3 : this.f706a) {
                jVar.L(32).k0(j3);
            }
        }
    }

    /* JADX INFO: renamed from: E2.d$d, reason: collision with other inner class name */
    public final class C0015d implements Closeable {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final String f719b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final long f720c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private final List f721d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private final long[] f722e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        final /* synthetic */ d f723f;

        public C0015d(d dVar, String str, long j3, List list, long[] jArr) {
            t2.j.f(str, "key");
            t2.j.f(list, "sources");
            t2.j.f(jArr, "lengths");
            this.f723f = dVar;
            this.f719b = str;
            this.f720c = j3;
            this.f721d = list;
            this.f722e = jArr;
        }

        public final b b() {
            return this.f723f.Z(this.f719b, this.f720c);
        }

        @Override // java.io.Closeable, java.lang.AutoCloseable
        public void close() {
            Iterator it = this.f721d.iterator();
            while (it.hasNext()) {
                C2.c.j((F) it.next());
            }
        }

        public final F i(int i3) {
            return (F) this.f721d.get(i3);
        }
    }

    public static final class e extends F2.a {
        e(String str) {
            super(str, false, 2, null);
        }

        @Override // F2.a
        public long f() {
            synchronized (d.this) {
                if (!d.this.f689l || d.this.f0()) {
                    return -1L;
                }
                try {
                    d.this.F0();
                } catch (IOException unused) {
                    d.this.f691n = true;
                }
                try {
                    if (d.this.w0()) {
                        d.this.B0();
                        d.this.f686i = 0;
                    }
                } catch (IOException unused2) {
                    d.this.f692o = true;
                    d.this.f684g = t.c(t.b());
                }
                return -1L;
            }
        }
    }

    static final class f extends k implements l {
        f() {
            super(1);
        }

        @Override // s2.l
        public /* bridge */ /* synthetic */ Object d(Object obj) {
            e((IOException) obj);
            return r.f9288a;
        }

        public final void e(IOException iOException) {
            t2.j.f(iOException, "it");
            d dVar = d.this;
            if (!C2.c.f585h || Thread.holdsLock(dVar)) {
                d.this.f687j = true;
                return;
            }
            StringBuilder sb = new StringBuilder();
            sb.append("Thread ");
            Thread threadCurrentThread = Thread.currentThread();
            t2.j.e(threadCurrentThread, "Thread.currentThread()");
            sb.append(threadCurrentThread.getName());
            sb.append(" MUST hold lock on ");
            sb.append(dVar);
            throw new AssertionError(sb.toString());
        }
    }

    public d(K2.a aVar, File file, int i3, int i4, long j3, F2.e eVar) {
        t2.j.f(aVar, "fileSystem");
        t2.j.f(file, "directory");
        t2.j.f(eVar, "taskRunner");
        this.f696s = aVar;
        this.f697t = file;
        this.f698u = i3;
        this.f699v = i4;
        this.f679b = j3;
        this.f685h = new LinkedHashMap(0, 0.75f, true);
        this.f694q = eVar.i();
        this.f695r = new e(C2.c.f586i + " Cache");
        if (!(j3 > 0)) {
            throw new IllegalArgumentException("maxSize <= 0");
        }
        if (!(i4 > 0)) {
            throw new IllegalArgumentException("valueCount <= 0");
        }
        this.f680c = new File(file, f675w);
        this.f681d = new File(file, f676x);
        this.f682e = new File(file, f677y);
    }

    private final void A0(String str) throws IOException {
        String strSubstring;
        int I3 = g.I(str, ' ', 0, false, 6, null);
        if (I3 == -1) {
            throw new IOException("unexpected journal line: " + str);
        }
        int i3 = I3 + 1;
        int I4 = g.I(str, ' ', i3, false, 4, null);
        if (I4 == -1) {
            if (str == null) {
                throw new NullPointerException("null cannot be cast to non-null type java.lang.String");
            }
            strSubstring = str.substring(i3);
            t2.j.e(strSubstring, "(this as java.lang.String).substring(startIndex)");
            String str2 = f672F;
            if (I3 == str2.length() && g.u(str, str2, false, 2, null)) {
                this.f685h.remove(strSubstring);
                return;
            }
        } else {
            if (str == null) {
                throw new NullPointerException("null cannot be cast to non-null type java.lang.String");
            }
            strSubstring = str.substring(i3, I4);
            t2.j.e(strSubstring, "(this as java.lang.Strin…ing(startIndex, endIndex)");
        }
        c cVar = (c) this.f685h.get(strSubstring);
        if (cVar == null) {
            cVar = new c(this, strSubstring);
            this.f685h.put(strSubstring, cVar);
        }
        if (I4 != -1) {
            String str3 = f670D;
            if (I3 == str3.length() && g.u(str, str3, false, 2, null)) {
                int i4 = I4 + 1;
                if (str == null) {
                    throw new NullPointerException("null cannot be cast to non-null type java.lang.String");
                }
                String strSubstring2 = str.substring(i4);
                t2.j.e(strSubstring2, "(this as java.lang.String).substring(startIndex)");
                List listF0 = g.f0(strSubstring2, new char[]{' '}, false, 0, 6, null);
                cVar.o(true);
                cVar.l(null);
                cVar.m(listF0);
                return;
            }
        }
        if (I4 == -1) {
            String str4 = f671E;
            if (I3 == str4.length() && g.u(str, str4, false, 2, null)) {
                cVar.l(new b(this, cVar));
                return;
            }
        }
        if (I4 == -1) {
            String str5 = f673G;
            if (I3 == str5.length() && g.u(str, str5, false, 2, null)) {
                return;
            }
        }
        throw new IOException("unexpected journal line: " + str);
    }

    private final synchronized void D() {
        if (this.f690m) {
            throw new IllegalStateException("cache is closed");
        }
    }

    private final boolean E0() {
        for (c cVar : this.f685h.values()) {
            if (!cVar.i()) {
                t2.j.e(cVar, "toEvict");
                D0(cVar);
                return true;
            }
        }
        return false;
    }

    private final void G0(String str) {
        if (f669C.a(str)) {
            return;
        }
        throw new IllegalArgumentException(("keys must match regex [a-z0-9_-]{1,120}: \"" + str + '\"').toString());
    }

    public static /* synthetic */ b d0(d dVar, String str, long j3, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            j3 = f668B;
        }
        return dVar.Z(str, j3);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final boolean w0() {
        int i3 = this.f686i;
        return i3 >= 2000 && i3 >= this.f685h.size();
    }

    private final j x0() {
        return t.c(new E2.e(this.f696s.e(this.f680c), new f()));
    }

    private final void y0() {
        this.f696s.a(this.f681d);
        Iterator it = this.f685h.values().iterator();
        while (it.hasNext()) {
            Object next = it.next();
            t2.j.e(next, "i.next()");
            c cVar = (c) next;
            int i3 = 0;
            if (cVar.b() == null) {
                int i4 = this.f699v;
                while (i3 < i4) {
                    this.f683f += cVar.e()[i3];
                    i3++;
                }
            } else {
                cVar.l(null);
                int i5 = this.f699v;
                while (i3 < i5) {
                    this.f696s.a((File) cVar.a().get(i3));
                    this.f696s.a((File) cVar.c().get(i3));
                    i3++;
                }
                it.remove();
            }
        }
    }

    private final void z0() throws IOException {
        Q2.k kVarD = t.d(this.f696s.b(this.f680c));
        try {
            String strH = kVarD.H();
            String strH2 = kVarD.H();
            String strH3 = kVarD.H();
            String strH4 = kVarD.H();
            String strH5 = kVarD.H();
            if (!t2.j.b(f678z, strH) || !t2.j.b(f667A, strH2) || !t2.j.b(String.valueOf(this.f698u), strH3) || !t2.j.b(String.valueOf(this.f699v), strH4) || strH5.length() > 0) {
                throw new IOException("unexpected journal header: [" + strH + ", " + strH2 + ", " + strH4 + ", " + strH5 + ']');
            }
            int i3 = 0;
            while (true) {
                try {
                    A0(kVarD.H());
                    i3++;
                } catch (EOFException unused) {
                    this.f686i = i3 - this.f685h.size();
                    if (kVarD.K()) {
                        this.f684g = x0();
                    } else {
                        B0();
                    }
                    r rVar = r.f9288a;
                    AbstractC0663a.a(kVarD, null);
                    return;
                }
            }
        } finally {
        }
    }

    public final synchronized void B0() {
        try {
            j jVar = this.f684g;
            if (jVar != null) {
                jVar.close();
            }
            j jVarC = t.c(this.f696s.c(this.f681d));
            try {
                jVarC.j0(f678z).L(10);
                jVarC.j0(f667A).L(10);
                jVarC.k0(this.f698u).L(10);
                jVarC.k0(this.f699v).L(10);
                jVarC.L(10);
                for (c cVar : this.f685h.values()) {
                    if (cVar.b() != null) {
                        jVarC.j0(f671E).L(32);
                        jVarC.j0(cVar.d());
                        jVarC.L(10);
                    } else {
                        jVarC.j0(f670D).L(32);
                        jVarC.j0(cVar.d());
                        cVar.s(jVarC);
                        jVarC.L(10);
                    }
                }
                r rVar = r.f9288a;
                AbstractC0663a.a(jVarC, null);
                if (this.f696s.f(this.f680c)) {
                    this.f696s.g(this.f680c, this.f682e);
                }
                this.f696s.g(this.f681d, this.f680c);
                this.f696s.a(this.f682e);
                this.f684g = x0();
                this.f687j = false;
                this.f692o = false;
            } finally {
            }
        } catch (Throwable th) {
            throw th;
        }
    }

    public final synchronized boolean C0(String str) {
        t2.j.f(str, "key");
        v0();
        D();
        G0(str);
        c cVar = (c) this.f685h.get(str);
        if (cVar == null) {
            return false;
        }
        t2.j.e(cVar, "lruEntries[key] ?: return false");
        boolean zD0 = D0(cVar);
        if (zD0 && this.f683f <= this.f679b) {
            this.f691n = false;
        }
        return zD0;
    }

    public final boolean D0(c cVar) {
        j jVar;
        t2.j.f(cVar, "entry");
        if (!this.f688k) {
            if (cVar.f() > 0 && (jVar = this.f684g) != null) {
                jVar.j0(f671E);
                jVar.L(32);
                jVar.j0(cVar.d());
                jVar.L(10);
                jVar.flush();
            }
            if (cVar.f() > 0 || cVar.b() != null) {
                cVar.q(true);
                return true;
            }
        }
        b bVarB = cVar.b();
        if (bVarB != null) {
            bVarB.c();
        }
        int i3 = this.f699v;
        for (int i4 = 0; i4 < i3; i4++) {
            this.f696s.a((File) cVar.a().get(i4));
            this.f683f -= cVar.e()[i4];
            cVar.e()[i4] = 0;
        }
        this.f686i++;
        j jVar2 = this.f684g;
        if (jVar2 != null) {
            jVar2.j0(f672F);
            jVar2.L(32);
            jVar2.j0(cVar.d());
            jVar2.L(10);
        }
        this.f685h.remove(cVar.d());
        if (w0()) {
            F2.d.j(this.f694q, this.f695r, 0L, 2, null);
        }
        return true;
    }

    public final void F0() {
        while (this.f683f > this.f679b) {
            if (!E0()) {
                return;
            }
        }
        this.f691n = false;
    }

    public final synchronized void P(b bVar, boolean z3) {
        t2.j.f(bVar, "editor");
        c cVarD = bVar.d();
        if (!t2.j.b(cVarD.b(), bVar)) {
            throw new IllegalStateException("Check failed.");
        }
        if (z3 && !cVarD.g()) {
            int i3 = this.f699v;
            for (int i4 = 0; i4 < i3; i4++) {
                boolean[] zArrE = bVar.e();
                t2.j.c(zArrE);
                if (!zArrE[i4]) {
                    bVar.a();
                    throw new IllegalStateException("Newly created entry didn't create value for index " + i4);
                }
                if (!this.f696s.f((File) cVarD.c().get(i4))) {
                    bVar.a();
                    return;
                }
            }
        }
        int i5 = this.f699v;
        for (int i6 = 0; i6 < i5; i6++) {
            File file = (File) cVarD.c().get(i6);
            if (!z3 || cVarD.i()) {
                this.f696s.a(file);
            } else if (this.f696s.f(file)) {
                File file2 = (File) cVarD.a().get(i6);
                this.f696s.g(file, file2);
                long j3 = cVarD.e()[i6];
                long jH = this.f696s.h(file2);
                cVarD.e()[i6] = jH;
                this.f683f = (this.f683f - j3) + jH;
            }
        }
        cVarD.l(null);
        if (cVarD.i()) {
            D0(cVarD);
            return;
        }
        this.f686i++;
        j jVar = this.f684g;
        t2.j.c(jVar);
        if (cVarD.g() || z3) {
            cVarD.o(true);
            jVar.j0(f670D).L(32);
            jVar.j0(cVarD.d());
            cVarD.s(jVar);
            jVar.L(10);
            if (z3) {
                long j4 = this.f693p;
                this.f693p = 1 + j4;
                cVarD.p(j4);
            }
        } else {
            this.f685h.remove(cVarD.d());
            jVar.j0(f672F).L(32);
            jVar.j0(cVarD.d());
            jVar.L(10);
        }
        jVar.flush();
        if (this.f683f > this.f679b || w0()) {
            F2.d.j(this.f694q, this.f695r, 0L, 2, null);
        }
    }

    public final void W() {
        close();
        this.f696s.d(this.f697t);
    }

    public final synchronized b Z(String str, long j3) {
        t2.j.f(str, "key");
        v0();
        D();
        G0(str);
        c cVar = (c) this.f685h.get(str);
        if (j3 != f668B && (cVar == null || cVar.h() != j3)) {
            return null;
        }
        if ((cVar != null ? cVar.b() : null) != null) {
            return null;
        }
        if (cVar != null && cVar.f() != 0) {
            return null;
        }
        if (!this.f691n && !this.f692o) {
            j jVar = this.f684g;
            t2.j.c(jVar);
            jVar.j0(f671E).L(32).j0(str).L(10);
            jVar.flush();
            if (this.f687j) {
                return null;
            }
            if (cVar == null) {
                cVar = new c(this, str);
                this.f685h.put(str, cVar);
            }
            b bVar = new b(this, cVar);
            cVar.l(bVar);
            return bVar;
        }
        F2.d.j(this.f694q, this.f695r, 0L, 2, null);
        return null;
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public synchronized void close() {
        b bVarB;
        try {
            if (this.f689l && !this.f690m) {
                Collection collectionValues = this.f685h.values();
                t2.j.e(collectionValues, "lruEntries.values");
                Object[] array = collectionValues.toArray(new c[0]);
                if (array == null) {
                    throw new NullPointerException("null cannot be cast to non-null type kotlin.Array<T>");
                }
                for (c cVar : (c[]) array) {
                    if (cVar.b() != null && (bVarB = cVar.b()) != null) {
                        bVarB.c();
                    }
                }
                F0();
                j jVar = this.f684g;
                t2.j.c(jVar);
                jVar.close();
                this.f684g = null;
                this.f690m = true;
                return;
            }
            this.f690m = true;
        } catch (Throwable th) {
            throw th;
        }
    }

    public final synchronized C0015d e0(String str) {
        t2.j.f(str, "key");
        v0();
        D();
        G0(str);
        c cVar = (c) this.f685h.get(str);
        if (cVar == null) {
            return null;
        }
        t2.j.e(cVar, "lruEntries[key] ?: return null");
        C0015d c0015dR = cVar.r();
        if (c0015dR == null) {
            return null;
        }
        this.f686i++;
        j jVar = this.f684g;
        t2.j.c(jVar);
        jVar.j0(f673G).L(32).j0(str).L(10);
        if (w0()) {
            F2.d.j(this.f694q, this.f695r, 0L, 2, null);
        }
        return c0015dR;
    }

    public final boolean f0() {
        return this.f690m;
    }

    @Override // java.io.Flushable
    public synchronized void flush() {
        if (this.f689l) {
            D();
            F0();
            j jVar = this.f684g;
            t2.j.c(jVar);
            jVar.flush();
        }
    }

    public final File n0() {
        return this.f697t;
    }

    public final K2.a t0() {
        return this.f696s;
    }

    public final int u0() {
        return this.f699v;
    }

    public final synchronized void v0() {
        try {
            if (C2.c.f585h && !Thread.holdsLock(this)) {
                StringBuilder sb = new StringBuilder();
                sb.append("Thread ");
                Thread threadCurrentThread = Thread.currentThread();
                t2.j.e(threadCurrentThread, "Thread.currentThread()");
                sb.append(threadCurrentThread.getName());
                sb.append(" MUST hold lock on ");
                sb.append(this);
                throw new AssertionError(sb.toString());
            }
            if (this.f689l) {
                return;
            }
            if (this.f696s.f(this.f682e)) {
                if (this.f696s.f(this.f680c)) {
                    this.f696s.a(this.f682e);
                } else {
                    this.f696s.g(this.f682e, this.f680c);
                }
            }
            this.f688k = C2.c.C(this.f696s, this.f682e);
            if (this.f696s.f(this.f680c)) {
                try {
                    z0();
                    y0();
                    this.f689l = true;
                    return;
                } catch (IOException e3) {
                    L2.j.f1746c.g().k("DiskLruCache " + this.f697t + " is corrupt: " + e3.getMessage() + ", removing", 5, e3);
                    try {
                        W();
                        this.f690m = false;
                        B0();
                        this.f689l = true;
                    } catch (Throwable th) {
                        this.f690m = false;
                        throw th;
                    }
                }
            }
            B0();
            this.f689l = true;
        } catch (Throwable th2) {
            throw th2;
        }
    }
}
