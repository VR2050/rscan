package p458k.p459p0.p460d;

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
import kotlin.TypeCastException;
import kotlin.Unit;
import kotlin.jvm.JvmField;
import kotlin.jvm.JvmOverloads;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import kotlin.p472io.CloseableKt;
import kotlin.text.Regex;
import kotlin.text.StringsKt__StringsJVMKt;
import kotlin.text.StringsKt__StringsKt;
import kotlin.text.Typography;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p458k.p459p0.C4401c;
import p458k.p459p0.p461e.AbstractC4408a;
import p458k.p459p0.p461e.C4409b;
import p458k.p459p0.p461e.C4410c;
import p458k.p459p0.p466j.InterfaceC4456b;
import p458k.p459p0.p467k.C4463g;
import p474l.C4743e;
import p474l.InterfaceC4745g;
import p474l.InterfaceC4746h;
import p474l.InterfaceC4762x;
import p474l.InterfaceC4764z;

/* renamed from: k.p0.d.e */
/* loaded from: classes3.dex */
public final class C4406e implements Closeable, Flushable {

    /* renamed from: A */
    public final int f11575A;

    /* renamed from: B */
    public final int f11576B;

    /* renamed from: i */
    public long f11577i;

    /* renamed from: j */
    public final File f11578j;

    /* renamed from: k */
    public final File f11579k;

    /* renamed from: l */
    public final File f11580l;

    /* renamed from: m */
    public long f11581m;

    /* renamed from: n */
    public InterfaceC4745g f11582n;

    /* renamed from: o */
    @NotNull
    public final LinkedHashMap<String, b> f11583o;

    /* renamed from: p */
    public int f11584p;

    /* renamed from: q */
    public boolean f11585q;

    /* renamed from: r */
    public boolean f11586r;

    /* renamed from: s */
    public boolean f11587s;

    /* renamed from: t */
    public boolean f11588t;

    /* renamed from: u */
    public boolean f11589u;

    /* renamed from: v */
    public long f11590v;

    /* renamed from: w */
    public final C4409b f11591w;

    /* renamed from: x */
    public final d f11592x;

    /* renamed from: y */
    @NotNull
    public final InterfaceC4456b f11593y;

    /* renamed from: z */
    @NotNull
    public final File f11594z;

    /* renamed from: c */
    @JvmField
    @NotNull
    public static final Regex f11570c = new Regex("[a-z0-9_-]{1,120}");

    /* renamed from: e */
    @JvmField
    @NotNull
    public static final String f11571e = f11571e;

    /* renamed from: e */
    @JvmField
    @NotNull
    public static final String f11571e = f11571e;

    /* renamed from: f */
    @JvmField
    @NotNull
    public static final String f11572f = f11572f;

    /* renamed from: f */
    @JvmField
    @NotNull
    public static final String f11572f = f11572f;

    /* renamed from: g */
    @JvmField
    @NotNull
    public static final String f11573g = f11573g;

    /* renamed from: g */
    @JvmField
    @NotNull
    public static final String f11573g = f11573g;

    /* renamed from: h */
    @JvmField
    @NotNull
    public static final String f11574h = f11574h;

    /* renamed from: h */
    @JvmField
    @NotNull
    public static final String f11574h = f11574h;

    /* renamed from: k.p0.d.e$a */
    public final class a {

        /* renamed from: a */
        @Nullable
        public final boolean[] f11595a;

        /* renamed from: b */
        public boolean f11596b;

        /* renamed from: c */
        @NotNull
        public final b f11597c;

        /* renamed from: d */
        public final /* synthetic */ C4406e f11598d;

        /* renamed from: k.p0.d.e$a$a, reason: collision with other inner class name */
        public static final class C5134a extends Lambda implements Function1<IOException, Unit> {
            public C5134a(int i2) {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public Unit invoke(IOException iOException) {
                Unit unit;
                IOException it = iOException;
                Intrinsics.checkParameterIsNotNull(it, "it");
                synchronized (a.this.f11598d) {
                    a.this.m5062c();
                    unit = Unit.INSTANCE;
                }
                return unit;
            }
        }

        public a(@NotNull C4406e c4406e, b entry) {
            Intrinsics.checkParameterIsNotNull(entry, "entry");
            this.f11598d = c4406e;
            this.f11597c = entry;
            this.f11595a = entry.f11603d ? null : new boolean[c4406e.f11576B];
        }

        /* renamed from: a */
        public final void m5060a() {
            synchronized (this.f11598d) {
                if (!(!this.f11596b)) {
                    throw new IllegalStateException("Check failed.".toString());
                }
                if (Intrinsics.areEqual(this.f11597c.f11604e, this)) {
                    this.f11598d.m5052d(this, false);
                }
                this.f11596b = true;
                Unit unit = Unit.INSTANCE;
            }
        }

        /* renamed from: b */
        public final void m5061b() {
            synchronized (this.f11598d) {
                if (!(!this.f11596b)) {
                    throw new IllegalStateException("Check failed.".toString());
                }
                if (Intrinsics.areEqual(this.f11597c.f11604e, this)) {
                    this.f11598d.m5052d(this, true);
                }
                this.f11596b = true;
                Unit unit = Unit.INSTANCE;
            }
        }

        /* renamed from: c */
        public final void m5062c() {
            if (Intrinsics.areEqual(this.f11597c.f11604e, this)) {
                int i2 = this.f11598d.f11576B;
                for (int i3 = 0; i3 < i2; i3++) {
                    try {
                        this.f11598d.f11593y.mo5229f(this.f11597c.f11602c.get(i3));
                    } catch (IOException unused) {
                    }
                }
                this.f11597c.f11604e = null;
            }
        }

        @NotNull
        /* renamed from: d */
        public final InterfaceC4762x m5063d(int i2) {
            synchronized (this.f11598d) {
                if (!(!this.f11596b)) {
                    throw new IllegalStateException("Check failed.".toString());
                }
                if (!Intrinsics.areEqual(this.f11597c.f11604e, this)) {
                    return new C4743e();
                }
                if (!this.f11597c.f11603d) {
                    boolean[] zArr = this.f11595a;
                    if (zArr == null) {
                        Intrinsics.throwNpe();
                    }
                    zArr[i2] = true;
                }
                try {
                    return new C4407f(this.f11598d.f11593y.mo5225b(this.f11597c.f11602c.get(i2)), new C5134a(i2));
                } catch (FileNotFoundException unused) {
                    return new C4743e();
                }
            }
        }
    }

    /* renamed from: k.p0.d.e$b */
    public final class b {

        /* renamed from: a */
        @NotNull
        public final long[] f11600a;

        /* renamed from: b */
        @NotNull
        public final List<File> f11601b;

        /* renamed from: c */
        @NotNull
        public final List<File> f11602c;

        /* renamed from: d */
        public boolean f11603d;

        /* renamed from: e */
        @Nullable
        public a f11604e;

        /* renamed from: f */
        public long f11605f;

        /* renamed from: g */
        @NotNull
        public final String f11606g;

        /* renamed from: h */
        public final /* synthetic */ C4406e f11607h;

        public b(@NotNull C4406e c4406e, String key) {
            Intrinsics.checkParameterIsNotNull(key, "key");
            this.f11607h = c4406e;
            this.f11606g = key;
            this.f11600a = new long[c4406e.f11576B];
            this.f11601b = new ArrayList();
            this.f11602c = new ArrayList();
            StringBuilder sb = new StringBuilder(key);
            sb.append('.');
            int length = sb.length();
            int i2 = c4406e.f11576B;
            for (int i3 = 0; i3 < i2; i3++) {
                sb.append(i3);
                this.f11601b.add(new File(c4406e.f11594z, sb.toString()));
                sb.append(".tmp");
                this.f11602c.add(new File(c4406e.f11594z, sb.toString()));
                sb.setLength(length);
            }
        }

        @Nullable
        /* renamed from: a */
        public final c m5064a() {
            byte[] bArr = C4401c.f11556a;
            ArrayList arrayList = new ArrayList();
            long[] jArr = (long[]) this.f11600a.clone();
            try {
                int i2 = this.f11607h.f11576B;
                for (int i3 = 0; i3 < i2; i3++) {
                    arrayList.add(this.f11607h.f11593y.mo5224a(this.f11601b.get(i3)));
                }
                return new c(this.f11607h, this.f11606g, this.f11605f, arrayList, jArr);
            } catch (FileNotFoundException unused) {
                Iterator it = arrayList.iterator();
                while (it.hasNext()) {
                    C4401c.m5019d((InterfaceC4764z) it.next());
                }
                try {
                    this.f11607h.m5048E(this);
                    return null;
                } catch (IOException unused2) {
                    return null;
                }
            }
        }

        /* renamed from: b */
        public final void m5065b(@NotNull InterfaceC4745g writer) {
            Intrinsics.checkParameterIsNotNull(writer, "writer");
            for (long j2 : this.f11600a) {
                writer.mo5388n(32).mo5361N(j2);
            }
        }
    }

    /* renamed from: k.p0.d.e$c */
    public final class c implements Closeable {

        /* renamed from: c */
        public final String f11608c;

        /* renamed from: e */
        public final long f11609e;

        /* renamed from: f */
        public final List<InterfaceC4764z> f11610f;

        /* renamed from: g */
        public final /* synthetic */ C4406e f11611g;

        /* JADX WARN: Multi-variable type inference failed */
        public c(@NotNull C4406e c4406e, String key, @NotNull long j2, @NotNull List<? extends InterfaceC4764z> sources, long[] lengths) {
            Intrinsics.checkParameterIsNotNull(key, "key");
            Intrinsics.checkParameterIsNotNull(sources, "sources");
            Intrinsics.checkParameterIsNotNull(lengths, "lengths");
            this.f11611g = c4406e;
            this.f11608c = key;
            this.f11609e = j2;
            this.f11610f = sources;
        }

        @Override // java.io.Closeable, java.lang.AutoCloseable
        public void close() {
            Iterator<InterfaceC4764z> it = this.f11610f.iterator();
            while (it.hasNext()) {
                C4401c.m5019d(it.next());
            }
        }
    }

    /* renamed from: k.p0.d.e$d */
    public static final class d extends AbstractC4408a {
        public d(String str) {
            super(str, true);
        }

        @Override // p458k.p459p0.p461e.AbstractC4408a
        /* renamed from: a */
        public long mo5066a() {
            synchronized (C4406e.this) {
                C4406e c4406e = C4406e.this;
                if (!c4406e.f11586r || c4406e.f11587s) {
                    return -1L;
                }
                try {
                    c4406e.m5049I();
                } catch (IOException unused) {
                    C4406e.this.f11588t = true;
                }
                try {
                    if (C4406e.this.m5056q()) {
                        C4406e.this.m5047D();
                        C4406e.this.f11584p = 0;
                    }
                } catch (IOException unused2) {
                    C4406e c4406e2 = C4406e.this;
                    c4406e2.f11589u = true;
                    c4406e2.f11582n = C2354n.m2497n(new C4743e());
                }
                return -1L;
            }
        }
    }

    /* renamed from: k.p0.d.e$e */
    public static final class e extends Lambda implements Function1<IOException, Unit> {
        public e() {
            super(1);
        }

        @Override // kotlin.jvm.functions.Function1
        public Unit invoke(IOException iOException) {
            IOException it = iOException;
            Intrinsics.checkParameterIsNotNull(it, "it");
            C4406e c4406e = C4406e.this;
            byte[] bArr = C4401c.f11556a;
            c4406e.f11585q = true;
            return Unit.INSTANCE;
        }
    }

    public C4406e(@NotNull InterfaceC4456b fileSystem, @NotNull File directory, int i2, int i3, long j2, @NotNull C4410c taskRunner) {
        Intrinsics.checkParameterIsNotNull(fileSystem, "fileSystem");
        Intrinsics.checkParameterIsNotNull(directory, "directory");
        Intrinsics.checkParameterIsNotNull(taskRunner, "taskRunner");
        this.f11593y = fileSystem;
        this.f11594z = directory;
        this.f11575A = i2;
        this.f11576B = i3;
        this.f11577i = j2;
        this.f11583o = new LinkedHashMap<>(0, 0.75f, true);
        this.f11591w = taskRunner.m5078f();
        this.f11592x = new d("OkHttp Cache");
        if (!(j2 > 0)) {
            throw new IllegalArgumentException("maxSize <= 0".toString());
        }
        if (!(i3 > 0)) {
            throw new IllegalArgumentException("valueCount <= 0".toString());
        }
        this.f11578j = new File(directory, "journal");
        this.f11579k = new File(directory, "journal.tmp");
        this.f11580l = new File(directory, "journal.bkp");
    }

    /* renamed from: C */
    public final void m5046C(String str) {
        String substring;
        int indexOf$default = StringsKt__StringsKt.indexOf$default((CharSequence) str, ' ', 0, false, 6, (Object) null);
        if (indexOf$default == -1) {
            throw new IOException(C1499a.m637w("unexpected journal line: ", str));
        }
        int i2 = indexOf$default + 1;
        int indexOf$default2 = StringsKt__StringsKt.indexOf$default((CharSequence) str, ' ', i2, false, 4, (Object) null);
        if (indexOf$default2 == -1) {
            if (str == null) {
                throw new TypeCastException("null cannot be cast to non-null type java.lang.String");
            }
            substring = str.substring(i2);
            Intrinsics.checkExpressionValueIsNotNull(substring, "(this as java.lang.String).substring(startIndex)");
            String str2 = f11573g;
            if (indexOf$default == str2.length() && StringsKt__StringsJVMKt.startsWith$default(str, str2, false, 2, null)) {
                this.f11583o.remove(substring);
                return;
            }
        } else {
            if (str == null) {
                throw new TypeCastException("null cannot be cast to non-null type java.lang.String");
            }
            substring = str.substring(i2, indexOf$default2);
            Intrinsics.checkExpressionValueIsNotNull(substring, "(this as java.lang.Strin…ing(startIndex, endIndex)");
        }
        b bVar = this.f11583o.get(substring);
        if (bVar == null) {
            bVar = new b(this, substring);
            this.f11583o.put(substring, bVar);
        }
        if (indexOf$default2 != -1) {
            String str3 = f11571e;
            if (indexOf$default == str3.length() && StringsKt__StringsJVMKt.startsWith$default(str, str3, false, 2, null)) {
                int i3 = indexOf$default2 + 1;
                if (str == null) {
                    throw new TypeCastException("null cannot be cast to non-null type java.lang.String");
                }
                String substring2 = str.substring(i3);
                Intrinsics.checkExpressionValueIsNotNull(substring2, "(this as java.lang.String).substring(startIndex)");
                List strings = StringsKt__StringsKt.split$default((CharSequence) substring2, new char[]{' '}, false, 0, 6, (Object) null);
                bVar.f11603d = true;
                bVar.f11604e = null;
                Intrinsics.checkParameterIsNotNull(strings, "strings");
                if (strings.size() != bVar.f11607h.f11576B) {
                    throw new IOException("unexpected journal line: " + strings);
                }
                try {
                    int size = strings.size();
                    for (int i4 = 0; i4 < size; i4++) {
                        bVar.f11600a[i4] = Long.parseLong((String) strings.get(i4));
                    }
                    return;
                } catch (NumberFormatException unused) {
                    throw new IOException("unexpected journal line: " + strings);
                }
            }
        }
        if (indexOf$default2 == -1) {
            String str4 = f11572f;
            if (indexOf$default == str4.length() && StringsKt__StringsJVMKt.startsWith$default(str, str4, false, 2, null)) {
                bVar.f11604e = new a(this, bVar);
                return;
            }
        }
        if (indexOf$default2 == -1) {
            String str5 = f11574h;
            if (indexOf$default == str5.length() && StringsKt__StringsJVMKt.startsWith$default(str, str5, false, 2, null)) {
                return;
            }
        }
        throw new IOException(C1499a.m637w("unexpected journal line: ", str));
    }

    /* renamed from: D */
    public final synchronized void m5047D() {
        InterfaceC4745g interfaceC4745g = this.f11582n;
        if (interfaceC4745g != null) {
            interfaceC4745g.close();
        }
        InterfaceC4745g m2497n = C2354n.m2497n(this.f11593y.mo5225b(this.f11579k));
        try {
            m2497n.mo5393u("libcore.io.DiskLruCache").mo5388n(10);
            m2497n.mo5393u("1").mo5388n(10);
            m2497n.mo5361N(this.f11575A).mo5388n(10);
            m2497n.mo5361N(this.f11576B).mo5388n(10);
            m2497n.mo5388n(10);
            for (b bVar : this.f11583o.values()) {
                if (bVar.f11604e != null) {
                    m2497n.mo5393u(f11572f).mo5388n(32);
                    m2497n.mo5393u(bVar.f11606g);
                    m2497n.mo5388n(10);
                } else {
                    m2497n.mo5393u(f11571e).mo5388n(32);
                    m2497n.mo5393u(bVar.f11606g);
                    bVar.m5065b(m2497n);
                    m2497n.mo5388n(10);
                }
            }
            Unit unit = Unit.INSTANCE;
            CloseableKt.closeFinally(m2497n, null);
            if (this.f11593y.mo5227d(this.f11578j)) {
                this.f11593y.mo5228e(this.f11578j, this.f11580l);
            }
            this.f11593y.mo5228e(this.f11579k, this.f11578j);
            this.f11593y.mo5229f(this.f11580l);
            this.f11582n = m5057s();
            this.f11585q = false;
            this.f11589u = false;
        } finally {
        }
    }

    /* renamed from: E */
    public final boolean m5048E(@NotNull b entry) {
        Intrinsics.checkParameterIsNotNull(entry, "entry");
        a aVar = entry.f11604e;
        if (aVar != null) {
            aVar.m5062c();
        }
        int i2 = this.f11576B;
        for (int i3 = 0; i3 < i2; i3++) {
            this.f11593y.mo5229f(entry.f11601b.get(i3));
            long j2 = this.f11581m;
            long[] jArr = entry.f11600a;
            this.f11581m = j2 - jArr[i3];
            jArr[i3] = 0;
        }
        this.f11584p++;
        InterfaceC4745g interfaceC4745g = this.f11582n;
        if (interfaceC4745g == null) {
            Intrinsics.throwNpe();
        }
        interfaceC4745g.mo5393u(f11573g).mo5388n(32).mo5393u(entry.f11606g).mo5388n(10);
        this.f11583o.remove(entry.f11606g);
        if (m5056q()) {
            C4409b.m5067d(this.f11591w, this.f11592x, 0L, 2);
        }
        return true;
    }

    /* renamed from: I */
    public final void m5049I() {
        while (this.f11581m > this.f11577i) {
            b next = this.f11583o.values().iterator().next();
            Intrinsics.checkExpressionValueIsNotNull(next, "lruEntries.values.iterator().next()");
            m5048E(next);
        }
        this.f11588t = false;
    }

    /* renamed from: P */
    public final void m5050P(String str) {
        if (f11570c.matches(str)) {
            return;
        }
        throw new IllegalArgumentException(("keys must match regex [a-z0-9_-]{1,120}: \"" + str + Typography.quote).toString());
    }

    /* renamed from: b */
    public final synchronized void m5051b() {
        if (!(!this.f11587s)) {
            throw new IllegalStateException("cache is closed".toString());
        }
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public synchronized void close() {
        if (this.f11586r && !this.f11587s) {
            Collection<b> values = this.f11583o.values();
            Intrinsics.checkExpressionValueIsNotNull(values, "lruEntries.values");
            Object[] array = values.toArray(new b[0]);
            if (array == null) {
                throw new TypeCastException("null cannot be cast to non-null type kotlin.Array<T>");
            }
            for (b bVar : (b[]) array) {
                a aVar = bVar.f11604e;
                if (aVar != null) {
                    if (aVar == null) {
                        Intrinsics.throwNpe();
                    }
                    aVar.m5060a();
                }
            }
            m5049I();
            InterfaceC4745g interfaceC4745g = this.f11582n;
            if (interfaceC4745g == null) {
                Intrinsics.throwNpe();
            }
            interfaceC4745g.close();
            this.f11582n = null;
            this.f11587s = true;
            return;
        }
        this.f11587s = true;
    }

    /* renamed from: d */
    public final synchronized void m5052d(@NotNull a editor, boolean z) {
        Intrinsics.checkParameterIsNotNull(editor, "editor");
        b bVar = editor.f11597c;
        if (!Intrinsics.areEqual(bVar.f11604e, editor)) {
            throw new IllegalStateException("Check failed.".toString());
        }
        if (z && !bVar.f11603d) {
            int i2 = this.f11576B;
            for (int i3 = 0; i3 < i2; i3++) {
                boolean[] zArr = editor.f11595a;
                if (zArr == null) {
                    Intrinsics.throwNpe();
                }
                if (!zArr[i3]) {
                    editor.m5060a();
                    throw new IllegalStateException("Newly created entry didn't create value for index " + i3);
                }
                if (!this.f11593y.mo5227d(bVar.f11602c.get(i3))) {
                    editor.m5060a();
                    return;
                }
            }
        }
        int i4 = this.f11576B;
        for (int i5 = 0; i5 < i4; i5++) {
            File file = bVar.f11602c.get(i5);
            if (!z) {
                this.f11593y.mo5229f(file);
            } else if (this.f11593y.mo5227d(file)) {
                File file2 = bVar.f11601b.get(i5);
                this.f11593y.mo5228e(file, file2);
                long j2 = bVar.f11600a[i5];
                long mo5231h = this.f11593y.mo5231h(file2);
                bVar.f11600a[i5] = mo5231h;
                this.f11581m = (this.f11581m - j2) + mo5231h;
            }
        }
        this.f11584p++;
        bVar.f11604e = null;
        InterfaceC4745g interfaceC4745g = this.f11582n;
        if (interfaceC4745g == null) {
            Intrinsics.throwNpe();
        }
        if (!bVar.f11603d && !z) {
            this.f11583o.remove(bVar.f11606g);
            interfaceC4745g.mo5393u(f11573g).mo5388n(32);
            interfaceC4745g.mo5393u(bVar.f11606g);
            interfaceC4745g.mo5388n(10);
            interfaceC4745g.flush();
            if (this.f11581m <= this.f11577i || m5056q()) {
                C4409b.m5067d(this.f11591w, this.f11592x, 0L, 2);
            }
        }
        bVar.f11603d = true;
        interfaceC4745g.mo5393u(f11571e).mo5388n(32);
        interfaceC4745g.mo5393u(bVar.f11606g);
        bVar.m5065b(interfaceC4745g);
        interfaceC4745g.mo5388n(10);
        if (z) {
            long j3 = this.f11590v;
            this.f11590v = 1 + j3;
            bVar.f11605f = j3;
        }
        interfaceC4745g.flush();
        if (this.f11581m <= this.f11577i) {
        }
        C4409b.m5067d(this.f11591w, this.f11592x, 0L, 2);
    }

    @JvmOverloads
    @Nullable
    /* renamed from: e */
    public final synchronized a m5053e(@NotNull String key, long j2) {
        Intrinsics.checkParameterIsNotNull(key, "key");
        m5055o();
        m5051b();
        m5050P(key);
        b bVar = this.f11583o.get(key);
        if (j2 != -1 && (bVar == null || bVar.f11605f != j2)) {
            return null;
        }
        if ((bVar != null ? bVar.f11604e : null) != null) {
            return null;
        }
        if (!this.f11588t && !this.f11589u) {
            InterfaceC4745g interfaceC4745g = this.f11582n;
            if (interfaceC4745g == null) {
                Intrinsics.throwNpe();
            }
            interfaceC4745g.mo5393u(f11572f).mo5388n(32).mo5393u(key).mo5388n(10);
            interfaceC4745g.flush();
            if (this.f11585q) {
                return null;
            }
            if (bVar == null) {
                bVar = new b(this, key);
                this.f11583o.put(key, bVar);
            }
            a aVar = new a(this, bVar);
            bVar.f11604e = aVar;
            return aVar;
        }
        C4409b.m5067d(this.f11591w, this.f11592x, 0L, 2);
        return null;
    }

    @Override // java.io.Flushable
    public synchronized void flush() {
        if (this.f11586r) {
            m5051b();
            m5049I();
            InterfaceC4745g interfaceC4745g = this.f11582n;
            if (interfaceC4745g == null) {
                Intrinsics.throwNpe();
            }
            interfaceC4745g.flush();
        }
    }

    @Nullable
    /* renamed from: k */
    public final synchronized c m5054k(@NotNull String key) {
        Intrinsics.checkParameterIsNotNull(key, "key");
        m5055o();
        m5051b();
        m5050P(key);
        b bVar = this.f11583o.get(key);
        if (bVar == null) {
            return null;
        }
        Intrinsics.checkExpressionValueIsNotNull(bVar, "lruEntries[key] ?: return null");
        if (!bVar.f11603d) {
            return null;
        }
        c m5064a = bVar.m5064a();
        if (m5064a == null) {
            return null;
        }
        this.f11584p++;
        InterfaceC4745g interfaceC4745g = this.f11582n;
        if (interfaceC4745g == null) {
            Intrinsics.throwNpe();
        }
        interfaceC4745g.mo5393u(f11574h).mo5388n(32).mo5393u(key).mo5388n(10);
        if (m5056q()) {
            C4409b.m5067d(this.f11591w, this.f11592x, 0L, 2);
        }
        return m5064a;
    }

    /* renamed from: o */
    public final synchronized void m5055o() {
        byte[] bArr = C4401c.f11556a;
        if (this.f11586r) {
            return;
        }
        if (this.f11593y.mo5227d(this.f11580l)) {
            if (this.f11593y.mo5227d(this.f11578j)) {
                this.f11593y.mo5229f(this.f11580l);
            } else {
                this.f11593y.mo5228e(this.f11580l, this.f11578j);
            }
        }
        if (this.f11593y.mo5227d(this.f11578j)) {
            try {
                m5059v();
                m5058t();
                this.f11586r = true;
                return;
            } catch (IOException e2) {
                C4463g.a aVar = C4463g.f11988c;
                C4463g.f11986a.mo5236k("DiskLruCache " + this.f11594z + " is corrupt: " + e2.getMessage() + ", removing", 5, e2);
                try {
                    close();
                    this.f11593y.mo5226c(this.f11594z);
                    this.f11587s = false;
                } catch (Throwable th) {
                    this.f11587s = false;
                    throw th;
                }
            }
        }
        m5047D();
        this.f11586r = true;
    }

    /* renamed from: q */
    public final boolean m5056q() {
        int i2 = this.f11584p;
        return i2 >= 2000 && i2 >= this.f11583o.size();
    }

    /* renamed from: s */
    public final InterfaceC4745g m5057s() {
        return C2354n.m2497n(new C4407f(this.f11593y.mo5230g(this.f11578j), new e()));
    }

    /* renamed from: t */
    public final void m5058t() {
        this.f11593y.mo5229f(this.f11579k);
        Iterator<b> it = this.f11583o.values().iterator();
        while (it.hasNext()) {
            b next = it.next();
            Intrinsics.checkExpressionValueIsNotNull(next, "i.next()");
            b bVar = next;
            int i2 = 0;
            if (bVar.f11604e == null) {
                int i3 = this.f11576B;
                while (i2 < i3) {
                    this.f11581m += bVar.f11600a[i2];
                    i2++;
                }
            } else {
                bVar.f11604e = null;
                int i4 = this.f11576B;
                while (i2 < i4) {
                    this.f11593y.mo5229f(bVar.f11601b.get(i2));
                    this.f11593y.mo5229f(bVar.f11602c.get(i2));
                    i2++;
                }
                it.remove();
            }
        }
    }

    /* renamed from: v */
    public final void m5059v() {
        InterfaceC4746h m2500o = C2354n.m2500o(this.f11593y.mo5224a(this.f11578j));
        try {
            String mo5351B = m2500o.mo5351B();
            String mo5351B2 = m2500o.mo5351B();
            String mo5351B3 = m2500o.mo5351B();
            String mo5351B4 = m2500o.mo5351B();
            String mo5351B5 = m2500o.mo5351B();
            if (!(!Intrinsics.areEqual("libcore.io.DiskLruCache", mo5351B)) && !(!Intrinsics.areEqual("1", mo5351B2)) && !(!Intrinsics.areEqual(String.valueOf(this.f11575A), mo5351B3)) && !(!Intrinsics.areEqual(String.valueOf(this.f11576B), mo5351B4))) {
                int i2 = 0;
                if (!(mo5351B5.length() > 0)) {
                    while (true) {
                        try {
                            m5046C(m2500o.mo5351B());
                            i2++;
                        } catch (EOFException unused) {
                            this.f11584p = i2 - this.f11583o.size();
                            if (m2500o.mo5387m()) {
                                this.f11582n = m5057s();
                            } else {
                                m5047D();
                            }
                            Unit unit = Unit.INSTANCE;
                            CloseableKt.closeFinally(m2500o, null);
                            return;
                        }
                    }
                }
            }
            throw new IOException("unexpected journal header: [" + mo5351B + ", " + mo5351B2 + ", " + mo5351B4 + ", " + mo5351B5 + ']');
        } finally {
        }
    }
}
