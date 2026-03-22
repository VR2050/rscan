package p458k;

import java.io.Closeable;
import java.io.File;
import java.io.Flushable;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import kotlin.TypeCastException;
import kotlin.collections.CollectionsKt__CollectionsKt;
import kotlin.collections.SetsKt__SetsKt;
import kotlin.jvm.JvmStatic;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.StringCompanionObject;
import kotlin.text.StringsKt__StringsJVMKt;
import kotlin.text.StringsKt__StringsKt;
import kotlin.text.Typography;
import org.conscrypt.EvpMdRef;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p458k.C4371b0;
import p458k.C4488y;
import p458k.p459p0.C4401c;
import p458k.p459p0.p460d.C4406e;
import p458k.p459p0.p460d.InterfaceC4404c;
import p458k.p459p0.p461e.C4410c;
import p458k.p459p0.p463g.C4433j;
import p458k.p459p0.p466j.InterfaceC4456b;
import p458k.p459p0.p467k.C4463g;
import p474l.AbstractC4748j;
import p474l.AbstractC4749k;
import p474l.C4744f;
import p474l.C4744f.a;
import p474l.C4747i;
import p474l.C4757s;
import p474l.C4758t;
import p474l.InterfaceC4745g;
import p474l.InterfaceC4746h;
import p474l.InterfaceC4762x;
import p474l.InterfaceC4764z;

/* renamed from: k.d */
/* loaded from: classes3.dex */
public final class C4374d implements Closeable, Flushable {

    /* renamed from: c */
    @NotNull
    public final C4406e f11329c;

    /* renamed from: e */
    public int f11330e;

    /* renamed from: f */
    public int f11331f;

    /* renamed from: g */
    public int f11332g;

    /* renamed from: h */
    public int f11333h;

    /* renamed from: i */
    public int f11334i;

    /* renamed from: k.d$a */
    public static final class a extends AbstractC4393m0 {

        /* renamed from: e */
        public final InterfaceC4746h f11335e;

        /* renamed from: f */
        @NotNull
        public final C4406e.c f11336f;

        /* renamed from: g */
        public final String f11337g;

        /* renamed from: h */
        public final String f11338h;

        /* renamed from: k.d$a$a, reason: collision with other inner class name */
        public static final class C5133a extends AbstractC4749k {

            /* renamed from: f */
            public final /* synthetic */ InterfaceC4764z f11340f;

            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            public C5133a(InterfaceC4764z interfaceC4764z, InterfaceC4764z interfaceC4764z2) {
                super(interfaceC4764z2);
                this.f11340f = interfaceC4764z;
            }

            @Override // p474l.AbstractC4749k, p474l.InterfaceC4764z, java.io.Closeable, java.lang.AutoCloseable
            public void close() {
                a.this.f11336f.close();
                this.f12141c.close();
            }
        }

        public a(@NotNull C4406e.c snapshot, @Nullable String str, @Nullable String str2) {
            Intrinsics.checkParameterIsNotNull(snapshot, "snapshot");
            this.f11336f = snapshot;
            this.f11337g = str;
            this.f11338h = str2;
            InterfaceC4764z interfaceC4764z = snapshot.f11610f.get(1);
            this.f11335e = C2354n.m2500o(new C5133a(interfaceC4764z, interfaceC4764z));
        }

        @Override // p458k.AbstractC4393m0
        /* renamed from: d */
        public long mo4925d() {
            String toLongOrDefault = this.f11338h;
            if (toLongOrDefault != null) {
                byte[] bArr = C4401c.f11556a;
                Intrinsics.checkParameterIsNotNull(toLongOrDefault, "$this$toLongOrDefault");
                try {
                    return Long.parseLong(toLongOrDefault);
                } catch (NumberFormatException unused) {
                }
            }
            return -1L;
        }

        @Override // p458k.AbstractC4393m0
        @Nullable
        /* renamed from: e */
        public C4371b0 mo4926e() {
            String str = this.f11337g;
            if (str == null) {
                return null;
            }
            C4371b0.a aVar = C4371b0.f11309c;
            return C4371b0.a.m4946b(str);
        }

        @Override // p458k.AbstractC4393m0
        @NotNull
        /* renamed from: k */
        public InterfaceC4746h mo4927k() {
            return this.f11335e;
        }
    }

    /* renamed from: k.d$c */
    public final class c implements InterfaceC4404c {

        /* renamed from: a */
        public final InterfaceC4762x f11353a;

        /* renamed from: b */
        public final InterfaceC4762x f11354b;

        /* renamed from: c */
        public boolean f11355c;

        /* renamed from: d */
        public final C4406e.a f11356d;

        /* renamed from: e */
        public final /* synthetic */ C4374d f11357e;

        /* renamed from: k.d$c$a */
        public static final class a extends AbstractC4748j {
            public a(InterfaceC4762x interfaceC4762x) {
                super(interfaceC4762x);
            }

            @Override // p474l.AbstractC4748j, p474l.InterfaceC4762x, java.io.Closeable, java.lang.AutoCloseable
            public void close() {
                synchronized (c.this.f11357e) {
                    c cVar = c.this;
                    if (cVar.f11355c) {
                        return;
                    }
                    cVar.f11355c = true;
                    cVar.f11357e.f11330e++;
                    this.f12140c.close();
                    c.this.f11356d.m5061b();
                }
            }
        }

        public c(@NotNull C4374d c4374d, C4406e.a editor) {
            Intrinsics.checkParameterIsNotNull(editor, "editor");
            this.f11357e = c4374d;
            this.f11356d = editor;
            InterfaceC4762x m5063d = editor.m5063d(1);
            this.f11353a = m5063d;
            this.f11354b = new a(m5063d);
        }

        @Override // p458k.p459p0.p460d.InterfaceC4404c
        /* renamed from: a */
        public void mo4954a() {
            synchronized (this.f11357e) {
                if (this.f11355c) {
                    return;
                }
                this.f11355c = true;
                this.f11357e.f11331f++;
                C4401c.m5019d(this.f11353a);
                try {
                    this.f11356d.m5060a();
                } catch (IOException unused) {
                }
            }
        }
    }

    public C4374d(@NotNull File directory, long j2) {
        Intrinsics.checkParameterIsNotNull(directory, "directory");
        InterfaceC4456b fileSystem = InterfaceC4456b.f11958a;
        Intrinsics.checkParameterIsNotNull(directory, "directory");
        Intrinsics.checkParameterIsNotNull(fileSystem, "fileSystem");
        this.f11329c = new C4406e(fileSystem, directory, 201105, 2, j2, C4410c.f11626a);
    }

    @JvmStatic
    @NotNull
    /* renamed from: b */
    public static final String m4948b(@NotNull C4489z url) {
        Intrinsics.checkParameterIsNotNull(url, "url");
        return C4747i.f12136e.m5412c(url.f12054l).mo5399b(EvpMdRef.MD5.JCA_NAME).mo5401d();
    }

    /* renamed from: e */
    public static final Set<String> m4949e(@NotNull C4488y c4488y) {
        int size = c4488y.size();
        TreeSet treeSet = null;
        for (int i2 = 0; i2 < size; i2++) {
            if (StringsKt__StringsJVMKt.equals("Vary", c4488y.m5278b(i2), true)) {
                String m5280d = c4488y.m5280d(i2);
                if (treeSet == null) {
                    treeSet = new TreeSet(StringsKt__StringsJVMKt.getCASE_INSENSITIVE_ORDER(StringCompanionObject.INSTANCE));
                }
                for (String str : StringsKt__StringsKt.split$default((CharSequence) m5280d, new char[]{','}, false, 0, 6, (Object) null)) {
                    if (str == null) {
                        throw new TypeCastException("null cannot be cast to non-null type kotlin.CharSequence");
                    }
                    treeSet.add(StringsKt__StringsKt.trim((CharSequence) str).toString());
                }
            }
        }
        return treeSet != null ? treeSet : SetsKt__SetsKt.emptySet();
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        this.f11329c.close();
    }

    /* renamed from: d */
    public final void m4950d(@NotNull C4381g0 request) {
        Intrinsics.checkParameterIsNotNull(request, "request");
        C4406e c4406e = this.f11329c;
        C4489z url = request.f11440b;
        Intrinsics.checkParameterIsNotNull(url, "url");
        String key = C4747i.f12136e.m5412c(url.f12054l).mo5399b(EvpMdRef.MD5.JCA_NAME).mo5401d();
        synchronized (c4406e) {
            Intrinsics.checkParameterIsNotNull(key, "key");
            c4406e.m5055o();
            c4406e.m5051b();
            c4406e.m5050P(key);
            C4406e.b bVar = c4406e.f11583o.get(key);
            if (bVar != null) {
                Intrinsics.checkExpressionValueIsNotNull(bVar, "lruEntries[key] ?: return false");
                c4406e.m5048E(bVar);
                if (c4406e.f11581m <= c4406e.f11577i) {
                    c4406e.f11588t = false;
                }
            }
        }
    }

    @Override // java.io.Flushable
    public void flush() {
        this.f11329c.flush();
    }

    /* renamed from: k.d$b */
    public static final class b {

        /* renamed from: a */
        public static final String f11341a;

        /* renamed from: b */
        public static final String f11342b;

        /* renamed from: c */
        public final String f11343c;

        /* renamed from: d */
        public final C4488y f11344d;

        /* renamed from: e */
        public final String f11345e;

        /* renamed from: f */
        public final EnumC4377e0 f11346f;

        /* renamed from: g */
        public final int f11347g;

        /* renamed from: h */
        public final String f11348h;

        /* renamed from: i */
        public final C4488y f11349i;

        /* renamed from: j */
        public final C4487x f11350j;

        /* renamed from: k */
        public final long f11351k;

        /* renamed from: l */
        public final long f11352l;

        static {
            C4463g.a aVar = C4463g.f11988c;
            Objects.requireNonNull(C4463g.f11986a);
            f11341a = "OkHttp-Sent-Millis";
            Objects.requireNonNull(C4463g.f11986a);
            f11342b = "OkHttp-Received-Millis";
        }

        public b(@NotNull InterfaceC4764z rawSource) {
            Intrinsics.checkParameterIsNotNull(rawSource, "rawSource");
            try {
                InterfaceC4746h source = C2354n.m2500o(rawSource);
                C4758t c4758t = (C4758t) source;
                this.f11343c = c4758t.mo5351B();
                this.f11345e = c4758t.mo5351B();
                C4488y.a aVar = new C4488y.a();
                Intrinsics.checkParameterIsNotNull(source, "source");
                try {
                    C4758t c4758t2 = (C4758t) source;
                    long m5418d = c4758t2.m5418d();
                    String mo5351B = c4758t2.mo5351B();
                    if (m5418d >= 0) {
                        long j2 = Integer.MAX_VALUE;
                        if (m5418d <= j2) {
                            boolean z = true;
                            if (!(mo5351B.length() > 0)) {
                                int i2 = (int) m5418d;
                                for (int i3 = 0; i3 < i2; i3++) {
                                    aVar.m5283b(c4758t.mo5351B());
                                }
                                this.f11344d = aVar.m5285d();
                                C4433j m5144a = C4433j.m5144a(c4758t.mo5351B());
                                this.f11346f = m5144a.f11748a;
                                this.f11347g = m5144a.f11749b;
                                this.f11348h = m5144a.f11750c;
                                C4488y.a aVar2 = new C4488y.a();
                                Intrinsics.checkParameterIsNotNull(source, "source");
                                try {
                                    long m5418d2 = c4758t2.m5418d();
                                    String mo5351B2 = c4758t2.mo5351B();
                                    if (m5418d2 >= 0 && m5418d2 <= j2) {
                                        if (!(mo5351B2.length() > 0)) {
                                            int i4 = (int) m5418d2;
                                            for (int i5 = 0; i5 < i4; i5++) {
                                                aVar2.m5283b(c4758t.mo5351B());
                                            }
                                            String str = f11341a;
                                            String m5286e = aVar2.m5286e(str);
                                            String str2 = f11342b;
                                            String m5286e2 = aVar2.m5286e(str2);
                                            aVar2.m5287f(str);
                                            aVar2.m5287f(str2);
                                            this.f11351k = m5286e != null ? Long.parseLong(m5286e) : 0L;
                                            this.f11352l = m5286e2 != null ? Long.parseLong(m5286e2) : 0L;
                                            this.f11349i = aVar2.m5285d();
                                            if (StringsKt__StringsJVMKt.startsWith$default(this.f11343c, "https://", false, 2, null)) {
                                                String mo5351B3 = c4758t.mo5351B();
                                                if (mo5351B3.length() <= 0) {
                                                    z = false;
                                                }
                                                if (z) {
                                                    throw new IOException("expected \"\" but was \"" + mo5351B3 + Typography.quote);
                                                }
                                                this.f11350j = C4487x.f12033b.m5275b(!c4758t.mo5387m() ? EnumC4397o0.f11537j.m5012a(c4758t.mo5351B()) : EnumC4397o0.SSL_3_0, C4386j.f11481s.m4984b(c4758t.mo5351B()), m4951a(source), m4951a(source));
                                            } else {
                                                this.f11350j = null;
                                            }
                                            return;
                                        }
                                    }
                                    throw new IOException("expected an int but was \"" + m5418d2 + mo5351B2 + Typography.quote);
                                } catch (NumberFormatException e2) {
                                    throw new IOException(e2.getMessage());
                                }
                            }
                        }
                    }
                    throw new IOException("expected an int but was \"" + m5418d + mo5351B + Typography.quote);
                } catch (NumberFormatException e3) {
                    throw new IOException(e3.getMessage());
                }
            } finally {
                rawSource.close();
            }
        }

        /* renamed from: a */
        public final List<Certificate> m4951a(InterfaceC4746h source) {
            Intrinsics.checkParameterIsNotNull(source, "source");
            try {
                C4758t c4758t = (C4758t) source;
                long m5418d = c4758t.m5418d();
                String mo5351B = c4758t.mo5351B();
                if (m5418d >= 0 && m5418d <= Integer.MAX_VALUE) {
                    if (!(mo5351B.length() > 0)) {
                        int i2 = (int) m5418d;
                        if (i2 == -1) {
                            return CollectionsKt__CollectionsKt.emptyList();
                        }
                        try {
                            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                            ArrayList arrayList = new ArrayList(i2);
                            for (int i3 = 0; i3 < i2; i3++) {
                                String mo5351B2 = c4758t.mo5351B();
                                C4744f c4744f = new C4744f();
                                C4747i m5410a = C4747i.f12136e.m5410a(mo5351B2);
                                if (m5410a == null) {
                                    Intrinsics.throwNpe();
                                }
                                c4744f.m5370X(m5410a);
                                arrayList.add(certificateFactory.generateCertificate(c4744f.new a()));
                            }
                            return arrayList;
                        } catch (CertificateException e2) {
                            throw new IOException(e2.getMessage());
                        }
                    }
                }
                throw new IOException("expected an int but was \"" + m5418d + mo5351B + Typography.quote);
            } catch (NumberFormatException e3) {
                throw new IOException(e3.getMessage());
            }
        }

        /* renamed from: b */
        public final void m4952b(InterfaceC4745g interfaceC4745g, List<? extends Certificate> list) {
            try {
                C4757s c4757s = (C4757s) interfaceC4745g;
                c4757s.mo5361N(list.size()).mo5388n(10);
                int size = list.size();
                for (int i2 = 0; i2 < size; i2++) {
                    byte[] bytes = list.get(i2).getEncoded();
                    C4747i.a aVar = C4747i.f12136e;
                    Intrinsics.checkExpressionValueIsNotNull(bytes, "bytes");
                    c4757s.mo5393u(C4747i.a.m5409d(aVar, bytes, 0, 0, 3).mo5398a()).mo5388n(10);
                }
            } catch (CertificateEncodingException e2) {
                throw new IOException(e2.getMessage());
            }
        }

        /* renamed from: c */
        public final void m4953c(@NotNull C4406e.a editor) {
            Intrinsics.checkParameterIsNotNull(editor, "editor");
            InterfaceC4745g m2497n = C2354n.m2497n(editor.m5063d(0));
            C4757s c4757s = (C4757s) m2497n;
            c4757s.mo5393u(this.f11343c).mo5388n(10);
            c4757s.mo5393u(this.f11345e).mo5388n(10);
            c4757s.mo5361N(this.f11344d.size()).mo5388n(10);
            int size = this.f11344d.size();
            for (int i2 = 0; i2 < size; i2++) {
                c4757s.mo5393u(this.f11344d.m5278b(i2)).mo5393u(": ").mo5393u(this.f11344d.m5280d(i2)).mo5388n(10);
            }
            c4757s.mo5393u(new C4433j(this.f11346f, this.f11347g, this.f11348h).toString()).mo5388n(10);
            c4757s.mo5361N(this.f11349i.size() + 2).mo5388n(10);
            int size2 = this.f11349i.size();
            for (int i3 = 0; i3 < size2; i3++) {
                c4757s.mo5393u(this.f11349i.m5278b(i3)).mo5393u(": ").mo5393u(this.f11349i.m5280d(i3)).mo5388n(10);
            }
            c4757s.mo5393u(f11341a).mo5393u(": ").mo5361N(this.f11351k).mo5388n(10);
            c4757s.mo5393u(f11342b).mo5393u(": ").mo5361N(this.f11352l).mo5388n(10);
            if (StringsKt__StringsJVMKt.startsWith$default(this.f11343c, "https://", false, 2, null)) {
                c4757s.mo5388n(10);
                C4487x c4487x = this.f11350j;
                if (c4487x == null) {
                    Intrinsics.throwNpe();
                }
                c4757s.mo5393u(c4487x.f12036e.f11482t).mo5388n(10);
                m4952b(m2497n, this.f11350j.m5273b());
                m4952b(m2497n, this.f11350j.f12037f);
                c4757s.mo5393u(this.f11350j.f12035d.f11538k).mo5388n(10);
            }
            c4757s.close();
        }

        public b(@NotNull C4389k0 varyHeaders) {
            C4488y m5285d;
            Intrinsics.checkParameterIsNotNull(varyHeaders, "response");
            this.f11343c = varyHeaders.f11485e.f11440b.f12054l;
            Intrinsics.checkParameterIsNotNull(varyHeaders, "$this$varyHeaders");
            C4389k0 c4389k0 = varyHeaders.f11492l;
            if (c4389k0 == null) {
                Intrinsics.throwNpe();
            }
            C4488y c4488y = c4389k0.f11485e.f11442d;
            Set<String> m4949e = C4374d.m4949e(varyHeaders.f11490j);
            if (m4949e.isEmpty()) {
                m5285d = C4401c.f11557b;
            } else {
                C4488y.a aVar = new C4488y.a();
                int size = c4488y.size();
                for (int i2 = 0; i2 < size; i2++) {
                    String m5278b = c4488y.m5278b(i2);
                    if (m4949e.contains(m5278b)) {
                        aVar.m5282a(m5278b, c4488y.m5280d(i2));
                    }
                }
                m5285d = aVar.m5285d();
            }
            this.f11344d = m5285d;
            this.f11345e = varyHeaders.f11485e.f11441c;
            this.f11346f = varyHeaders.f11486f;
            this.f11347g = varyHeaders.f11488h;
            this.f11348h = varyHeaders.f11487g;
            this.f11349i = varyHeaders.f11490j;
            this.f11350j = varyHeaders.f11489i;
            this.f11351k = varyHeaders.f11495o;
            this.f11352l = varyHeaders.f11496p;
        }
    }
}
