package p476m.p477a.p478a.p479a;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p476m.p477a.p478a.p479a.C4772h;
import p476m.p477a.p478a.p479a.C4772h.b;
import p476m.p477a.p478a.p479a.InterfaceC4767c;
import p476m.p477a.p478a.p479a.p480l.C4776a;
import p476m.p477a.p478a.p479a.p480l.C4777b;
import p476m.p477a.p478a.p479a.p481m.AbstractC4780c;
import p476m.p477a.p478a.p479a.p481m.C4779b;
import p476m.p477a.p478a.p479a.p481m.InterfaceC4778a;
import p476m.p477a.p478a.p483b.C4786c;

/* renamed from: m.a.a.a.e */
/* loaded from: classes3.dex */
public abstract class AbstractC4769e {

    /* renamed from: a */
    public long f12182a = -1;

    /* renamed from: b */
    public long f12183b = -1;

    /* renamed from: c */
    public String f12184c;

    /* renamed from: m.a.a.a.e$a */
    public class a {

        /* renamed from: a */
        public final C4772h f12185a;

        /* renamed from: b */
        public final C4772h.d f12186b;

        /* renamed from: c */
        public final byte[] f12187c;

        /* renamed from: d */
        public b f12188d;

        /* renamed from: e */
        public String f12189e;

        /* renamed from: f */
        public boolean f12190f;

        /* renamed from: g */
        public boolean f12191g;

        /* renamed from: h */
        public boolean f12192h;

        /* renamed from: m.a.a.a.e$a$a, reason: collision with other inner class name */
        public class C5137a extends AbstractC4780c {
            public C5137a(a aVar, InputStream inputStream, long j2, AbstractC4769e abstractC4769e) {
                super(inputStream, j2);
            }

            @Override // p476m.p477a.p478a.p479a.p481m.AbstractC4780c
            /* renamed from: b */
            public void mo5439b(long j2, long j3) {
                throw new c(new g(String.format("the request was rejected because its size (%s) exceeds the configured maximum (%s)", Long.valueOf(j3), Long.valueOf(j2)), j3, j2));
            }
        }

        /* renamed from: m.a.a.a.e$a$b */
        public class b implements InterfaceC4767c {

            /* renamed from: a */
            public final String f12194a;

            /* renamed from: b */
            public final String f12195b;

            /* renamed from: c */
            public final String f12196c;

            /* renamed from: d */
            public final boolean f12197d;

            /* renamed from: e */
            public final InputStream f12198e;

            /* renamed from: f */
            public InterfaceC4766b f12199f;

            /* renamed from: m.a.a.a.e$a$b$a, reason: collision with other inner class name */
            public class C5138a extends AbstractC4780c {

                /* renamed from: g */
                public final /* synthetic */ C4772h.b f12200g;

                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                public C5138a(InputStream inputStream, long j2, a aVar, C4772h.b bVar) {
                    super(inputStream, j2);
                    this.f12200g = bVar;
                }

                @Override // p476m.p477a.p478a.p479a.p481m.AbstractC4780c
                /* renamed from: b */
                public void mo5439b(long j2, long j3) {
                    this.f12200g.m5446b(true);
                    b bVar = new b(String.format("The field %s exceeds its maximum permitted size of %s bytes.", b.this.f12195b, Long.valueOf(j2)), j3, j2);
                    String str = b.this.f12195b;
                    throw new c(bVar);
                }
            }

            /* JADX WARN: Multi-variable type inference failed */
            /* JADX WARN: Type inference failed for: r8v0, types: [m.a.a.a.e$a$b$a] */
            public b(a aVar, String str, String str2, String str3, boolean z, long j2) {
                this.f12196c = str;
                this.f12195b = str2;
                this.f12194a = str3;
                this.f12197d = z;
                long j3 = AbstractC4769e.this.f12183b;
                if (j3 != -1 && j2 != -1 && j2 > j3) {
                    throw new c(new b(String.format("The field %s exceeds its maximum permitted size of %s bytes.", str2, Long.valueOf(AbstractC4769e.this.f12183b)), j2, AbstractC4769e.this.f12183b));
                }
                C4772h c4772h = aVar.f12185a;
                Objects.requireNonNull(c4772h);
                C4772h.b bVar = c4772h.new b();
                this.f12198e = AbstractC4769e.this.f12183b != -1 ? new C5138a(bVar, AbstractC4769e.this.f12183b, aVar, bVar) : bVar;
            }

            /* renamed from: a */
            public InputStream m5440a() {
                if (((InterfaceC4778a) this.f12198e).isClosed()) {
                    throw new InterfaceC4767c.a();
                }
                return this.f12198e;
            }
        }

        public a(InterfaceC4775k interfaceC4775k) {
            InputStream mo550d;
            Objects.requireNonNull(interfaceC4775k, "ctx parameter");
            String contentType = interfaceC4775k.getContentType();
            if (contentType == null || !contentType.toLowerCase(Locale.ENGLISH).startsWith("multipart/")) {
                throw new e(String.format("the request doesn't contain a %s or %s stream, content type header is %s", "multipart/form-data", "multipart/mixed", contentType));
            }
            long mo548b = InterfaceC4775k.class.isAssignableFrom(interfaceC4775k.getClass()) ? interfaceC4775k.mo548b() : interfaceC4775k.mo549c();
            long j2 = AbstractC4769e.this.f12182a;
            if (j2 < 0) {
                mo550d = interfaceC4775k.mo550d();
            } else {
                if (mo548b != -1 && mo548b > j2) {
                    throw new g(String.format("the request was rejected because its size (%s) exceeds the configured maximum (%s)", Long.valueOf(mo548b), Long.valueOf(AbstractC4769e.this.f12182a)), mo548b, AbstractC4769e.this.f12182a);
                }
                mo550d = new C5137a(this, interfaceC4775k.mo550d(), AbstractC4769e.this.f12182a, AbstractC4769e.this);
            }
            String str = AbstractC4769e.this.f12184c;
            str = str == null ? interfaceC4775k.mo551e() : str;
            byte[] m5432a = AbstractC4769e.this.m5432a(contentType);
            this.f12187c = m5432a;
            if (m5432a == null) {
                int i2 = C4786c.f12262a;
                if (mo550d != null) {
                    try {
                        mo550d.close();
                    } catch (IOException unused) {
                    }
                }
                throw new C4770f("the request was rejected because no multipart boundary was found");
            }
            C4772h.d dVar = new C4772h.d(null, mo548b);
            this.f12186b = dVar;
            try {
                C4772h c4772h = new C4772h(mo550d, m5432a, dVar);
                this.f12185a = c4772h;
                c4772h.f12218n = str;
                this.f12190f = true;
                m5436a();
            } catch (IllegalArgumentException e2) {
                int i3 = C4786c.f12262a;
                if (mo550d != null) {
                    try {
                        mo550d.close();
                    } catch (IOException unused2) {
                    }
                }
                throw new e(String.format("The boundary specified in the %s header is too long", "Content-type"), e2);
            }
        }

        /* JADX WARN: Code restructure failed: missing block: B:104:0x0164, code lost:
        
            r5 = r14.f12193i.m5433b(r10);
            r6 = r10.m5459a("Content-type");
         */
        /* JADX WARN: Code restructure failed: missing block: B:105:0x0172, code lost:
        
            if (r5 != null) goto L70;
         */
        /* JADX WARN: Code restructure failed: missing block: B:106:0x0174, code lost:
        
            r7 = true;
         */
        /* JADX WARN: Code restructure failed: missing block: B:109:0x0181, code lost:
        
            r12 = java.lang.Long.parseLong(r10.m5459a("Content-length"));
         */
        /* JADX WARN: Code restructure failed: missing block: B:113:0x0183, code lost:
        
            r12 = -1;
         */
        /* JADX WARN: Code restructure failed: missing block: B:114:0x0176, code lost:
        
            r7 = false;
         */
        /* renamed from: a */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public final boolean m5436a() {
            /*
                Method dump skipped, instructions count: 609
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: p476m.p477a.p478a.p479a.AbstractC4769e.a.m5436a():boolean");
        }

        /* renamed from: b */
        public boolean m5437b() {
            if (this.f12192h) {
                return false;
            }
            if (this.f12191g) {
                return true;
            }
            try {
                return m5436a();
            } catch (c e2) {
                throw e2.f12202c;
            }
        }

        /* renamed from: c */
        public InterfaceC4767c m5438c() {
            if (this.f12192h || !(this.f12191g || m5437b())) {
                throw new NoSuchElementException();
            }
            this.f12191g = false;
            return this.f12188d;
        }
    }

    /* renamed from: m.a.a.a.e$b */
    public static class b extends f {
        private static final long serialVersionUID = 8150776562029630058L;

        public b(String str, long j2, long j3) {
            super(str, j2, j3);
        }
    }

    /* renamed from: m.a.a.a.e$c */
    public static class c extends IOException {
        private static final long serialVersionUID = -7047616958165584154L;

        /* renamed from: c */
        public final C4770f f12202c;

        public c(C4770f c4770f) {
            this.f12202c = c4770f;
        }

        @Override // java.lang.Throwable
        public Throwable getCause() {
            return this.f12202c;
        }
    }

    /* renamed from: m.a.a.a.e$d */
    public static class d extends C4770f {
        private static final long serialVersionUID = 1749796615868477269L;

        /* renamed from: e */
        public final IOException f12203e;

        public d(String str, IOException iOException) {
            super(str);
            this.f12203e = iOException;
        }

        @Override // p476m.p477a.p478a.p479a.C4770f, java.lang.Throwable
        public Throwable getCause() {
            return this.f12203e;
        }
    }

    /* renamed from: m.a.a.a.e$e */
    public static class e extends C4770f {
        private static final long serialVersionUID = -9073026332015646668L;

        public e(String str) {
            super(str);
        }

        public e(String str, Throwable th) {
            super(str, th);
        }
    }

    /* renamed from: m.a.a.a.e$f */
    public static abstract class f extends C4770f {
        private static final long serialVersionUID = -8776225574705254126L;

        public f(String str, long j2, long j3) {
            super(str);
        }
    }

    /* renamed from: m.a.a.a.e$g */
    public static class g extends f {
        private static final long serialVersionUID = -2474893167098052828L;

        public g(String str, long j2, long j3) {
            super(str, j2, j3);
        }
    }

    /* renamed from: a */
    public byte[] m5432a(String str) {
        C4773i c4773i = new C4773i();
        c4773i.f12233f = true;
        char[] cArr = {';', ','};
        char c2 = cArr[0];
        int length = str.length();
        for (int i2 = 0; i2 < 2; i2++) {
            char c3 = cArr[i2];
            int indexOf = str.indexOf(c3);
            if (indexOf != -1 && indexOf < length) {
                c2 = c3;
                length = indexOf;
            }
        }
        String str2 = c4773i.m5452d(str, c2).get("boundary");
        if (str2 == null) {
            return null;
        }
        try {
            return str2.getBytes("ISO-8859-1");
        } catch (UnsupportedEncodingException unused) {
            return str2.getBytes();
        }
    }

    /* renamed from: b */
    public String m5433b(InterfaceC4766b interfaceC4766b) {
        String m5459a = ((C4779b) interfaceC4766b).m5459a("Content-disposition");
        if (m5459a != null) {
            String lowerCase = m5459a.toLowerCase(Locale.ENGLISH);
            if (lowerCase.startsWith("form-data") || lowerCase.startsWith("attachment")) {
                C4773i c4773i = new C4773i();
                c4773i.f12233f = true;
                Map<String, String> m5452d = c4773i.m5452d(m5459a, ';');
                if (m5452d.containsKey("filename")) {
                    String str = m5452d.get("filename");
                    return str != null ? str.trim() : "";
                }
            }
        }
        return null;
    }

    /* renamed from: c */
    public final int m5434c(String str, int i2) {
        int i3;
        while (true) {
            int indexOf = str.indexOf(13, i2);
            if (indexOf == -1 || (i3 = indexOf + 1) >= str.length()) {
                break;
            }
            if (str.charAt(i3) == '\n') {
                return indexOf;
            }
            i2 = i3;
        }
        throw new IllegalStateException("Expected headers to be terminated by an empty line.");
    }

    /* renamed from: d */
    public List<InterfaceC4765a> m5435d(InterfaceC4775k interfaceC4775k) {
        ArrayList arrayList = new ArrayList();
        try {
            try {
                try {
                    try {
                        a aVar = new a(interfaceC4775k);
                        C4777b c4777b = ((C4768d) this).f12181d;
                        if (c4777b == null) {
                            throw new NullPointerException("No FileItemFactory has been set.");
                        }
                        while (aVar.m5437b()) {
                            InterfaceC4767c m5438c = aVar.m5438c();
                            InterfaceC4765a m5458a = c4777b.m5458a(((a.b) m5438c).f12195b, ((a.b) m5438c).f12194a, ((a.b) m5438c).f12197d, ((a.b) m5438c).f12196c);
                            arrayList.add(m5458a);
                            try {
                                C2354n.m2395H(((a.b) m5438c).m5440a(), ((C4776a) m5458a).m5454f(), true);
                            } catch (c e2) {
                                throw e2.f12202c;
                            } catch (IOException e3) {
                                throw new d(String.format("Processing of %s request failed. %s", "multipart/form-data", e3.getMessage()), e3);
                            }
                        }
                        return arrayList;
                    } catch (c e4) {
                        throw e4.f12202c;
                    }
                } catch (IOException e5) {
                    throw new C4770f(e5.getMessage(), e5);
                }
            } catch (Throwable th) {
                Iterator it = arrayList.iterator();
                while (it.hasNext()) {
                    try {
                        ((InterfaceC4765a) it.next()).mo5428a();
                    } catch (Exception unused) {
                    }
                }
                throw th;
            }
        } catch (c e6) {
            throw e6.f12202c;
        }
    }
}
