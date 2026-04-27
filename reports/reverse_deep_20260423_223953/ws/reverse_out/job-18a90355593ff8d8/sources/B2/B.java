package B2;

import B2.t;
import B2.u;
import h2.C0563i;
import i2.AbstractC0586n;
import java.net.URL;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/* JADX INFO: loaded from: classes.dex */
public final class B {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private C0166d f86a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final u f87b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final String f88c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final t f89d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final C f90e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final Map f91f;

    public B(u uVar, String str, t tVar, C c3, Map map) {
        t2.j.f(uVar, "url");
        t2.j.f(str, "method");
        t2.j.f(tVar, "headers");
        t2.j.f(map, "tags");
        this.f87b = uVar;
        this.f88c = str;
        this.f89d = tVar;
        this.f90e = c3;
        this.f91f = map;
    }

    public final C a() {
        return this.f90e;
    }

    public final C0166d b() {
        C0166d c0166d = this.f86a;
        if (c0166d != null) {
            return c0166d;
        }
        C0166d c0166dB = C0166d.f194p.b(this.f89d);
        this.f86a = c0166dB;
        return c0166dB;
    }

    public final Map c() {
        return this.f91f;
    }

    public final String d(String str) {
        t2.j.f(str, "name");
        return this.f89d.a(str);
    }

    public final t e() {
        return this.f89d;
    }

    public final List f(String str) {
        t2.j.f(str, "name");
        return this.f89d.i(str);
    }

    public final boolean g() {
        return this.f87b.i();
    }

    public final String h() {
        return this.f88c;
    }

    public final a i() {
        return new a(this);
    }

    public final Object j() {
        return k(Object.class);
    }

    public final Object k(Class cls) {
        t2.j.f(cls, "type");
        return cls.cast(this.f91f.get(cls));
    }

    public final u l() {
        return this.f87b;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Request{method=");
        sb.append(this.f88c);
        sb.append(", url=");
        sb.append(this.f87b);
        if (this.f89d.size() != 0) {
            sb.append(", headers=[");
            int i3 = 0;
            for (Object obj : this.f89d) {
                int i4 = i3 + 1;
                if (i3 < 0) {
                    AbstractC0586n.n();
                }
                C0563i c0563i = (C0563i) obj;
                String str = (String) c0563i.a();
                String str2 = (String) c0563i.b();
                if (i3 > 0) {
                    sb.append(", ");
                }
                sb.append(str);
                sb.append(':');
                sb.append(str2);
                i3 = i4;
            }
            sb.append(']');
        }
        if (!this.f91f.isEmpty()) {
            sb.append(", tags=");
            sb.append(this.f91f);
        }
        sb.append('}');
        String string = sb.toString();
        t2.j.e(string, "StringBuilder().apply(builderAction).toString()");
        return string;
    }

    public static class a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private u f92a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private String f93b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private t.a f94c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private C f95d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private Map f96e;

        public a() {
            this.f96e = new LinkedHashMap();
            this.f93b = "GET";
            this.f94c = new t.a();
        }

        public a a(String str, String str2) {
            t2.j.f(str, "name");
            t2.j.f(str2, "value");
            this.f94c.a(str, str2);
            return this;
        }

        public B b() {
            u uVar = this.f92a;
            if (uVar != null) {
                return new B(uVar, this.f93b, this.f94c.e(), this.f95d, C2.c.S(this.f96e));
            }
            throw new IllegalStateException("url == null");
        }

        public a c(C0166d c0166d) {
            t2.j.f(c0166d, "cacheControl");
            String string = c0166d.toString();
            return string.length() == 0 ? i("Cache-Control") : e("Cache-Control", string);
        }

        public a d() {
            return g("GET", null);
        }

        public a e(String str, String str2) {
            t2.j.f(str, "name");
            t2.j.f(str2, "value");
            this.f94c.i(str, str2);
            return this;
        }

        public a f(t tVar) {
            t2.j.f(tVar, "headers");
            this.f94c = tVar.e();
            return this;
        }

        public a g(String str, C c3) {
            t2.j.f(str, "method");
            if (!(str.length() > 0)) {
                throw new IllegalArgumentException("method.isEmpty() == true");
            }
            if (c3 == null) {
                if (H2.f.e(str)) {
                    throw new IllegalArgumentException(("method " + str + " must have a request body.").toString());
                }
            } else if (!H2.f.b(str)) {
                throw new IllegalArgumentException(("method " + str + " must not have a request body.").toString());
            }
            this.f93b = str;
            this.f95d = c3;
            return this;
        }

        public a h(C c3) {
            t2.j.f(c3, "body");
            return g("POST", c3);
        }

        public a i(String str) {
            t2.j.f(str, "name");
            this.f94c.h(str);
            return this;
        }

        public a j(Class cls, Object obj) {
            t2.j.f(cls, "type");
            if (obj == null) {
                this.f96e.remove(cls);
            } else {
                if (this.f96e.isEmpty()) {
                    this.f96e = new LinkedHashMap();
                }
                Map map = this.f96e;
                Object objCast = cls.cast(obj);
                t2.j.c(objCast);
                map.put(cls, objCast);
            }
            return this;
        }

        public a k(Object obj) {
            return j(Object.class, obj);
        }

        public a l(u uVar) {
            t2.j.f(uVar, "url");
            this.f92a = uVar;
            return this;
        }

        public a m(String str) {
            t2.j.f(str, "url");
            if (z2.g.s(str, "ws:", true)) {
                StringBuilder sb = new StringBuilder();
                sb.append("http:");
                String strSubstring = str.substring(3);
                t2.j.e(strSubstring, "(this as java.lang.String).substring(startIndex)");
                sb.append(strSubstring);
                str = sb.toString();
            } else if (z2.g.s(str, "wss:", true)) {
                StringBuilder sb2 = new StringBuilder();
                sb2.append("https:");
                String strSubstring2 = str.substring(4);
                t2.j.e(strSubstring2, "(this as java.lang.String).substring(startIndex)");
                sb2.append(strSubstring2);
                str = sb2.toString();
            }
            return l(u.f414l.d(str));
        }

        public a n(URL url) {
            t2.j.f(url, "url");
            u.b bVar = u.f414l;
            String string = url.toString();
            t2.j.e(string, "url.toString()");
            return l(bVar.d(string));
        }

        public a(B b3) {
            Map mapQ;
            t2.j.f(b3, "request");
            this.f96e = new LinkedHashMap();
            this.f92a = b3.l();
            this.f93b = b3.h();
            this.f95d = b3.a();
            if (b3.c().isEmpty()) {
                mapQ = new LinkedHashMap();
            } else {
                mapQ = i2.D.q(b3.c());
            }
            this.f96e = mapQ;
            this.f94c = b3.e().e();
        }
    }
}
