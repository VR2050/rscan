package E2;

import B2.B;
import B2.C0166d;
import B2.D;
import B2.t;
import java.util.Date;
import java.util.concurrent.TimeUnit;
import kotlin.jvm.internal.DefaultConstructorMarker;
import t2.j;
import z2.g;

/* JADX INFO: loaded from: classes.dex */
public final class c {

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public static final a f652c = new a(null);

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final B f653a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final D f654b;

    public static final class a {
        private a() {
        }

        /* JADX WARN: Removed duplicated region for block: B:24:0x003b  */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public final boolean a(B2.D r5, B2.B r6) {
            /*
                r4 = this;
                java.lang.String r0 = "response"
                t2.j.f(r5, r0)
                java.lang.String r0 = "request"
                t2.j.f(r6, r0)
                int r0 = r5.A()
                r1 = 200(0xc8, float:2.8E-43)
                r2 = 0
                if (r0 == r1) goto L65
                r1 = 410(0x19a, float:5.75E-43)
                if (r0 == r1) goto L65
                r1 = 414(0x19e, float:5.8E-43)
                if (r0 == r1) goto L65
                r1 = 501(0x1f5, float:7.02E-43)
                if (r0 == r1) goto L65
                r1 = 203(0xcb, float:2.84E-43)
                if (r0 == r1) goto L65
                r1 = 204(0xcc, float:2.86E-43)
                if (r0 == r1) goto L65
                r1 = 307(0x133, float:4.3E-43)
                if (r0 == r1) goto L3b
                r1 = 308(0x134, float:4.32E-43)
                if (r0 == r1) goto L65
                r1 = 404(0x194, float:5.66E-43)
                if (r0 == r1) goto L65
                r1 = 405(0x195, float:5.68E-43)
                if (r0 == r1) goto L65
                switch(r0) {
                    case 300: goto L65;
                    case 301: goto L65;
                    case 302: goto L3b;
                    default: goto L3a;
                }
            L3a:
                return r2
            L3b:
                java.lang.String r0 = "Expires"
                r1 = 2
                r3 = 0
                java.lang.String r0 = B2.D.d0(r5, r0, r3, r1, r3)
                if (r0 != 0) goto L65
                B2.d r0 = r5.v()
                int r0 = r0.c()
                r1 = -1
                if (r0 != r1) goto L65
                B2.d r0 = r5.v()
                boolean r0 = r0.b()
                if (r0 != 0) goto L65
                B2.d r0 = r5.v()
                boolean r0 = r0.a()
                if (r0 != 0) goto L65
                return r2
            L65:
                B2.d r5 = r5.v()
                boolean r5 = r5.h()
                if (r5 != 0) goto L7a
                B2.d r5 = r6.b()
                boolean r5 = r5.h()
                if (r5 != 0) goto L7a
                r2 = 1
            L7a:
                return r2
            */
            throw new UnsupportedOperationException("Method not decompiled: E2.c.a.a(B2.D, B2.B):boolean");
        }

        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    public static final class b {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private Date f655a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private String f656b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private Date f657c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private String f658d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private Date f659e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        private long f660f;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        private long f661g;

        /* JADX INFO: renamed from: h, reason: collision with root package name */
        private String f662h;

        /* JADX INFO: renamed from: i, reason: collision with root package name */
        private int f663i;

        /* JADX INFO: renamed from: j, reason: collision with root package name */
        private final long f664j;

        /* JADX INFO: renamed from: k, reason: collision with root package name */
        private final B f665k;

        /* JADX INFO: renamed from: l, reason: collision with root package name */
        private final D f666l;

        public b(long j3, B b3, D d3) {
            j.f(b3, "request");
            this.f664j = j3;
            this.f665k = b3;
            this.f666l = d3;
            this.f663i = -1;
            if (d3 != null) {
                this.f660f = d3.z0();
                this.f661g = d3.x0();
                t tVarE0 = d3.e0();
                int size = tVarE0.size();
                for (int i3 = 0; i3 < size; i3++) {
                    String strB = tVarE0.b(i3);
                    String strH = tVarE0.h(i3);
                    if (g.j(strB, "Date", true)) {
                        this.f655a = H2.c.a(strH);
                        this.f656b = strH;
                    } else if (g.j(strB, "Expires", true)) {
                        this.f659e = H2.c.a(strH);
                    } else if (g.j(strB, "Last-Modified", true)) {
                        this.f657c = H2.c.a(strH);
                        this.f658d = strH;
                    } else if (g.j(strB, "ETag", true)) {
                        this.f662h = strH;
                    } else if (g.j(strB, "Age", true)) {
                        this.f663i = C2.c.U(strH, -1);
                    }
                }
            }
        }

        private final long a() {
            Date date = this.f655a;
            long jMax = date != null ? Math.max(0L, this.f661g - date.getTime()) : 0L;
            int i3 = this.f663i;
            if (i3 != -1) {
                jMax = Math.max(jMax, TimeUnit.SECONDS.toMillis(i3));
            }
            long j3 = this.f661g;
            return jMax + (j3 - this.f660f) + (this.f664j - j3);
        }

        private final c c() {
            String str;
            if (this.f666l == null) {
                return new c(this.f665k, null);
            }
            if (this.f665k.g() && this.f666l.P() == null) {
                return new c(this.f665k, null);
            }
            if (!c.f652c.a(this.f666l, this.f665k)) {
                return new c(this.f665k, null);
            }
            C0166d c0166dB = this.f665k.b();
            if (c0166dB.g() || e(this.f665k)) {
                return new c(this.f665k, null);
            }
            C0166d c0166dV = this.f666l.v();
            long jA = a();
            long jD = d();
            if (c0166dB.c() != -1) {
                jD = Math.min(jD, TimeUnit.SECONDS.toMillis(c0166dB.c()));
            }
            long millis = 0;
            long millis2 = c0166dB.e() != -1 ? TimeUnit.SECONDS.toMillis(c0166dB.e()) : 0L;
            if (!c0166dV.f() && c0166dB.d() != -1) {
                millis = TimeUnit.SECONDS.toMillis(c0166dB.d());
            }
            if (!c0166dV.g()) {
                long j3 = millis2 + jA;
                if (j3 < millis + jD) {
                    D.a aVarU0 = this.f666l.u0();
                    if (j3 >= jD) {
                        aVarU0.a("Warning", "110 HttpURLConnection \"Response is stale\"");
                    }
                    if (jA > 86400000 && f()) {
                        aVarU0.a("Warning", "113 HttpURLConnection \"Heuristic expiration\"");
                    }
                    return new c(null, aVarU0.c());
                }
            }
            String str2 = this.f662h;
            if (str2 != null) {
                str = "If-None-Match";
            } else {
                if (this.f657c != null) {
                    str2 = this.f658d;
                } else {
                    if (this.f655a == null) {
                        return new c(this.f665k, null);
                    }
                    str2 = this.f656b;
                }
                str = "If-Modified-Since";
            }
            t.a aVarE = this.f665k.e().e();
            j.c(str2);
            aVarE.c(str, str2);
            return new c(this.f665k.i().f(aVarE.e()).b(), this.f666l);
        }

        private final long d() {
            D d3 = this.f666l;
            j.c(d3);
            if (d3.v().c() != -1) {
                return TimeUnit.SECONDS.toMillis(r0.c());
            }
            Date date = this.f659e;
            if (date != null) {
                Date date2 = this.f655a;
                long time = date.getTime() - (date2 != null ? date2.getTime() : this.f661g);
                if (time > 0) {
                    return time;
                }
                return 0L;
            }
            if (this.f657c == null || this.f666l.y0().l().m() != null) {
                return 0L;
            }
            Date date3 = this.f655a;
            long time2 = date3 != null ? date3.getTime() : this.f660f;
            Date date4 = this.f657c;
            j.c(date4);
            long time3 = time2 - date4.getTime();
            if (time3 > 0) {
                return time3 / ((long) 10);
            }
            return 0L;
        }

        private final boolean e(B b3) {
            return (b3.d("If-Modified-Since") == null && b3.d("If-None-Match") == null) ? false : true;
        }

        private final boolean f() {
            D d3 = this.f666l;
            j.c(d3);
            return d3.v().c() == -1 && this.f659e == null;
        }

        public final c b() {
            c cVarC = c();
            return (cVarC.b() == null || !this.f665k.b().i()) ? cVarC : new c(null, null);
        }
    }

    public c(B b3, D d3) {
        this.f653a = b3;
        this.f654b = d3;
    }

    public final D a() {
        return this.f654b;
    }

    public final B b() {
        return this.f653a;
    }
}
