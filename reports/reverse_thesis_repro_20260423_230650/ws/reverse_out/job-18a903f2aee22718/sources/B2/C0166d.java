package B2;

import java.util.concurrent.TimeUnit;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: renamed from: B2.d, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0166d {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final boolean f195a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final boolean f196b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final int f197c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final int f198d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final boolean f199e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final boolean f200f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private final boolean f201g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private final int f202h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private final int f203i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private final boolean f204j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private final boolean f205k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private final boolean f206l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private String f207m;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    public static final b f194p = new b(null);

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    public static final C0166d f192n = new a().d().a();

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    public static final C0166d f193o = new a().f().c(Integer.MAX_VALUE, TimeUnit.SECONDS).a();

    /* JADX INFO: renamed from: B2.d$a */
    public static final class a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private boolean f208a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private boolean f209b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private int f210c = -1;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private int f211d = -1;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private int f212e = -1;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        private boolean f213f;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        private boolean f214g;

        /* JADX INFO: renamed from: h, reason: collision with root package name */
        private boolean f215h;

        private final int b(long j3) {
            if (j3 > Integer.MAX_VALUE) {
                return Integer.MAX_VALUE;
            }
            return (int) j3;
        }

        public final C0166d a() {
            return new C0166d(this.f208a, this.f209b, this.f210c, -1, false, false, false, this.f211d, this.f212e, this.f213f, this.f214g, this.f215h, null, null);
        }

        public final a c(int i3, TimeUnit timeUnit) {
            t2.j.f(timeUnit, "timeUnit");
            if (i3 >= 0) {
                this.f211d = b(timeUnit.toSeconds(i3));
                return this;
            }
            throw new IllegalArgumentException(("maxStale < 0: " + i3).toString());
        }

        public final a d() {
            this.f208a = true;
            return this;
        }

        public final a e() {
            this.f209b = true;
            return this;
        }

        public final a f() {
            this.f213f = true;
            return this;
        }
    }

    /* JADX INFO: renamed from: B2.d$b */
    public static final class b {
        private b() {
        }

        private final int a(String str, String str2, int i3) {
            int length = str.length();
            while (i3 < length) {
                if (z2.g.y(str2, str.charAt(i3), false, 2, null)) {
                    return i3;
                }
                i3++;
            }
            return str.length();
        }

        /* JADX WARN: Removed duplicated region for block: B:15:0x004b  */
        /* JADX WARN: Removed duplicated region for block: B:38:0x00de  */
        /* JADX WARN: Removed duplicated region for block: B:40:0x00e2  */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public final B2.C0166d b(B2.t r32) {
            /*
                Method dump skipped, instruction units count: 416
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: B2.C0166d.b.b(B2.t):B2.d");
        }

        public /* synthetic */ b(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    private C0166d(boolean z3, boolean z4, int i3, int i4, boolean z5, boolean z6, boolean z7, int i5, int i6, boolean z8, boolean z9, boolean z10, String str) {
        this.f195a = z3;
        this.f196b = z4;
        this.f197c = i3;
        this.f198d = i4;
        this.f199e = z5;
        this.f200f = z6;
        this.f201g = z7;
        this.f202h = i5;
        this.f203i = i6;
        this.f204j = z8;
        this.f205k = z9;
        this.f206l = z10;
        this.f207m = str;
    }

    public final boolean a() {
        return this.f199e;
    }

    public final boolean b() {
        return this.f200f;
    }

    public final int c() {
        return this.f197c;
    }

    public final int d() {
        return this.f202h;
    }

    public final int e() {
        return this.f203i;
    }

    public final boolean f() {
        return this.f201g;
    }

    public final boolean g() {
        return this.f195a;
    }

    public final boolean h() {
        return this.f196b;
    }

    public final boolean i() {
        return this.f204j;
    }

    public String toString() {
        String str = this.f207m;
        if (str != null) {
            return str;
        }
        StringBuilder sb = new StringBuilder();
        if (this.f195a) {
            sb.append("no-cache, ");
        }
        if (this.f196b) {
            sb.append("no-store, ");
        }
        if (this.f197c != -1) {
            sb.append("max-age=");
            sb.append(this.f197c);
            sb.append(", ");
        }
        if (this.f198d != -1) {
            sb.append("s-maxage=");
            sb.append(this.f198d);
            sb.append(", ");
        }
        if (this.f199e) {
            sb.append("private, ");
        }
        if (this.f200f) {
            sb.append("public, ");
        }
        if (this.f201g) {
            sb.append("must-revalidate, ");
        }
        if (this.f202h != -1) {
            sb.append("max-stale=");
            sb.append(this.f202h);
            sb.append(", ");
        }
        if (this.f203i != -1) {
            sb.append("min-fresh=");
            sb.append(this.f203i);
            sb.append(", ");
        }
        if (this.f204j) {
            sb.append("only-if-cached, ");
        }
        if (this.f205k) {
            sb.append("no-transform, ");
        }
        if (this.f206l) {
            sb.append("immutable, ");
        }
        if (sb.length() == 0) {
            return "";
        }
        sb.delete(sb.length() - 2, sb.length());
        String string = sb.toString();
        t2.j.e(string, "StringBuilder().apply(builderAction).toString()");
        this.f207m = string;
        return string;
    }

    public /* synthetic */ C0166d(boolean z3, boolean z4, int i3, int i4, boolean z5, boolean z6, boolean z7, int i5, int i6, boolean z8, boolean z9, boolean z10, String str, DefaultConstructorMarker defaultConstructorMarker) {
        this(z3, z4, i3, i4, z5, z6, z7, i5, i6, z8, z9, z10, str);
    }
}
