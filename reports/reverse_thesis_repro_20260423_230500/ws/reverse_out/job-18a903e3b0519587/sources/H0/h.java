package H0;

import f0.AbstractC0524b;
import java.util.Arrays;
import kotlin.jvm.internal.DefaultConstructorMarker;
import t2.j;
import t2.w;

/* JADX INFO: loaded from: classes.dex */
public final class h {

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public static final a f1025c = new a(null);

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private static final h f1026d = new h(-1, false);

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private static final h f1027e = new h(-2, false);

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private static final h f1028f = new h(-1, true);

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final int f1029a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final boolean f1030b;

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final h a() {
            return h.f1026d;
        }

        public final h b() {
            return h.f1027e;
        }

        private a() {
        }
    }

    private h(int i3, boolean z3) {
        this.f1029a = i3;
        this.f1030b = z3;
    }

    public static final h c() {
        return f1025c.a();
    }

    public static final h e() {
        return f1025c.b();
    }

    public final boolean d() {
        return this.f1030b;
    }

    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof h)) {
            return false;
        }
        h hVar = (h) obj;
        return this.f1029a == hVar.f1029a && this.f1030b == hVar.f1030b;
    }

    public final int f() {
        if (h()) {
            throw new IllegalStateException("Rotation is set to use EXIF");
        }
        return this.f1029a;
    }

    public final boolean g() {
        return this.f1029a != -2;
    }

    public final boolean h() {
        return this.f1029a == -1;
    }

    public int hashCode() {
        return AbstractC0524b.b(Integer.valueOf(this.f1029a), Boolean.valueOf(this.f1030b));
    }

    public String toString() {
        w wVar = w.f10219a;
        String str = String.format(null, "%d defer:%b", Arrays.copyOf(new Object[]{Integer.valueOf(this.f1029a), Boolean.valueOf(this.f1030b)}, 2));
        j.e(str, "format(...)");
        return str;
    }
}
