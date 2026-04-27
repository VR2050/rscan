package H0;

import f0.AbstractC0524b;
import java.util.Arrays;
import kotlin.jvm.internal.DefaultConstructorMarker;
import t2.j;
import t2.w;

/* JADX INFO: loaded from: classes.dex */
public final class g {

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    public static final a f1020e = new a(null);

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public final int f1021a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public final int f1022b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public final float f1023c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    public final float f1024d;

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    public g(int i3, int i4, float f3, float f4) {
        this.f1021a = i3;
        this.f1022b = i4;
        this.f1023c = f3;
        this.f1024d = f4;
        if (i3 <= 0) {
            throw new IllegalStateException("Check failed.");
        }
        if (i4 <= 0) {
            throw new IllegalStateException("Check failed.");
        }
    }

    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof g) {
            g gVar = (g) obj;
            if (this.f1021a == gVar.f1021a && this.f1022b == gVar.f1022b) {
                return true;
            }
        }
        return false;
    }

    public int hashCode() {
        return AbstractC0524b.a(this.f1021a, this.f1022b);
    }

    public String toString() {
        w wVar = w.f10219a;
        String str = String.format(null, "%dx%d", Arrays.copyOf(new Object[]{Integer.valueOf(this.f1021a), Integer.valueOf(this.f1022b)}, 2));
        j.e(str, "format(...)");
        return str;
    }

    public /* synthetic */ g(int i3, int i4, float f3, float f4, int i5, DefaultConstructorMarker defaultConstructorMarker) {
        this(i3, i4, (i5 & 4) != 0 ? 2048.0f : f3, (i5 & 8) != 0 ? 0.6666667f : f4);
    }
}
