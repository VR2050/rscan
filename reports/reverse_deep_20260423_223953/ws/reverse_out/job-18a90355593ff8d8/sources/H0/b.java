package H0;

import X.k;
import h2.AbstractC0558d;
import java.util.Arrays;
import java.util.regex.Pattern;
import kotlin.Lazy;
import kotlin.jvm.internal.DefaultConstructorMarker;
import s2.InterfaceC0688a;
import t2.j;
import t2.w;

/* JADX INFO: loaded from: classes.dex */
public final class b {

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public static final a f985c = new a(null);

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private static final Lazy f986d = AbstractC0558d.b(new InterfaceC0688a() { // from class: H0.a
        @Override // s2.InterfaceC0688a
        public final Object a() {
            return b.e();
        }
    });

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public final int f987a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public final int f988b;

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private final Pattern d() {
            Object value = b.f986d.getValue();
            j.e(value, "getValue(...)");
            return (Pattern) value;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public final String f(int i3) {
            return i3 == Integer.MAX_VALUE ? "" : String.valueOf(i3);
        }

        public final b b(int i3) {
            k.b(Boolean.valueOf(i3 >= 0));
            return new b(i3, Integer.MAX_VALUE);
        }

        public final b c(String str) {
            if (str == null) {
                return null;
            }
            try {
                String[] strArrSplit = d().split(str);
                k.b(Boolean.valueOf(strArrSplit.length == 4));
                k.b(Boolean.valueOf(j.b(strArrSplit[0], "bytes")));
                String str2 = strArrSplit[1];
                j.e(str2, "get(...)");
                int i3 = Integer.parseInt(str2);
                String str3 = strArrSplit[2];
                j.e(str3, "get(...)");
                int i4 = Integer.parseInt(str3);
                String str4 = strArrSplit[3];
                j.e(str4, "get(...)");
                int i5 = Integer.parseInt(str4);
                k.b(Boolean.valueOf(i4 > i3));
                k.b(Boolean.valueOf(i5 > i4));
                return i4 < i5 - 1 ? new b(i3, i4) : new b(i3, Integer.MAX_VALUE);
            } catch (IllegalArgumentException e3) {
                w wVar = w.f10219a;
                String str5 = String.format(null, "Invalid Content-Range header value: \"%s\"", Arrays.copyOf(new Object[]{str}, 1));
                j.e(str5, "format(...)");
                throw new IllegalArgumentException(str5, e3);
            }
        }

        public final b e(int i3) {
            k.b(Boolean.valueOf(i3 > 0));
            return new b(0, i3);
        }

        private a() {
        }
    }

    public b(int i3, int i4) {
        this.f987a = i3;
        this.f988b = i4;
    }

    public static final b d(int i3) {
        return f985c.b(i3);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Pattern e() {
        return Pattern.compile("[-/ ]");
    }

    public static final b g(int i3) {
        return f985c.e(i3);
    }

    public final boolean c(b bVar) {
        return bVar != null && this.f987a <= bVar.f987a && bVar.f988b <= this.f988b;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!j.b(b.class, obj != null ? obj.getClass() : null)) {
            return false;
        }
        j.d(obj, "null cannot be cast to non-null type com.facebook.imagepipeline.common.BytesRange");
        b bVar = (b) obj;
        return this.f987a == bVar.f987a && this.f988b == bVar.f988b;
    }

    public final String f() {
        w wVar = w.f10219a;
        a aVar = f985c;
        String str = String.format(null, "bytes=%s-%s", Arrays.copyOf(new Object[]{aVar.f(this.f987a), aVar.f(this.f988b)}, 2));
        j.e(str, "format(...)");
        return str;
    }

    public int hashCode() {
        return (this.f987a * 31) + this.f988b;
    }

    public String toString() {
        w wVar = w.f10219a;
        a aVar = f985c;
        String str = String.format(null, "%s-%s", Arrays.copyOf(new Object[]{aVar.f(this.f987a), aVar.f(this.f988b)}, 2));
        j.e(str, "format(...)");
        return str;
    }
}
