package I2;

import B2.t;
import Q2.k;
import kotlin.jvm.internal.DefaultConstructorMarker;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class a {

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public static final C0019a f1423c = new C0019a(null);

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private long f1424a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final k f1425b;

    /* JADX INFO: renamed from: I2.a$a, reason: collision with other inner class name */
    public static final class C0019a {
        private C0019a() {
        }

        public /* synthetic */ C0019a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    public a(k kVar) {
        j.f(kVar, "source");
        this.f1425b = kVar;
        this.f1424a = 262144;
    }

    public final t a() {
        t.a aVar = new t.a();
        while (true) {
            String strB = b();
            if (strB.length() == 0) {
                return aVar.e();
            }
            aVar.b(strB);
        }
    }

    public final String b() {
        String strV = this.f1425b.V(this.f1424a);
        this.f1424a -= (long) strV.length();
        return strV;
    }
}
