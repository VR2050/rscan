package E0;

import B2.D;
import B2.t;
import kotlin.jvm.internal.DefaultConstructorMarker;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class d extends Exception {

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    public static final a f630d = new a(null);

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final Integer f631b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final t f632c;

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final d a(D d3) {
            j.f(d3, "response");
            D dT0 = d3.t0();
            Integer numValueOf = dT0 != null ? Integer.valueOf(dT0.A()) : null;
            D dT02 = d3.t0();
            return new d(numValueOf, dT02 != null ? dT02.e0() : null);
        }

        private a() {
        }
    }

    public d(Integer num, t tVar) {
        this.f631b = num;
        this.f632c = tVar;
    }
}
