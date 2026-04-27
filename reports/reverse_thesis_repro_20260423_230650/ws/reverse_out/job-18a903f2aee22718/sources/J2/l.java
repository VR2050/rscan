package J2;

import java.util.List;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public interface l {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public static final a f1684b = new a(null);

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final l f1683a = new a.C0024a();

    public static final class a {

        /* JADX INFO: renamed from: J2.l$a$a, reason: collision with other inner class name */
        private static final class C0024a implements l {
            @Override // J2.l
            public boolean a(int i3, List list) {
                t2.j.f(list, "requestHeaders");
                return true;
            }

            @Override // J2.l
            public boolean b(int i3, List list, boolean z3) {
                t2.j.f(list, "responseHeaders");
                return true;
            }

            @Override // J2.l
            public boolean c(int i3, Q2.k kVar, int i4, boolean z3) {
                t2.j.f(kVar, "source");
                kVar.t(i4);
                return true;
            }

            @Override // J2.l
            public void d(int i3, b bVar) {
                t2.j.f(bVar, "errorCode");
            }
        }

        private a() {
        }

        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    boolean a(int i3, List list);

    boolean b(int i3, List list, boolean z3);

    boolean c(int i3, Q2.k kVar, int i4, boolean z3);

    void d(int i3, b bVar);
}
