package B2;

import i2.AbstractC0586n;
import java.util.List;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public interface n {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public static final a f389b = new a(null);

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final n f388a = new a.C0007a();

    public static final class a {

        /* JADX INFO: renamed from: B2.n$a$a, reason: collision with other inner class name */
        private static final class C0007a implements n {
            @Override // B2.n
            public void b(u uVar, List list) {
                t2.j.f(uVar, "url");
                t2.j.f(list, "cookies");
            }

            @Override // B2.n
            public List c(u uVar) {
                t2.j.f(uVar, "url");
                return AbstractC0586n.g();
            }
        }

        private a() {
        }

        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    void b(u uVar, List list);

    List c(u uVar);
}
