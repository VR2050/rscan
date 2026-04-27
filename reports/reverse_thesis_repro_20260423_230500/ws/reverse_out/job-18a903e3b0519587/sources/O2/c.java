package O2;

import java.util.List;
import javax.net.ssl.X509TrustManager;
import kotlin.jvm.internal.DefaultConstructorMarker;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public abstract class c {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final a f2150a = new a(null);

    public static final class a {
        private a() {
        }

        public final c a(X509TrustManager x509TrustManager) {
            j.f(x509TrustManager, "trustManager");
            return L2.j.f1746c.g().c(x509TrustManager);
        }

        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    public abstract List a(List list, String str);
}
