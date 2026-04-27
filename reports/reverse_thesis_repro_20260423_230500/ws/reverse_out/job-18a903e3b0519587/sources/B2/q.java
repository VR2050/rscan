package B2;

import i2.AbstractC0580h;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public interface q {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public static final a f399b = new a(null);

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final q f398a = new a.C0008a();

    public static final class a {

        /* JADX INFO: renamed from: B2.q$a$a, reason: collision with other inner class name */
        private static final class C0008a implements q {
            @Override // B2.q
            public List a(String str) throws UnknownHostException {
                t2.j.f(str, "hostname");
                try {
                    InetAddress[] allByName = InetAddress.getAllByName(str);
                    t2.j.e(allByName, "InetAddress.getAllByName(hostname)");
                    return AbstractC0580h.B(allByName);
                } catch (NullPointerException e3) {
                    UnknownHostException unknownHostException = new UnknownHostException("Broken system behaviour for dns lookup of " + str);
                    unknownHostException.initCause(e3);
                    throw unknownHostException;
                }
            }
        }

        private a() {
        }

        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    List a(String str);
}
