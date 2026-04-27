package B2;

import java.io.IOException;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public enum A {
    HTTP_1_0("http/1.0"),
    HTTP_1_1("http/1.1"),
    SPDY_3("spdy/3.1"),
    HTTP_2("h2"),
    H2_PRIOR_KNOWLEDGE("h2_prior_knowledge"),
    QUIC("quic");


    /* JADX INFO: renamed from: j, reason: collision with root package name */
    public static final a f84j = new a(null);

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final String f85b;

    public static final class a {
        private a() {
        }

        public final A a(String str) throws IOException {
            t2.j.f(str, "protocol");
            A a3 = A.HTTP_1_0;
            if (!t2.j.b(str, a3.f85b)) {
                a3 = A.HTTP_1_1;
                if (!t2.j.b(str, a3.f85b)) {
                    a3 = A.H2_PRIOR_KNOWLEDGE;
                    if (!t2.j.b(str, a3.f85b)) {
                        a3 = A.HTTP_2;
                        if (!t2.j.b(str, a3.f85b)) {
                            a3 = A.SPDY_3;
                            if (!t2.j.b(str, a3.f85b)) {
                                a3 = A.QUIC;
                                if (!t2.j.b(str, a3.f85b)) {
                                    throw new IOException("Unexpected protocol: " + str);
                                }
                            }
                        }
                    }
                }
            }
            return a3;
        }

        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    A(String str) {
        this.f85b = str;
    }

    @Override // java.lang.Enum
    public String toString() {
        return this.f85b;
    }
}
