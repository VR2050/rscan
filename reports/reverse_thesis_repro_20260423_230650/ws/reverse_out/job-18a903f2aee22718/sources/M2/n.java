package M2;

import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public final class n extends h {

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    public static final a f1834j = new a(null);

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private final Class f1835h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private final Class f1836i;

    public static final class a {
        private a() {
        }

        public static /* synthetic */ m b(a aVar, String str, int i3, Object obj) {
            if ((i3 & 1) != 0) {
                str = "com.android.org.conscrypt";
            }
            return aVar.a(str);
        }

        public final m a(String str) {
            t2.j.f(str, "packageName");
            try {
                Class<?> cls = Class.forName(str + ".OpenSSLSocketImpl");
                Class<?> cls2 = Class.forName(str + ".OpenSSLSocketFactoryImpl");
                Class<?> cls3 = Class.forName(str + ".SSLParametersImpl");
                t2.j.e(cls3, "paramsClass");
                return new n(cls, cls2, cls3);
            } catch (Exception e3) {
                L2.j.f1746c.g().k("unable to load android socket classes", 5, e3);
                return null;
            }
        }

        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public n(Class cls, Class cls2, Class cls3) {
        super(cls);
        t2.j.f(cls, "sslSocketClass");
        t2.j.f(cls2, "sslSocketFactoryClass");
        t2.j.f(cls3, "paramClass");
        this.f1835h = cls2;
        this.f1836i = cls3;
    }
}
