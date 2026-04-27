package M2;

import M2.l;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.List;
import javax.net.ssl.SSLSocket;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public class h implements m {

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private static final l.a f1816f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    public static final a f1817g;

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Method f1818a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final Method f1819b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final Method f1820c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final Method f1821d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final Class f1822e;

    public static final class a {

        /* JADX INFO: renamed from: M2.h$a$a, reason: collision with other inner class name */
        public static final class C0029a implements l.a {

            /* JADX INFO: renamed from: a, reason: collision with root package name */
            final /* synthetic */ String f1823a;

            C0029a(String str) {
                this.f1823a = str;
            }

            @Override // M2.l.a
            public boolean a(SSLSocket sSLSocket) {
                t2.j.f(sSLSocket, "sslSocket");
                String name = sSLSocket.getClass().getName();
                t2.j.e(name, "sslSocket.javaClass.name");
                return z2.g.u(name, this.f1823a + '.', false, 2, null);
            }

            @Override // M2.l.a
            public m b(SSLSocket sSLSocket) {
                t2.j.f(sSLSocket, "sslSocket");
                return h.f1817g.b(sSLSocket.getClass());
            }
        }

        private a() {
        }

        /* JADX INFO: Access modifiers changed from: private */
        public final h b(Class cls) {
            Class superclass = cls;
            while (superclass != null && !t2.j.b(superclass.getSimpleName(), "OpenSSLSocketImpl")) {
                superclass = superclass.getSuperclass();
                if (superclass == null) {
                    throw new AssertionError("No OpenSSLSocketImpl superclass of socket of type " + cls);
                }
            }
            t2.j.c(superclass);
            return new h(superclass);
        }

        public final l.a c(String str) {
            t2.j.f(str, "packageName");
            return new C0029a(str);
        }

        public final l.a d() {
            return h.f1816f;
        }

        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    static {
        a aVar = new a(null);
        f1817g = aVar;
        f1816f = aVar.c("com.google.android.gms.org.conscrypt");
    }

    public h(Class cls) throws NoSuchMethodException {
        t2.j.f(cls, "sslSocketClass");
        this.f1822e = cls;
        Method declaredMethod = cls.getDeclaredMethod("setUseSessionTickets", Boolean.TYPE);
        t2.j.e(declaredMethod, "sslSocketClass.getDeclar…:class.javaPrimitiveType)");
        this.f1818a = declaredMethod;
        this.f1819b = cls.getMethod("setHostname", String.class);
        this.f1820c = cls.getMethod("getAlpnSelectedProtocol", new Class[0]);
        this.f1821d = cls.getMethod("setAlpnProtocols", byte[].class);
    }

    @Override // M2.m
    public boolean a(SSLSocket sSLSocket) {
        t2.j.f(sSLSocket, "sslSocket");
        return this.f1822e.isInstance(sSLSocket);
    }

    @Override // M2.m
    public boolean b() {
        return L2.b.f1718g.b();
    }

    @Override // M2.m
    public String c(SSLSocket sSLSocket) {
        t2.j.f(sSLSocket, "sslSocket");
        if (!a(sSLSocket)) {
            return null;
        }
        try {
            byte[] bArr = (byte[]) this.f1820c.invoke(sSLSocket, new Object[0]);
            if (bArr == null) {
                return null;
            }
            Charset charset = StandardCharsets.UTF_8;
            t2.j.e(charset, "StandardCharsets.UTF_8");
            return new String(bArr, charset);
        } catch (IllegalAccessException e3) {
            throw new AssertionError(e3);
        } catch (NullPointerException e4) {
            if (t2.j.b(e4.getMessage(), "ssl == null")) {
                return null;
            }
            throw e4;
        } catch (InvocationTargetException e5) {
            throw new AssertionError(e5);
        }
    }

    @Override // M2.m
    public void d(SSLSocket sSLSocket, String str, List list) {
        t2.j.f(sSLSocket, "sslSocket");
        t2.j.f(list, "protocols");
        if (a(sSLSocket)) {
            try {
                this.f1818a.invoke(sSLSocket, Boolean.TRUE);
                if (str != null) {
                    this.f1819b.invoke(sSLSocket, str);
                }
                this.f1821d.invoke(sSLSocket, L2.j.f1746c.c(list));
            } catch (IllegalAccessException e3) {
                throw new AssertionError(e3);
            } catch (InvocationTargetException e4) {
                throw new AssertionError(e4);
            }
        }
    }
}
