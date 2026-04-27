package H1;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CancellationException;
import java.util.concurrent.Executor;
import n1.InterfaceC0634a;

/* JADX INFO: loaded from: classes.dex */
public class d implements InterfaceC0634a {

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    public static final Executor f1034i = H1.c.f1033c;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    public static final Executor f1035j = H1.c.f1032b;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private static d f1036k = new d((Object) null);

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private static d f1037l = new d(Boolean.TRUE);

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private static d f1038m = new d(Boolean.FALSE);

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private static d f1039n = new d(true);

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private boolean f1041b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private boolean f1042c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private Object f1043d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private Exception f1044e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private boolean f1045f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private H1.f f1046g;

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Object f1040a = new Object();

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private List f1047h = new ArrayList();

    class a implements H1.a {
        a() {
        }

        @Override // H1.a
        /* JADX INFO: renamed from: b, reason: merged with bridge method [inline-methods] */
        public d a(d dVar) {
            return dVar.q() ? d.e() : dVar.s() ? d.l(dVar.n()) : d.m(null);
        }
    }

    class b implements Runnable {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ H1.e f1049b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ Callable f1050c;

        b(H1.e eVar, Callable callable) {
            this.f1049b = eVar;
            this.f1050c = callable;
        }

        @Override // java.lang.Runnable
        public void run() {
            try {
                this.f1049b.d(this.f1050c.call());
            } catch (CancellationException unused) {
                this.f1049b.b();
            } catch (Exception e3) {
                this.f1049b.c(e3);
            }
        }
    }

    class c implements H1.a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ H1.e f1051a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ H1.a f1052b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ Executor f1053c;

        c(H1.e eVar, H1.a aVar, Executor executor) {
            this.f1051a = eVar;
            this.f1052b = aVar;
            this.f1053c = executor;
        }

        @Override // H1.a
        /* JADX INFO: renamed from: b, reason: merged with bridge method [inline-methods] */
        public Void a(d dVar) {
            d.g(this.f1051a, this.f1052b, dVar, this.f1053c);
            return null;
        }
    }

    /* JADX INFO: renamed from: H1.d$d, reason: collision with other inner class name */
    class C0017d implements H1.a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ H1.e f1055a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ H1.a f1056b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ Executor f1057c;

        C0017d(H1.e eVar, H1.a aVar, Executor executor) {
            this.f1055a = eVar;
            this.f1056b = aVar;
            this.f1057c = executor;
        }

        @Override // H1.a
        /* JADX INFO: renamed from: b, reason: merged with bridge method [inline-methods] */
        public Void a(d dVar) {
            d.f(this.f1055a, this.f1056b, dVar, this.f1057c);
            return null;
        }
    }

    class e implements H1.a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ H1.a f1059a;

        e(H1.a aVar) {
            this.f1059a = aVar;
        }

        @Override // H1.a
        /* JADX INFO: renamed from: b, reason: merged with bridge method [inline-methods] */
        public d a(d dVar) {
            return dVar.s() ? d.l(dVar.n()) : dVar.q() ? d.e() : dVar.h(this.f1059a);
        }
    }

    class f implements H1.a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ H1.a f1061a;

        f(H1.a aVar) {
            this.f1061a = aVar;
        }

        @Override // H1.a
        /* JADX INFO: renamed from: b, reason: merged with bridge method [inline-methods] */
        public d a(d dVar) {
            return dVar.s() ? d.l(dVar.n()) : dVar.q() ? d.e() : dVar.j(this.f1061a);
        }
    }

    class g implements Runnable {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ H1.a f1063b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ d f1064c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final /* synthetic */ H1.e f1065d;

        g(H1.a aVar, d dVar, H1.e eVar) {
            this.f1063b = aVar;
            this.f1064c = dVar;
            this.f1065d = eVar;
        }

        @Override // java.lang.Runnable
        public void run() {
            try {
                this.f1065d.d(this.f1063b.a(this.f1064c));
            } catch (CancellationException unused) {
                this.f1065d.b();
            } catch (Exception e3) {
                this.f1065d.c(e3);
            }
        }
    }

    class h implements Runnable {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ H1.a f1066b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ d f1067c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final /* synthetic */ H1.e f1068d;

        class a implements H1.a {
            a() {
            }

            @Override // H1.a
            /* JADX INFO: renamed from: b, reason: merged with bridge method [inline-methods] */
            public Void a(d dVar) {
                if (dVar.q()) {
                    h.this.f1068d.b();
                    return null;
                }
                if (dVar.s()) {
                    h.this.f1068d.c(dVar.n());
                    return null;
                }
                h.this.f1068d.d(dVar.o());
                return null;
            }
        }

        h(H1.a aVar, d dVar, H1.e eVar) {
            this.f1066b = aVar;
            this.f1067c = dVar;
            this.f1068d = eVar;
        }

        @Override // java.lang.Runnable
        public void run() {
            try {
                d dVar = (d) this.f1066b.a(this.f1067c);
                if (dVar == null) {
                    this.f1068d.d(null);
                } else {
                    dVar.h(new a());
                }
            } catch (CancellationException unused) {
                this.f1068d.b();
            } catch (Exception e3) {
                this.f1068d.c(e3);
            }
        }
    }

    public interface i {
    }

    d() {
    }

    public static d c(Callable callable) {
        return d(callable, f1034i);
    }

    public static d d(Callable callable, Executor executor) {
        H1.e eVar = new H1.e();
        try {
            executor.execute(new b(eVar, callable));
        } catch (Exception e3) {
            eVar.c(new H1.b(e3));
        }
        return eVar.a();
    }

    public static d e() {
        return f1039n;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static void f(H1.e eVar, H1.a aVar, d dVar, Executor executor) {
        try {
            executor.execute(new h(aVar, dVar, eVar));
        } catch (Exception e3) {
            eVar.c(new H1.b(e3));
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static void g(H1.e eVar, H1.a aVar, d dVar, Executor executor) {
        try {
            executor.execute(new g(aVar, dVar, eVar));
        } catch (Exception e3) {
            eVar.c(new H1.b(e3));
        }
    }

    public static d l(Exception exc) {
        H1.e eVar = new H1.e();
        eVar.c(exc);
        return eVar.a();
    }

    public static d m(Object obj) {
        if (obj == null) {
            return f1036k;
        }
        if (obj instanceof Boolean) {
            return ((Boolean) obj).booleanValue() ? f1037l : f1038m;
        }
        H1.e eVar = new H1.e();
        eVar.d(obj);
        return eVar.a();
    }

    public static i p() {
        return null;
    }

    private void w() {
        synchronized (this.f1040a) {
            Iterator it = this.f1047h.iterator();
            while (it.hasNext()) {
                try {
                    ((H1.a) it.next()).a(this);
                } catch (RuntimeException e3) {
                    throw e3;
                } catch (Exception e4) {
                    throw new RuntimeException(e4);
                }
            }
            this.f1047h = null;
        }
    }

    public d h(H1.a aVar) {
        return i(aVar, f1034i);
    }

    public d i(H1.a aVar, Executor executor) {
        boolean zR;
        H1.e eVar = new H1.e();
        synchronized (this.f1040a) {
            try {
                zR = r();
                if (!zR) {
                    this.f1047h.add(new c(eVar, aVar, executor));
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        if (zR) {
            g(eVar, aVar, this, executor);
        }
        return eVar.a();
    }

    public d j(H1.a aVar) {
        return k(aVar, f1034i);
    }

    public d k(H1.a aVar, Executor executor) {
        boolean zR;
        H1.e eVar = new H1.e();
        synchronized (this.f1040a) {
            try {
                zR = r();
                if (!zR) {
                    this.f1047h.add(new C0017d(eVar, aVar, executor));
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        if (zR) {
            f(eVar, aVar, this, executor);
        }
        return eVar.a();
    }

    public Exception n() {
        Exception exc;
        synchronized (this.f1040a) {
            try {
                if (this.f1044e != null) {
                    this.f1045f = true;
                }
                exc = this.f1044e;
            } catch (Throwable th) {
                throw th;
            }
        }
        return exc;
    }

    public Object o() {
        Object obj;
        synchronized (this.f1040a) {
            obj = this.f1043d;
        }
        return obj;
    }

    public boolean q() {
        boolean z3;
        synchronized (this.f1040a) {
            z3 = this.f1042c;
        }
        return z3;
    }

    public boolean r() {
        boolean z3;
        synchronized (this.f1040a) {
            z3 = this.f1041b;
        }
        return z3;
    }

    public boolean s() {
        boolean z3;
        synchronized (this.f1040a) {
            z3 = n() != null;
        }
        return z3;
    }

    public d t() {
        return j(new a());
    }

    public d u(H1.a aVar, Executor executor) {
        return k(new e(aVar), executor);
    }

    public d v(H1.a aVar, Executor executor) {
        return k(new f(aVar), executor);
    }

    boolean x() {
        synchronized (this.f1040a) {
            try {
                if (this.f1041b) {
                    return false;
                }
                this.f1041b = true;
                this.f1042c = true;
                this.f1040a.notifyAll();
                w();
                return true;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    boolean y(Exception exc) {
        synchronized (this.f1040a) {
            try {
                if (this.f1041b) {
                    return false;
                }
                this.f1041b = true;
                this.f1044e = exc;
                this.f1045f = false;
                this.f1040a.notifyAll();
                w();
                if (!this.f1045f) {
                    p();
                }
                return true;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    boolean z(Object obj) {
        synchronized (this.f1040a) {
            try {
                if (this.f1041b) {
                    return false;
                }
                this.f1041b = true;
                this.f1043d = obj;
                this.f1040a.notifyAll();
                w();
                return true;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    private d(Object obj) {
        z(obj);
    }

    private d(boolean z3) {
        if (z3) {
            x();
        } else {
            z(null);
        }
    }
}
