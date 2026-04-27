package c1;

import android.app.Application;
import c1.Q;
import com.facebook.react.bridge.JSExceptionHandler;
import com.facebook.react.bridge.JavaScriptExecutorFactory;
import com.facebook.react.bridge.ReactMarker;
import com.facebook.react.bridge.ReactMarkerConstants;
import com.facebook.react.bridge.UIManagerProvider;
import com.facebook.react.common.LifecycleState;
import j1.InterfaceC0594c;
import java.util.Iterator;
import java.util.List;
import p1.InterfaceC0648b;

/* JADX INFO: loaded from: classes.dex */
public abstract class K {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Application f5508a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private G f5509b;

    class a implements d1.k {
        a() {
        }

        @Override // d1.k
        public d1.j f(String str) {
            return null;
        }
    }

    protected K(Application application) {
        this.f5508a = application;
    }

    protected G a() {
        ReactMarker.logMarker(ReactMarkerConstants.BUILD_REACT_INSTANCE_MANAGER_START);
        J jB = b();
        ReactMarker.logMarker(ReactMarkerConstants.BUILD_REACT_INSTANCE_MANAGER_END);
        return jB.b();
    }

    protected J b() {
        J jP = G.u().d(this.f5508a).n(j()).w(u()).h(f()).g(e()).t(r()).u(s()).m(i()).p(l());
        q();
        J jQ = jP.s(null).o(k()).v(t()).i(LifecycleState.f6642b).r(p()).l(h()).f(d()).q(n());
        Iterator it = m().iterator();
        while (it.hasNext()) {
            jQ.a((L) it.next());
        }
        String strG = g();
        if (strG != null) {
            jQ.j(strG);
        } else {
            jQ.e((String) Z0.a.c(c()));
        }
        return jQ;
    }

    protected String c() {
        return "index.android.bundle";
    }

    protected InterfaceC0648b d() {
        return null;
    }

    protected InterfaceC0594c e() {
        return null;
    }

    protected com.facebook.react.devsupport.H f() {
        return null;
    }

    protected String g() {
        return null;
    }

    protected abstract EnumC0334f h();

    protected JSExceptionHandler i() {
        return null;
    }

    protected abstract String j();

    protected JavaScriptExecutorFactory k() {
        return null;
    }

    public boolean l() {
        return false;
    }

    protected abstract List m();

    protected j1.h n() {
        return null;
    }

    public synchronized G o() {
        try {
            if (this.f5509b == null) {
                ReactMarker.logMarker(ReactMarkerConstants.INIT_REACT_RUNTIME_START);
                ReactMarker.logMarker(ReactMarkerConstants.GET_REACT_INSTANCE_MANAGER_START);
                this.f5509b = a();
                ReactMarker.logMarker(ReactMarkerConstants.GET_REACT_INSTANCE_MANAGER_END);
            }
        } catch (Throwable th) {
            throw th;
        }
        return this.f5509b;
    }

    protected abstract Q.a p();

    protected j1.i q() {
        return null;
    }

    public boolean r() {
        return true;
    }

    public d1.k s() {
        return new a();
    }

    protected abstract UIManagerProvider t();

    public abstract boolean u();

    public synchronized boolean v() {
        return this.f5509b != null;
    }
}
