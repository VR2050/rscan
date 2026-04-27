package c1;

import android.app.Activity;
import android.app.Application;
import android.content.Context;
import c1.Q;
import com.facebook.hermes.reactexecutor.HermesExecutor;
import com.facebook.react.bridge.JSBundleLoader;
import com.facebook.react.bridge.JSExceptionHandler;
import com.facebook.react.bridge.JavaScriptExecutorFactory;
import com.facebook.react.bridge.NotThreadSafeBridgeIdleDebugListener;
import com.facebook.react.bridge.UIManagerProvider;
import com.facebook.react.common.LifecycleState;
import com.facebook.react.devsupport.C0391i;
import com.facebook.react.jscexecutor.JSCExecutor;
import j1.InterfaceC0593b;
import j1.InterfaceC0594c;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import p1.InterfaceC0648b;
import s1.C0687a;

/* JADX INFO: loaded from: classes.dex */
public class J {

    /* JADX INFO: renamed from: B, reason: collision with root package name */
    private static final String f5480B = "J";

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private String f5483b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private JSBundleLoader f5484c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private String f5485d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private NotThreadSafeBridgeIdleDebugListener f5486e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private Application f5487f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private boolean f5488g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private com.facebook.react.devsupport.H f5489h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private boolean f5490i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private boolean f5491j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private LifecycleState f5492k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private JSExceptionHandler f5493l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private Activity f5494m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private A1.a f5495n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private boolean f5496o;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private InterfaceC0593b f5497p;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private JavaScriptExecutorFactory f5498q;

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    private UIManagerProvider f5501t;

    /* JADX INFO: renamed from: u, reason: collision with root package name */
    private Map f5502u;

    /* JADX INFO: renamed from: v, reason: collision with root package name */
    private Q.a f5503v;

    /* JADX INFO: renamed from: w, reason: collision with root package name */
    private d1.k f5504w;

    /* JADX INFO: renamed from: x, reason: collision with root package name */
    private InterfaceC0594c f5505x;

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final List f5482a = new ArrayList();

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    private int f5499r = 1;

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    private int f5500s = -1;

    /* JADX INFO: renamed from: y, reason: collision with root package name */
    private EnumC0334f f5506y = null;

    /* JADX INFO: renamed from: z, reason: collision with root package name */
    private InterfaceC0648b f5507z = null;

    /* JADX INFO: renamed from: A, reason: collision with root package name */
    private j1.h f5481A = null;

    J() {
    }

    private JavaScriptExecutorFactory c(String str, String str2, Context context) {
        G.J(context);
        EnumC0334f enumC0334f = this.f5506y;
        if (enumC0334f != null) {
            if (enumC0334f == EnumC0334f.f5564c) {
                HermesExecutor.e();
                return new B0.a();
            }
            JSCExecutor.b();
            return new C0687a(str, str2);
        }
        try {
            try {
                HermesExecutor.e();
                return new B0.a();
            } catch (UnsatisfiedLinkError unused) {
                JSCExecutor.b();
                return new C0687a(str, str2);
            }
        } catch (UnsatisfiedLinkError e3) {
            Y.a.m(f5480B, "Unable to load neither the Hermes nor the JSC native library. Your application is not built correctly and will fail to execute");
            if (e3.getMessage().contains("__cxa_bad_typeid")) {
                throw e3;
            }
            return null;
        }
    }

    public J a(L l3) {
        this.f5482a.add(l3);
        return this;
    }

    public G b() {
        String str;
        Z0.a.d(this.f5487f, "Application property has not been set with this builder");
        if (this.f5492k == LifecycleState.f6644d) {
            Z0.a.d(this.f5494m, "Activity needs to be set if initial lifecycle state is resumed");
        }
        boolean z3 = true;
        Z0.a.b((!this.f5488g && this.f5483b == null && this.f5484c == null) ? false : true, "JS Bundle File or Asset URL has to be provided when dev support is disabled");
        if (this.f5485d == null && this.f5483b == null && this.f5484c == null) {
            z3 = false;
        }
        Z0.a.b(z3, "Either MainModulePath or JS Bundle File needs to be provided");
        String packageName = this.f5487f.getPackageName();
        String strD = com.facebook.react.modules.systeminfo.a.d();
        Application application = this.f5487f;
        Activity activity = this.f5494m;
        A1.a aVar = this.f5495n;
        JavaScriptExecutorFactory javaScriptExecutorFactory = this.f5498q;
        JavaScriptExecutorFactory javaScriptExecutorFactoryC = javaScriptExecutorFactory == null ? c(packageName, strD, application.getApplicationContext()) : javaScriptExecutorFactory;
        JSBundleLoader jSBundleLoaderCreateAssetLoader = this.f5484c;
        if (jSBundleLoaderCreateAssetLoader == null && (str = this.f5483b) != null) {
            jSBundleLoaderCreateAssetLoader = JSBundleLoader.createAssetLoader(this.f5487f, str, false);
        }
        JSBundleLoader jSBundleLoader = jSBundleLoaderCreateAssetLoader;
        String str2 = this.f5485d;
        List list = this.f5482a;
        boolean z4 = this.f5488g;
        com.facebook.react.devsupport.H c0391i = this.f5489h;
        if (c0391i == null) {
            c0391i = new C0391i();
        }
        return new G(application, activity, aVar, javaScriptExecutorFactoryC, jSBundleLoader, str2, list, z4, c0391i, this.f5490i, this.f5491j, this.f5486e, (LifecycleState) Z0.a.d(this.f5492k, "Initial lifecycle state was not set"), this.f5493l, null, this.f5496o, this.f5497p, this.f5499r, this.f5500s, this.f5501t, this.f5502u, this.f5503v, this.f5504w, this.f5505x, this.f5507z, this.f5481A);
    }

    public J d(Application application) {
        this.f5487f = application;
        return this;
    }

    public J e(String str) {
        String str2;
        if (str == null) {
            str2 = null;
        } else {
            str2 = "assets://" + str;
        }
        this.f5483b = str2;
        this.f5484c = null;
        return this;
    }

    public J f(InterfaceC0648b interfaceC0648b) {
        this.f5507z = interfaceC0648b;
        return this;
    }

    public J g(InterfaceC0594c interfaceC0594c) {
        this.f5505x = interfaceC0594c;
        return this;
    }

    public J h(com.facebook.react.devsupport.H h3) {
        this.f5489h = h3;
        return this;
    }

    public J i(LifecycleState lifecycleState) {
        this.f5492k = lifecycleState;
        return this;
    }

    public J j(String str) {
        if (!str.startsWith("assets://")) {
            return k(JSBundleLoader.createFileLoader(str));
        }
        this.f5483b = str;
        this.f5484c = null;
        return this;
    }

    public J k(JSBundleLoader jSBundleLoader) {
        this.f5484c = jSBundleLoader;
        this.f5483b = null;
        return this;
    }

    public J l(EnumC0334f enumC0334f) {
        this.f5506y = enumC0334f;
        return this;
    }

    public J m(JSExceptionHandler jSExceptionHandler) {
        this.f5493l = jSExceptionHandler;
        return this;
    }

    public J n(String str) {
        this.f5485d = str;
        return this;
    }

    public J o(JavaScriptExecutorFactory javaScriptExecutorFactory) {
        this.f5498q = javaScriptExecutorFactory;
        return this;
    }

    public J p(boolean z3) {
        this.f5496o = z3;
        return this;
    }

    public J q(j1.h hVar) {
        this.f5481A = hVar;
        return this;
    }

    public J r(Q.a aVar) {
        this.f5503v = aVar;
        return this;
    }

    public J t(boolean z3) {
        this.f5490i = z3;
        return this;
    }

    public J u(d1.k kVar) {
        this.f5504w = kVar;
        return this;
    }

    public J v(UIManagerProvider uIManagerProvider) {
        this.f5501t = uIManagerProvider;
        return this;
    }

    public J w(boolean z3) {
        this.f5488g = z3;
        return this;
    }

    public J s(j1.i iVar) {
        return this;
    }
}
