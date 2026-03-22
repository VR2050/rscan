package p005b.p143g.p144a;

import android.content.ComponentCallbacks2;
import android.content.Context;
import android.content.res.Configuration;
import android.graphics.Bitmap;
import android.graphics.drawable.Drawable;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.view.View;
import androidx.annotation.CheckResult;
import androidx.annotation.GuardedBy;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.content.ContextCompat;
import com.bumptech.glide.load.resource.gif.GifDrawable;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;
import p005b.p143g.p144a.C1554d;
import p005b.p143g.p144a.p147m.p150t.AbstractC1643k;
import p005b.p143g.p144a.p163n.C1751e;
import p005b.p143g.p144a.p163n.C1752f;
import p005b.p143g.p144a.p163n.C1756j;
import p005b.p143g.p144a.p163n.C1760n;
import p005b.p143g.p144a.p163n.C1761o;
import p005b.p143g.p144a.p163n.InterfaceC1749c;
import p005b.p143g.p144a.p163n.InterfaceC1750d;
import p005b.p143g.p144a.p163n.InterfaceC1754h;
import p005b.p143g.p144a.p163n.InterfaceC1755i;
import p005b.p143g.p144a.p163n.InterfaceC1759m;
import p005b.p143g.p144a.p166q.C1779f;
import p005b.p143g.p144a.p166q.InterfaceC1775b;
import p005b.p143g.p144a.p166q.InterfaceC1778e;
import p005b.p143g.p144a.p166q.p167i.AbstractC1785d;
import p005b.p143g.p144a.p166q.p167i.InterfaceC1790i;
import p005b.p143g.p144a.p166q.p168j.InterfaceC1793b;
import p005b.p143g.p144a.p170s.C1807i;

/* renamed from: b.g.a.i */
/* loaded from: classes.dex */
public class ComponentCallbacks2C1559i implements ComponentCallbacks2, InterfaceC1755i {

    /* renamed from: c */
    public static final C1779f f1871c = new C1779f().mo1085h(Bitmap.class).mo1092s();

    /* renamed from: e */
    public static final C1779f f1872e = new C1779f().mo1085h(GifDrawable.class).mo1092s();

    /* renamed from: f */
    public final ComponentCallbacks2C1553c f1873f;

    /* renamed from: g */
    public final Context f1874g;

    /* renamed from: h */
    public final InterfaceC1754h f1875h;

    /* renamed from: i */
    @GuardedBy("this")
    public final C1760n f1876i;

    /* renamed from: j */
    @GuardedBy("this")
    public final InterfaceC1759m f1877j;

    /* renamed from: k */
    @GuardedBy("this")
    public final C1761o f1878k;

    /* renamed from: l */
    public final Runnable f1879l;

    /* renamed from: m */
    public final Handler f1880m;

    /* renamed from: n */
    public final InterfaceC1749c f1881n;

    /* renamed from: o */
    public final CopyOnWriteArrayList<InterfaceC1778e<Object>> f1882o;

    /* renamed from: p */
    @GuardedBy("this")
    public C1779f f1883p;

    /* renamed from: b.g.a.i$a */
    public class a implements Runnable {
        public a() {
        }

        @Override // java.lang.Runnable
        public void run() {
            ComponentCallbacks2C1559i componentCallbacks2C1559i = ComponentCallbacks2C1559i.this;
            componentCallbacks2C1559i.f1875h.mo1040a(componentCallbacks2C1559i);
        }
    }

    /* renamed from: b.g.a.i$b */
    public static class b extends AbstractC1785d<View, Object> {
        public b(@NonNull View view) {
            super(view);
        }

        @Override // p005b.p143g.p144a.p166q.p167i.InterfaceC1790i
        public void onLoadFailed(@Nullable Drawable drawable) {
        }

        @Override // p005b.p143g.p144a.p166q.p167i.InterfaceC1790i
        public void onResourceReady(@NonNull Object obj, @Nullable InterfaceC1793b<? super Object> interfaceC1793b) {
        }
    }

    /* renamed from: b.g.a.i$c */
    public class c implements InterfaceC1749c.a {

        /* renamed from: a */
        @GuardedBy("RequestManager.this")
        public final C1760n f1885a;

        public c(@NonNull C1760n c1760n) {
            this.f1885a = c1760n;
        }
    }

    static {
        C1779f.m1110L(AbstractC1643k.f2224c).mo1099z(EnumC1556f.LOW).mo1075E(true);
    }

    public ComponentCallbacks2C1559i(@NonNull ComponentCallbacks2C1553c componentCallbacks2C1553c, @NonNull InterfaceC1754h interfaceC1754h, @NonNull InterfaceC1759m interfaceC1759m, @NonNull Context context) {
        C1779f c1779f;
        C1760n c1760n = new C1760n();
        InterfaceC1750d interfaceC1750d = componentCallbacks2C1553c.f1817m;
        this.f1878k = new C1761o();
        a aVar = new a();
        this.f1879l = aVar;
        Handler handler = new Handler(Looper.getMainLooper());
        this.f1880m = handler;
        this.f1873f = componentCallbacks2C1553c;
        this.f1875h = interfaceC1754h;
        this.f1877j = interfaceC1759m;
        this.f1876i = c1760n;
        this.f1874g = context;
        Context applicationContext = context.getApplicationContext();
        c cVar = new c(c1760n);
        Objects.requireNonNull((C1752f) interfaceC1750d);
        boolean z = ContextCompat.checkSelfPermission(applicationContext, "android.permission.ACCESS_NETWORK_STATE") == 0;
        Log.isLoggable("ConnectivityMonitor", 3);
        InterfaceC1749c c1751e = z ? new C1751e(applicationContext, cVar) : new C1756j();
        this.f1881n = c1751e;
        if (C1807i.m1150g()) {
            handler.post(aVar);
        } else {
            interfaceC1754h.mo1040a(this);
        }
        interfaceC1754h.mo1040a(c1751e);
        this.f1882o = new CopyOnWriteArrayList<>(componentCallbacks2C1553c.f1813i.f1839f);
        C1555e c1555e = componentCallbacks2C1553c.f1813i;
        synchronized (c1555e) {
            if (c1555e.f1844k == null) {
                Objects.requireNonNull((C1554d.a) c1555e.f1838e);
                C1779f c1779f2 = new C1779f();
                c1779f2.f2675w = true;
                c1555e.f1844k = c1779f2;
            }
            c1779f = c1555e.f1844k;
        }
        mo779l(c1779f);
        synchronized (componentCallbacks2C1553c.f1818n) {
            if (componentCallbacks2C1553c.f1818n.contains(this)) {
                throw new IllegalStateException("Cannot register already registered manager");
            }
            componentCallbacks2C1553c.f1818n.add(this);
        }
    }

    @NonNull
    @CheckResult
    /* renamed from: a */
    public <ResourceType> C1558h<ResourceType> mo768a(@NonNull Class<ResourceType> cls) {
        return new C1558h<>(this.f1873f, this, cls, this.f1874g);
    }

    @NonNull
    @CheckResult
    /* renamed from: b */
    public C1558h<Bitmap> mo769b() {
        return mo768a(Bitmap.class).mo766a(f1871c);
    }

    @NonNull
    @CheckResult
    /* renamed from: c */
    public C1558h<Drawable> mo770c() {
        return mo768a(Drawable.class);
    }

    @NonNull
    @CheckResult
    /* renamed from: d */
    public C1558h<GifDrawable> mo771d() {
        return mo768a(GifDrawable.class).mo766a(f1872e);
    }

    /* renamed from: e */
    public void m772e(@Nullable InterfaceC1790i<?> interfaceC1790i) {
        boolean z;
        if (interfaceC1790i == null) {
            return;
        }
        boolean m780m = m780m(interfaceC1790i);
        InterfaceC1775b request = interfaceC1790i.getRequest();
        if (m780m) {
            return;
        }
        ComponentCallbacks2C1553c componentCallbacks2C1553c = this.f1873f;
        synchronized (componentCallbacks2C1553c.f1818n) {
            Iterator<ComponentCallbacks2C1559i> it = componentCallbacks2C1553c.f1818n.iterator();
            while (true) {
                if (!it.hasNext()) {
                    z = false;
                    break;
                } else if (it.next().m780m(interfaceC1790i)) {
                    z = true;
                    break;
                }
            }
        }
        if (z || request == null) {
            return;
        }
        interfaceC1790i.setRequest(null);
        request.clear();
    }

    @NonNull
    @CheckResult
    /* renamed from: f */
    public C1558h<Drawable> mo773f(@Nullable Drawable drawable) {
        return mo770c().mo759T(drawable);
    }

    @NonNull
    @CheckResult
    /* renamed from: g */
    public C1558h<Drawable> mo774g(@Nullable Object obj) {
        return mo770c().mo762W(obj);
    }

    @NonNull
    @CheckResult
    /* renamed from: h */
    public C1558h<Drawable> mo775h(@Nullable String str) {
        return mo770c().mo763X(str);
    }

    /* renamed from: i */
    public synchronized void m776i() {
        C1760n c1760n = this.f1876i;
        c1760n.f2634c = true;
        Iterator it = ((ArrayList) C1807i.m1148e(c1760n.f2632a)).iterator();
        while (it.hasNext()) {
            InterfaceC1775b interfaceC1775b = (InterfaceC1775b) it.next();
            if (interfaceC1775b.isRunning()) {
                interfaceC1775b.pause();
                c1760n.f2633b.add(interfaceC1775b);
            }
        }
    }

    /* renamed from: j */
    public synchronized void m777j() {
        C1760n c1760n = this.f1876i;
        c1760n.f2634c = false;
        Iterator it = ((ArrayList) C1807i.m1148e(c1760n.f2632a)).iterator();
        while (it.hasNext()) {
            InterfaceC1775b interfaceC1775b = (InterfaceC1775b) it.next();
            if (!interfaceC1775b.mo1102d() && !interfaceC1775b.isRunning()) {
                interfaceC1775b.mo1101c();
            }
        }
        c1760n.f2633b.clear();
    }

    @NonNull
    /* renamed from: k */
    public synchronized ComponentCallbacks2C1559i mo778k(@NonNull C1779f c1779f) {
        mo779l(c1779f);
        return this;
    }

    /* renamed from: l */
    public synchronized void mo779l(@NonNull C1779f c1779f) {
        this.f1883p = c1779f.clone().mo1082c();
    }

    /* renamed from: m */
    public synchronized boolean m780m(@NonNull InterfaceC1790i<?> interfaceC1790i) {
        InterfaceC1775b request = interfaceC1790i.getRequest();
        if (request == null) {
            return true;
        }
        if (!this.f1876i.m1060a(request)) {
            return false;
        }
        this.f1878k.f2635c.remove(interfaceC1790i);
        interfaceC1790i.setRequest(null);
        return true;
    }

    @Override // android.content.ComponentCallbacks
    public void onConfigurationChanged(Configuration configuration) {
    }

    @Override // p005b.p143g.p144a.p163n.InterfaceC1755i
    public synchronized void onDestroy() {
        this.f1878k.onDestroy();
        Iterator it = C1807i.m1148e(this.f1878k.f2635c).iterator();
        while (it.hasNext()) {
            m772e((InterfaceC1790i) it.next());
        }
        this.f1878k.f2635c.clear();
        C1760n c1760n = this.f1876i;
        Iterator it2 = ((ArrayList) C1807i.m1148e(c1760n.f2632a)).iterator();
        while (it2.hasNext()) {
            c1760n.m1060a((InterfaceC1775b) it2.next());
        }
        c1760n.f2633b.clear();
        this.f1875h.mo1041b(this);
        this.f1875h.mo1041b(this.f1881n);
        this.f1880m.removeCallbacks(this.f1879l);
        ComponentCallbacks2C1553c componentCallbacks2C1553c = this.f1873f;
        synchronized (componentCallbacks2C1553c.f1818n) {
            if (!componentCallbacks2C1553c.f1818n.contains(this)) {
                throw new IllegalStateException("Cannot unregister not yet registered manager");
            }
            componentCallbacks2C1553c.f1818n.remove(this);
        }
    }

    @Override // android.content.ComponentCallbacks
    public void onLowMemory() {
    }

    @Override // p005b.p143g.p144a.p163n.InterfaceC1755i
    public synchronized void onStart() {
        m777j();
        this.f1878k.onStart();
    }

    @Override // p005b.p143g.p144a.p163n.InterfaceC1755i
    public synchronized void onStop() {
        m776i();
        this.f1878k.onStop();
    }

    @Override // android.content.ComponentCallbacks2
    public void onTrimMemory(int i2) {
    }

    public synchronized String toString() {
        return super.toString() + "{tracker=" + this.f1876i + ", treeNode=" + this.f1877j + "}";
    }
}
