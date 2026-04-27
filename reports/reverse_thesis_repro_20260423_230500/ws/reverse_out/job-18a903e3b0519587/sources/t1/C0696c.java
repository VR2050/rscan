package t1;

import android.util.SparseArray;
import com.facebook.react.bridge.ReactContext;
import com.facebook.react.bridge.UiThreadUtil;
import java.lang.ref.WeakReference;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.WeakHashMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.atomic.AtomicInteger;
import kotlin.jvm.internal.DefaultConstructorMarker;
import t2.j;

/* JADX INFO: renamed from: t1.c, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0696c {

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    public static final a f10181g = new a(null);

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private static final WeakHashMap f10182h = new WeakHashMap();

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final WeakReference f10183a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final Set f10184b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final AtomicInteger f10185c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final Set f10186d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final Map f10187e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final SparseArray f10188f;

    /* JADX INFO: renamed from: t1.c$a */
    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final C0696c a(ReactContext reactContext) {
            j.f(reactContext, "context");
            WeakHashMap weakHashMap = C0696c.f10182h;
            Object c0696c = weakHashMap.get(reactContext);
            if (c0696c == null) {
                c0696c = new C0696c(reactContext, null);
                weakHashMap.put(reactContext, c0696c);
            }
            return (C0696c) c0696c;
        }

        private a() {
        }
    }

    public /* synthetic */ C0696c(ReactContext reactContext, DefaultConstructorMarker defaultConstructorMarker) {
        this(reactContext);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void e(C0696c c0696c, int i3) {
        Iterator it = c0696c.f10184b.iterator();
        while (it.hasNext()) {
            ((InterfaceC0697d) it.next()).b(i3);
        }
    }

    private final void i(int i3) {
        Runnable runnable = (Runnable) this.f10188f.get(i3);
        if (runnable != null) {
            UiThreadUtil.removeOnUiThread(runnable);
            this.f10188f.remove(i3);
        }
    }

    public final synchronized void c(InterfaceC0697d interfaceC0697d) {
        j.f(interfaceC0697d, "listener");
        this.f10184b.add(interfaceC0697d);
        Iterator it = this.f10186d.iterator();
        while (it.hasNext()) {
            interfaceC0697d.a(((Number) it.next()).intValue());
        }
    }

    public final synchronized void d(final int i3) {
        boolean zRemove = this.f10186d.remove(Integer.valueOf(i3));
        this.f10187e.remove(Integer.valueOf(i3));
        i(i3);
        if (zRemove) {
            UiThreadUtil.runOnUiThread(new Runnable() { // from class: t1.b
                @Override // java.lang.Runnable
                public final void run() {
                    C0696c.e(this.f10179b, i3);
                }
            });
        }
    }

    public final boolean f() {
        return !this.f10186d.isEmpty();
    }

    public final synchronized boolean g(int i3) {
        return this.f10186d.contains(Integer.valueOf(i3));
    }

    public final void h(InterfaceC0697d interfaceC0697d) {
        j.f(interfaceC0697d, "listener");
        this.f10184b.remove(interfaceC0697d);
    }

    public final synchronized boolean j(int i3) {
        throw new IllegalStateException(("Tried to retrieve non-existent task config with id " + i3 + ".").toString());
    }

    private C0696c(ReactContext reactContext) {
        this.f10183a = new WeakReference(reactContext);
        this.f10184b = new CopyOnWriteArraySet();
        this.f10185c = new AtomicInteger(0);
        this.f10186d = new CopyOnWriteArraySet();
        this.f10187e = new ConcurrentHashMap();
        this.f10188f = new SparseArray();
    }
}
