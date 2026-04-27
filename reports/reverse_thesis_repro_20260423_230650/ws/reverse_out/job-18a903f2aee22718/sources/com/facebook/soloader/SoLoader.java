package com.facebook.soloader;

import a2.AbstractC0226b;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.os.Bundle;
import android.os.StrictMode;
import android.text.TextUtils;
import b2.C0318f;
import b2.InterfaceC0320h;
import b2.InterfaceC0321i;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/* JADX INFO: loaded from: classes.dex */
public class SoLoader {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    static x f8328b;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private static int f8339m;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private static final ReentrantReadWriteLock f8329c = new ReentrantReadWriteLock();

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    static Context f8330d = null;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private static volatile E[] f8331e = null;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private static final AtomicInteger f8332f = new AtomicInteger(0);

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private static InterfaceC0321i f8333g = null;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private static final Set f8334h = Collections.newSetFromMap(new ConcurrentHashMap());

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private static final Map f8335i = new HashMap();

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private static final Set f8336j = Collections.newSetFromMap(new ConcurrentHashMap());

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private static final Map f8337k = new HashMap();

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private static boolean f8338l = true;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private static int f8340n = 0;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private static l f8341o = null;

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    static final boolean f8327a = true;

    public static final class a extends UnsatisfiedLinkError {
        a(Throwable th, String str) {
            super("APK was built for a different platform. Supported ABIs: " + Arrays.toString(SysUtil.j()) + " error: " + str);
            initCause(th);
        }
    }

    private static int A() {
        ReentrantReadWriteLock reentrantReadWriteLock = f8329c;
        reentrantReadWriteLock.writeLock().lock();
        try {
            int i3 = f8339m;
            int i4 = (i3 & 2) != 0 ? 1 : 0;
            if ((i3 & 256) != 0) {
                i4 |= 4;
            }
            if ((i3 & 128) == 0) {
                i4 |= 8;
            }
            reentrantReadWriteLock.writeLock().unlock();
            return i4;
        } catch (Throwable th) {
            f8329c.writeLock().unlock();
            throw th;
        }
    }

    private static int B(int i3) {
        return (i3 & 2048) != 0 ? 1 : 0;
    }

    private static InterfaceC0320h C(String str, UnsatisfiedLinkError unsatisfiedLinkError, InterfaceC0320h interfaceC0320h) {
        p.g("SoLoader", "Running a recovery step for " + str + " due to " + unsatisfiedLinkError.toString());
        ReentrantReadWriteLock reentrantReadWriteLock = f8329c;
        reentrantReadWriteLock.writeLock().lock();
        try {
            if (interfaceC0320h == null) {
                try {
                    interfaceC0320h = j();
                    if (interfaceC0320h == null) {
                        p.g("SoLoader", "No recovery strategy");
                        throw unsatisfiedLinkError;
                    }
                } catch (v e3) {
                    p.c("SoLoader", "Base APK not found during recovery", e3);
                    throw e3;
                } catch (Exception e4) {
                    p.c("SoLoader", "Got an exception during recovery, will throw the initial error instead", e4);
                    throw unsatisfiedLinkError;
                }
            }
            if (D(unsatisfiedLinkError, interfaceC0320h)) {
                f8332f.getAndIncrement();
                reentrantReadWriteLock.writeLock().unlock();
                return interfaceC0320h;
            }
            reentrantReadWriteLock.writeLock().unlock();
            p.g("SoLoader", "Failed to recover");
            throw unsatisfiedLinkError;
        } catch (Throwable th) {
            f8329c.writeLock().unlock();
            throw th;
        }
    }

    private static boolean D(UnsatisfiedLinkError unsatisfiedLinkError, InterfaceC0320h interfaceC0320h) {
        AbstractC0226b.h(interfaceC0320h);
        try {
            boolean zA = interfaceC0320h.a(unsatisfiedLinkError, f8331e);
            AbstractC0226b.g(null);
            return zA;
        } finally {
        }
    }

    private static void a(ArrayList arrayList, int i3) {
        C0495a c0495a = new C0495a(f8330d, i3);
        p.a("SoLoader", "Adding application source: " + c0495a.toString());
        arrayList.add(0, c0495a);
    }

    private static void b(Context context, ArrayList arrayList, boolean z3) {
        if ((f8339m & 8) != 0) {
            return;
        }
        arrayList.add(0, new C0497c(context, "lib-main", !z3));
    }

    private static void c(Context context, ArrayList arrayList) {
        C0498d c0498d = new C0498d(context);
        p.a("SoLoader", "validating/adding directApk source: " + c0498d.toString());
        if (c0498d.o()) {
            arrayList.add(0, c0498d);
        }
    }

    private static void d(ArrayList arrayList) {
        String str = SysUtil.k() ? "/system/lib64:/vendor/lib64" : "/system/lib:/vendor/lib";
        String str2 = System.getenv("LD_LIBRARY_PATH");
        if (str2 != null && !str2.equals("")) {
            str = str2 + ":" + str;
        }
        for (String str3 : new HashSet(Arrays.asList(str.split(":")))) {
            p.a("SoLoader", "adding system library source: " + str3);
            arrayList.add(new C0500f(new File(str3), 2));
        }
    }

    private static void e(Context context, ArrayList arrayList) {
        F f3 = new F();
        p.a("SoLoader", "adding systemLoadWrapper source: " + f3);
        arrayList.add(0, f3);
    }

    private static void f() {
        if (!r()) {
            throw new IllegalStateException("SoLoader.init() not yet called");
        }
    }

    private static void g(String str, String str2, int i3, StrictMode.ThreadPolicy threadPolicy) {
        boolean z3;
        ReentrantReadWriteLock reentrantReadWriteLock = f8329c;
        reentrantReadWriteLock.readLock().lock();
        try {
            if (f8331e == null) {
                p.b("SoLoader", "Could not load: " + str + " because SoLoader is not initialized");
                throw new UnsatisfiedLinkError("SoLoader not initialized, couldn't find DSO to load: " + str);
            }
            reentrantReadWriteLock.readLock().unlock();
            if (threadPolicy == null) {
                threadPolicy = StrictMode.allowThreadDiskReads();
                z3 = true;
            } else {
                z3 = false;
            }
            if (f8327a) {
                if (str2 != null) {
                    Api18TraceUtils.a("SoLoader.loadLibrary[", str2, "]");
                }
                Api18TraceUtils.a("SoLoader.loadLibrary[", str, "]");
            }
            try {
                reentrantReadWriteLock.readLock().lock();
                try {
                    try {
                        for (E e3 : f8331e) {
                            if (x(e3, str, i3, threadPolicy)) {
                                if (z3) {
                                    return;
                                } else {
                                    return;
                                }
                            }
                        }
                        throw B.b(str, f8330d, f8331e);
                    } catch (IOException e4) {
                        C c3 = new C(str, e4.toString());
                        c3.initCause(e4);
                        throw c3;
                    }
                } finally {
                }
            } finally {
                if (f8327a) {
                    if (str2 != null) {
                        Api18TraceUtils.b();
                    }
                    Api18TraceUtils.b();
                }
                if (z3) {
                    StrictMode.setThreadPolicy(threadPolicy);
                }
            }
        } finally {
        }
    }

    private static int h(Context context) {
        int i3 = f8340n;
        if (i3 != 0) {
            return i3;
        }
        if (context == null) {
            p.a("SoLoader", "context is null, fallback to THIRD_PARTY_APP appType");
            return 1;
        }
        ApplicationInfo applicationInfo = context.getApplicationInfo();
        int i4 = applicationInfo.flags;
        int i5 = (i4 & 1) != 0 ? (i4 & 128) != 0 ? 3 : 2 : 1;
        p.a("SoLoader", "ApplicationInfo.flags is: " + applicationInfo.flags + " appType is: " + i5);
        return i5;
    }

    private static int i() {
        int i3 = f8340n;
        if (i3 == 1) {
            return 0;
        }
        if (i3 == 2 || i3 == 3) {
            return 1;
        }
        throw new RuntimeException("Unsupported app type, we should not reach here");
    }

    public static void init(Context context, int i3) {
        k(context, i3, null);
    }

    private static synchronized InterfaceC0320h j() {
        InterfaceC0321i interfaceC0321i;
        interfaceC0321i = f8333g;
        return interfaceC0321i == null ? null : interfaceC0321i.get();
    }

    public static void k(Context context, int i3, x xVar) {
        if (r()) {
            p.g("SoLoader", "SoLoader already initialized");
            return;
        }
        p.g("SoLoader", "Initializing SoLoader: " + i3);
        StrictMode.ThreadPolicy threadPolicyAllowThreadDiskWrites = StrictMode.allowThreadDiskWrites();
        try {
            boolean zO = o(context);
            f8338l = zO;
            if (zO) {
                int iH = h(context);
                f8340n = iH;
                if ((i3 & 128) == 0 && SysUtil.l(context, iH)) {
                    i3 |= 8;
                }
                p(context, xVar, i3);
                q(context, i3);
                p.f("SoLoader", "Init SoLoader delegate");
                Z1.a.b(new u());
            } else {
                n();
                p.f("SoLoader", "Init System Loader delegate");
                Z1.a.b(new Z1.c());
            }
            p.g("SoLoader", "SoLoader initialized: " + i3);
            StrictMode.setThreadPolicy(threadPolicyAllowThreadDiskWrites);
        } catch (Throwable th) {
            StrictMode.setThreadPolicy(threadPolicyAllowThreadDiskWrites);
            throw th;
        }
    }

    public static void l(Context context, l lVar) {
        synchronized (SoLoader.class) {
            f8341o = lVar;
        }
        init(context, 0);
    }

    public static void m(Context context, boolean z3) {
        try {
            k(context, z3 ? 1 : 0, null);
        } catch (IOException e3) {
            throw new RuntimeException(e3);
        }
    }

    private static void n() {
        if (f8331e != null) {
            return;
        }
        ReentrantReadWriteLock reentrantReadWriteLock = f8329c;
        reentrantReadWriteLock.writeLock().lock();
        try {
            if (f8331e != null) {
                reentrantReadWriteLock.writeLock().unlock();
            } else {
                f8331e = new E[0];
                reentrantReadWriteLock.writeLock().unlock();
            }
        } catch (Throwable th) {
            f8329c.writeLock().unlock();
            throw th;
        }
    }

    private static boolean o(Context context) {
        String packageName;
        if (f8341o != null) {
            return true;
        }
        Bundle bundle = null;
        try {
            packageName = context.getPackageName();
        } catch (Exception e3) {
            e = e3;
            packageName = null;
        }
        try {
            bundle = context.getPackageManager().getApplicationInfo(packageName, 128).metaData;
        } catch (Exception e4) {
            e = e4;
            p.h("SoLoader", "Unexpected issue with package manager (" + packageName + ")", e);
        }
        return bundle == null || bundle.getBoolean("com.facebook.soloader.enabled", true);
    }

    private static synchronized void p(Context context, x xVar, int i3) {
        if (context != null) {
            try {
                Context applicationContext = context.getApplicationContext();
                if (applicationContext == null) {
                    p.g("SoLoader", "context.getApplicationContext returned null, holding reference to original context.ApplicationSoSource fallbacks to: " + context.getApplicationInfo().nativeLibraryDir);
                } else {
                    context = applicationContext;
                }
                f8330d = context;
                f8333g = new C0318f(context, B(i3));
            } catch (Throwable th) {
                throw th;
            }
        }
        if (xVar != null || f8328b == null) {
            if (xVar != null) {
                f8328b = xVar;
            } else {
                f8328b = new o(new y());
            }
        }
    }

    private static void q(Context context, int i3) {
        if (f8331e != null) {
            return;
        }
        ReentrantReadWriteLock reentrantReadWriteLock = f8329c;
        reentrantReadWriteLock.writeLock().lock();
        try {
            if (f8331e != null) {
                reentrantReadWriteLock.writeLock().unlock();
                return;
            }
            f8339m = i3;
            ArrayList arrayList = new ArrayList();
            boolean z3 = true;
            boolean z4 = (i3 & 512) != 0;
            boolean z5 = (i3 & 1024) != 0;
            if (z4) {
                e(context, arrayList);
            } else if (z5) {
                d(arrayList);
                arrayList.add(0, new C0499e("base"));
            } else {
                d(arrayList);
                if (context != null) {
                    if ((i3 & 1) != 0) {
                        a(arrayList, i());
                        p.a("SoLoader", "Adding exo package source: lib-main");
                        arrayList.add(0, new k(context, "lib-main"));
                    } else {
                        if (SysUtil.l(context, f8340n)) {
                            c(context, arrayList);
                        }
                        a(arrayList, i());
                        if ((i3 & 4096) == 0) {
                            z3 = false;
                        }
                        b(context, arrayList, z3);
                    }
                }
            }
            E[] eArr = (E[]) arrayList.toArray(new E[arrayList.size()]);
            int iA = A();
            int length = eArr.length;
            while (true) {
                int i4 = length - 1;
                if (length <= 0) {
                    f8331e = eArr;
                    f8332f.getAndIncrement();
                    p.d("SoLoader", "init finish: " + f8331e.length + " SO sources prepared");
                    f8329c.writeLock().unlock();
                    return;
                }
                p.d("SoLoader", "Preparing SO source: " + eArr[i4]);
                boolean z6 = f8327a;
                if (z6) {
                    Api18TraceUtils.a("SoLoader", "_", eArr[i4].getClass().getSimpleName());
                }
                eArr[i4].e(iA);
                if (z6) {
                    Api18TraceUtils.b();
                }
                length = i4;
            }
        } catch (Throwable th) {
            f8329c.writeLock().unlock();
            throw th;
        }
    }

    public static boolean r() {
        if (f8331e != null) {
            return true;
        }
        ReentrantReadWriteLock reentrantReadWriteLock = f8329c;
        reentrantReadWriteLock.readLock().lock();
        try {
            boolean z3 = f8331e != null;
            reentrantReadWriteLock.readLock().unlock();
            return z3;
        } catch (Throwable th) {
            f8329c.readLock().unlock();
            throw th;
        }
    }

    static void s(String str, int i3, StrictMode.ThreadPolicy threadPolicy) {
        AbstractC0226b.d(str, i3);
        try {
            AbstractC0226b.c(null, w(str, null, null, i3 | 1, threadPolicy));
        } finally {
        }
    }

    public static boolean t(String str) {
        return f8338l ? u(str, 0) : Z1.a.d(str);
    }

    public static boolean u(String str, int i3) {
        Boolean boolZ = z(str);
        if (boolZ != null) {
            return boolZ.booleanValue();
        }
        if (!f8338l) {
            return Z1.a.d(str);
        }
        if (f8340n != 2) {
        }
        return y(str, i3);
    }

    private static boolean v(String str, String str2, String str3, int i3, StrictMode.ThreadPolicy threadPolicy) {
        InterfaceC0320h interfaceC0320hC = null;
        while (true) {
            try {
                return w(str, str2, str3, i3, threadPolicy);
            } catch (UnsatisfiedLinkError e3) {
                interfaceC0320hC = C(str, e3, interfaceC0320hC);
            }
        }
    }

    private static boolean w(String str, String str2, String str3, int i3, StrictMode.ThreadPolicy threadPolicy) {
        boolean z3;
        Object obj;
        Object obj2;
        if (!TextUtils.isEmpty(str2) && f8336j.contains(str2)) {
            return false;
        }
        Set set = f8334h;
        if (set.contains(str) && str3 == null) {
            return false;
        }
        synchronized (SoLoader.class) {
            try {
                if (!set.contains(str)) {
                    z3 = false;
                } else {
                    if (str3 == null) {
                        return false;
                    }
                    z3 = true;
                }
                Map map = f8335i;
                if (map.containsKey(str)) {
                    obj = map.get(str);
                } else {
                    Object obj3 = new Object();
                    map.put(str, obj3);
                    obj = obj3;
                }
                Map map2 = f8337k;
                if (map2.containsKey(str2)) {
                    obj2 = map2.get(str2);
                } else {
                    Object obj4 = new Object();
                    map2.put(str2, obj4);
                    obj2 = obj4;
                }
                ReentrantReadWriteLock reentrantReadWriteLock = f8329c;
                reentrantReadWriteLock.readLock().lock();
                try {
                    synchronized (obj) {
                        if (!z3) {
                            if (set.contains(str)) {
                                if (str3 == null) {
                                    reentrantReadWriteLock.readLock().unlock();
                                    return false;
                                }
                                z3 = true;
                            }
                            if (!z3) {
                                try {
                                    p.a("SoLoader", "About to load: " + str);
                                    g(str, str2, i3, threadPolicy);
                                    p.a("SoLoader", "Loaded: " + str);
                                    set.add(str);
                                } catch (UnsatisfiedLinkError e3) {
                                    String message = e3.getMessage();
                                    if (message == null || !message.contains("unexpected e_machine:")) {
                                        throw e3;
                                    }
                                    throw new a(e3, message.substring(message.lastIndexOf("unexpected e_machine:")));
                                }
                            }
                        }
                        synchronized (obj2) {
                            if ((i3 & 16) == 0 && str3 != null) {
                                try {
                                    if (TextUtils.isEmpty(str2) || !f8336j.contains(str2)) {
                                        boolean z4 = f8327a;
                                        if (z4 && f8341o == null) {
                                            Api18TraceUtils.a("MergedSoMapping.invokeJniOnload[", str2, "]");
                                        }
                                        try {
                                            p.a("SoLoader", "About to invoke JNI_OnLoad for merged library " + str2 + ", which was merged into " + str);
                                            l lVar = f8341o;
                                            if (lVar != null) {
                                                lVar.a(str2);
                                            } else {
                                                r.a(str2);
                                            }
                                            f8336j.add(str2);
                                            if (z4 && f8341o == null) {
                                                Api18TraceUtils.b();
                                            }
                                        } catch (UnsatisfiedLinkError e4) {
                                            throw new RuntimeException("Failed to call JNI_OnLoad from '" + str2 + "', which has been merged into '" + str + "'.  See comment for details.", e4);
                                        }
                                    }
                                } catch (Throwable th) {
                                    if (f8327a && f8341o == null) {
                                        Api18TraceUtils.b();
                                    }
                                    throw th;
                                } finally {
                                }
                            }
                        }
                        reentrantReadWriteLock.readLock().unlock();
                        return !z3;
                    }
                } catch (Throwable th2) {
                    f8329c.readLock().unlock();
                    throw th2;
                }
            } finally {
            }
        }
    }

    private static boolean x(E e3, String str, int i3, StrictMode.ThreadPolicy threadPolicy) {
        AbstractC0226b.l(e3);
        try {
            boolean z3 = e3.d(str, i3, threadPolicy) != 0;
            AbstractC0226b.k(null);
            return z3;
        } finally {
        }
    }

    private static boolean y(String str, int i3) {
        l lVar = f8341o;
        String strB = lVar != null ? lVar.b(str) : r.b(str);
        String str2 = strB != null ? strB : str;
        AbstractC0226b.f(str, strB, i3);
        try {
            boolean zV = v(System.mapLibraryName(str2), str, strB, i3, null);
            AbstractC0226b.e(null, zV);
            return zV;
        } finally {
        }
    }

    private static Boolean z(String str) {
        Boolean boolValueOf;
        if (f8331e != null) {
            return null;
        }
        ReentrantReadWriteLock reentrantReadWriteLock = f8329c;
        reentrantReadWriteLock.readLock().lock();
        try {
            if (f8331e == null) {
                if (!"http://www.android.com/".equals(System.getProperty("java.vendor.url"))) {
                    synchronized (SoLoader.class) {
                        try {
                            boolean zContains = f8334h.contains(str);
                            boolean z3 = !zContains;
                            if (!zContains) {
                                System.loadLibrary(str);
                            }
                            boolValueOf = Boolean.valueOf(z3);
                        } finally {
                        }
                    }
                    reentrantReadWriteLock.readLock().unlock();
                    return boolValueOf;
                }
                f();
            }
            reentrantReadWriteLock.readLock().unlock();
            return null;
        } catch (Throwable th) {
            f8329c.readLock().unlock();
            throw th;
        }
    }
}
