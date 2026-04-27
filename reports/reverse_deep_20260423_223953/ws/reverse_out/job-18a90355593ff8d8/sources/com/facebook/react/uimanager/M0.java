package com.facebook.react.uimanager;

import android.os.SystemClock;
import android.view.View;
import c2.C0353a;
import c2.C0354b;
import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.GuardedRunnable;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContext;
import com.facebook.react.bridge.ReactNoCrashSoftException;
import com.facebook.react.bridge.ReactSoftExceptionLogger;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.RetryableMountingLayerException;
import com.facebook.react.bridge.UiThreadUtil;
import com.facebook.react.modules.core.b;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/* JADX INFO: loaded from: classes.dex */
public class M0 {

    /* JADX INFO: renamed from: A, reason: collision with root package name */
    private static final String f7385A = "M0";

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final C0436b0 f7387b;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final i f7390e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final ReactApplicationContext f7391f;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private M1.a f7396k;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private long f7400o;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private long f7401p;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private long f7402q;

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    private long f7403r;

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    private long f7404s;

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    private long f7405t;

    /* JADX INFO: renamed from: u, reason: collision with root package name */
    private long f7406u;

    /* JADX INFO: renamed from: v, reason: collision with root package name */
    private long f7407v;

    /* JADX INFO: renamed from: w, reason: collision with root package name */
    private long f7408w;

    /* JADX INFO: renamed from: x, reason: collision with root package name */
    private long f7409x;

    /* JADX INFO: renamed from: y, reason: collision with root package name */
    private long f7410y;

    /* JADX INFO: renamed from: z, reason: collision with root package name */
    private long f7411z;

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final int[] f7386a = new int[4];

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final Object f7388c = new Object();

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final Object f7389d = new Object();

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private ArrayList f7392g = new ArrayList();

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private ArrayList f7393h = new ArrayList();

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private ArrayList f7394i = new ArrayList();

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private ArrayDeque f7395j = new ArrayDeque();

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private boolean f7397l = false;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private boolean f7398m = false;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private boolean f7399n = false;

    class a implements Runnable {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ int f7412b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ ArrayList f7413c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final /* synthetic */ ArrayDeque f7414d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        final /* synthetic */ ArrayList f7415e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        final /* synthetic */ long f7416f;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        final /* synthetic */ long f7417g;

        /* JADX INFO: renamed from: h, reason: collision with root package name */
        final /* synthetic */ long f7418h;

        /* JADX INFO: renamed from: i, reason: collision with root package name */
        final /* synthetic */ long f7419i;

        a(int i3, ArrayList arrayList, ArrayDeque arrayDeque, ArrayList arrayList2, long j3, long j4, long j5, long j6) {
            this.f7412b = i3;
            this.f7413c = arrayList;
            this.f7414d = arrayDeque;
            this.f7415e = arrayList2;
            this.f7416f = j3;
            this.f7417g = j4;
            this.f7418h = j5;
            this.f7419i = j6;
        }

        @Override // java.lang.Runnable
        public void run() {
            C0354b.a(0L, "DispatchUI").a("BatchId", this.f7412b).c();
            try {
                try {
                    long jUptimeMillis = SystemClock.uptimeMillis();
                    ArrayList<g> arrayList = this.f7413c;
                    if (arrayList != null) {
                        for (g gVar : arrayList) {
                            try {
                                gVar.c();
                            } catch (RetryableMountingLayerException e3) {
                                if (gVar.a() == 0) {
                                    gVar.d();
                                    M0.this.f7392g.add(gVar);
                                } else {
                                    ReactSoftExceptionLogger.logSoftException(M0.f7385A, new ReactNoCrashSoftException(e3));
                                }
                            } catch (Throwable th) {
                                ReactSoftExceptionLogger.logSoftException(M0.f7385A, th);
                            }
                        }
                    }
                    ArrayDeque arrayDeque = this.f7414d;
                    if (arrayDeque != null) {
                        Iterator it = arrayDeque.iterator();
                        while (it.hasNext()) {
                            ((r) it.next()).b();
                        }
                    }
                    ArrayList arrayList2 = this.f7415e;
                    if (arrayList2 != null) {
                        Iterator it2 = arrayList2.iterator();
                        while (it2.hasNext()) {
                            ((r) it2.next()).b();
                        }
                    }
                    if (M0.this.f7399n && M0.this.f7401p == 0) {
                        M0.this.f7401p = this.f7416f;
                        M0.this.f7402q = SystemClock.uptimeMillis();
                        M0.this.f7403r = this.f7417g;
                        M0.this.f7404s = this.f7418h;
                        M0.this.f7405t = jUptimeMillis;
                        M0 m02 = M0.this;
                        m02.f7406u = m02.f7402q;
                        M0.this.f7409x = this.f7419i;
                        C0353a.b(0L, "delayBeforeDispatchViewUpdates", 0, M0.this.f7401p * 1000000);
                        C0353a.h(0L, "delayBeforeDispatchViewUpdates", 0, M0.this.f7404s * 1000000);
                        C0353a.b(0L, "delayBeforeBatchRunStart", 0, M0.this.f7404s * 1000000);
                        C0353a.h(0L, "delayBeforeBatchRunStart", 0, M0.this.f7405t * 1000000);
                    }
                    M0.this.f7387b.f();
                    if (M0.this.f7396k != null) {
                        M0.this.f7396k.b();
                    }
                    C0353a.i(0L);
                } catch (Exception e4) {
                    M0.this.f7398m = true;
                    throw e4;
                }
            } catch (Throwable th2) {
                C0353a.i(0L);
                throw th2;
            }
        }
    }

    class b extends GuardedRunnable {
        b(ReactContext reactContext) {
            super(reactContext);
        }

        @Override // com.facebook.react.bridge.GuardedRunnable
        public void runGuarded() {
            M0.this.R();
        }
    }

    private final class c extends v {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final int f7422c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private final boolean f7423d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private final boolean f7424e;

        public c(int i3, int i4, boolean z3, boolean z4) {
            super(i3);
            this.f7422c = i4;
            this.f7424e = z3;
            this.f7423d = z4;
        }

        @Override // com.facebook.react.uimanager.M0.r
        public void b() {
            if (this.f7424e) {
                M0.this.f7387b.e();
            } else {
                M0.this.f7387b.y(this.f7476a, this.f7422c, this.f7423d);
            }
        }
    }

    private class d implements r {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final ReadableMap f7426a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final Callback f7427b;

        @Override // com.facebook.react.uimanager.M0.r
        public void b() {
            M0.this.f7387b.h(this.f7426a, this.f7427b);
        }

        private d(ReadableMap readableMap, Callback callback) {
            this.f7426a = readableMap;
            this.f7427b = callback;
        }
    }

    private final class e extends v {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final B0 f7429c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private final String f7430d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private final C0469s0 f7431e;

        public e(B0 b02, int i3, String str, C0469s0 c0469s0) {
            super(i3);
            this.f7429c = b02;
            this.f7430d = str;
            this.f7431e = c0469s0;
            C0353a.l(0L, "createView", this.f7476a);
        }

        @Override // com.facebook.react.uimanager.M0.r
        public void b() {
            C0353a.f(0L, "createView", this.f7476a);
            M0.this.f7387b.j(this.f7429c, this.f7476a, this.f7430d, this.f7431e);
        }
    }

    private final class f extends v implements g {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final int f7433c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private final ReadableArray f7434d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private int f7435e;

        public f(int i3, int i4, ReadableArray readableArray) {
            super(i3);
            this.f7435e = 0;
            this.f7433c = i4;
            this.f7434d = readableArray;
        }

        @Override // com.facebook.react.uimanager.M0.g
        public int a() {
            return this.f7435e;
        }

        @Override // com.facebook.react.uimanager.M0.r
        public void b() {
            try {
                M0.this.f7387b.k(this.f7476a, this.f7433c, this.f7434d);
            } catch (Throwable th) {
                ReactSoftExceptionLogger.logSoftException(M0.f7385A, new RuntimeException("Error dispatching View Command", th));
            }
        }

        @Override // com.facebook.react.uimanager.M0.g
        public void c() {
            M0.this.f7387b.k(this.f7476a, this.f7433c, this.f7434d);
        }

        @Override // com.facebook.react.uimanager.M0.g
        public void d() {
            this.f7435e++;
        }
    }

    private interface g {
        int a();

        void c();

        void d();
    }

    private final class h extends v implements g {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final String f7437c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private final ReadableArray f7438d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private int f7439e;

        public h(int i3, String str, ReadableArray readableArray) {
            super(i3);
            this.f7439e = 0;
            this.f7437c = str;
            this.f7438d = readableArray;
        }

        @Override // com.facebook.react.uimanager.M0.g
        public int a() {
            return this.f7439e;
        }

        @Override // com.facebook.react.uimanager.M0.r
        public void b() {
            try {
                M0.this.f7387b.l(this.f7476a, this.f7437c, this.f7438d);
            } catch (Throwable th) {
                ReactSoftExceptionLogger.logSoftException(M0.f7385A, new RuntimeException("Error dispatching View Command", th));
            }
        }

        @Override // com.facebook.react.uimanager.M0.g
        public void c() {
            M0.this.f7387b.l(this.f7476a, this.f7437c, this.f7438d);
        }

        @Override // com.facebook.react.uimanager.M0.g
        public void d() {
            this.f7439e++;
        }
    }

    private class i extends M {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final int f7441b;

        private void b(long j3) throws Exception {
            r rVar;
            while (16 - ((System.nanoTime() - j3) / 1000000) >= this.f7441b) {
                synchronized (M0.this.f7389d) {
                    try {
                        if (M0.this.f7395j.isEmpty()) {
                            return;
                        } else {
                            rVar = (r) M0.this.f7395j.pollFirst();
                        }
                    } catch (Throwable th) {
                        throw th;
                    }
                }
                try {
                    long jUptimeMillis = SystemClock.uptimeMillis();
                    rVar.b();
                    M0.this.f7400o += SystemClock.uptimeMillis() - jUptimeMillis;
                } catch (Exception e3) {
                    M0.this.f7398m = true;
                    throw e3;
                }
            }
        }

        @Override // com.facebook.react.uimanager.M
        public void a(long j3) {
            if (M0.this.f7398m) {
                Y.a.I("ReactNative", "Not flushing pending UI operations because of previously thrown Exception");
                return;
            }
            C0353a.c(0L, "dispatchNonBatchedUIOperations");
            try {
                b(j3);
                C0353a.i(0L);
                M0.this.R();
                com.facebook.react.modules.core.b.h().k(b.a.f7050d, this);
            } catch (Throwable th) {
                C0353a.i(0L);
                throw th;
            }
        }

        private i(ReactContext reactContext, int i3) {
            super(reactContext);
            this.f7441b = i3;
        }
    }

    private final class j implements r {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final int f7443a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final float f7444b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final float f7445c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private final Callback f7446d;

        @Override // com.facebook.react.uimanager.M0.r
        public void b() {
            try {
                M0.this.f7387b.s(this.f7443a, M0.this.f7386a);
                float f3 = M0.this.f7386a[0];
                float f4 = M0.this.f7386a[1];
                int iN = M0.this.f7387b.n(this.f7443a, this.f7444b, this.f7445c);
                try {
                    M0.this.f7387b.s(iN, M0.this.f7386a);
                    this.f7446d.invoke(Integer.valueOf(iN), Float.valueOf(C0444f0.f(M0.this.f7386a[0] - f3)), Float.valueOf(C0444f0.f(M0.this.f7386a[1] - f4)), Float.valueOf(C0444f0.f(M0.this.f7386a[2])), Float.valueOf(C0444f0.f(M0.this.f7386a[3])));
                } catch (P unused) {
                    this.f7446d.invoke(new Object[0]);
                }
            } catch (P unused2) {
                this.f7446d.invoke(new Object[0]);
            }
        }

        private j(int i3, float f3, float f4, Callback callback) {
            this.f7443a = i3;
            this.f7444b = f3;
            this.f7445c = f4;
            this.f7446d = callback;
        }
    }

    private final class k extends v {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final int[] f7448c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private final O0[] f7449d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private final int[] f7450e;

        public k(int i3, int[] iArr, O0[] o0Arr, int[] iArr2) {
            super(i3);
            this.f7448c = iArr;
            this.f7449d = o0Arr;
            this.f7450e = iArr2;
        }

        @Override // com.facebook.react.uimanager.M0.r
        public void b() {
            M0.this.f7387b.q(this.f7476a, this.f7448c, this.f7449d, this.f7450e);
        }
    }

    private final class l implements r {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final int f7452a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final Callback f7453b;

        @Override // com.facebook.react.uimanager.M0.r
        public void b() {
            try {
                M0.this.f7387b.t(this.f7452a, M0.this.f7386a);
                this.f7453b.invoke(Float.valueOf(C0444f0.f(M0.this.f7386a[0])), Float.valueOf(C0444f0.f(M0.this.f7386a[1])), Float.valueOf(C0444f0.f(M0.this.f7386a[2])), Float.valueOf(C0444f0.f(M0.this.f7386a[3])));
            } catch (C0440d0 unused) {
                this.f7453b.invoke(new Object[0]);
            }
        }

        private l(int i3, Callback callback) {
            this.f7452a = i3;
            this.f7453b = callback;
        }
    }

    private final class m implements r {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final int f7455a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final Callback f7456b;

        @Override // com.facebook.react.uimanager.M0.r
        public void b() {
            try {
                M0.this.f7387b.s(this.f7455a, M0.this.f7386a);
                this.f7456b.invoke(0, 0, Float.valueOf(C0444f0.f(M0.this.f7386a[2])), Float.valueOf(C0444f0.f(M0.this.f7386a[3])), Float.valueOf(C0444f0.f(M0.this.f7386a[0])), Float.valueOf(C0444f0.f(M0.this.f7386a[1])));
            } catch (C0440d0 unused) {
                this.f7456b.invoke(new Object[0]);
            }
        }

        private m(int i3, Callback callback) {
            this.f7455a = i3;
            this.f7456b = callback;
        }
    }

    private final class n extends v {
        public n(int i3) {
            super(i3);
        }

        @Override // com.facebook.react.uimanager.M0.r
        public void b() {
            M0.this.f7387b.u(this.f7476a);
        }
    }

    private final class o extends v {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final int f7459c;

        @Override // com.facebook.react.uimanager.M0.r
        public void b() {
            try {
                M0.this.f7387b.x(this.f7476a, this.f7459c);
            } catch (RetryableMountingLayerException e3) {
                ReactSoftExceptionLogger.logSoftException(M0.f7385A, e3);
            }
        }

        private o(int i3, int i4) {
            super(i3);
            this.f7459c = i4;
        }
    }

    private class p implements r {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final boolean f7461a;

        @Override // com.facebook.react.uimanager.M0.r
        public void b() {
            M0.this.f7387b.z(this.f7461a);
        }

        private p(boolean z3) {
            this.f7461a = z3;
        }
    }

    private class q implements r {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final F0 f7463a;

        public q(F0 f02) {
            this.f7463a = f02;
        }

        @Override // com.facebook.react.uimanager.M0.r
        public void b() {
            this.f7463a.a(M0.this.f7387b);
        }
    }

    public interface r {
        void b();
    }

    private final class s extends v {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final int f7465c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private final int f7466d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private final int f7467e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        private final int f7468f;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        private final int f7469g;

        /* JADX INFO: renamed from: h, reason: collision with root package name */
        private final com.facebook.yoga.h f7470h;

        public s(int i3, int i4, int i5, int i6, int i7, int i8, com.facebook.yoga.h hVar) {
            super(i4);
            this.f7465c = i3;
            this.f7466d = i5;
            this.f7467e = i6;
            this.f7468f = i7;
            this.f7469g = i8;
            this.f7470h = hVar;
            C0353a.l(0L, "updateLayout", this.f7476a);
        }

        @Override // com.facebook.react.uimanager.M0.r
        public void b() {
            C0353a.f(0L, "updateLayout", this.f7476a);
            M0.this.f7387b.A(this.f7465c, this.f7476a, this.f7466d, this.f7467e, this.f7468f, this.f7469g, this.f7470h);
        }
    }

    private final class t extends v {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final C0469s0 f7472c;

        @Override // com.facebook.react.uimanager.M0.r
        public void b() {
            M0.this.f7387b.C(this.f7476a, this.f7472c);
        }

        private t(int i3, C0469s0 c0469s0) {
            super(i3);
            this.f7472c = c0469s0;
        }
    }

    private final class u extends v {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final Object f7474c;

        public u(int i3, Object obj) {
            super(i3);
            this.f7474c = obj;
        }

        @Override // com.facebook.react.uimanager.M0.r
        public void b() {
            M0.this.f7387b.D(this.f7476a, this.f7474c);
        }
    }

    private abstract class v implements r {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        public int f7476a;

        public v(int i3) {
            this.f7476a = i3;
        }
    }

    public M0(ReactApplicationContext reactApplicationContext, C0436b0 c0436b0, int i3) {
        this.f7387b = c0436b0;
        this.f7390e = new i(reactApplicationContext, i3 == -1 ? 8 : i3);
        this.f7391f = reactApplicationContext;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void R() {
        if (this.f7398m) {
            Y.a.I("ReactNative", "Not flushing pending UI operations because of previously thrown Exception");
            return;
        }
        synchronized (this.f7388c) {
            if (this.f7394i.isEmpty()) {
                return;
            }
            ArrayList arrayList = this.f7394i;
            this.f7394i = new ArrayList();
            long jUptimeMillis = SystemClock.uptimeMillis();
            Iterator it = arrayList.iterator();
            while (it.hasNext()) {
                ((Runnable) it.next()).run();
            }
            if (this.f7399n) {
                this.f7407v = SystemClock.uptimeMillis() - jUptimeMillis;
                this.f7408w = this.f7400o;
                this.f7399n = false;
                C0353a.b(0L, "batchedExecutionTime", 0, jUptimeMillis * 1000000);
                C0353a.g(0L, "batchedExecutionTime", 0);
            }
            this.f7400o = 0L;
        }
    }

    public void A() {
        this.f7393h.add(new c(0, 0, true, false));
    }

    public void B(ReadableMap readableMap, Callback callback) {
        this.f7393h.add(new d(readableMap, callback));
    }

    public void C(B0 b02, int i3, String str, C0469s0 c0469s0) {
        synchronized (this.f7389d) {
            this.f7410y++;
            this.f7395j.addLast(new e(b02, i3, str, c0469s0));
        }
    }

    public void D(int i3, int i4, ReadableArray readableArray) {
        this.f7392g.add(new f(i3, i4, readableArray));
    }

    public void E(int i3, String str, ReadableArray readableArray) {
        this.f7392g.add(new h(i3, str, readableArray));
    }

    public void F(int i3, float f3, float f4, Callback callback) {
        this.f7393h.add(new j(i3, f3, f4, callback));
    }

    public void G(int i3, int[] iArr, O0[] o0Arr, int[] iArr2) {
        this.f7393h.add(new k(i3, iArr, o0Arr, iArr2));
    }

    public void H(int i3, Callback callback) {
        this.f7393h.add(new m(i3, callback));
    }

    public void I(int i3, Callback callback) {
        this.f7393h.add(new l(i3, callback));
    }

    public void J(int i3) {
        this.f7393h.add(new n(i3));
    }

    public void K(int i3, int i4) {
        this.f7393h.add(new o(i3, i4));
    }

    public void L(int i3, int i4, boolean z3) {
        this.f7393h.add(new c(i3, i4, false, z3));
    }

    public void M(boolean z3) {
        this.f7393h.add(new p(z3));
    }

    public void N(F0 f02) {
        this.f7393h.add(new q(f02));
    }

    public void O(int i3, Object obj) {
        this.f7393h.add(new u(i3, obj));
    }

    public void P(int i3, int i4, int i5, int i6, int i7, int i8, com.facebook.yoga.h hVar) {
        this.f7393h.add(new s(i3, i4, i5, i6, i7, i8, hVar));
    }

    public void Q(int i3, String str, C0469s0 c0469s0) {
        this.f7411z++;
        this.f7393h.add(new t(i3, c0469s0));
    }

    C0436b0 S() {
        return this.f7387b;
    }

    public Map T() {
        HashMap map = new HashMap();
        map.put("CommitStartTime", Long.valueOf(this.f7401p));
        map.put("CommitEndTime", Long.valueOf(this.f7402q));
        map.put("LayoutTime", Long.valueOf(this.f7403r));
        map.put("DispatchViewUpdatesTime", Long.valueOf(this.f7404s));
        map.put("RunStartTime", Long.valueOf(this.f7405t));
        map.put("RunEndTime", Long.valueOf(this.f7406u));
        map.put("BatchedExecutionTime", Long.valueOf(this.f7407v));
        map.put("NonBatchedExecutionTime", Long.valueOf(this.f7408w));
        map.put("NativeModulesThreadCpuTime", Long.valueOf(this.f7409x));
        map.put("CreateViewCount", Long.valueOf(this.f7410y));
        map.put("UpdatePropsCount", Long.valueOf(this.f7411z));
        return map;
    }

    public boolean U() {
        return this.f7393h.isEmpty() && this.f7392g.isEmpty();
    }

    void V() {
        this.f7397l = false;
        com.facebook.react.modules.core.b.h().n(b.a.f7050d, this.f7390e);
        R();
    }

    public void W(F0 f02) {
        this.f7393h.add(0, new q(f02));
    }

    public void X() {
        this.f7399n = true;
        this.f7401p = 0L;
        this.f7410y = 0L;
        this.f7411z = 0L;
    }

    void Y() {
        this.f7397l = true;
        com.facebook.react.modules.core.b.h().k(b.a.f7050d, this.f7390e);
    }

    public void Z(M1.a aVar) {
        this.f7396k = aVar;
    }

    public void y(int i3, View view) {
        this.f7387b.b(i3, view);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r2v11 */
    /* JADX WARN: Type inference failed for: r2v12 */
    /* JADX WARN: Type inference failed for: r2v13 */
    /* JADX WARN: Type inference failed for: r2v3 */
    /* JADX WARN: Type inference failed for: r2v6 */
    /* JADX WARN: Type inference failed for: r2v9 */
    public void z(int i3, long j3, long j4) throws Throwable {
        long j5;
        long jUptimeMillis;
        long jCurrentThreadTimeMillis;
        ArrayList arrayList;
        ArrayList arrayList2;
        ArrayDeque arrayDeque;
        C0354b.a(0L, "UIViewOperationQueue.dispatchViewUpdates").a("batchId", i3).c();
        try {
            jUptimeMillis = SystemClock.uptimeMillis();
            jCurrentThreadTimeMillis = SystemClock.currentThreadTimeMillis();
            j5 = 0;
            j5 = 0;
            if (this.f7392g.isEmpty()) {
                arrayList = null;
            } else {
                ArrayList arrayList3 = this.f7392g;
                this.f7392g = new ArrayList();
                arrayList = arrayList3;
            }
            if (this.f7393h.isEmpty()) {
                arrayList2 = null;
            } else {
                ArrayList arrayList4 = this.f7393h;
                this.f7393h = new ArrayList();
                arrayList2 = arrayList4;
            }
            synchronized (this.f7389d) {
                try {
                    try {
                        if (!this.f7395j.isEmpty()) {
                            ArrayDeque arrayDeque2 = this.f7395j;
                            this.f7395j = new ArrayDeque();
                            j5 = arrayDeque2;
                        }
                        arrayDeque = j5;
                    } finally {
                        th = th;
                        while (true) {
                            try {
                            } catch (Throwable th) {
                                th = th;
                            }
                        }
                    }
                } catch (Throwable th2) {
                    th = th2;
                }
            }
            M1.a aVar = this.f7396k;
            if (aVar != null) {
                aVar.a();
            }
        } catch (Throwable th3) {
            th = th3;
            j5 = 0;
        }
        try {
            a aVar2 = new a(i3, arrayList, arrayDeque, arrayList2, j3, j4, jUptimeMillis, jCurrentThreadTimeMillis);
            j5 = 0;
            j5 = 0;
            C0354b.a(0L, "acquiring mDispatchRunnablesLock").a("batchId", i3).c();
            synchronized (this.f7388c) {
                C0353a.i(0L);
                this.f7394i.add(aVar2);
            }
            if (!this.f7397l) {
                UiThreadUtil.runOnUiThread(new b(this.f7391f));
            }
            C0353a.i(0L);
        } catch (Throwable th4) {
            th = th4;
            j5 = 0;
            C0353a.i(j5);
            throw th;
        }
    }
}
