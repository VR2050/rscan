package com.facebook.react.modules.debug;

import android.view.Choreographer;
import com.facebook.react.bridge.ReactContext;
import com.facebook.react.bridge.UiThreadUtil;
import com.facebook.react.uimanager.UIManagerModule;
import java.util.TreeMap;
import kotlin.jvm.internal.DefaultConstructorMarker;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class h implements Choreographer.FrameCallback {

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private static final a f7068n = new a(null);

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final ReactContext f7069a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private Choreographer f7070b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final UIManagerModule f7071c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final d f7072d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private long f7073e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private long f7074f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private int f7075g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private int f7076h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private int f7077i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private int f7078j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private boolean f7079k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private double f7080l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private TreeMap f7081m;

    private static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    public static final class b {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final int f7082a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final int f7083b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final int f7084c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private final int f7085d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private final double f7086e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        private final double f7087f;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        private final int f7088g;

        public b(int i3, int i4, int i5, int i6, double d3, double d4, int i7) {
            this.f7082a = i3;
            this.f7083b = i4;
            this.f7084c = i5;
            this.f7085d = i6;
            this.f7086e = d3;
            this.f7087f = d4;
            this.f7088g = i7;
        }
    }

    public h(ReactContext reactContext) {
        j.f(reactContext, "reactContext");
        this.f7069a = reactContext;
        this.f7071c = (UIManagerModule) reactContext.getNativeModule(UIManagerModule.class);
        this.f7072d = new d();
        this.f7073e = -1L;
        this.f7074f = -1L;
        this.f7080l = 60.0d;
    }

    public static /* synthetic */ void l(h hVar, double d3, int i3, Object obj) {
        if ((i3 & 1) != 0) {
            d3 = hVar.f7080l;
        }
        hVar.k(d3);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void m(h hVar) {
        Choreographer choreographer = Choreographer.getInstance();
        hVar.f7070b = choreographer;
        if (choreographer != null) {
            choreographer.postFrameCallback(hVar);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void o(h hVar) {
        Choreographer choreographer = Choreographer.getInstance();
        hVar.f7070b = choreographer;
        if (choreographer != null) {
            choreographer.removeFrameCallback(hVar);
        }
    }

    public final int c() {
        return this.f7077i;
    }

    public final int d() {
        return (int) (((this.f7080l * ((double) i())) / ((double) 1000)) + ((double) 1));
    }

    @Override // android.view.Choreographer.FrameCallback
    public void doFrame(long j3) {
        if (this.f7073e == -1) {
            this.f7073e = j3;
        }
        long j4 = this.f7074f;
        this.f7074f = j3;
        if (this.f7072d.d(j4, j3)) {
            this.f7078j++;
        }
        this.f7075g++;
        int iD = d();
        if ((iD - this.f7076h) - 1 >= 4) {
            this.f7077i++;
        }
        if (this.f7079k) {
            Z0.a.c(this.f7081m);
            b bVar = new b(g(), h(), iD, this.f7077i, e(), f(), i());
            TreeMap treeMap = this.f7081m;
            if (treeMap != null) {
            }
        }
        this.f7076h = iD;
        Choreographer choreographer = this.f7070b;
        if (choreographer != null) {
            choreographer.postFrameCallback(this);
        }
    }

    public final double e() {
        if (this.f7074f == this.f7073e) {
            return 0.0d;
        }
        return (((double) g()) * 1.0E9d) / (this.f7074f - this.f7073e);
    }

    public final double f() {
        if (this.f7074f == this.f7073e) {
            return 0.0d;
        }
        return (((double) h()) * 1.0E9d) / (this.f7074f - this.f7073e);
    }

    public final int g() {
        return this.f7075g - 1;
    }

    public final int h() {
        return this.f7078j - 1;
    }

    public final int i() {
        return (int) ((this.f7074f - this.f7073e) / 1000000.0d);
    }

    public final void j() {
        this.f7073e = -1L;
        this.f7074f = -1L;
        this.f7075g = 0;
        this.f7077i = 0;
        this.f7078j = 0;
        this.f7079k = false;
        this.f7081m = null;
    }

    public final void k(double d3) {
        if (!this.f7069a.isBridgeless()) {
            this.f7069a.getCatalystInstance().addBridgeIdleDebugListener(this.f7072d);
        }
        UIManagerModule uIManagerModule = this.f7071c;
        if (uIManagerModule != null) {
            uIManagerModule.setViewHierarchyUpdateDebugListener(this.f7072d);
        }
        this.f7080l = d3;
        UiThreadUtil.runOnUiThread(new Runnable() { // from class: com.facebook.react.modules.debug.f
            @Override // java.lang.Runnable
            public final void run() {
                h.m(this.f7066b);
            }
        });
    }

    public final void n() {
        if (!this.f7069a.isBridgeless()) {
            this.f7069a.getCatalystInstance().removeBridgeIdleDebugListener(this.f7072d);
        }
        UIManagerModule uIManagerModule = this.f7071c;
        if (uIManagerModule != null) {
            uIManagerModule.setViewHierarchyUpdateDebugListener(null);
        }
        UiThreadUtil.runOnUiThread(new Runnable() { // from class: com.facebook.react.modules.debug.g
            @Override // java.lang.Runnable
            public final void run() {
                h.o(this.f7067b);
            }
        });
    }
}
