package com.facebook.react.views.scroll;

import android.os.SystemClock;
import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.ReactSoftExceptionLogger;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.uimanager.C0444f0;
import com.facebook.react.views.scroll.l;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public final class k extends O1.d {

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    public static final a f8001r = new a(null);

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    private static final String f8002s = k.class.getSimpleName();

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    private static final q.f f8003t = new q.f(3);

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private float f8004h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private float f8005i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private float f8006j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private float f8007k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private int f8008l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private int f8009m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private int f8010n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private int f8011o;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private l f8012p;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private long f8013q;

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final k a(int i3, int i4, l lVar, float f3, float f4, float f5, float f6, int i5, int i6, int i7, int i8) {
            k kVar = (k) k.f8003t.b();
            if (kVar == null) {
                kVar = new k(null);
            }
            kVar.w(i3, i4, lVar, f3, f4, f5, f6, i5, i6, i7, i8);
            return kVar;
        }

        public final k b(int i3, l lVar, float f3, float f4, float f5, float f6, int i4, int i5, int i6, int i7) {
            return a(-1, i3, lVar, f3, f4, f5, f6, i4, i5, i6, i7);
        }

        private a() {
        }
    }

    public /* synthetic */ k(DefaultConstructorMarker defaultConstructorMarker) {
        this();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void w(int i3, int i4, l lVar, float f3, float f4, float f5, float f6, int i5, int i6, int i7, int i8) {
        super.q(i3, i4);
        this.f8012p = lVar;
        this.f8004h = f3;
        this.f8005i = f4;
        this.f8006j = f5;
        this.f8007k = f6;
        this.f8008l = i5;
        this.f8009m = i6;
        this.f8010n = i7;
        this.f8011o = i8;
        this.f8013q = SystemClock.uptimeMillis();
    }

    public static final k x(int i3, int i4, l lVar, float f3, float f4, float f5, float f6, int i5, int i6, int i7, int i8) {
        return f8001r.a(i3, i4, lVar, f3, f4, f5, f6, i5, i6, i7, i8);
    }

    public static final k y(int i3, l lVar, float f3, float f4, float f5, float f6, int i4, int i5, int i6, int i7) {
        return f8001r.b(i3, lVar, f3, f4, f5, f6, i4, i5, i6, i7);
    }

    @Override // O1.d
    public boolean a() {
        return this.f8012p == l.f8017e;
    }

    @Override // O1.d
    protected WritableMap j() {
        WritableMap writableMapCreateMap = Arguments.createMap();
        writableMapCreateMap.putDouble("top", 0.0d);
        writableMapCreateMap.putDouble("bottom", 0.0d);
        writableMapCreateMap.putDouble("left", 0.0d);
        writableMapCreateMap.putDouble("right", 0.0d);
        WritableMap writableMapCreateMap2 = Arguments.createMap();
        writableMapCreateMap2.putDouble("x", C0444f0.f(this.f8004h));
        writableMapCreateMap2.putDouble("y", C0444f0.f(this.f8005i));
        WritableMap writableMapCreateMap3 = Arguments.createMap();
        writableMapCreateMap3.putDouble("width", C0444f0.f(this.f8008l));
        writableMapCreateMap3.putDouble("height", C0444f0.f(this.f8009m));
        WritableMap writableMapCreateMap4 = Arguments.createMap();
        writableMapCreateMap4.putDouble("width", C0444f0.f(this.f8010n));
        writableMapCreateMap4.putDouble("height", C0444f0.f(this.f8011o));
        WritableMap writableMapCreateMap5 = Arguments.createMap();
        writableMapCreateMap5.putDouble("x", this.f8006j);
        writableMapCreateMap5.putDouble("y", this.f8007k);
        WritableMap writableMapCreateMap6 = Arguments.createMap();
        writableMapCreateMap6.putMap("contentInset", writableMapCreateMap);
        writableMapCreateMap6.putMap("contentOffset", writableMapCreateMap2);
        writableMapCreateMap6.putMap("contentSize", writableMapCreateMap3);
        writableMapCreateMap6.putMap("layoutMeasurement", writableMapCreateMap4);
        writableMapCreateMap6.putMap("velocity", writableMapCreateMap5);
        writableMapCreateMap6.putInt("target", o());
        writableMapCreateMap6.putDouble("timestamp", this.f8013q);
        writableMapCreateMap6.putBoolean("responderIgnoreScroll", true);
        t2.j.c(writableMapCreateMap6);
        return writableMapCreateMap6;
    }

    @Override // O1.d
    public String k() {
        l.a aVar = l.f8014b;
        Object objC = Z0.a.c(this.f8012p);
        t2.j.e(objC, "assertNotNull(...)");
        return aVar.a((l) objC);
    }

    @Override // O1.d
    public void t() {
        try {
            f8003t.a(this);
        } catch (IllegalStateException e3) {
            String str = f8002s;
            t2.j.e(str, "TAG");
            ReactSoftExceptionLogger.logSoftException(str, e3);
        }
    }

    private k() {
    }
}
