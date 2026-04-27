package com.facebook.react.uimanager;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.WritableMap;

/* JADX INFO: renamed from: com.facebook.react.uimanager.e0, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0442e0 extends O1.d {

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private static final q.f f7598l = new q.f(20);

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private int f7599h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private int f7600i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private int f7601j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private int f7602k;

    private C0442e0() {
    }

    public static C0442e0 v(int i3, int i4, int i5, int i6, int i7, int i8) {
        C0442e0 c0442e0 = (C0442e0) f7598l.b();
        if (c0442e0 == null) {
            c0442e0 = new C0442e0();
        }
        c0442e0.u(i3, i4, i5, i6, i7, i8);
        return c0442e0;
    }

    @Override // O1.d
    protected WritableMap j() {
        WritableMap writableMapCreateMap = Arguments.createMap();
        writableMapCreateMap.putDouble("x", C0444f0.f(this.f7599h));
        writableMapCreateMap.putDouble("y", C0444f0.f(this.f7600i));
        writableMapCreateMap.putDouble("width", C0444f0.f(this.f7601j));
        writableMapCreateMap.putDouble("height", C0444f0.f(this.f7602k));
        WritableMap writableMapCreateMap2 = Arguments.createMap();
        writableMapCreateMap2.putMap("layout", writableMapCreateMap);
        writableMapCreateMap2.putInt("target", o());
        return writableMapCreateMap2;
    }

    @Override // O1.d
    public String k() {
        return "topLayout";
    }

    @Override // O1.d
    public void t() {
        f7598l.a(this);
    }

    protected void u(int i3, int i4, int i5, int i6, int i7, int i8) {
        super.q(i3, i4);
        this.f7599h = i5;
        this.f7600i = i6;
        this.f7601j = i7;
        this.f7602k = i8;
    }
}
