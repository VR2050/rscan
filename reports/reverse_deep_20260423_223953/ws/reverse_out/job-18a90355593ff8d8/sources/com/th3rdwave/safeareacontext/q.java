package com.th3rdwave.safeareacontext;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.uimanager.C0444f0;
import i2.D;
import java.util.Map;

/* JADX INFO: loaded from: classes.dex */
public abstract class q {
    public static final Map a(a aVar) {
        t2.j.f(aVar, "insets");
        return D.h(h2.n.a("top", Float.valueOf(C0444f0.f(aVar.d()))), h2.n.a("right", Float.valueOf(C0444f0.f(aVar.c()))), h2.n.a("bottom", Float.valueOf(C0444f0.f(aVar.a()))), h2.n.a("left", Float.valueOf(C0444f0.f(aVar.b()))));
    }

    public static final WritableMap b(a aVar) {
        t2.j.f(aVar, "insets");
        WritableMap writableMapCreateMap = Arguments.createMap();
        writableMapCreateMap.putDouble("top", C0444f0.f(aVar.d()));
        writableMapCreateMap.putDouble("right", C0444f0.f(aVar.c()));
        writableMapCreateMap.putDouble("bottom", C0444f0.f(aVar.a()));
        writableMapCreateMap.putDouble("left", C0444f0.f(aVar.b()));
        t2.j.c(writableMapCreateMap);
        return writableMapCreateMap;
    }

    public static final Map c(c cVar) {
        t2.j.f(cVar, "rect");
        return D.h(h2.n.a("x", Float.valueOf(C0444f0.f(cVar.c()))), h2.n.a("y", Float.valueOf(C0444f0.f(cVar.d()))), h2.n.a("width", Float.valueOf(C0444f0.f(cVar.b()))), h2.n.a("height", Float.valueOf(C0444f0.f(cVar.a()))));
    }

    public static final WritableMap d(c cVar) {
        t2.j.f(cVar, "rect");
        WritableMap writableMapCreateMap = Arguments.createMap();
        writableMapCreateMap.putDouble("x", C0444f0.f(cVar.c()));
        writableMapCreateMap.putDouble("y", C0444f0.f(cVar.d()));
        writableMapCreateMap.putDouble("width", C0444f0.f(cVar.b()));
        writableMapCreateMap.putDouble("height", C0444f0.f(cVar.a()));
        t2.j.c(writableMapCreateMap);
        return writableMapCreateMap;
    }
}
