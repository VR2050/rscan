package com.facebook.react.animated;

import com.facebook.react.bridge.JavaOnlyMap;
import com.facebook.react.bridge.ReadableMap;

/* JADX INFO: loaded from: classes.dex */
public final class u extends b {

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final o f6608f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private final JavaOnlyMap f6609g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private final int f6610h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private final int f6611i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private final int f6612j;

    public u(ReadableMap readableMap, o oVar) {
        t2.j.f(readableMap, "config");
        t2.j.f(oVar, "nativeAnimatedNodesManager");
        this.f6608f = oVar;
        this.f6609g = JavaOnlyMap.Companion.deepClone(readableMap.getMap("animationConfig"));
        this.f6610h = readableMap.getInt("animationId");
        this.f6611i = readableMap.getInt("toValue");
        this.f6612j = readableMap.getInt("value");
    }

    @Override // com.facebook.react.animated.b
    public String e() {
        return "TrackingAnimatedNode[" + this.f6507d + "]: animationID: " + this.f6610h + " toValueNode: " + this.f6611i + " valueNode: " + this.f6612j + " animationConfig: " + this.f6609g;
    }

    @Override // com.facebook.react.animated.b
    public void h() {
        b bVarL = this.f6608f.l(this.f6611i);
        w wVar = bVarL instanceof w ? (w) bVarL : null;
        if (wVar != null) {
            this.f6609g.putDouble("toValue", wVar.l());
        } else {
            this.f6609g.putNull("toValue");
        }
        this.f6608f.x(this.f6610h, this.f6612j, this.f6609g, null);
    }
}
