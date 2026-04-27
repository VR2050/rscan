package com.facebook.react.animated;

import com.facebook.react.bridge.JSApplicationCausedNativeException;
import com.facebook.react.bridge.ReadableMap;

/* JADX INFO: loaded from: classes.dex */
public final class l extends w {

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private final o f6559i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private final int f6560j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private final double f6561k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public l(ReadableMap readableMap, o oVar) {
        super(null, 1, null);
        t2.j.f(readableMap, "config");
        t2.j.f(oVar, "nativeAnimatedNodesManager");
        this.f6559i = oVar;
        this.f6560j = readableMap.getInt("input");
        this.f6561k = readableMap.getDouble("modulus");
    }

    @Override // com.facebook.react.animated.w, com.facebook.react.animated.b
    public String e() {
        return "NativeAnimatedNodesManager[" + this.f6507d + "] inputNode: " + this.f6560j + " modulus: " + this.f6561k + " super: " + super.e();
    }

    @Override // com.facebook.react.animated.b
    public void h() {
        b bVarL = this.f6559i.l(this.f6560j);
        if (!(bVarL instanceof w)) {
            throw new JSApplicationCausedNativeException("Illegal node ID set as an input for Animated.modulus node");
        }
        double dL = ((w) bVarL).l();
        double d3 = this.f6561k;
        this.f6621f = ((dL % d3) + d3) % d3;
    }
}
