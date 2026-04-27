package com.facebook.react.animated;

import com.facebook.react.bridge.JSApplicationCausedNativeException;
import com.facebook.react.bridge.ReadableMap;

/* JADX INFO: loaded from: classes.dex */
public final class h extends w {

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private final o f6528i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private final int f6529j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private final double f6530k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private final double f6531l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private double f6532m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public h(ReadableMap readableMap, o oVar) {
        super(null, 1, null);
        t2.j.f(readableMap, "config");
        t2.j.f(oVar, "nativeAnimatedNodesManager");
        this.f6528i = oVar;
        this.f6529j = readableMap.getInt("input");
        this.f6530k = readableMap.getDouble("min");
        this.f6531l = readableMap.getDouble("max");
        this.f6621f = this.f6532m;
    }

    private final double o() {
        b bVarL = this.f6528i.l(this.f6529j);
        if (bVarL == null || !(bVarL instanceof w)) {
            throw new JSApplicationCausedNativeException("Illegal node ID set as an input for Animated.DiffClamp node");
        }
        return ((w) bVarL).l();
    }

    @Override // com.facebook.react.animated.w, com.facebook.react.animated.b
    public String e() {
        return "DiffClampAnimatedNode[" + this.f6507d + "]: InputNodeTag: " + this.f6529j + " min: " + this.f6530k + " max: " + this.f6531l + " lastValue: " + this.f6532m + " super: " + super.e();
    }

    @Override // com.facebook.react.animated.b
    public void h() {
        double dO = o();
        double d3 = dO - this.f6532m;
        this.f6532m = dO;
        this.f6621f = Math.min(Math.max(this.f6621f + d3, this.f6530k), this.f6531l);
    }
}
