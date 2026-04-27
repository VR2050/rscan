package com.facebook.react.animated;

import com.facebook.react.bridge.ReadableMap;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public class w extends b {

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    public double f6621f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    public double f6622g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private c f6623h;

    public w(ReadableMap readableMap) {
        this.f6621f = readableMap != null ? readableMap.getDouble("value") : Double.NaN;
        this.f6622g = readableMap != null ? readableMap.getDouble("offset") : 0.0d;
    }

    @Override // com.facebook.react.animated.b
    public String e() {
        return "ValueAnimatedNode[" + this.f6507d + "]: value: " + this.f6621f + " offset: " + this.f6622g;
    }

    public final void i() {
        this.f6622g += this.f6621f;
        this.f6621f = 0.0d;
    }

    public final void j() {
        this.f6621f += this.f6622g;
        this.f6622g = 0.0d;
    }

    public Object k() {
        return null;
    }

    public final double l() {
        if (Double.isNaN(this.f6622g + this.f6621f)) {
            h();
        }
        return this.f6622g + this.f6621f;
    }

    public final void m() {
        c cVar = this.f6623h;
        if (cVar != null) {
            cVar.a(l());
        }
    }

    public final void n(c cVar) {
        this.f6623h = cVar;
    }

    public /* synthetic */ w(ReadableMap readableMap, int i3, DefaultConstructorMarker defaultConstructorMarker) {
        this((i3 & 1) != 0 ? null : readableMap);
    }
}
