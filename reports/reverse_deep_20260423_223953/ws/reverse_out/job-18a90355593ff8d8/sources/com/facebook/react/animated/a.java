package com.facebook.react.animated;

import com.facebook.react.bridge.JSApplicationCausedNativeException;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.ReadableMap;
import i2.AbstractC0580h;

/* JADX INFO: loaded from: classes.dex */
public final class a extends w {

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private final o f6501i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private final int[] f6502j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(ReadableMap readableMap, o oVar) {
        int[] iArr;
        super(null, 1, null);
        t2.j.f(readableMap, "config");
        t2.j.f(oVar, "nativeAnimatedNodesManager");
        this.f6501i = oVar;
        ReadableArray array = readableMap.getArray("input");
        if (array == null) {
            iArr = new int[0];
        } else {
            int size = array.size();
            int[] iArr2 = new int[size];
            for (int i3 = 0; i3 < size; i3++) {
                iArr2[i3] = array.getInt(i3);
            }
            iArr = iArr2;
        }
        this.f6502j = iArr;
    }

    @Override // com.facebook.react.animated.w, com.facebook.react.animated.b
    public String e() {
        return "AdditionAnimatedNode[" + this.f6507d + "]: input nodes: " + AbstractC0580h.w(this.f6502j, null, null, null, 0, null, null, 63, null) + " - super: " + super.e();
    }

    @Override // com.facebook.react.animated.b
    public void h() {
        this.f6621f = 0.0d;
        double dL = 0.0d;
        for (int i3 : this.f6502j) {
            b bVarL = this.f6501i.l(i3);
            if (!(bVarL instanceof w)) {
                throw new JSApplicationCausedNativeException("Illegal node ID set as an input for Animated.Add node");
            }
            dL += ((w) bVarL).l();
        }
        this.f6621f = 0.0d + dL;
    }
}
