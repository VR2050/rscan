package com.facebook.react.animated;

import com.facebook.react.bridge.JSApplicationCausedNativeException;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.ReadableMap;

/* JADX INFO: loaded from: classes.dex */
public final class m extends w {

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private final o f6562i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private int[] f6563j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public m(ReadableMap readableMap, o oVar) {
        int[] iArr;
        super(null, 1, null);
        t2.j.f(readableMap, "config");
        t2.j.f(oVar, "nativeAnimatedNodesManager");
        this.f6562i = oVar;
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
        this.f6563j = iArr;
    }

    @Override // com.facebook.react.animated.w, com.facebook.react.animated.b
    public String e() {
        return "MultiplicationAnimatedNode[" + this.f6507d + "]: input nodes: " + this.f6563j + " - super: " + super.e();
    }

    @Override // com.facebook.react.animated.b
    public void h() {
        this.f6621f = 1.0d;
        int length = this.f6563j.length;
        for (int i3 = 0; i3 < length; i3++) {
            b bVarL = this.f6562i.l(this.f6563j[i3]);
            if (bVarL == null || !(bVarL instanceof w)) {
                throw new JSApplicationCausedNativeException("Illegal node ID set as an input for Animated.multiply node");
            }
            this.f6621f *= ((w) bVarL).l();
        }
    }
}
