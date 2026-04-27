package com.th3rdwave.safeareacontext;

import com.facebook.react.bridge.Dynamic;
import com.facebook.react.bridge.ReadableType;
import com.facebook.react.uimanager.C0438c0;
import com.facebook.react.uimanager.C0444f0;
import com.facebook.react.uimanager.U;
import com.facebook.react.uimanager.Z0;

/* JADX INFO: loaded from: classes.dex */
public final class p extends U {

    /* JADX INFO: renamed from: A, reason: collision with root package name */
    private n f8773A;

    /* JADX INFO: renamed from: B, reason: collision with root package name */
    private final float[] f8774B;

    /* JADX INFO: renamed from: C, reason: collision with root package name */
    private final float[] f8775C;

    /* JADX INFO: renamed from: D, reason: collision with root package name */
    private boolean f8776D;

    public p() {
        int[] iArr = Z0.f7565c;
        this.f8774B = new float[iArr.length];
        this.f8775C = new float[iArr.length];
        int length = iArr.length;
        for (int i3 = 0; i3 < length; i3++) {
            this.f8774B[i3] = Float.NaN;
            this.f8775C[i3] = Float.NaN;
        }
    }

    private final float w1(l lVar, float f3, float f4) {
        return lVar == l.f8757b ? f4 : lVar == l.f8759d ? Math.max(f3, f4) : f3 + f4;
    }

    private final void x1(o oVar) {
        if (oVar == o.f8769b) {
            super.S(1, this.f8774B[1]);
            super.S(2, this.f8774B[2]);
            super.S(3, this.f8774B[3]);
            super.S(0, this.f8774B[0]);
        } else {
            super.V0(1, this.f8775C[1]);
            super.V0(2, this.f8775C[2]);
            super.V0(3, this.f8775C[3]);
            super.V0(0, this.f8775C[0]);
        }
        y0();
    }

    private final void y1() {
        n nVar = this.f8773A;
        if (nVar == null) {
            return;
        }
        o oVarC = nVar.c();
        o oVar = o.f8769b;
        float[] fArr = oVarC == oVar ? this.f8774B : this.f8775C;
        float f3 = fArr[8];
        if (Float.isNaN(f3)) {
            f3 = 0.0f;
        }
        float f4 = f3;
        float f5 = f4;
        float f6 = f5;
        float f7 = fArr[7];
        if (!Float.isNaN(f7)) {
            f3 = f7;
            f5 = f3;
        }
        float f8 = fArr[6];
        if (!Float.isNaN(f8)) {
            f4 = f8;
            f6 = f4;
        }
        float f9 = fArr[1];
        if (!Float.isNaN(f9)) {
            f3 = f9;
        }
        float f10 = fArr[2];
        if (!Float.isNaN(f10)) {
            f4 = f10;
        }
        float f11 = fArr[3];
        if (!Float.isNaN(f11)) {
            f5 = f11;
        }
        float f12 = fArr[0];
        if (!Float.isNaN(f12)) {
            f6 = f12;
        }
        float fH = C0444f0.h(f3);
        float fH2 = C0444f0.h(f4);
        float fH3 = C0444f0.h(f5);
        float fH4 = C0444f0.h(f6);
        m mVarA = nVar.a();
        a aVarB = nVar.b();
        if (nVar.c() == oVar) {
            super.S(1, w1(mVarA.d(), aVarB.d(), fH));
            super.S(2, w1(mVarA.c(), aVarB.c(), fH2));
            super.S(3, w1(mVarA.a(), aVarB.a(), fH3));
            super.S(0, w1(mVarA.b(), aVarB.b(), fH4));
            return;
        }
        super.V0(1, w1(mVarA.d(), aVarB.d(), fH));
        super.V0(2, w1(mVarA.c(), aVarB.c(), fH2));
        super.V0(3, w1(mVarA.a(), aVarB.a(), fH3));
        super.V0(0, w1(mVarA.b(), aVarB.b(), fH4));
    }

    @Override // com.facebook.react.uimanager.C0467r0, com.facebook.react.uimanager.InterfaceC0466q0
    public void O(C0438c0 c0438c0) {
        t2.j.f(c0438c0, "nativeViewHierarchyOptimizer");
        if (this.f8776D) {
            this.f8776D = false;
            y1();
        }
    }

    @Override // com.facebook.react.uimanager.C0467r0, com.facebook.react.uimanager.InterfaceC0466q0
    public void k(Object obj) {
        t2.j.f(obj, "data");
        if (obj instanceof n) {
            n nVar = this.f8773A;
            if (nVar != null && nVar.c() != ((n) obj).c()) {
                x1(nVar.c());
            }
            this.f8773A = (n) obj;
            this.f8776D = false;
            y1();
        }
    }

    @Override // com.facebook.react.uimanager.U
    @K1.b(names = {"margin", "marginVertical", "marginHorizontal", "marginStart", "marginEnd", "marginTop", "marginBottom", "marginLeft", "marginRight"})
    public void setMargins(int i3, Dynamic dynamic) {
        t2.j.f(dynamic, "margin");
        this.f8775C[Z0.f7565c[i3]] = dynamic.getType() == ReadableType.Number ? (float) dynamic.asDouble() : Float.NaN;
        super.setMargins(i3, dynamic);
        this.f8776D = true;
    }

    @Override // com.facebook.react.uimanager.U
    @K1.b(names = {"padding", "paddingVertical", "paddingHorizontal", "paddingStart", "paddingEnd", "paddingTop", "paddingBottom", "paddingLeft", "paddingRight"})
    public void setPaddings(int i3, Dynamic dynamic) {
        t2.j.f(dynamic, "padding");
        this.f8774B[Z0.f7565c[i3]] = dynamic.getType() == ReadableType.Number ? (float) dynamic.asDouble() : Float.NaN;
        super.setPaddings(i3, dynamic);
        this.f8776D = true;
    }
}
