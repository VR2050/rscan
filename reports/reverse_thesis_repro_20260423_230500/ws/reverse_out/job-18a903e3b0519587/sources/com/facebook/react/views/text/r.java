package com.facebook.react.views.text;

import com.facebook.react.uimanager.C0444f0;

/* JADX INFO: loaded from: classes.dex */
public class r {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private boolean f8166a = true;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private float f8167b = Float.NaN;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private float f8168c = Float.NaN;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private float f8169d = Float.NaN;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private float f8170e = Float.NaN;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private float f8171f = Float.NaN;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private t f8172g = t.f8182g;

    public r a(r rVar) {
        r rVar2 = new r();
        rVar2.f8166a = this.f8166a;
        rVar2.f8167b = !Float.isNaN(rVar.f8167b) ? rVar.f8167b : this.f8167b;
        rVar2.f8168c = !Float.isNaN(rVar.f8168c) ? rVar.f8168c : this.f8168c;
        rVar2.f8169d = !Float.isNaN(rVar.f8169d) ? rVar.f8169d : this.f8169d;
        rVar2.f8170e = !Float.isNaN(rVar.f8170e) ? rVar.f8170e : this.f8170e;
        rVar2.f8171f = !Float.isNaN(rVar.f8171f) ? rVar.f8171f : this.f8171f;
        t tVar = rVar.f8172g;
        if (tVar == t.f8182g) {
            tVar = this.f8172g;
        }
        rVar2.f8172g = tVar;
        return rVar2;
    }

    public boolean b() {
        return this.f8166a;
    }

    public int c() {
        float f3 = !Float.isNaN(this.f8167b) ? this.f8167b : 14.0f;
        return (int) (this.f8166a ? Math.ceil(C0444f0.k(f3, f())) : Math.ceil(C0444f0.h(f3)));
    }

    public float d() {
        if (Float.isNaN(this.f8169d)) {
            return Float.NaN;
        }
        return (this.f8166a ? C0444f0.k(this.f8169d, f()) : C0444f0.h(this.f8169d)) / c();
    }

    public float e() {
        if (Float.isNaN(this.f8168c)) {
            return Float.NaN;
        }
        float fK = this.f8166a ? C0444f0.k(this.f8168c, f()) : C0444f0.h(this.f8168c);
        if (Float.isNaN(this.f8171f)) {
            return fK;
        }
        float f3 = this.f8171f;
        return f3 > fK ? f3 : fK;
    }

    public float f() {
        if (Float.isNaN(this.f8170e)) {
            return 0.0f;
        }
        return this.f8170e;
    }

    public float g() {
        return this.f8167b;
    }

    public float h() {
        return this.f8171f;
    }

    public float i() {
        return this.f8169d;
    }

    public float j() {
        return this.f8168c;
    }

    public float k() {
        return this.f8170e;
    }

    public t l() {
        return this.f8172g;
    }

    public void m(boolean z3) {
        this.f8166a = z3;
    }

    public void n(float f3) {
        this.f8167b = f3;
    }

    public void o(float f3) {
        this.f8171f = f3;
    }

    public void p(float f3) {
        this.f8169d = f3;
    }

    public void q(float f3) {
        this.f8168c = f3;
    }

    public void r(float f3) {
        if (f3 == 0.0f || f3 >= 1.0f) {
            this.f8170e = f3;
        } else {
            Y.a.I("ReactNative", "maxFontSizeMultiplier must be NaN, 0, or >= 1");
            this.f8170e = Float.NaN;
        }
    }

    public void s(t tVar) {
        this.f8172g = tVar;
    }

    public String toString() {
        return "TextAttributes {\n  getAllowFontScaling(): " + b() + "\n  getFontSize(): " + g() + "\n  getEffectiveFontSize(): " + c() + "\n  getHeightOfTallestInlineViewOrImage(): " + h() + "\n  getLetterSpacing(): " + i() + "\n  getEffectiveLetterSpacing(): " + d() + "\n  getLineHeight(): " + j() + "\n  getEffectiveLineHeight(): " + e() + "\n  getTextTransform(): " + l() + "\n  getMaxFontSizeMultiplier(): " + k() + "\n  getEffectiveMaxFontSizeMultiplier(): " + f() + "\n}";
    }
}
