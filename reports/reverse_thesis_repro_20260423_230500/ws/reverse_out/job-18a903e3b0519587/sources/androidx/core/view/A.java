package androidx.core.view;

import android.view.View;
import android.view.ViewParent;

/* JADX INFO: loaded from: classes.dex */
public class A {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private ViewParent f4388a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private ViewParent f4389b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final View f4390c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private boolean f4391d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private int[] f4392e;

    public A(View view) {
        this.f4390c = view;
    }

    private boolean g(int i3, int i4, int i5, int i6, int[] iArr, int i7, int[] iArr2) {
        ViewParent viewParentH;
        int i8;
        int i9;
        int[] iArr3;
        if (!l() || (viewParentH = h(i7)) == null) {
            return false;
        }
        if (i3 == 0 && i4 == 0 && i5 == 0 && i6 == 0) {
            if (iArr != null) {
                iArr[0] = 0;
                iArr[1] = 0;
            }
            return false;
        }
        if (iArr != null) {
            this.f4390c.getLocationInWindow(iArr);
            i8 = iArr[0];
            i9 = iArr[1];
        } else {
            i8 = 0;
            i9 = 0;
        }
        if (iArr2 == null) {
            int[] iArrI = i();
            iArrI[0] = 0;
            iArrI[1] = 0;
            iArr3 = iArrI;
        } else {
            iArr3 = iArr2;
        }
        AbstractC0257c0.d(viewParentH, this.f4390c, i3, i4, i5, i6, i7, iArr3);
        if (iArr != null) {
            this.f4390c.getLocationInWindow(iArr);
            iArr[0] = iArr[0] - i8;
            iArr[1] = iArr[1] - i9;
        }
        return true;
    }

    private ViewParent h(int i3) {
        if (i3 == 0) {
            return this.f4388a;
        }
        if (i3 != 1) {
            return null;
        }
        return this.f4389b;
    }

    private int[] i() {
        if (this.f4392e == null) {
            this.f4392e = new int[2];
        }
        return this.f4392e;
    }

    private void n(int i3, ViewParent viewParent) {
        if (i3 == 0) {
            this.f4388a = viewParent;
        } else {
            if (i3 != 1) {
                return;
            }
            this.f4389b = viewParent;
        }
    }

    public boolean a(float f3, float f4, boolean z3) {
        ViewParent viewParentH;
        if (!l() || (viewParentH = h(0)) == null) {
            return false;
        }
        return AbstractC0257c0.a(viewParentH, this.f4390c, f3, f4, z3);
    }

    public boolean b(float f3, float f4) {
        ViewParent viewParentH;
        if (!l() || (viewParentH = h(0)) == null) {
            return false;
        }
        return AbstractC0257c0.b(viewParentH, this.f4390c, f3, f4);
    }

    public boolean c(int i3, int i4, int[] iArr, int[] iArr2) {
        return d(i3, i4, iArr, iArr2, 0);
    }

    public boolean d(int i3, int i4, int[] iArr, int[] iArr2, int i5) {
        ViewParent viewParentH;
        int i6;
        int i7;
        if (!l() || (viewParentH = h(i5)) == null) {
            return false;
        }
        if (i3 == 0 && i4 == 0) {
            if (iArr2 == null) {
                return false;
            }
            iArr2[0] = 0;
            iArr2[1] = 0;
            return false;
        }
        if (iArr2 != null) {
            this.f4390c.getLocationInWindow(iArr2);
            i6 = iArr2[0];
            i7 = iArr2[1];
        } else {
            i6 = 0;
            i7 = 0;
        }
        if (iArr == null) {
            iArr = i();
        }
        iArr[0] = 0;
        iArr[1] = 0;
        AbstractC0257c0.c(viewParentH, this.f4390c, i3, i4, iArr, i5);
        if (iArr2 != null) {
            this.f4390c.getLocationInWindow(iArr2);
            iArr2[0] = iArr2[0] - i6;
            iArr2[1] = iArr2[1] - i7;
        }
        return (iArr[0] == 0 && iArr[1] == 0) ? false : true;
    }

    public void e(int i3, int i4, int i5, int i6, int[] iArr, int i7, int[] iArr2) {
        g(i3, i4, i5, i6, iArr, i7, iArr2);
    }

    public boolean f(int i3, int i4, int i5, int i6, int[] iArr) {
        return g(i3, i4, i5, i6, iArr, 0, null);
    }

    public boolean j() {
        return k(0);
    }

    public boolean k(int i3) {
        return h(i3) != null;
    }

    public boolean l() {
        return this.f4391d;
    }

    public void m(boolean z3) {
        if (this.f4391d) {
            V.o0(this.f4390c);
        }
        this.f4391d = z3;
    }

    public boolean o(int i3) {
        return p(i3, 0);
    }

    public boolean p(int i3, int i4) {
        if (k(i4)) {
            return true;
        }
        if (!l()) {
            return false;
        }
        View view = this.f4390c;
        for (ViewParent parent = this.f4390c.getParent(); parent != null; parent = parent.getParent()) {
            if (AbstractC0257c0.f(parent, view, this.f4390c, i3, i4)) {
                n(i4, parent);
                AbstractC0257c0.e(parent, view, this.f4390c, i3, i4);
                return true;
            }
            if (parent instanceof View) {
                view = (View) parent;
            }
        }
        return false;
    }

    public void q() {
        r(0);
    }

    public void r(int i3) {
        ViewParent viewParentH = h(i3);
        if (viewParentH != null) {
            AbstractC0257c0.g(viewParentH, this.f4390c, i3);
            n(i3, null);
        }
    }
}
