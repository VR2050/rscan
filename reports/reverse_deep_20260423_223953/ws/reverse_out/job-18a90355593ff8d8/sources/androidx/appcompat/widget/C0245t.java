package androidx.appcompat.widget;

import android.content.Context;
import android.util.AttributeSet;
import android.view.View;
import android.widget.PopupWindow;

/* JADX INFO: renamed from: androidx.appcompat.widget.t, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
class C0245t extends PopupWindow {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private static final boolean f4177b = false;

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private boolean f4178a;

    public C0245t(Context context, AttributeSet attributeSet, int i3, int i4) {
        super(context, attributeSet, i3, i4);
        a(context, attributeSet, i3, i4);
    }

    private void a(Context context, AttributeSet attributeSet, int i3, int i4) {
        g0 g0VarU = g0.u(context, attributeSet, d.j.f9038Y1, i3, i4);
        if (g0VarU.r(d.j.f9045a2)) {
            b(g0VarU.a(d.j.f9045a2, false));
        }
        setBackgroundDrawable(g0VarU.f(d.j.f9041Z1));
        g0VarU.w();
    }

    private void b(boolean z3) {
        if (f4177b) {
            this.f4178a = z3;
        } else {
            androidx.core.widget.h.a(this, z3);
        }
    }

    @Override // android.widget.PopupWindow
    public void showAsDropDown(View view, int i3, int i4) {
        if (f4177b && this.f4178a) {
            i4 -= view.getHeight();
        }
        super.showAsDropDown(view, i3, i4);
    }

    @Override // android.widget.PopupWindow
    public void update(View view, int i3, int i4, int i5, int i6) {
        if (f4177b && this.f4178a) {
            i4 -= view.getHeight();
        }
        super.update(view, i3, i4, i5, i6);
    }

    @Override // android.widget.PopupWindow
    public void showAsDropDown(View view, int i3, int i4, int i5) {
        if (f4177b && this.f4178a) {
            i4 -= view.getHeight();
        }
        super.showAsDropDown(view, i3, i4, i5);
    }
}
