package androidx.appcompat.view.menu;

import android.content.Context;
import android.graphics.Point;
import android.graphics.Rect;
import android.view.Display;
import android.view.View;
import android.view.WindowManager;
import android.widget.PopupWindow;
import androidx.appcompat.view.menu.j;
import androidx.core.view.AbstractC0281s;

/* JADX INFO: loaded from: classes.dex */
public class i {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Context f3553a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final e f3554b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final boolean f3555c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final int f3556d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final int f3557e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private View f3558f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private int f3559g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private boolean f3560h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private j.a f3561i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private h f3562j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private PopupWindow.OnDismissListener f3563k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private final PopupWindow.OnDismissListener f3564l;

    class a implements PopupWindow.OnDismissListener {
        a() {
        }

        @Override // android.widget.PopupWindow.OnDismissListener
        public void onDismiss() {
            i.this.e();
        }
    }

    public i(Context context, e eVar, View view, boolean z3, int i3) {
        this(context, eVar, view, z3, i3, 0);
    }

    private h a() {
        Display defaultDisplay = ((WindowManager) this.f3553a.getSystemService("window")).getDefaultDisplay();
        Point point = new Point();
        defaultDisplay.getRealSize(point);
        h bVar = Math.min(point.x, point.y) >= this.f3553a.getResources().getDimensionPixelSize(d.d.f8824a) ? new b(this.f3553a, this.f3558f, this.f3556d, this.f3557e, this.f3555c) : new l(this.f3553a, this.f3554b, this.f3558f, this.f3556d, this.f3557e, this.f3555c);
        bVar.l(this.f3554b);
        bVar.u(this.f3564l);
        bVar.p(this.f3558f);
        bVar.k(this.f3561i);
        bVar.r(this.f3560h);
        bVar.s(this.f3559g);
        return bVar;
    }

    private void l(int i3, int i4, boolean z3, boolean z4) {
        h hVarC = c();
        hVarC.v(z4);
        if (z3) {
            if ((AbstractC0281s.a(this.f3559g, this.f3558f.getLayoutDirection()) & 7) == 5) {
                i3 -= this.f3558f.getWidth();
            }
            hVarC.t(i3);
            hVarC.w(i4);
            int i5 = (int) ((this.f3553a.getResources().getDisplayMetrics().density * 48.0f) / 2.0f);
            hVarC.q(new Rect(i3 - i5, i4 - i5, i3 + i5, i4 + i5));
        }
        hVarC.b();
    }

    public void b() {
        if (d()) {
            this.f3562j.dismiss();
        }
    }

    public h c() {
        if (this.f3562j == null) {
            this.f3562j = a();
        }
        return this.f3562j;
    }

    public boolean d() {
        h hVar = this.f3562j;
        return hVar != null && hVar.a();
    }

    protected void e() {
        this.f3562j = null;
        PopupWindow.OnDismissListener onDismissListener = this.f3563k;
        if (onDismissListener != null) {
            onDismissListener.onDismiss();
        }
    }

    public void f(View view) {
        this.f3558f = view;
    }

    public void g(boolean z3) {
        this.f3560h = z3;
        h hVar = this.f3562j;
        if (hVar != null) {
            hVar.r(z3);
        }
    }

    public void h(int i3) {
        this.f3559g = i3;
    }

    public void i(PopupWindow.OnDismissListener onDismissListener) {
        this.f3563k = onDismissListener;
    }

    public void j(j.a aVar) {
        this.f3561i = aVar;
        h hVar = this.f3562j;
        if (hVar != null) {
            hVar.k(aVar);
        }
    }

    public void k() {
        if (!m()) {
            throw new IllegalStateException("MenuPopupHelper cannot be used without an anchor");
        }
    }

    public boolean m() {
        if (d()) {
            return true;
        }
        if (this.f3558f == null) {
            return false;
        }
        l(0, 0, false, false);
        return true;
    }

    public boolean n(int i3, int i4) {
        if (d()) {
            return true;
        }
        if (this.f3558f == null) {
            return false;
        }
        l(i3, i4, true, true);
        return true;
    }

    public i(Context context, e eVar, View view, boolean z3, int i3, int i4) {
        this.f3559g = 8388611;
        this.f3564l = new a();
        this.f3553a = context;
        this.f3554b = eVar;
        this.f3558f = view;
        this.f3555c = z3;
        this.f3556d = i3;
        this.f3557e = i4;
    }
}
