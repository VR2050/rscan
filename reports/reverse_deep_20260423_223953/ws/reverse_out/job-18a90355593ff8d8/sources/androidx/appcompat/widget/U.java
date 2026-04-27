package androidx.appcompat.widget;

import android.content.Context;
import android.content.res.TypedArray;
import android.database.DataSetObserver;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.os.Handler;
import android.util.AttributeSet;
import android.util.Log;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.widget.AbsListView;
import android.widget.AdapterView;
import android.widget.LinearLayout;
import android.widget.ListAdapter;
import android.widget.ListView;
import android.widget.PopupWindow;
import java.lang.reflect.Method;

/* JADX INFO: loaded from: classes.dex */
public abstract class U implements i.e {

    /* JADX INFO: renamed from: H, reason: collision with root package name */
    private static Method f3878H;

    /* JADX INFO: renamed from: I, reason: collision with root package name */
    private static Method f3879I;

    /* JADX INFO: renamed from: A, reason: collision with root package name */
    private final e f3880A;

    /* JADX INFO: renamed from: B, reason: collision with root package name */
    private Runnable f3881B;

    /* JADX INFO: renamed from: C, reason: collision with root package name */
    final Handler f3882C;

    /* JADX INFO: renamed from: D, reason: collision with root package name */
    private final Rect f3883D;

    /* JADX INFO: renamed from: E, reason: collision with root package name */
    private Rect f3884E;

    /* JADX INFO: renamed from: F, reason: collision with root package name */
    private boolean f3885F;

    /* JADX INFO: renamed from: G, reason: collision with root package name */
    PopupWindow f3886G;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private Context f3887b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private ListAdapter f3888c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    P f3889d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private int f3890e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private int f3891f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private int f3892g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private int f3893h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private int f3894i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private boolean f3895j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private boolean f3896k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private boolean f3897l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private int f3898m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private boolean f3899n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private boolean f3900o;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    int f3901p;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private View f3902q;

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    private int f3903r;

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    private DataSetObserver f3904s;

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    private View f3905t;

    /* JADX INFO: renamed from: u, reason: collision with root package name */
    private Drawable f3906u;

    /* JADX INFO: renamed from: v, reason: collision with root package name */
    private AdapterView.OnItemClickListener f3907v;

    /* JADX INFO: renamed from: w, reason: collision with root package name */
    private AdapterView.OnItemSelectedListener f3908w;

    /* JADX INFO: renamed from: x, reason: collision with root package name */
    final i f3909x;

    /* JADX INFO: renamed from: y, reason: collision with root package name */
    private final h f3910y;

    /* JADX INFO: renamed from: z, reason: collision with root package name */
    private final g f3911z;

    class a implements Runnable {
        a() {
        }

        @Override // java.lang.Runnable
        public void run() {
            View viewT = U.this.t();
            if (viewT == null || viewT.getWindowToken() == null) {
                return;
            }
            U.this.b();
        }
    }

    class b implements AdapterView.OnItemSelectedListener {
        b() {
        }

        @Override // android.widget.AdapterView.OnItemSelectedListener
        public void onItemSelected(AdapterView adapterView, View view, int i3, long j3) {
            P p3;
            if (i3 == -1 || (p3 = U.this.f3889d) == null) {
                return;
            }
            p3.setListSelectionHidden(false);
        }

        @Override // android.widget.AdapterView.OnItemSelectedListener
        public void onNothingSelected(AdapterView adapterView) {
        }
    }

    static class c {
        static int a(PopupWindow popupWindow, View view, int i3, boolean z3) {
            return popupWindow.getMaxAvailableHeight(view, i3, z3);
        }
    }

    static class d {
        static void a(PopupWindow popupWindow, Rect rect) {
            popupWindow.setEpicenterBounds(rect);
        }

        static void b(PopupWindow popupWindow, boolean z3) {
            popupWindow.setIsClippedToScreen(z3);
        }
    }

    private class e implements Runnable {
        e() {
        }

        @Override // java.lang.Runnable
        public void run() {
            U.this.r();
        }
    }

    private class f extends DataSetObserver {
        f() {
        }

        @Override // android.database.DataSetObserver
        public void onChanged() {
            if (U.this.a()) {
                U.this.b();
            }
        }

        @Override // android.database.DataSetObserver
        public void onInvalidated() {
            U.this.dismiss();
        }
    }

    private class g implements AbsListView.OnScrollListener {
        g() {
        }

        @Override // android.widget.AbsListView.OnScrollListener
        public void onScroll(AbsListView absListView, int i3, int i4, int i5) {
        }

        @Override // android.widget.AbsListView.OnScrollListener
        public void onScrollStateChanged(AbsListView absListView, int i3) {
            if (i3 != 1 || U.this.w() || U.this.f3886G.getContentView() == null) {
                return;
            }
            U u3 = U.this;
            u3.f3882C.removeCallbacks(u3.f3909x);
            U.this.f3909x.run();
        }
    }

    private class h implements View.OnTouchListener {
        h() {
        }

        @Override // android.view.View.OnTouchListener
        public boolean onTouch(View view, MotionEvent motionEvent) {
            PopupWindow popupWindow;
            int action = motionEvent.getAction();
            int x3 = (int) motionEvent.getX();
            int y3 = (int) motionEvent.getY();
            if (action == 0 && (popupWindow = U.this.f3886G) != null && popupWindow.isShowing() && x3 >= 0 && x3 < U.this.f3886G.getWidth() && y3 >= 0 && y3 < U.this.f3886G.getHeight()) {
                U u3 = U.this;
                u3.f3882C.postDelayed(u3.f3909x, 250L);
                return false;
            }
            if (action != 1) {
                return false;
            }
            U u4 = U.this;
            u4.f3882C.removeCallbacks(u4.f3909x);
            return false;
        }
    }

    private class i implements Runnable {
        i() {
        }

        @Override // java.lang.Runnable
        public void run() {
            P p3 = U.this.f3889d;
            if (p3 == null || !p3.isAttachedToWindow() || U.this.f3889d.getCount() <= U.this.f3889d.getChildCount()) {
                return;
            }
            int childCount = U.this.f3889d.getChildCount();
            U u3 = U.this;
            if (childCount <= u3.f3901p) {
                u3.f3886G.setInputMethodMode(2);
                U.this.b();
            }
        }
    }

    static {
        if (Build.VERSION.SDK_INT <= 28) {
            try {
                f3878H = PopupWindow.class.getDeclaredMethod("setClipToScreenEnabled", Boolean.TYPE);
            } catch (NoSuchMethodException unused) {
                Log.i("ListPopupWindow", "Could not find method setClipToScreenEnabled() on PopupWindow. Oh well.");
            }
            try {
                f3879I = PopupWindow.class.getDeclaredMethod("setEpicenterBounds", Rect.class);
            } catch (NoSuchMethodException unused2) {
                Log.i("ListPopupWindow", "Could not find method setEpicenterBounds(Rect) on PopupWindow. Oh well.");
            }
        }
    }

    public U(Context context, AttributeSet attributeSet, int i3) {
        this(context, attributeSet, i3, 0);
    }

    private void J(boolean z3) {
        if (Build.VERSION.SDK_INT > 28) {
            d.b(this.f3886G, z3);
            return;
        }
        Method method = f3878H;
        if (method != null) {
            try {
                method.invoke(this.f3886G, Boolean.valueOf(z3));
            } catch (Exception unused) {
                Log.i("ListPopupWindow", "Could not call setClipToScreenEnabled() on PopupWindow. Oh well.");
            }
        }
    }

    private int q() {
        int measuredHeight;
        int i3;
        int iMakeMeasureSpec;
        View view;
        int i4;
        if (this.f3889d == null) {
            Context context = this.f3887b;
            this.f3881B = new a();
            P pS = s(context, !this.f3885F);
            this.f3889d = pS;
            Drawable drawable = this.f3906u;
            if (drawable != null) {
                pS.setSelector(drawable);
            }
            this.f3889d.setAdapter(this.f3888c);
            this.f3889d.setOnItemClickListener(this.f3907v);
            this.f3889d.setFocusable(true);
            this.f3889d.setFocusableInTouchMode(true);
            this.f3889d.setOnItemSelectedListener(new b());
            this.f3889d.setOnScrollListener(this.f3911z);
            AdapterView.OnItemSelectedListener onItemSelectedListener = this.f3908w;
            if (onItemSelectedListener != null) {
                this.f3889d.setOnItemSelectedListener(onItemSelectedListener);
            }
            P p3 = this.f3889d;
            View view2 = this.f3902q;
            if (view2 != null) {
                LinearLayout linearLayout = new LinearLayout(context);
                linearLayout.setOrientation(1);
                LinearLayout.LayoutParams layoutParams = new LinearLayout.LayoutParams(-1, 0, 1.0f);
                int i5 = this.f3903r;
                if (i5 == 0) {
                    linearLayout.addView(view2);
                    linearLayout.addView(p3, layoutParams);
                } else if (i5 != 1) {
                    Log.e("ListPopupWindow", "Invalid hint position " + this.f3903r);
                } else {
                    linearLayout.addView(p3, layoutParams);
                    linearLayout.addView(view2);
                }
                int i6 = this.f3891f;
                if (i6 >= 0) {
                    i4 = Integer.MIN_VALUE;
                } else {
                    i6 = 0;
                    i4 = 0;
                }
                view2.measure(View.MeasureSpec.makeMeasureSpec(i6, i4), 0);
                LinearLayout.LayoutParams layoutParams2 = (LinearLayout.LayoutParams) view2.getLayoutParams();
                measuredHeight = view2.getMeasuredHeight() + layoutParams2.topMargin + layoutParams2.bottomMargin;
                view = linearLayout;
            } else {
                measuredHeight = 0;
                view = p3;
            }
            this.f3886G.setContentView(view);
        } else {
            View view3 = this.f3902q;
            if (view3 != null) {
                LinearLayout.LayoutParams layoutParams3 = (LinearLayout.LayoutParams) view3.getLayoutParams();
                measuredHeight = view3.getMeasuredHeight() + layoutParams3.topMargin + layoutParams3.bottomMargin;
            } else {
                measuredHeight = 0;
            }
        }
        Drawable background = this.f3886G.getBackground();
        if (background != null) {
            background.getPadding(this.f3883D);
            Rect rect = this.f3883D;
            int i7 = rect.top;
            i3 = rect.bottom + i7;
            if (!this.f3895j) {
                this.f3893h = -i7;
            }
        } else {
            this.f3883D.setEmpty();
            i3 = 0;
        }
        int iU = u(t(), this.f3893h, this.f3886G.getInputMethodMode() == 2);
        if (this.f3899n || this.f3890e == -1) {
            return iU + i3;
        }
        int i8 = this.f3891f;
        if (i8 == -2) {
            int i9 = this.f3887b.getResources().getDisplayMetrics().widthPixels;
            Rect rect2 = this.f3883D;
            iMakeMeasureSpec = View.MeasureSpec.makeMeasureSpec(i9 - (rect2.left + rect2.right), Integer.MIN_VALUE);
        } else if (i8 != -1) {
            iMakeMeasureSpec = View.MeasureSpec.makeMeasureSpec(i8, 1073741824);
        } else {
            int i10 = this.f3887b.getResources().getDisplayMetrics().widthPixels;
            Rect rect3 = this.f3883D;
            iMakeMeasureSpec = View.MeasureSpec.makeMeasureSpec(i10 - (rect3.left + rect3.right), 1073741824);
        }
        int iD = this.f3889d.d(iMakeMeasureSpec, 0, -1, iU - measuredHeight, -1);
        if (iD > 0) {
            measuredHeight += i3 + this.f3889d.getPaddingTop() + this.f3889d.getPaddingBottom();
        }
        return iD + measuredHeight;
    }

    private int u(View view, int i3, boolean z3) {
        return c.a(this.f3886G, view, i3, z3);
    }

    private void y() {
        View view = this.f3902q;
        if (view != null) {
            ViewParent parent = view.getParent();
            if (parent instanceof ViewGroup) {
                ((ViewGroup) parent).removeView(this.f3902q);
            }
        }
    }

    public void A(int i3) {
        this.f3886G.setAnimationStyle(i3);
    }

    public void B(int i3) {
        Drawable background = this.f3886G.getBackground();
        if (background == null) {
            M(i3);
            return;
        }
        background.getPadding(this.f3883D);
        Rect rect = this.f3883D;
        this.f3891f = rect.left + rect.right + i3;
    }

    public void C(int i3) {
        this.f3898m = i3;
    }

    public void D(Rect rect) {
        this.f3884E = rect != null ? new Rect(rect) : null;
    }

    public void E(int i3) {
        this.f3886G.setInputMethodMode(i3);
    }

    public void F(boolean z3) {
        this.f3885F = z3;
        this.f3886G.setFocusable(z3);
    }

    public void G(PopupWindow.OnDismissListener onDismissListener) {
        this.f3886G.setOnDismissListener(onDismissListener);
    }

    public void H(AdapterView.OnItemClickListener onItemClickListener) {
        this.f3907v = onItemClickListener;
    }

    public void I(boolean z3) {
        this.f3897l = true;
        this.f3896k = z3;
    }

    public void K(int i3) {
        this.f3903r = i3;
    }

    public void L(int i3) {
        P p3 = this.f3889d;
        if (!a() || p3 == null) {
            return;
        }
        p3.setListSelectionHidden(false);
        p3.setSelection(i3);
        if (p3.getChoiceMode() != 0) {
            p3.setItemChecked(i3, true);
        }
    }

    public void M(int i3) {
        this.f3891f = i3;
    }

    @Override // i.e
    public boolean a() {
        return this.f3886G.isShowing();
    }

    @Override // i.e
    public void b() {
        int iQ = q();
        boolean zW = w();
        androidx.core.widget.h.b(this.f3886G, this.f3894i);
        if (this.f3886G.isShowing()) {
            if (t().isAttachedToWindow()) {
                int width = this.f3891f;
                if (width == -1) {
                    width = -1;
                } else if (width == -2) {
                    width = t().getWidth();
                }
                int i3 = this.f3890e;
                if (i3 == -1) {
                    if (!zW) {
                        iQ = -1;
                    }
                    if (zW) {
                        this.f3886G.setWidth(this.f3891f == -1 ? -1 : 0);
                        this.f3886G.setHeight(0);
                    } else {
                        this.f3886G.setWidth(this.f3891f == -1 ? -1 : 0);
                        this.f3886G.setHeight(-1);
                    }
                } else if (i3 != -2) {
                    iQ = i3;
                }
                this.f3886G.setOutsideTouchable((this.f3900o || this.f3899n) ? false : true);
                this.f3886G.update(t(), this.f3892g, this.f3893h, width < 0 ? -1 : width, iQ < 0 ? -1 : iQ);
                return;
            }
            return;
        }
        int width2 = this.f3891f;
        if (width2 == -1) {
            width2 = -1;
        } else if (width2 == -2) {
            width2 = t().getWidth();
        }
        int i4 = this.f3890e;
        if (i4 == -1) {
            iQ = -1;
        } else if (i4 != -2) {
            iQ = i4;
        }
        this.f3886G.setWidth(width2);
        this.f3886G.setHeight(iQ);
        J(true);
        this.f3886G.setOutsideTouchable((this.f3900o || this.f3899n) ? false : true);
        this.f3886G.setTouchInterceptor(this.f3910y);
        if (this.f3897l) {
            androidx.core.widget.h.a(this.f3886G, this.f3896k);
        }
        if (Build.VERSION.SDK_INT <= 28) {
            Method method = f3879I;
            if (method != null) {
                try {
                    method.invoke(this.f3886G, this.f3884E);
                } catch (Exception e3) {
                    Log.e("ListPopupWindow", "Could not invoke setEpicenterBounds on PopupWindow", e3);
                }
            }
        } else {
            d.a(this.f3886G, this.f3884E);
        }
        androidx.core.widget.h.c(this.f3886G, t(), this.f3892g, this.f3893h, this.f3898m);
        this.f3889d.setSelection(-1);
        if (!this.f3885F || this.f3889d.isInTouchMode()) {
            r();
        }
        if (this.f3885F) {
            return;
        }
        this.f3882C.post(this.f3880A);
    }

    public int c() {
        return this.f3892g;
    }

    @Override // i.e
    public void dismiss() {
        this.f3886G.dismiss();
        y();
        this.f3886G.setContentView(null);
        this.f3889d = null;
        this.f3882C.removeCallbacks(this.f3909x);
    }

    public Drawable f() {
        return this.f3886G.getBackground();
    }

    @Override // i.e
    public ListView g() {
        return this.f3889d;
    }

    public void i(Drawable drawable) {
        this.f3886G.setBackgroundDrawable(drawable);
    }

    public void j(int i3) {
        this.f3893h = i3;
        this.f3895j = true;
    }

    public void l(int i3) {
        this.f3892g = i3;
    }

    public int n() {
        if (this.f3895j) {
            return this.f3893h;
        }
        return 0;
    }

    public void p(ListAdapter listAdapter) {
        DataSetObserver dataSetObserver = this.f3904s;
        if (dataSetObserver == null) {
            this.f3904s = new f();
        } else {
            ListAdapter listAdapter2 = this.f3888c;
            if (listAdapter2 != null) {
                listAdapter2.unregisterDataSetObserver(dataSetObserver);
            }
        }
        this.f3888c = listAdapter;
        if (listAdapter != null) {
            listAdapter.registerDataSetObserver(this.f3904s);
        }
        P p3 = this.f3889d;
        if (p3 != null) {
            p3.setAdapter(this.f3888c);
        }
    }

    public void r() {
        P p3 = this.f3889d;
        if (p3 != null) {
            p3.setListSelectionHidden(true);
            p3.requestLayout();
        }
    }

    P s(Context context, boolean z3) {
        return new P(context, z3);
    }

    public View t() {
        return this.f3905t;
    }

    public int v() {
        return this.f3891f;
    }

    public boolean w() {
        return this.f3886G.getInputMethodMode() == 2;
    }

    public boolean x() {
        return this.f3885F;
    }

    public void z(View view) {
        this.f3905t = view;
    }

    public U(Context context, AttributeSet attributeSet, int i3, int i4) {
        this.f3890e = -2;
        this.f3891f = -2;
        this.f3894i = 1002;
        this.f3898m = 0;
        this.f3899n = false;
        this.f3900o = false;
        this.f3901p = Integer.MAX_VALUE;
        this.f3903r = 0;
        this.f3909x = new i();
        this.f3910y = new h();
        this.f3911z = new g();
        this.f3880A = new e();
        this.f3883D = new Rect();
        this.f3887b = context;
        this.f3882C = new Handler(context.getMainLooper());
        TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(attributeSet, d.j.f9088l1, i3, i4);
        this.f3892g = typedArrayObtainStyledAttributes.getDimensionPixelOffset(d.j.f9092m1, 0);
        int dimensionPixelOffset = typedArrayObtainStyledAttributes.getDimensionPixelOffset(d.j.f9096n1, 0);
        this.f3893h = dimensionPixelOffset;
        if (dimensionPixelOffset != 0) {
            this.f3895j = true;
        }
        typedArrayObtainStyledAttributes.recycle();
        C0245t c0245t = new C0245t(context, attributeSet, i3, i4);
        this.f3886G = c0245t;
        c0245t.setInputMethodMode(1);
    }
}
