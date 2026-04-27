package androidx.appcompat.widget;

import android.app.Activity;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.res.Resources;
import android.graphics.Rect;
import android.util.DisplayMetrics;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.widget.TextView;

/* JADX INFO: loaded from: classes.dex */
class p0 {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Context f4153a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final View f4154b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final TextView f4155c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final WindowManager.LayoutParams f4156d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final Rect f4157e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final int[] f4158f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private final int[] f4159g;

    p0(Context context) {
        WindowManager.LayoutParams layoutParams = new WindowManager.LayoutParams();
        this.f4156d = layoutParams;
        this.f4157e = new Rect();
        this.f4158f = new int[2];
        this.f4159g = new int[2];
        this.f4153a = context;
        View viewInflate = LayoutInflater.from(context).inflate(d.g.f8926q, (ViewGroup) null);
        this.f4154b = viewInflate;
        this.f4155c = (TextView) viewInflate.findViewById(d.f.f8901r);
        layoutParams.setTitle(getClass().getSimpleName());
        layoutParams.packageName = context.getPackageName();
        layoutParams.type = 1002;
        layoutParams.width = -2;
        layoutParams.height = -2;
        layoutParams.format = -3;
        layoutParams.windowAnimations = d.i.f8941a;
        layoutParams.flags = 24;
    }

    private void a(View view, int i3, int i4, boolean z3, WindowManager.LayoutParams layoutParams) {
        int height;
        int i5;
        layoutParams.token = view.getApplicationWindowToken();
        int dimensionPixelOffset = this.f4153a.getResources().getDimensionPixelOffset(d.d.f8830g);
        if (view.getWidth() < dimensionPixelOffset) {
            i3 = view.getWidth() / 2;
        }
        if (view.getHeight() >= dimensionPixelOffset) {
            int dimensionPixelOffset2 = this.f4153a.getResources().getDimensionPixelOffset(d.d.f8829f);
            height = i4 + dimensionPixelOffset2;
            i5 = i4 - dimensionPixelOffset2;
        } else {
            height = view.getHeight();
            i5 = 0;
        }
        layoutParams.gravity = 49;
        int dimensionPixelOffset3 = this.f4153a.getResources().getDimensionPixelOffset(z3 ? d.d.f8832i : d.d.f8831h);
        View viewB = b(view);
        if (viewB == null) {
            Log.e("TooltipPopup", "Cannot find app view");
            return;
        }
        viewB.getWindowVisibleDisplayFrame(this.f4157e);
        Rect rect = this.f4157e;
        if (rect.left < 0 && rect.top < 0) {
            Resources resources = this.f4153a.getResources();
            int identifier = resources.getIdentifier("status_bar_height", "dimen", "android");
            int dimensionPixelSize = identifier != 0 ? resources.getDimensionPixelSize(identifier) : 0;
            DisplayMetrics displayMetrics = resources.getDisplayMetrics();
            this.f4157e.set(0, dimensionPixelSize, displayMetrics.widthPixels, displayMetrics.heightPixels);
        }
        viewB.getLocationOnScreen(this.f4159g);
        view.getLocationOnScreen(this.f4158f);
        int[] iArr = this.f4158f;
        int i6 = iArr[0];
        int[] iArr2 = this.f4159g;
        int i7 = i6 - iArr2[0];
        iArr[0] = i7;
        iArr[1] = iArr[1] - iArr2[1];
        layoutParams.x = (i7 + i3) - (viewB.getWidth() / 2);
        int iMakeMeasureSpec = View.MeasureSpec.makeMeasureSpec(0, 0);
        this.f4154b.measure(iMakeMeasureSpec, iMakeMeasureSpec);
        int measuredHeight = this.f4154b.getMeasuredHeight();
        int i8 = this.f4158f[1];
        int i9 = ((i5 + i8) - dimensionPixelOffset3) - measuredHeight;
        int i10 = i8 + height + dimensionPixelOffset3;
        if (z3) {
            if (i9 >= 0) {
                layoutParams.y = i9;
                return;
            } else {
                layoutParams.y = i10;
                return;
            }
        }
        if (measuredHeight + i10 <= this.f4157e.height()) {
            layoutParams.y = i10;
        } else {
            layoutParams.y = i9;
        }
    }

    private static View b(View view) {
        View rootView = view.getRootView();
        ViewGroup.LayoutParams layoutParams = rootView.getLayoutParams();
        if ((layoutParams instanceof WindowManager.LayoutParams) && ((WindowManager.LayoutParams) layoutParams).type == 2) {
            return rootView;
        }
        for (Context context = view.getContext(); context instanceof ContextWrapper; context = ((ContextWrapper) context).getBaseContext()) {
            if (context instanceof Activity) {
                return ((Activity) context).getWindow().getDecorView();
            }
        }
        return rootView;
    }

    void c() {
        if (d()) {
            ((WindowManager) this.f4153a.getSystemService("window")).removeView(this.f4154b);
        }
    }

    boolean d() {
        return this.f4154b.getParent() != null;
    }

    void e(View view, int i3, int i4, boolean z3, CharSequence charSequence) {
        if (d()) {
            c();
        }
        this.f4155c.setText(charSequence);
        a(view, i3, i4, z3, this.f4156d);
        ((WindowManager) this.f4153a.getSystemService("window")).addView(this.f4154b, this.f4156d);
    }
}
