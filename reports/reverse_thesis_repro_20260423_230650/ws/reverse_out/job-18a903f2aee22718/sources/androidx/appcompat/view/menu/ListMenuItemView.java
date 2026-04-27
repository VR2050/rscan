package androidx.appcompat.view.menu;

import android.R;
import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.util.AttributeSet;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AbsListView;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RadioButton;
import android.widget.TextView;
import androidx.appcompat.view.menu.k;
import androidx.appcompat.widget.g0;
import d.AbstractC0502a;

/* JADX INFO: loaded from: classes.dex */
public class ListMenuItemView extends LinearLayout implements k.a, AbsListView.SelectionBoundsAdjuster {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private g f3408b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private ImageView f3409c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private RadioButton f3410d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private TextView f3411e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private CheckBox f3412f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private TextView f3413g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private ImageView f3414h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private ImageView f3415i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private LinearLayout f3416j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private Drawable f3417k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private int f3418l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private Context f3419m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private boolean f3420n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private Drawable f3421o;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private boolean f3422p;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private LayoutInflater f3423q;

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    private boolean f3424r;

    public ListMenuItemView(Context context, AttributeSet attributeSet) {
        this(context, attributeSet, AbstractC0502a.f8780A);
    }

    private void b(View view) {
        c(view, -1);
    }

    private void c(View view, int i3) {
        LinearLayout linearLayout = this.f3416j;
        if (linearLayout != null) {
            linearLayout.addView(view, i3);
        } else {
            addView(view, i3);
        }
    }

    private void d() {
        CheckBox checkBox = (CheckBox) getInflater().inflate(d.g.f8917h, (ViewGroup) this, false);
        this.f3412f = checkBox;
        b(checkBox);
    }

    private void f() {
        ImageView imageView = (ImageView) getInflater().inflate(d.g.f8918i, (ViewGroup) this, false);
        this.f3409c = imageView;
        c(imageView, 0);
    }

    private void g() {
        RadioButton radioButton = (RadioButton) getInflater().inflate(d.g.f8920k, (ViewGroup) this, false);
        this.f3410d = radioButton;
        b(radioButton);
    }

    private LayoutInflater getInflater() {
        if (this.f3423q == null) {
            this.f3423q = LayoutInflater.from(getContext());
        }
        return this.f3423q;
    }

    private void setSubMenuArrowVisible(boolean z3) {
        ImageView imageView = this.f3414h;
        if (imageView != null) {
            imageView.setVisibility(z3 ? 0 : 8);
        }
    }

    @Override // androidx.appcompat.view.menu.k.a
    public boolean a() {
        return false;
    }

    @Override // android.widget.AbsListView.SelectionBoundsAdjuster
    public void adjustListItemSelectionBounds(Rect rect) {
        ImageView imageView = this.f3415i;
        if (imageView == null || imageView.getVisibility() != 0) {
            return;
        }
        LinearLayout.LayoutParams layoutParams = (LinearLayout.LayoutParams) this.f3415i.getLayoutParams();
        rect.top += this.f3415i.getHeight() + layoutParams.topMargin + layoutParams.bottomMargin;
    }

    @Override // androidx.appcompat.view.menu.k.a
    public void e(g gVar, int i3) {
        this.f3408b = gVar;
        setVisibility(gVar.isVisible() ? 0 : 8);
        setTitle(gVar.i(this));
        setCheckable(gVar.isCheckable());
        h(gVar.A(), gVar.g());
        setIcon(gVar.getIcon());
        setEnabled(gVar.isEnabled());
        setSubMenuArrowVisible(gVar.hasSubMenu());
        setContentDescription(gVar.getContentDescription());
    }

    @Override // androidx.appcompat.view.menu.k.a
    public g getItemData() {
        return this.f3408b;
    }

    public void h(boolean z3, char c3) {
        int i3 = (z3 && this.f3408b.A()) ? 0 : 8;
        if (i3 == 0) {
            this.f3413g.setText(this.f3408b.h());
        }
        if (this.f3413g.getVisibility() != i3) {
            this.f3413g.setVisibility(i3);
        }
    }

    @Override // android.view.View
    protected void onFinishInflate() {
        super.onFinishInflate();
        setBackground(this.f3417k);
        TextView textView = (TextView) findViewById(d.f.f8880C);
        this.f3411e = textView;
        int i3 = this.f3418l;
        if (i3 != -1) {
            textView.setTextAppearance(this.f3419m, i3);
        }
        this.f3413g = (TextView) findViewById(d.f.f8906w);
        ImageView imageView = (ImageView) findViewById(d.f.f8909z);
        this.f3414h = imageView;
        if (imageView != null) {
            imageView.setImageDrawable(this.f3421o);
        }
        this.f3415i = (ImageView) findViewById(d.f.f8900q);
        this.f3416j = (LinearLayout) findViewById(d.f.f8895l);
    }

    @Override // android.widget.LinearLayout, android.view.View
    protected void onMeasure(int i3, int i4) {
        if (this.f3409c != null && this.f3420n) {
            ViewGroup.LayoutParams layoutParams = getLayoutParams();
            LinearLayout.LayoutParams layoutParams2 = (LinearLayout.LayoutParams) this.f3409c.getLayoutParams();
            int i5 = layoutParams.height;
            if (i5 > 0 && layoutParams2.width <= 0) {
                layoutParams2.width = i5;
            }
        }
        super.onMeasure(i3, i4);
    }

    public void setCheckable(boolean z3) {
        CompoundButton compoundButton;
        View view;
        if (!z3 && this.f3410d == null && this.f3412f == null) {
            return;
        }
        if (this.f3408b.m()) {
            if (this.f3410d == null) {
                g();
            }
            compoundButton = this.f3410d;
            view = this.f3412f;
        } else {
            if (this.f3412f == null) {
                d();
            }
            compoundButton = this.f3412f;
            view = this.f3410d;
        }
        if (z3) {
            compoundButton.setChecked(this.f3408b.isChecked());
            if (compoundButton.getVisibility() != 0) {
                compoundButton.setVisibility(0);
            }
            if (view == null || view.getVisibility() == 8) {
                return;
            }
            view.setVisibility(8);
            return;
        }
        CheckBox checkBox = this.f3412f;
        if (checkBox != null) {
            checkBox.setVisibility(8);
        }
        RadioButton radioButton = this.f3410d;
        if (radioButton != null) {
            radioButton.setVisibility(8);
        }
    }

    public void setChecked(boolean z3) {
        CompoundButton compoundButton;
        if (this.f3408b.m()) {
            if (this.f3410d == null) {
                g();
            }
            compoundButton = this.f3410d;
        } else {
            if (this.f3412f == null) {
                d();
            }
            compoundButton = this.f3412f;
        }
        compoundButton.setChecked(z3);
    }

    public void setForceShowIcon(boolean z3) {
        this.f3424r = z3;
        this.f3420n = z3;
    }

    public void setGroupDividerEnabled(boolean z3) {
        ImageView imageView = this.f3415i;
        if (imageView != null) {
            imageView.setVisibility((this.f3422p || !z3) ? 8 : 0);
        }
    }

    public void setIcon(Drawable drawable) {
        boolean z3 = this.f3408b.z() || this.f3424r;
        if (z3 || this.f3420n) {
            ImageView imageView = this.f3409c;
            if (imageView == null && drawable == null && !this.f3420n) {
                return;
            }
            if (imageView == null) {
                f();
            }
            if (drawable == null && !this.f3420n) {
                this.f3409c.setVisibility(8);
                return;
            }
            ImageView imageView2 = this.f3409c;
            if (!z3) {
                drawable = null;
            }
            imageView2.setImageDrawable(drawable);
            if (this.f3409c.getVisibility() != 0) {
                this.f3409c.setVisibility(0);
            }
        }
    }

    public void setTitle(CharSequence charSequence) {
        if (charSequence == null) {
            if (this.f3411e.getVisibility() != 8) {
                this.f3411e.setVisibility(8);
            }
        } else {
            this.f3411e.setText(charSequence);
            if (this.f3411e.getVisibility() != 0) {
                this.f3411e.setVisibility(0);
            }
        }
    }

    public ListMenuItemView(Context context, AttributeSet attributeSet, int i3) {
        super(context, attributeSet);
        g0 g0VarU = g0.u(getContext(), attributeSet, d.j.f9023T1, i3, 0);
        this.f3417k = g0VarU.f(d.j.f9029V1);
        this.f3418l = g0VarU.m(d.j.f9026U1, -1);
        this.f3420n = g0VarU.a(d.j.f9032W1, false);
        this.f3419m = context;
        this.f3421o = g0VarU.f(d.j.f9035X1);
        TypedArray typedArrayObtainStyledAttributes = context.getTheme().obtainStyledAttributes(null, new int[]{R.attr.divider}, AbstractC0502a.f8812x, 0);
        this.f3422p = typedArrayObtainStyledAttributes.hasValue(0);
        g0VarU.w();
        typedArrayObtainStyledAttributes.recycle();
    }
}
