package com.flyco.tablayout;

import android.R;
import android.animation.TypeEvaluator;
import android.animation.ValueAnimator;
import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.Rect;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.os.Parcelable;
import android.util.AttributeSet;
import android.util.SparseArray;
import android.view.View;
import android.view.animation.OvershootInterpolator;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import com.jbzd.media.movecartoons.bean.response.ChatMsgBean;
import java.util.ArrayList;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p187j.p188a.ViewOnClickListenerC1875a;
import p005b.p187j.p188a.p189d.InterfaceC1878a;
import p005b.p187j.p188a.p189d.InterfaceC1879b;

/* loaded from: classes.dex */
public class CommonTabLayout extends FrameLayout implements ValueAnimator.AnimatorUpdateListener {

    /* renamed from: A */
    public float f9031A;

    /* renamed from: B */
    public long f9032B;

    /* renamed from: C */
    public boolean f9033C;

    /* renamed from: D */
    public boolean f9034D;

    /* renamed from: E */
    public int f9035E;

    /* renamed from: F */
    public int f9036F;

    /* renamed from: G */
    public float f9037G;

    /* renamed from: H */
    public int f9038H;

    /* renamed from: I */
    public int f9039I;

    /* renamed from: J */
    public float f9040J;

    /* renamed from: K */
    public float f9041K;

    /* renamed from: L */
    public float f9042L;

    /* renamed from: M */
    public float f9043M;

    /* renamed from: N */
    public int f9044N;

    /* renamed from: O */
    public int f9045O;

    /* renamed from: P */
    public int f9046P;

    /* renamed from: Q */
    public boolean f9047Q;

    /* renamed from: R */
    public boolean f9048R;

    /* renamed from: S */
    public int f9049S;

    /* renamed from: T */
    public float f9050T;

    /* renamed from: U */
    public float f9051U;

    /* renamed from: V */
    public float f9052V;

    /* renamed from: W */
    public ValueAnimator f9053W;

    /* renamed from: a0 */
    public OvershootInterpolator f9054a0;

    /* renamed from: b0 */
    public boolean f9055b0;

    /* renamed from: c */
    public Context f9056c;

    /* renamed from: c0 */
    public InterfaceC1879b f9057c0;

    /* renamed from: d0 */
    public C3249a f9058d0;

    /* renamed from: e */
    public ArrayList<InterfaceC1878a> f9059e;

    /* renamed from: e0 */
    public C3249a f9060e0;

    /* renamed from: f */
    public LinearLayout f9061f;

    /* renamed from: g */
    public int f9062g;

    /* renamed from: h */
    public int f9063h;

    /* renamed from: i */
    public int f9064i;

    /* renamed from: j */
    public Rect f9065j;

    /* renamed from: k */
    public GradientDrawable f9066k;

    /* renamed from: l */
    public Paint f9067l;

    /* renamed from: m */
    public Paint f9068m;

    /* renamed from: n */
    public Paint f9069n;

    /* renamed from: o */
    public Path f9070o;

    /* renamed from: p */
    public int f9071p;

    /* renamed from: q */
    public float f9072q;

    /* renamed from: r */
    public boolean f9073r;

    /* renamed from: s */
    public float f9074s;

    /* renamed from: t */
    public int f9075t;

    /* renamed from: u */
    public float f9076u;

    /* renamed from: v */
    public float f9077v;

    /* renamed from: w */
    public float f9078w;

    /* renamed from: x */
    public float f9079x;

    /* renamed from: y */
    public float f9080y;

    /* renamed from: z */
    public float f9081z;

    /* renamed from: com.flyco.tablayout.CommonTabLayout$a */
    public class C3249a {

        /* renamed from: a */
        public float f9082a;

        /* renamed from: b */
        public float f9083b;

        public C3249a(CommonTabLayout commonTabLayout) {
        }
    }

    /* renamed from: com.flyco.tablayout.CommonTabLayout$b */
    public class C3250b implements TypeEvaluator<C3249a> {
        public C3250b() {
        }

        @Override // android.animation.TypeEvaluator
        public C3249a evaluate(float f2, C3249a c3249a, C3249a c3249a2) {
            C3249a c3249a3 = c3249a;
            C3249a c3249a4 = c3249a2;
            float f3 = c3249a3.f9082a;
            float m627m = C1499a.m627m(c3249a4.f9082a, f3, f2, f3);
            float f4 = c3249a3.f9083b;
            float m627m2 = C1499a.m627m(c3249a4.f9083b, f4, f2, f4);
            C3249a c3249a5 = new C3249a(CommonTabLayout.this);
            c3249a5.f9082a = m627m;
            c3249a5.f9083b = m627m2;
            return c3249a5;
        }
    }

    public CommonTabLayout(Context context) {
        this(context, null, 0);
    }

    /* renamed from: a */
    public final void m3996a() {
        View childAt = this.f9061f.getChildAt(this.f9062g);
        float left = childAt.getLeft();
        float right = childAt.getRight();
        Rect rect = this.f9065j;
        rect.left = (int) left;
        rect.right = (int) right;
        if (this.f9077v < 0.0f) {
            return;
        }
        float left2 = childAt.getLeft();
        float width = childAt.getWidth();
        float f2 = this.f9077v;
        float f3 = ((width - f2) / 2.0f) + left2;
        Rect rect2 = this.f9065j;
        int i2 = (int) f3;
        rect2.left = i2;
        rect2.right = (int) (i2 + f2);
    }

    /* renamed from: b */
    public int m3997b(float f2) {
        return (int) ((f2 * this.f9056c.getResources().getDisplayMetrics().density) + 0.5f);
    }

    /* renamed from: c */
    public void m3998c() {
        this.f9061f.removeAllViews();
        this.f9064i = this.f9059e.size();
        for (int i2 = 0; i2 < this.f9064i; i2++) {
            int i3 = this.f9049S;
            View inflate = i3 == 3 ? View.inflate(this.f9056c, R$layout.layout_tab_left, null) : i3 == 5 ? View.inflate(this.f9056c, R$layout.layout_tab_right, null) : i3 == 80 ? View.inflate(this.f9056c, R$layout.layout_tab_bottom, null) : View.inflate(this.f9056c, R$layout.layout_tab_top, null);
            inflate.setTag(Integer.valueOf(i2));
            ((TextView) inflate.findViewById(R$id.tv_tab_title)).setText(this.f9059e.get(i2).getTabTitle());
            ((ImageView) inflate.findViewById(R$id.iv_tab_icon)).setImageResource(this.f9059e.get(i2).getTabUnselectedIcon());
            inflate.setOnClickListener(new ViewOnClickListenerC1875a(this));
            LinearLayout.LayoutParams layoutParams = this.f9073r ? new LinearLayout.LayoutParams(0, -1, 1.0f) : new LinearLayout.LayoutParams(-2, -1);
            if (this.f9074s > 0.0f) {
                layoutParams = new LinearLayout.LayoutParams((int) this.f9074s, -1);
            }
            this.f9061f.addView(inflate, i2, layoutParams);
        }
        m4001f();
    }

    /* renamed from: d */
    public int m3999d(float f2) {
        return (int) ((f2 * this.f9056c.getResources().getDisplayMetrics().scaledDensity) + 0.5f);
    }

    /* renamed from: e */
    public final void m4000e(int i2) {
        int i3 = 0;
        while (i3 < this.f9064i) {
            View childAt = this.f9061f.getChildAt(i3);
            boolean z = i3 == i2;
            TextView textView = (TextView) childAt.findViewById(R$id.tv_tab_title);
            textView.setTextColor(z ? this.f9044N : this.f9045O);
            textView.setTextSize(0, i3 == this.f9062g ? this.f9043M : this.f9042L);
            ImageView imageView = (ImageView) childAt.findViewById(R$id.iv_tab_icon);
            InterfaceC1878a interfaceC1878a = this.f9059e.get(i3);
            imageView.setImageResource(z ? interfaceC1878a.getTabSelectedIcon() : interfaceC1878a.getTabUnselectedIcon());
            int i4 = this.f9046P;
            if (i4 == 2) {
                textView.setTypeface(Typeface.defaultFromStyle(1));
            } else if (i4 == 0) {
                textView.setTypeface(Typeface.defaultFromStyle(0));
            } else if (i4 == 1) {
                textView.setTypeface(Typeface.defaultFromStyle(i3 != this.f9062g ? 0 : 1));
            }
            i3++;
        }
    }

    /* renamed from: f */
    public final void m4001f() {
        int i2 = 0;
        while (i2 < this.f9064i) {
            View childAt = this.f9061f.getChildAt(i2);
            float f2 = this.f9072q;
            childAt.setPadding((int) f2, 0, (int) f2, 0);
            TextView textView = (TextView) childAt.findViewById(R$id.tv_tab_title);
            textView.setTextColor(i2 == this.f9062g ? this.f9044N : this.f9045O);
            textView.setTextSize(0, i2 == this.f9062g ? this.f9043M : this.f9042L);
            if (this.f9047Q) {
                textView.setText(textView.getText().toString().toUpperCase());
            }
            int i3 = this.f9046P;
            if (i3 == 2) {
                textView.setTypeface(Typeface.defaultFromStyle(1));
            } else if (i3 == 0) {
                textView.setTypeface(Typeface.defaultFromStyle(0));
            } else if (i3 == 1) {
                textView.setTypeface(Typeface.defaultFromStyle(i2 != this.f9062g ? 0 : 1));
            }
            ImageView imageView = (ImageView) childAt.findViewById(R$id.iv_tab_icon);
            if (this.f9048R) {
                imageView.setVisibility(0);
                InterfaceC1878a interfaceC1878a = this.f9059e.get(i2);
                imageView.setImageResource(i2 == this.f9062g ? interfaceC1878a.getTabSelectedIcon() : interfaceC1878a.getTabUnselectedIcon());
                float f3 = this.f9050T;
                int i4 = f3 <= 0.0f ? -2 : (int) f3;
                float f4 = this.f9051U;
                LinearLayout.LayoutParams layoutParams = new LinearLayout.LayoutParams(i4, f4 > 0.0f ? (int) f4 : -2);
                int i5 = this.f9049S;
                if (i5 == 3) {
                    layoutParams.rightMargin = (int) this.f9052V;
                } else if (i5 == 5) {
                    layoutParams.leftMargin = (int) this.f9052V;
                } else if (i5 == 80) {
                    layoutParams.topMargin = (int) this.f9052V;
                } else {
                    layoutParams.bottomMargin = (int) this.f9052V;
                }
                imageView.setLayoutParams(layoutParams);
            } else {
                imageView.setVisibility(8);
            }
            i2++;
        }
    }

    public int getCurrentTab() {
        return this.f9062g;
    }

    public int getDividerColor() {
        return this.f9039I;
    }

    public float getDividerPadding() {
        return this.f9041K;
    }

    public float getDividerWidth() {
        return this.f9040J;
    }

    public int getIconGravity() {
        return this.f9049S;
    }

    public float getIconHeight() {
        return this.f9051U;
    }

    public float getIconMargin() {
        return this.f9052V;
    }

    public float getIconWidth() {
        return this.f9050T;
    }

    public long getIndicatorAnimDuration() {
        return this.f9032B;
    }

    public int getIndicatorColor() {
        return this.f9075t;
    }

    public float getIndicatorCornerRadius() {
        return this.f9078w;
    }

    public float getIndicatorHeight() {
        return this.f9076u;
    }

    public float getIndicatorMarginBottom() {
        return this.f9031A;
    }

    public float getIndicatorMarginLeft() {
        return this.f9079x;
    }

    public float getIndicatorMarginRight() {
        return this.f9081z;
    }

    public float getIndicatorMarginTop() {
        return this.f9080y;
    }

    public int getIndicatorStyle() {
        return this.f9071p;
    }

    public float getIndicatorWidth() {
        return this.f9077v;
    }

    public int getTabCount() {
        return this.f9064i;
    }

    public float getTabPadding() {
        return this.f9072q;
    }

    public float getTabWidth() {
        return this.f9074s;
    }

    public int getTextBold() {
        return this.f9046P;
    }

    public int getTextSelectColor() {
        return this.f9044N;
    }

    public int getTextUnselectColor() {
        return this.f9045O;
    }

    public float getTextsize() {
        return this.f9042L;
    }

    public int getUnderlineColor() {
        return this.f9036F;
    }

    public float getUnderlineHeight() {
        return this.f9037G;
    }

    @Override // android.animation.ValueAnimator.AnimatorUpdateListener
    public void onAnimationUpdate(ValueAnimator valueAnimator) {
        View childAt = this.f9061f.getChildAt(this.f9062g);
        C3249a c3249a = (C3249a) valueAnimator.getAnimatedValue();
        Rect rect = this.f9065j;
        float f2 = c3249a.f9082a;
        rect.left = (int) f2;
        rect.right = (int) c3249a.f9083b;
        if (this.f9077v >= 0.0f) {
            float width = childAt.getWidth();
            float f3 = this.f9077v;
            Rect rect2 = this.f9065j;
            int i2 = (int) (((width - f3) / 2.0f) + f2);
            rect2.left = i2;
            rect2.right = (int) (i2 + f3);
        }
        invalidate();
    }

    @Override // android.view.View
    public void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        if (isInEditMode() || this.f9064i <= 0) {
            return;
        }
        int height = getHeight();
        int paddingLeft = getPaddingLeft();
        float f2 = this.f9040J;
        if (f2 > 0.0f) {
            this.f9068m.setStrokeWidth(f2);
            this.f9068m.setColor(this.f9039I);
            for (int i2 = 0; i2 < this.f9064i - 1; i2++) {
                View childAt = this.f9061f.getChildAt(i2);
                canvas.drawLine(childAt.getRight() + paddingLeft, this.f9041K, childAt.getRight() + paddingLeft, height - this.f9041K, this.f9068m);
            }
        }
        if (this.f9037G > 0.0f) {
            this.f9067l.setColor(this.f9036F);
            if (this.f9038H == 80) {
                float f3 = height;
                canvas.drawRect(paddingLeft, f3 - this.f9037G, this.f9061f.getWidth() + paddingLeft, f3, this.f9067l);
            } else {
                canvas.drawRect(paddingLeft, 0.0f, this.f9061f.getWidth() + paddingLeft, this.f9037G, this.f9067l);
            }
        }
        if (!this.f9033C) {
            m3996a();
        } else if (this.f9055b0) {
            this.f9055b0 = false;
            m3996a();
        }
        int i3 = this.f9071p;
        if (i3 == 1) {
            if (this.f9076u > 0.0f) {
                this.f9069n.setColor(this.f9075t);
                this.f9070o.reset();
                float f4 = height;
                this.f9070o.moveTo(this.f9065j.left + paddingLeft, f4);
                Path path = this.f9070o;
                Rect rect = this.f9065j;
                path.lineTo((rect.right / 2) + (rect.left / 2) + paddingLeft, f4 - this.f9076u);
                this.f9070o.lineTo(paddingLeft + this.f9065j.right, f4);
                this.f9070o.close();
                canvas.drawPath(this.f9070o, this.f9069n);
                return;
            }
            return;
        }
        if (i3 == 2) {
            if (this.f9076u < 0.0f) {
                this.f9076u = (height - this.f9080y) - this.f9031A;
            }
            float f5 = this.f9076u;
            if (f5 > 0.0f) {
                float f6 = this.f9078w;
                if (f6 < 0.0f || f6 > f5 / 2.0f) {
                    this.f9078w = f5 / 2.0f;
                }
                this.f9066k.setColor(this.f9075t);
                GradientDrawable gradientDrawable = this.f9066k;
                int i4 = ((int) this.f9079x) + paddingLeft + this.f9065j.left;
                float f7 = this.f9080y;
                gradientDrawable.setBounds(i4, (int) f7, (int) ((paddingLeft + r2.right) - this.f9081z), (int) (f7 + this.f9076u));
                this.f9066k.setCornerRadius(this.f9078w);
                this.f9066k.draw(canvas);
                return;
            }
            return;
        }
        if (this.f9076u > 0.0f) {
            this.f9066k.setColor(this.f9075t);
            if (this.f9035E == 80) {
                GradientDrawable gradientDrawable2 = this.f9066k;
                int i5 = ((int) this.f9079x) + paddingLeft;
                Rect rect2 = this.f9065j;
                int i6 = i5 + rect2.left;
                int i7 = height - ((int) this.f9076u);
                float f8 = this.f9031A;
                gradientDrawable2.setBounds(i6, i7 - ((int) f8), (paddingLeft + rect2.right) - ((int) this.f9081z), height - ((int) f8));
            } else {
                GradientDrawable gradientDrawable3 = this.f9066k;
                int i8 = ((int) this.f9079x) + paddingLeft;
                Rect rect3 = this.f9065j;
                int i9 = i8 + rect3.left;
                float f9 = this.f9080y;
                gradientDrawable3.setBounds(i9, (int) f9, (paddingLeft + rect3.right) - ((int) this.f9081z), ((int) this.f9076u) + ((int) f9));
            }
            this.f9066k.setCornerRadius(this.f9078w);
            this.f9066k.draw(canvas);
        }
    }

    @Override // android.view.View
    public void onRestoreInstanceState(Parcelable parcelable) {
        if (parcelable instanceof Bundle) {
            Bundle bundle = (Bundle) parcelable;
            this.f9062g = bundle.getInt("mCurrentTab");
            parcelable = bundle.getParcelable("instanceState");
            if (this.f9062g != 0 && this.f9061f.getChildCount() > 0) {
                m4000e(this.f9062g);
            }
        }
        super.onRestoreInstanceState(parcelable);
    }

    @Override // android.view.View
    public Parcelable onSaveInstanceState() {
        Bundle bundle = new Bundle();
        bundle.putParcelable("instanceState", super.onSaveInstanceState());
        bundle.putInt("mCurrentTab", this.f9062g);
        return bundle;
    }

    public void setCurrentTab(int i2) {
        this.f9063h = this.f9062g;
        this.f9062g = i2;
        m4000e(i2);
        if (!this.f9033C) {
            invalidate();
            return;
        }
        View childAt = this.f9061f.getChildAt(this.f9062g);
        this.f9058d0.f9082a = childAt.getLeft();
        this.f9058d0.f9083b = childAt.getRight();
        View childAt2 = this.f9061f.getChildAt(this.f9063h);
        this.f9060e0.f9082a = childAt2.getLeft();
        this.f9060e0.f9083b = childAt2.getRight();
        C3249a c3249a = this.f9060e0;
        float f2 = c3249a.f9082a;
        C3249a c3249a2 = this.f9058d0;
        if (f2 == c3249a2.f9082a && c3249a.f9083b == c3249a2.f9083b) {
            invalidate();
            return;
        }
        this.f9053W.setObjectValues(c3249a, c3249a2);
        if (this.f9034D) {
            this.f9053W.setInterpolator(this.f9054a0);
        }
        if (this.f9032B < 0) {
            this.f9032B = this.f9034D ? 500L : 250L;
        }
        this.f9053W.setDuration(this.f9032B);
        this.f9053W.start();
    }

    public void setDividerColor(int i2) {
        this.f9039I = i2;
        invalidate();
    }

    public void setDividerPadding(float f2) {
        this.f9041K = m3997b(f2);
        invalidate();
    }

    public void setDividerWidth(float f2) {
        this.f9040J = m3997b(f2);
        invalidate();
    }

    public void setIconGravity(int i2) {
        this.f9049S = i2;
        m3998c();
    }

    public void setIconHeight(float f2) {
        this.f9051U = m3997b(f2);
        m4001f();
    }

    public void setIconMargin(float f2) {
        this.f9052V = m3997b(f2);
        m4001f();
    }

    public void setIconVisible(boolean z) {
        this.f9048R = z;
        m4001f();
    }

    public void setIconWidth(float f2) {
        this.f9050T = m3997b(f2);
        m4001f();
    }

    public void setIndicatorAnimDuration(long j2) {
        this.f9032B = j2;
    }

    public void setIndicatorAnimEnable(boolean z) {
        this.f9033C = z;
    }

    public void setIndicatorBounceEnable(boolean z) {
        this.f9034D = z;
    }

    public void setIndicatorColor(int i2) {
        this.f9075t = i2;
        invalidate();
    }

    public void setIndicatorCornerRadius(float f2) {
        this.f9078w = m3997b(f2);
        invalidate();
    }

    public void setIndicatorGravity(int i2) {
        this.f9035E = i2;
        invalidate();
    }

    public void setIndicatorHeight(float f2) {
        this.f9076u = m3997b(f2);
        invalidate();
    }

    public void setIndicatorStyle(int i2) {
        this.f9071p = i2;
        invalidate();
    }

    public void setIndicatorWidth(float f2) {
        this.f9077v = m3997b(f2);
        invalidate();
    }

    public void setOnTabSelectListener(InterfaceC1879b interfaceC1879b) {
        this.f9057c0 = interfaceC1879b;
    }

    public void setTabData(ArrayList<InterfaceC1878a> arrayList) {
        if (arrayList == null || arrayList.size() == 0) {
            throw new IllegalStateException("TabEntitys can not be NULL or EMPTY !");
        }
        this.f9059e.clear();
        this.f9059e.addAll(arrayList);
        m3998c();
    }

    public void setTabPadding(float f2) {
        this.f9072q = m3997b(f2);
        m4001f();
    }

    public void setTabSpaceEqual(boolean z) {
        this.f9073r = z;
        m4001f();
    }

    public void setTabWidth(float f2) {
        this.f9074s = m3997b(f2);
        m4001f();
    }

    public void setTextAllCaps(boolean z) {
        this.f9047Q = z;
        m4001f();
    }

    public void setTextBold(int i2) {
        this.f9046P = i2;
        m4001f();
    }

    public void setTextSelectColor(int i2) {
        this.f9044N = i2;
        m4001f();
    }

    public void setTextSelectSize(float f2) {
        this.f9043M = m3999d(f2);
        m4001f();
    }

    public void setTextUnselectColor(int i2) {
        this.f9045O = i2;
        m4001f();
    }

    public void setTextsize(float f2) {
        this.f9042L = m3999d(f2);
        m4001f();
    }

    public void setUnderlineColor(int i2) {
        this.f9036F = i2;
        invalidate();
    }

    public void setUnderlineGravity(int i2) {
        this.f9038H = i2;
        invalidate();
    }

    public void setUnderlineHeight(float f2) {
        this.f9037G = m3997b(f2);
        invalidate();
    }

    public CommonTabLayout(Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 0);
    }

    public CommonTabLayout(Context context, AttributeSet attributeSet, int i2) {
        super(context, attributeSet, i2);
        float f2;
        this.f9059e = new ArrayList<>();
        this.f9065j = new Rect();
        this.f9066k = new GradientDrawable();
        this.f9067l = new Paint(1);
        this.f9068m = new Paint(1);
        this.f9069n = new Paint(1);
        this.f9070o = new Path();
        this.f9071p = 0;
        this.f9054a0 = new OvershootInterpolator(1.5f);
        this.f9055b0 = true;
        new Paint(1);
        new SparseArray();
        this.f9058d0 = new C3249a(this);
        this.f9060e0 = new C3249a(this);
        setWillNotDraw(false);
        setClipChildren(false);
        setClipToPadding(false);
        this.f9056c = context;
        LinearLayout linearLayout = new LinearLayout(context);
        this.f9061f = linearLayout;
        addView(linearLayout);
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, R$styleable.CommonTabLayout);
        int i3 = obtainStyledAttributes.getInt(R$styleable.CommonTabLayout_tl_indicator_style, 0);
        this.f9071p = i3;
        this.f9075t = obtainStyledAttributes.getColor(R$styleable.CommonTabLayout_tl_indicator_color, Color.parseColor(i3 == 2 ? "#4B6A87" : "#ffffff"));
        int i4 = R$styleable.CommonTabLayout_tl_indicator_height;
        int i5 = this.f9071p;
        if (i5 == 1) {
            f2 = 4.0f;
        } else {
            f2 = i5 == 2 ? -1 : 2;
        }
        this.f9076u = obtainStyledAttributes.getDimension(i4, m3997b(f2));
        this.f9077v = obtainStyledAttributes.getDimension(R$styleable.CommonTabLayout_tl_indicator_width, m3997b(this.f9071p == 1 ? 10.0f : -1.0f));
        this.f9078w = obtainStyledAttributes.getDimension(R$styleable.CommonTabLayout_tl_indicator_corner_radius, m3997b(this.f9071p == 2 ? -1.0f : 0.0f));
        this.f9079x = obtainStyledAttributes.getDimension(R$styleable.CommonTabLayout_tl_indicator_margin_left, m3997b(0.0f));
        this.f9080y = obtainStyledAttributes.getDimension(R$styleable.CommonTabLayout_tl_indicator_margin_top, m3997b(this.f9071p == 2 ? 7.0f : 0.0f));
        this.f9081z = obtainStyledAttributes.getDimension(R$styleable.CommonTabLayout_tl_indicator_margin_right, m3997b(0.0f));
        this.f9031A = obtainStyledAttributes.getDimension(R$styleable.CommonTabLayout_tl_indicator_margin_bottom, m3997b(this.f9071p != 2 ? 0.0f : 7.0f));
        this.f9033C = obtainStyledAttributes.getBoolean(R$styleable.CommonTabLayout_tl_indicator_anim_enable, true);
        this.f9034D = obtainStyledAttributes.getBoolean(R$styleable.CommonTabLayout_tl_indicator_bounce_enable, true);
        this.f9032B = obtainStyledAttributes.getInt(R$styleable.CommonTabLayout_tl_indicator_anim_duration, -1);
        this.f9035E = obtainStyledAttributes.getInt(R$styleable.CommonTabLayout_tl_indicator_gravity, 80);
        this.f9036F = obtainStyledAttributes.getColor(R$styleable.CommonTabLayout_tl_underline_color, Color.parseColor("#ffffff"));
        this.f9037G = obtainStyledAttributes.getDimension(R$styleable.CommonTabLayout_tl_underline_height, m3997b(0.0f));
        this.f9038H = obtainStyledAttributes.getInt(R$styleable.CommonTabLayout_tl_underline_gravity, 80);
        this.f9039I = obtainStyledAttributes.getColor(R$styleable.CommonTabLayout_tl_divider_color, Color.parseColor("#ffffff"));
        this.f9040J = obtainStyledAttributes.getDimension(R$styleable.CommonTabLayout_tl_divider_width, m3997b(0.0f));
        this.f9041K = obtainStyledAttributes.getDimension(R$styleable.CommonTabLayout_tl_divider_padding, m3997b(12.0f));
        this.f9042L = obtainStyledAttributes.getDimension(R$styleable.CommonTabLayout_tl_textsize, m3999d(13.0f));
        this.f9043M = obtainStyledAttributes.getDimension(R$styleable.CommonTabLayout_tl_textSelectSize, m3999d(13.0f));
        this.f9044N = obtainStyledAttributes.getColor(R$styleable.CommonTabLayout_tl_textSelectColor, Color.parseColor("#ffffff"));
        this.f9045O = obtainStyledAttributes.getColor(R$styleable.CommonTabLayout_tl_textUnselectColor, Color.parseColor("#AAffffff"));
        this.f9046P = obtainStyledAttributes.getInt(R$styleable.CommonTabLayout_tl_textBold, 0);
        this.f9047Q = obtainStyledAttributes.getBoolean(R$styleable.CommonTabLayout_tl_textAllCaps, false);
        this.f9048R = obtainStyledAttributes.getBoolean(R$styleable.CommonTabLayout_tl_iconVisible, true);
        this.f9049S = obtainStyledAttributes.getInt(R$styleable.CommonTabLayout_tl_iconGravity, 48);
        this.f9050T = obtainStyledAttributes.getDimension(R$styleable.CommonTabLayout_tl_iconWidth, m3997b(0.0f));
        this.f9051U = obtainStyledAttributes.getDimension(R$styleable.CommonTabLayout_tl_iconHeight, m3997b(0.0f));
        this.f9052V = obtainStyledAttributes.getDimension(R$styleable.CommonTabLayout_tl_iconMargin, m3997b(2.5f));
        this.f9073r = obtainStyledAttributes.getBoolean(R$styleable.CommonTabLayout_tl_tab_space_equal, true);
        float dimension = obtainStyledAttributes.getDimension(R$styleable.CommonTabLayout_tl_tab_width, m3997b(-1.0f));
        this.f9074s = dimension;
        this.f9072q = obtainStyledAttributes.getDimension(R$styleable.CommonTabLayout_tl_tab_padding, (this.f9073r || dimension > 0.0f) ? m3997b(0.0f) : m3997b(10.0f));
        obtainStyledAttributes.recycle();
        String attributeValue = attributeSet.getAttributeValue("http://schemas.android.com/apk/res/android", "layout_height");
        if (!attributeValue.equals(ChatMsgBean.SERVICE_ID) && !attributeValue.equals("-2")) {
            TypedArray obtainStyledAttributes2 = context.obtainStyledAttributes(attributeSet, new int[]{R.attr.layout_height});
            obtainStyledAttributes2.getDimensionPixelSize(0, -2);
            obtainStyledAttributes2.recycle();
        }
        ValueAnimator ofObject = ValueAnimator.ofObject(new C3250b(), this.f9060e0, this.f9058d0);
        this.f9053W = ofObject;
        ofObject.addUpdateListener(this);
    }
}
