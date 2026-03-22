package com.flyco.tablayout;

import android.R;
import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.Rect;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.os.Parcelable;
import android.util.AttributeSet;
import android.util.SparseArray;
import android.view.View;
import android.widget.HorizontalScrollView;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.viewpager.widget.ViewPager;
import com.jbzd.media.movecartoons.bean.response.ChatMsgBean;
import java.util.ArrayList;
import java.util.Collections;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p187j.p188a.ViewOnClickListenerC1877c;
import p005b.p187j.p188a.p189d.InterfaceC1879b;

/* loaded from: classes.dex */
public class SlidingTabLayout extends HorizontalScrollView implements ViewPager.OnPageChangeListener {

    /* renamed from: A */
    public float f9131A;

    /* renamed from: B */
    public float f9132B;

    /* renamed from: C */
    public float f9133C;

    /* renamed from: D */
    public float f9134D;

    /* renamed from: E */
    public int f9135E;

    /* renamed from: F */
    public boolean f9136F;

    /* renamed from: G */
    public int f9137G;

    /* renamed from: H */
    public int f9138H;

    /* renamed from: I */
    public int f9139I;

    /* renamed from: J */
    public float f9140J;

    /* renamed from: K */
    public int f9141K;

    /* renamed from: L */
    public int f9142L;

    /* renamed from: M */
    public float f9143M;

    /* renamed from: N */
    public float f9144N;

    /* renamed from: O */
    public float f9145O;

    /* renamed from: P */
    public float f9146P;

    /* renamed from: Q */
    public int f9147Q;

    /* renamed from: R */
    public int f9148R;

    /* renamed from: S */
    public int f9149S;

    /* renamed from: T */
    public boolean f9150T;

    /* renamed from: U */
    public int f9151U;

    /* renamed from: V */
    public boolean f9152V;

    /* renamed from: W */
    public float f9153W;

    /* renamed from: a0 */
    public Paint f9154a0;

    /* renamed from: b0 */
    public InterfaceC1879b f9155b0;

    /* renamed from: c */
    public Context f9156c;

    /* renamed from: c0 */
    public String f9157c0;

    /* renamed from: e */
    public ViewPager f9158e;

    /* renamed from: f */
    public ArrayList<String> f9159f;

    /* renamed from: g */
    public LinearLayout f9160g;

    /* renamed from: h */
    public int f9161h;

    /* renamed from: i */
    public float f9162i;

    /* renamed from: j */
    public int f9163j;

    /* renamed from: k */
    public Rect f9164k;

    /* renamed from: l */
    public Rect f9165l;

    /* renamed from: m */
    public Drawable f9166m;

    /* renamed from: n */
    public Paint f9167n;

    /* renamed from: o */
    public Paint f9168o;

    /* renamed from: p */
    public Paint f9169p;

    /* renamed from: q */
    public Path f9170q;

    /* renamed from: r */
    public int f9171r;

    /* renamed from: s */
    public float f9172s;

    /* renamed from: t */
    public boolean f9173t;

    /* renamed from: u */
    public float f9174u;

    /* renamed from: v */
    public int f9175v;

    /* renamed from: w */
    public int f9176w;

    /* renamed from: x */
    public float f9177x;

    /* renamed from: y */
    public float f9178y;

    /* renamed from: z */
    public float f9179z;

    public SlidingTabLayout(Context context) {
        this(context, null, 0);
    }

    /* renamed from: a */
    public final void m4007a() {
        View childAt = this.f9160g.getChildAt(this.f9161h);
        float left = childAt.getLeft();
        float right = childAt.getRight();
        if (this.f9171r == 0 && this.f9136F) {
            TextView textView = (TextView) childAt.findViewById(R$id.tv_tab_title);
            this.f9154a0.setTextSize(this.f9145O);
            this.f9153W = ((right - left) - this.f9154a0.measureText(textView.getText().toString())) / 2.0f;
        }
        int i2 = this.f9161h;
        if (i2 < this.f9163j - 1) {
            View childAt2 = this.f9160g.getChildAt(i2 + 1);
            float left2 = childAt2.getLeft();
            float right2 = childAt2.getRight();
            float f2 = this.f9162i;
            left = C1499a.m627m(left2, left, f2, left);
            right = C1499a.m627m(right2, right, f2, right);
            if (this.f9171r == 0 && this.f9136F) {
                TextView textView2 = (TextView) childAt2.findViewById(R$id.tv_tab_title);
                this.f9154a0.setTextSize(this.f9145O);
                float measureText = ((right2 - left2) - this.f9154a0.measureText(textView2.getText().toString())) / 2.0f;
                float f3 = this.f9153W;
                this.f9153W = C1499a.m627m(measureText, f3, this.f9162i, f3);
            }
        }
        Rect rect = this.f9164k;
        int i3 = (int) left;
        rect.left = i3;
        int i4 = (int) right;
        rect.right = i4;
        if (this.f9171r == 0 && this.f9136F) {
            float f4 = this.f9153W;
            rect.left = (int) ((left + f4) - 1.0f);
            rect.right = (int) ((right - f4) - 1.0f);
        }
        Rect rect2 = this.f9165l;
        rect2.left = i3;
        rect2.right = i4;
        if (this.f9178y < 0.0f) {
            return;
        }
        float width = ((childAt.getWidth() - this.f9178y) / 2.0f) + childAt.getLeft();
        int i5 = this.f9161h;
        if (i5 < this.f9163j - 1) {
            View childAt3 = this.f9160g.getChildAt(i5 + 1);
            width += this.f9162i * ((childAt3.getWidth() / 2) + (childAt.getWidth() / 2));
        }
        Rect rect3 = this.f9164k;
        int i6 = (int) width;
        rect3.left = i6;
        rect3.right = (int) (i6 + this.f9178y);
    }

    /* renamed from: b */
    public int m4008b(float f2) {
        return (int) ((f2 * this.f9156c.getResources().getDisplayMetrics().density) + 0.5f);
    }

    /* renamed from: c */
    public void m4009c() {
        this.f9160g.removeAllViews();
        ArrayList<String> arrayList = this.f9159f;
        this.f9163j = arrayList == null ? this.f9158e.getAdapter().getCount() : arrayList.size();
        for (int i2 = 0; i2 < this.f9163j; i2++) {
            View inflate = View.inflate(this.f9156c, R$layout.layout_tab, null);
            ArrayList<String> arrayList2 = this.f9159f;
            String charSequence = (arrayList2 == null ? this.f9158e.getAdapter().getPageTitle(i2) : arrayList2.get(i2)).toString();
            TextView textView = (TextView) inflate.findViewById(R$id.tv_tab_title);
            if (textView != null && charSequence != null) {
                textView.setText(charSequence);
            }
            inflate.setOnClickListener(new ViewOnClickListenerC1877c(this));
            LinearLayout.LayoutParams layoutParams = this.f9173t ? new LinearLayout.LayoutParams(0, -1, 1.0f) : new LinearLayout.LayoutParams(-2, -1);
            if (this.f9174u > 0.0f) {
                layoutParams = new LinearLayout.LayoutParams((int) this.f9174u, -1);
            }
            this.f9160g.addView(inflate, i2, layoutParams);
        }
        m4014h();
    }

    /* renamed from: d */
    public final void m4010d() {
        if (this.f9163j <= 0) {
            return;
        }
        int width = (int) (this.f9162i * this.f9160g.getChildAt(this.f9161h).getWidth());
        int left = this.f9160g.getChildAt(this.f9161h).getLeft() + width;
        if (this.f9161h > 0 || width > 0) {
            int width2 = left - ((getWidth() / 2) - getPaddingLeft());
            m4007a();
            Rect rect = this.f9165l;
            left = width2 + ((rect.right - rect.left) / 2);
        }
        if (left != this.f9151U) {
            this.f9151U = left;
            scrollTo(left, 0);
        }
    }

    /* renamed from: e */
    public void m4011e(ViewPager viewPager, String[] strArr) {
        if (viewPager == null || viewPager.getAdapter() == null) {
            throw new IllegalStateException("ViewPager or ViewPager adapter can not be NULL !");
        }
        if (strArr == null || strArr.length == 0) {
            throw new IllegalStateException("Titles can not be EMPTY !");
        }
        if (strArr.length != viewPager.getAdapter().getCount()) {
            throw new IllegalStateException("Titles length must be the same as the page count !");
        }
        this.f9158e = viewPager;
        ArrayList<String> arrayList = new ArrayList<>();
        this.f9159f = arrayList;
        Collections.addAll(arrayList, strArr);
        this.f9158e.removeOnPageChangeListener(this);
        this.f9158e.addOnPageChangeListener(this);
        m4009c();
    }

    /* renamed from: f */
    public int m4012f(float f2) {
        return (int) ((f2 * this.f9156c.getResources().getDisplayMetrics().scaledDensity) + 0.5f);
    }

    /* renamed from: g */
    public final void m4013g(int i2) {
        int i3 = 0;
        while (i3 < this.f9163j) {
            View childAt = this.f9160g.getChildAt(i3);
            int i4 = i3 == i2 ? 1 : 0;
            TextView textView = (TextView) childAt.findViewById(R$id.tv_tab_title);
            ImageView imageView = (ImageView) childAt.findViewById(R$id.tv_tab_indicator);
            if (imageView != null && this.f9176w != -1) {
                imageView.setVisibility(i3 == this.f9161h ? 0 : 4);
                imageView.setImageResource(this.f9176w);
            }
            if (textView != null) {
                textView.setTextColor(i4 != 0 ? this.f9147Q : this.f9148R);
                textView.setTextSize(0, i3 == this.f9161h ? this.f9146P : this.f9145O);
                if (this.f9149S == 1) {
                    textView.setTypeface(Typeface.defaultFromStyle(i4));
                }
            }
            i3++;
        }
    }

    public int getCurrentTab() {
        return this.f9161h;
    }

    public int getDividerColor() {
        return this.f9142L;
    }

    public float getDividerPadding() {
        return this.f9144N;
    }

    public float getDividerWidth() {
        return this.f9143M;
    }

    public int getIndicatorColor() {
        return this.f9175v;
    }

    public float getIndicatorCornerRadius() {
        return this.f9179z;
    }

    public float getIndicatorHeight() {
        return this.f9177x;
    }

    public float getIndicatorMarginBottom() {
        return this.f9134D;
    }

    public float getIndicatorMarginLeft() {
        return this.f9131A;
    }

    public float getIndicatorMarginRight() {
        return this.f9133C;
    }

    public float getIndicatorMarginTop() {
        return this.f9132B;
    }

    public int getIndicatorStyle() {
        return this.f9171r;
    }

    public float getIndicatorWidth() {
        return this.f9178y;
    }

    public int getTabCount() {
        return this.f9163j;
    }

    public float getTabPadding() {
        return this.f9172s;
    }

    public float getTabWidth() {
        return this.f9174u;
    }

    public int getTextBold() {
        return this.f9149S;
    }

    public int getTextSelectColor() {
        return this.f9147Q;
    }

    public int getTextUnselectColor() {
        return this.f9148R;
    }

    public float getTextsize() {
        return this.f9145O;
    }

    public int getUnderlineColor() {
        return this.f9139I;
    }

    public float getUnderlineHeight() {
        return this.f9140J;
    }

    /* renamed from: h */
    public final void m4014h() {
        Typeface createFromAsset = this.f9157c0 != null ? Typeface.createFromAsset(getContext().getAssets(), this.f9157c0) : null;
        int i2 = 0;
        while (i2 < this.f9163j) {
            View childAt = this.f9160g.getChildAt(i2);
            TextView textView = (TextView) childAt.findViewById(R$id.tv_tab_title);
            if (this.f9157c0 != null) {
                textView.setTypeface(createFromAsset);
            }
            ImageView imageView = (ImageView) childAt.findViewById(R$id.tv_tab_indicator);
            if (imageView != null && this.f9176w != -1) {
                imageView.setVisibility(i2 == this.f9161h ? 0 : 4);
                imageView.setImageResource(this.f9176w);
            }
            if (textView != null) {
                textView.setTextColor(i2 == this.f9161h ? this.f9147Q : this.f9148R);
                textView.setTextSize(0, i2 == this.f9161h ? this.f9146P : this.f9145O);
                float f2 = this.f9172s;
                textView.setPadding((int) f2, 0, (int) f2, 0);
                if (this.f9150T) {
                    textView.setText(textView.getText().toString().toUpperCase());
                }
                int i3 = this.f9149S;
                if (i3 == 2) {
                    textView.setTypeface(Typeface.defaultFromStyle(1));
                } else if (i3 == 0) {
                    textView.setTypeface(Typeface.defaultFromStyle(0));
                } else if (i3 == 1) {
                    textView.setTypeface(Typeface.defaultFromStyle(i2 != this.f9161h ? 0 : 1));
                }
            }
            i2++;
        }
    }

    @Override // android.view.View
    public void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        if (isInEditMode() || this.f9163j <= 0) {
            return;
        }
        int height = getHeight();
        int paddingLeft = getPaddingLeft();
        float f2 = this.f9143M;
        if (f2 > 0.0f) {
            this.f9168o.setStrokeWidth(f2);
            this.f9168o.setColor(this.f9142L);
            for (int i2 = 0; i2 < this.f9163j - 1; i2++) {
                View childAt = this.f9160g.getChildAt(i2);
                canvas.drawLine(childAt.getRight() + paddingLeft, this.f9144N, childAt.getRight() + paddingLeft, height - this.f9144N, this.f9168o);
            }
        }
        if (this.f9140J > 0.0f) {
            this.f9167n.setColor(this.f9139I);
            if (this.f9141K == 80) {
                float f3 = height;
                canvas.drawRect(paddingLeft, f3 - this.f9140J, this.f9160g.getWidth() + paddingLeft, f3, this.f9167n);
            } else {
                canvas.drawRect(paddingLeft, 0.0f, this.f9160g.getWidth() + paddingLeft, this.f9140J, this.f9167n);
            }
        }
        m4007a();
        int i3 = this.f9171r;
        if (i3 == 1) {
            if (this.f9177x > 0.0f) {
                this.f9169p.setColor(this.f9175v);
                this.f9170q.reset();
                float f4 = height;
                this.f9170q.moveTo(this.f9164k.left + paddingLeft, f4);
                this.f9170q.lineTo((this.f9164k.width() / 2.0f) + paddingLeft, f4 - this.f9177x);
                this.f9170q.lineTo(paddingLeft + this.f9164k.right, f4);
                this.f9170q.close();
                canvas.drawPath(this.f9170q, this.f9169p);
                return;
            }
            return;
        }
        if (i3 != 2) {
            if (this.f9177x > 0.0f) {
                Drawable drawable = this.f9166m;
                if (drawable instanceof GradientDrawable) {
                    ((GradientDrawable) drawable).setColor(this.f9175v);
                }
                if (this.f9135E == 80) {
                    Drawable drawable2 = this.f9166m;
                    int i4 = ((int) this.f9131A) + paddingLeft;
                    Rect rect = this.f9164k;
                    int i5 = i4 + rect.left;
                    int i6 = height - ((int) this.f9177x);
                    float f5 = this.f9134D;
                    drawable2.setBounds(i5, i6 - ((int) f5), (paddingLeft + rect.right) - ((int) this.f9133C), height - ((int) f5));
                } else {
                    Drawable drawable3 = this.f9166m;
                    int i7 = ((int) this.f9131A) + paddingLeft;
                    Rect rect2 = this.f9164k;
                    int i8 = i7 + rect2.left;
                    float f6 = this.f9132B;
                    drawable3.setBounds(i8, (int) f6, (paddingLeft + rect2.right) - ((int) this.f9133C), ((int) this.f9177x) + ((int) f6));
                }
                Drawable drawable4 = this.f9166m;
                if (drawable4 instanceof GradientDrawable) {
                    ((GradientDrawable) drawable4).setCornerRadius(this.f9179z);
                }
                this.f9166m.draw(canvas);
                return;
            }
            return;
        }
        if (this.f9177x < 0.0f) {
            this.f9177x = (height - this.f9132B) - this.f9134D;
        }
        float f7 = this.f9177x;
        if (f7 > 0.0f) {
            float f8 = this.f9179z;
            if (f8 < 0.0f || f8 > f7 / 2.0f) {
                this.f9179z = f7 / 2.0f;
            }
            Drawable drawable5 = this.f9166m;
            if (drawable5 instanceof GradientDrawable) {
                ((GradientDrawable) drawable5).setColor(this.f9175v);
                Drawable drawable6 = this.f9166m;
                int i9 = ((int) this.f9131A) + paddingLeft + this.f9164k.left;
                float f9 = this.f9132B;
                drawable6.setBounds(i9, (int) f9, (int) ((paddingLeft + r2.right) - this.f9133C), (int) (f9 + this.f9177x));
            } else {
                float min = this.f9137G * Math.min(((this.f9164k.width() - this.f9133C) - this.f9131A) / this.f9137G, this.f9177x / this.f9138H);
                getHeight();
                int i10 = ((int) min) / 2;
                this.f9166m.setBounds(this.f9164k.centerX() - i10, (int) this.f9132B, this.f9164k.centerX() + i10, (int) (this.f9132B + this.f9177x));
            }
            Drawable drawable7 = this.f9166m;
            if (drawable7 instanceof GradientDrawable) {
                ((GradientDrawable) drawable7).setCornerRadius(this.f9179z);
            }
            this.f9166m.draw(canvas);
        }
    }

    @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
    public void onPageScrollStateChanged(int i2) {
    }

    @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
    public void onPageScrolled(int i2, float f2, int i3) {
        this.f9161h = i2;
        this.f9162i = f2;
        m4010d();
        invalidate();
    }

    @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
    public void onPageSelected(int i2) {
        m4013g(i2);
    }

    @Override // android.widget.HorizontalScrollView, android.view.View
    public void onRestoreInstanceState(Parcelable parcelable) {
        if (parcelable instanceof Bundle) {
            Bundle bundle = (Bundle) parcelable;
            this.f9161h = bundle.getInt("mCurrentTab");
            parcelable = bundle.getParcelable("instanceState");
            if (this.f9161h != 0 && this.f9160g.getChildCount() > 0) {
                m4013g(this.f9161h);
                m4010d();
            }
        }
        super.onRestoreInstanceState(parcelable);
    }

    @Override // android.widget.HorizontalScrollView, android.view.View
    public Parcelable onSaveInstanceState() {
        Bundle bundle = new Bundle();
        bundle.putParcelable("instanceState", super.onSaveInstanceState());
        bundle.putInt("mCurrentTab", this.f9161h);
        return bundle;
    }

    public void setCurrentTab(int i2) {
        this.f9161h = i2;
        this.f9158e.setCurrentItem(i2);
    }

    public void setDividerColor(int i2) {
        this.f9142L = i2;
        invalidate();
    }

    public void setDividerPadding(float f2) {
        this.f9144N = m4008b(f2);
        invalidate();
    }

    public void setDividerWidth(float f2) {
        this.f9143M = m4008b(f2);
        invalidate();
    }

    public void setIndicatorColor(int i2) {
        this.f9175v = i2;
        invalidate();
    }

    public void setIndicatorCornerRadius(float f2) {
        this.f9179z = m4008b(f2);
        invalidate();
    }

    public void setIndicatorGravity(int i2) {
        this.f9135E = i2;
        invalidate();
    }

    public void setIndicatorHeight(float f2) {
        this.f9177x = m4008b(f2);
        invalidate();
    }

    public void setIndicatorStyle(int i2) {
        this.f9171r = i2;
        invalidate();
    }

    public void setIndicatorWidth(float f2) {
        this.f9178y = m4008b(f2);
        invalidate();
    }

    public void setIndicatorWidthEqualTitle(boolean z) {
        this.f9136F = z;
        invalidate();
    }

    public void setOnTabSelectListener(InterfaceC1879b interfaceC1879b) {
        this.f9155b0 = interfaceC1879b;
    }

    public void setSnapOnTabClick(boolean z) {
        this.f9152V = z;
    }

    public void setTabPadding(float f2) {
        this.f9172s = m4008b(f2);
        m4014h();
    }

    public void setTabSpaceEqual(boolean z) {
        this.f9173t = z;
        m4014h();
    }

    public void setTabWidth(float f2) {
        this.f9174u = m4008b(f2);
        m4014h();
    }

    public void setTextAllCaps(boolean z) {
        this.f9150T = z;
        m4014h();
    }

    public void setTextBold(int i2) {
        this.f9149S = i2;
        m4014h();
    }

    public void setTextSelectColor(int i2) {
        this.f9147Q = i2;
        m4014h();
    }

    public void setTextUnselectColor(int i2) {
        this.f9148R = i2;
        m4014h();
    }

    public void setTextsize(float f2) {
        this.f9145O = m4012f(f2);
        m4014h();
    }

    public void setTypeface(String str) {
        if (!str.endsWith(".TTF")) {
            str = C1499a.m637w(str, ".TTF");
        }
        this.f9157c0 = str;
    }

    public void setUnderlineColor(int i2) {
        this.f9139I = i2;
        invalidate();
    }

    public void setUnderlineGravity(int i2) {
        this.f9141K = i2;
        invalidate();
    }

    public void setUnderlineHeight(float f2) {
        this.f9140J = m4008b(f2);
        invalidate();
    }

    public void setViewPager(ViewPager viewPager) {
        if (viewPager == null || viewPager.getAdapter() == null) {
            throw new IllegalStateException("ViewPager or ViewPager adapter can not be NULL !");
        }
        this.f9158e = viewPager;
        viewPager.removeOnPageChangeListener(this);
        this.f9158e.addOnPageChangeListener(this);
        m4009c();
    }

    public void setmIndicatorDrawable(int i2) {
        this.f9176w = i2;
        invalidate();
    }

    public SlidingTabLayout(Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 0);
    }

    public SlidingTabLayout(Context context, AttributeSet attributeSet, int i2) {
        super(context, attributeSet, i2);
        float f2;
        this.f9164k = new Rect();
        this.f9165l = new Rect();
        this.f9167n = new Paint(1);
        this.f9168o = new Paint(1);
        this.f9169p = new Paint(1);
        this.f9170q = new Path();
        this.f9171r = 0;
        this.f9176w = -1;
        this.f9154a0 = new Paint(1);
        new SparseArray();
        this.f9157c0 = null;
        setFillViewport(true);
        setWillNotDraw(false);
        setClipChildren(false);
        setClipToPadding(false);
        this.f9156c = context;
        LinearLayout linearLayout = new LinearLayout(context);
        this.f9160g = linearLayout;
        addView(linearLayout);
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, R$styleable.SlidingTabLayout);
        int i3 = obtainStyledAttributes.getInt(R$styleable.SlidingTabLayout_tl_indicator_style, 0);
        this.f9171r = i3;
        int i4 = R$styleable.SlidingTabLayout_tl_indicator_height;
        if (i3 == 1) {
            f2 = 4.0f;
        } else {
            f2 = i3 != 2 ? 2 : -1;
        }
        this.f9177x = obtainStyledAttributes.getDimension(i4, m4008b(f2));
        this.f9178y = obtainStyledAttributes.getDimension(R$styleable.SlidingTabLayout_tl_indicator_width, m4008b(this.f9171r == 1 ? 10.0f : -1.0f));
        int i5 = R$styleable.SlidingTabLayout_tl_indicator_icon;
        if (obtainStyledAttributes.hasValue(i5)) {
            this.f9171r = 2;
            this.f9177x = -1.0f;
            this.f9178y = -1.0f;
            Drawable drawable = obtainStyledAttributes.getDrawable(i5);
            this.f9166m = drawable;
            if (drawable != null) {
                this.f9137G = drawable.getIntrinsicWidth();
                this.f9138H = this.f9166m.getIntrinsicHeight();
            }
        } else {
            this.f9166m = new GradientDrawable();
            this.f9175v = obtainStyledAttributes.getColor(R$styleable.SlidingTabLayout_tl_indicator_color, Color.parseColor(this.f9171r == 2 ? "#4B6A87" : "#ffffff"));
        }
        this.f9179z = obtainStyledAttributes.getDimension(R$styleable.SlidingTabLayout_tl_indicator_corner_radius, m4008b(this.f9171r == 2 ? -1.0f : 0.0f));
        this.f9131A = obtainStyledAttributes.getDimension(R$styleable.SlidingTabLayout_tl_indicator_margin_left, m4008b(0.0f));
        this.f9132B = obtainStyledAttributes.getDimension(R$styleable.SlidingTabLayout_tl_indicator_margin_top, 0.0f);
        this.f9133C = obtainStyledAttributes.getDimension(R$styleable.SlidingTabLayout_tl_indicator_margin_right, m4008b(0.0f));
        this.f9134D = obtainStyledAttributes.getDimension(R$styleable.SlidingTabLayout_tl_indicator_margin_bottom, 0.0f);
        this.f9135E = obtainStyledAttributes.getInt(R$styleable.SlidingTabLayout_tl_indicator_gravity, 80);
        this.f9136F = obtainStyledAttributes.getBoolean(R$styleable.SlidingTabLayout_tl_indicator_width_equal_title, false);
        this.f9139I = obtainStyledAttributes.getColor(R$styleable.SlidingTabLayout_tl_underline_color, Color.parseColor("#ffffff"));
        this.f9140J = obtainStyledAttributes.getDimension(R$styleable.SlidingTabLayout_tl_underline_height, m4008b(0.0f));
        this.f9141K = obtainStyledAttributes.getInt(R$styleable.SlidingTabLayout_tl_underline_gravity, 80);
        this.f9142L = obtainStyledAttributes.getColor(R$styleable.SlidingTabLayout_tl_divider_color, Color.parseColor("#ffffff"));
        this.f9143M = obtainStyledAttributes.getDimension(R$styleable.SlidingTabLayout_tl_divider_width, m4008b(0.0f));
        this.f9144N = obtainStyledAttributes.getDimension(R$styleable.SlidingTabLayout_tl_divider_padding, m4008b(12.0f));
        this.f9145O = obtainStyledAttributes.getDimension(R$styleable.SlidingTabLayout_tl_textsize, m4012f(14.0f));
        this.f9146P = obtainStyledAttributes.getDimension(R$styleable.SlidingTabLayout_tl_textSelectSize, m4012f(18.0f));
        this.f9147Q = obtainStyledAttributes.getColor(R$styleable.SlidingTabLayout_tl_textSelectColor, Color.parseColor("#ffffff"));
        this.f9148R = obtainStyledAttributes.getColor(R$styleable.SlidingTabLayout_tl_textUnselectColor, Color.parseColor("#AAffffff"));
        this.f9149S = obtainStyledAttributes.getInt(R$styleable.SlidingTabLayout_tl_textBold, 0);
        this.f9150T = obtainStyledAttributes.getBoolean(R$styleable.SlidingTabLayout_tl_textAllCaps, false);
        this.f9173t = obtainStyledAttributes.getBoolean(R$styleable.SlidingTabLayout_tl_tab_space_equal, false);
        float dimension = obtainStyledAttributes.getDimension(R$styleable.SlidingTabLayout_tl_tab_width, m4008b(-1.0f));
        this.f9174u = dimension;
        this.f9172s = obtainStyledAttributes.getDimension(R$styleable.SlidingTabLayout_tl_tab_padding, (this.f9173t || dimension > 0.0f) ? m4008b(0.0f) : m4008b(20.0f));
        obtainStyledAttributes.recycle();
        String attributeValue = attributeSet.getAttributeValue("http://schemas.android.com/apk/res/android", "layout_height");
        if (attributeValue.equals(ChatMsgBean.SERVICE_ID) || attributeValue.equals("-2")) {
            return;
        }
        TypedArray obtainStyledAttributes2 = context.obtainStyledAttributes(attributeSet, new int[]{R.attr.layout_height});
        obtainStyledAttributes2.getDimensionPixelSize(0, -2);
        obtainStyledAttributes2.recycle();
    }
}
