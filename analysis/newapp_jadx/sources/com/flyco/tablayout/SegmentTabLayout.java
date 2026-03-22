package com.flyco.tablayout;

import android.R;
import android.animation.TypeEvaluator;
import android.animation.ValueAnimator;
import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Rect;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.os.Parcelable;
import android.util.AttributeSet;
import android.util.SparseArray;
import android.view.View;
import android.view.animation.OvershootInterpolator;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;
import com.jbzd.media.movecartoons.bean.response.ChatMsgBean;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p187j.p188a.ViewOnClickListenerC1876b;
import p005b.p187j.p188a.p189d.InterfaceC1879b;

/* loaded from: classes.dex */
public class SegmentTabLayout extends FrameLayout implements ValueAnimator.AnimatorUpdateListener {

    /* renamed from: A */
    public int f9087A;

    /* renamed from: B */
    public float f9088B;

    /* renamed from: C */
    public float f9089C;

    /* renamed from: D */
    public float f9090D;

    /* renamed from: E */
    public int f9091E;

    /* renamed from: F */
    public int f9092F;

    /* renamed from: G */
    public int f9093G;

    /* renamed from: H */
    public boolean f9094H;

    /* renamed from: I */
    public int f9095I;

    /* renamed from: J */
    public int f9096J;

    /* renamed from: K */
    public float f9097K;

    /* renamed from: L */
    public ValueAnimator f9098L;

    /* renamed from: M */
    public OvershootInterpolator f9099M;

    /* renamed from: N */
    public float[] f9100N;

    /* renamed from: O */
    public boolean f9101O;

    /* renamed from: P */
    public InterfaceC1879b f9102P;

    /* renamed from: Q */
    public C3251a f9103Q;

    /* renamed from: R */
    public C3251a f9104R;

    /* renamed from: c */
    public Context f9105c;

    /* renamed from: e */
    public String[] f9106e;

    /* renamed from: f */
    public LinearLayout f9107f;

    /* renamed from: g */
    public int f9108g;

    /* renamed from: h */
    public int f9109h;

    /* renamed from: i */
    public int f9110i;

    /* renamed from: j */
    public Rect f9111j;

    /* renamed from: k */
    public GradientDrawable f9112k;

    /* renamed from: l */
    public GradientDrawable f9113l;

    /* renamed from: m */
    public Paint f9114m;

    /* renamed from: n */
    public float f9115n;

    /* renamed from: o */
    public boolean f9116o;

    /* renamed from: p */
    public float f9117p;

    /* renamed from: q */
    public int f9118q;

    /* renamed from: r */
    public float f9119r;

    /* renamed from: s */
    public float f9120s;

    /* renamed from: t */
    public float f9121t;

    /* renamed from: u */
    public float f9122u;

    /* renamed from: v */
    public float f9123v;

    /* renamed from: w */
    public float f9124w;

    /* renamed from: x */
    public long f9125x;

    /* renamed from: y */
    public boolean f9126y;

    /* renamed from: z */
    public boolean f9127z;

    /* renamed from: com.flyco.tablayout.SegmentTabLayout$a */
    public class C3251a {

        /* renamed from: a */
        public float f9128a;

        /* renamed from: b */
        public float f9129b;

        public C3251a(SegmentTabLayout segmentTabLayout) {
        }
    }

    /* renamed from: com.flyco.tablayout.SegmentTabLayout$b */
    public class C3252b implements TypeEvaluator<C3251a> {
        public C3252b() {
        }

        @Override // android.animation.TypeEvaluator
        public C3251a evaluate(float f2, C3251a c3251a, C3251a c3251a2) {
            C3251a c3251a3 = c3251a;
            C3251a c3251a4 = c3251a2;
            float f3 = c3251a3.f9128a;
            float m627m = C1499a.m627m(c3251a4.f9128a, f3, f2, f3);
            float f4 = c3251a3.f9129b;
            float m627m2 = C1499a.m627m(c3251a4.f9129b, f4, f2, f4);
            C3251a c3251a5 = new C3251a(SegmentTabLayout.this);
            c3251a5.f9128a = m627m;
            c3251a5.f9129b = m627m2;
            return c3251a5;
        }
    }

    public SegmentTabLayout(Context context) {
        this(context, null, 0);
    }

    /* renamed from: a */
    public final void m4002a() {
        View childAt = this.f9107f.getChildAt(this.f9108g);
        float left = childAt.getLeft();
        float right = childAt.getRight();
        Rect rect = this.f9111j;
        rect.left = (int) left;
        rect.right = (int) right;
        if (this.f9126y) {
            float[] fArr = this.f9100N;
            float f2 = this.f9120s;
            fArr[0] = f2;
            fArr[1] = f2;
            fArr[2] = f2;
            fArr[3] = f2;
            fArr[4] = f2;
            fArr[5] = f2;
            fArr[6] = f2;
            fArr[7] = f2;
            return;
        }
        int i2 = this.f9108g;
        if (i2 == 0) {
            float[] fArr2 = this.f9100N;
            float f3 = this.f9120s;
            fArr2[0] = f3;
            fArr2[1] = f3;
            fArr2[2] = 0.0f;
            fArr2[3] = 0.0f;
            fArr2[4] = 0.0f;
            fArr2[5] = 0.0f;
            fArr2[6] = f3;
            fArr2[7] = f3;
            return;
        }
        if (i2 != this.f9110i - 1) {
            float[] fArr3 = this.f9100N;
            fArr3[0] = 0.0f;
            fArr3[1] = 0.0f;
            fArr3[2] = 0.0f;
            fArr3[3] = 0.0f;
            fArr3[4] = 0.0f;
            fArr3[5] = 0.0f;
            fArr3[6] = 0.0f;
            fArr3[7] = 0.0f;
            return;
        }
        float[] fArr4 = this.f9100N;
        fArr4[0] = 0.0f;
        fArr4[1] = 0.0f;
        float f4 = this.f9120s;
        fArr4[2] = f4;
        fArr4[3] = f4;
        fArr4[4] = f4;
        fArr4[5] = f4;
        fArr4[6] = 0.0f;
        fArr4[7] = 0.0f;
    }

    /* renamed from: b */
    public int m4003b(float f2) {
        return (int) ((f2 * this.f9105c.getResources().getDisplayMetrics().density) + 0.5f);
    }

    /* renamed from: c */
    public int m4004c(float f2) {
        return (int) ((f2 * this.f9105c.getResources().getDisplayMetrics().scaledDensity) + 0.5f);
    }

    /* renamed from: d */
    public final void m4005d(int i2) {
        int i3 = 0;
        while (i3 < this.f9110i) {
            View childAt = this.f9107f.getChildAt(i3);
            boolean z = i3 == i2;
            TextView textView = (TextView) childAt.findViewById(R$id.tv_tab_title);
            textView.setTextColor(z ? this.f9091E : this.f9092F);
            if (this.f9093G == 1) {
                textView.getPaint().setFakeBoldText(z);
            }
            i3++;
        }
    }

    /* renamed from: e */
    public final void m4006e() {
        int i2 = 0;
        while (i2 < this.f9110i) {
            View childAt = this.f9107f.getChildAt(i2);
            float f2 = this.f9115n;
            childAt.setPadding((int) f2, 0, (int) f2, 0);
            TextView textView = (TextView) childAt.findViewById(R$id.tv_tab_title);
            textView.setTextColor(i2 == this.f9108g ? this.f9091E : this.f9092F);
            textView.setTextSize(0, this.f9090D);
            if (this.f9094H) {
                textView.setText(textView.getText().toString().toUpperCase());
            }
            int i3 = this.f9093G;
            if (i3 == 2) {
                textView.getPaint().setFakeBoldText(true);
            } else if (i3 == 0) {
                textView.getPaint().setFakeBoldText(false);
            }
            i2++;
        }
    }

    public int getCurrentTab() {
        return this.f9108g;
    }

    public int getDividerColor() {
        return this.f9087A;
    }

    public float getDividerPadding() {
        return this.f9089C;
    }

    public float getDividerWidth() {
        return this.f9088B;
    }

    public long getIndicatorAnimDuration() {
        return this.f9125x;
    }

    public int getIndicatorColor() {
        return this.f9118q;
    }

    public float getIndicatorCornerRadius() {
        return this.f9120s;
    }

    public float getIndicatorHeight() {
        return this.f9119r;
    }

    public float getIndicatorMarginBottom() {
        return this.f9124w;
    }

    public float getIndicatorMarginLeft() {
        return this.f9121t;
    }

    public float getIndicatorMarginRight() {
        return this.f9123v;
    }

    public float getIndicatorMarginTop() {
        return this.f9122u;
    }

    public int getTabCount() {
        return this.f9110i;
    }

    public float getTabPadding() {
        return this.f9115n;
    }

    public float getTabWidth() {
        return this.f9117p;
    }

    public int getTextBold() {
        return this.f9093G;
    }

    public int getTextSelectColor() {
        return this.f9091E;
    }

    public int getTextUnselectColor() {
        return this.f9092F;
    }

    public float getTextsize() {
        return this.f9090D;
    }

    @Override // android.animation.ValueAnimator.AnimatorUpdateListener
    public void onAnimationUpdate(ValueAnimator valueAnimator) {
        C3251a c3251a = (C3251a) valueAnimator.getAnimatedValue();
        Rect rect = this.f9111j;
        rect.left = (int) c3251a.f9128a;
        rect.right = (int) c3251a.f9129b;
        invalidate();
    }

    @Override // android.view.View
    public void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        if (isInEditMode() || this.f9110i <= 0) {
            return;
        }
        int height = getHeight();
        int paddingLeft = getPaddingLeft();
        if (this.f9119r < 0.0f) {
            this.f9119r = (height - this.f9122u) - this.f9124w;
        }
        float f2 = this.f9120s;
        if (f2 < 0.0f || f2 > this.f9119r / 2.0f) {
            this.f9120s = this.f9119r / 2.0f;
        }
        this.f9113l.setColor(this.f9095I);
        this.f9113l.setStroke((int) this.f9097K, this.f9096J);
        this.f9113l.setCornerRadius(this.f9120s);
        this.f9113l.setBounds(getPaddingLeft(), getPaddingTop(), getWidth() - getPaddingRight(), getHeight() - getPaddingBottom());
        this.f9113l.draw(canvas);
        if (!this.f9126y) {
            float f3 = this.f9088B;
            if (f3 > 0.0f) {
                this.f9114m.setStrokeWidth(f3);
                this.f9114m.setColor(this.f9087A);
                for (int i2 = 0; i2 < this.f9110i - 1; i2++) {
                    View childAt = this.f9107f.getChildAt(i2);
                    canvas.drawLine(childAt.getRight() + paddingLeft, this.f9089C, childAt.getRight() + paddingLeft, height - this.f9089C, this.f9114m);
                }
            }
        }
        if (!this.f9126y) {
            m4002a();
        } else if (this.f9101O) {
            this.f9101O = false;
            m4002a();
        }
        this.f9112k.setColor(this.f9118q);
        GradientDrawable gradientDrawable = this.f9112k;
        int i3 = ((int) this.f9121t) + paddingLeft + this.f9111j.left;
        float f4 = this.f9122u;
        gradientDrawable.setBounds(i3, (int) f4, (int) ((paddingLeft + r3.right) - this.f9123v), (int) (f4 + this.f9119r));
        this.f9112k.setCornerRadii(this.f9100N);
        this.f9112k.draw(canvas);
    }

    @Override // android.view.View
    public void onRestoreInstanceState(Parcelable parcelable) {
        if (parcelable instanceof Bundle) {
            Bundle bundle = (Bundle) parcelable;
            this.f9108g = bundle.getInt("mCurrentTab");
            parcelable = bundle.getParcelable("instanceState");
            if (this.f9108g != 0 && this.f9107f.getChildCount() > 0) {
                m4005d(this.f9108g);
            }
        }
        super.onRestoreInstanceState(parcelable);
    }

    @Override // android.view.View
    public Parcelable onSaveInstanceState() {
        Bundle bundle = new Bundle();
        bundle.putParcelable("instanceState", super.onSaveInstanceState());
        bundle.putInt("mCurrentTab", this.f9108g);
        return bundle;
    }

    public void setCurrentTab(int i2) {
        this.f9109h = this.f9108g;
        this.f9108g = i2;
        m4005d(i2);
        if (!this.f9126y) {
            invalidate();
            return;
        }
        View childAt = this.f9107f.getChildAt(this.f9108g);
        this.f9103Q.f9128a = childAt.getLeft();
        this.f9103Q.f9129b = childAt.getRight();
        View childAt2 = this.f9107f.getChildAt(this.f9109h);
        this.f9104R.f9128a = childAt2.getLeft();
        this.f9104R.f9129b = childAt2.getRight();
        C3251a c3251a = this.f9104R;
        float f2 = c3251a.f9128a;
        C3251a c3251a2 = this.f9103Q;
        if (f2 == c3251a2.f9128a && c3251a.f9129b == c3251a2.f9129b) {
            invalidate();
            return;
        }
        this.f9098L.setObjectValues(c3251a, c3251a2);
        if (this.f9127z) {
            this.f9098L.setInterpolator(this.f9099M);
        }
        if (this.f9125x < 0) {
            this.f9125x = this.f9127z ? 500L : 250L;
        }
        this.f9098L.setDuration(this.f9125x);
        this.f9098L.start();
    }

    public void setDividerColor(int i2) {
        this.f9087A = i2;
        invalidate();
    }

    public void setDividerPadding(float f2) {
        this.f9089C = m4003b(f2);
        invalidate();
    }

    public void setDividerWidth(float f2) {
        this.f9088B = m4003b(f2);
        invalidate();
    }

    public void setIndicatorAnimDuration(long j2) {
        this.f9125x = j2;
    }

    public void setIndicatorAnimEnable(boolean z) {
        this.f9126y = z;
    }

    public void setIndicatorBounceEnable(boolean z) {
        this.f9127z = z;
    }

    public void setIndicatorColor(int i2) {
        this.f9118q = i2;
        invalidate();
    }

    public void setIndicatorCornerRadius(float f2) {
        this.f9120s = m4003b(f2);
        invalidate();
    }

    public void setIndicatorHeight(float f2) {
        this.f9119r = m4003b(f2);
        invalidate();
    }

    public void setOnTabSelectListener(InterfaceC1879b interfaceC1879b) {
        this.f9102P = interfaceC1879b;
    }

    public void setTabData(String[] strArr) {
        if (strArr == null || strArr.length == 0) {
            throw new IllegalStateException("Titles can not be NULL or EMPTY !");
        }
        this.f9106e = strArr;
        this.f9107f.removeAllViews();
        this.f9110i = this.f9106e.length;
        for (int i2 = 0; i2 < this.f9110i; i2++) {
            View inflate = View.inflate(this.f9105c, R$layout.layout_tab_segment, null);
            inflate.setTag(Integer.valueOf(i2));
            ((TextView) inflate.findViewById(R$id.tv_tab_title)).setText(this.f9106e[i2]);
            inflate.setOnClickListener(new ViewOnClickListenerC1876b(this));
            LinearLayout.LayoutParams layoutParams = this.f9116o ? new LinearLayout.LayoutParams(0, -1, 1.0f) : new LinearLayout.LayoutParams(-2, -1);
            if (this.f9117p > 0.0f) {
                layoutParams = new LinearLayout.LayoutParams((int) this.f9117p, -1);
            }
            this.f9107f.addView(inflate, i2, layoutParams);
        }
        m4006e();
    }

    public void setTabPadding(float f2) {
        this.f9115n = m4003b(f2);
        m4006e();
    }

    public void setTabSpaceEqual(boolean z) {
        this.f9116o = z;
        m4006e();
    }

    public void setTabWidth(float f2) {
        this.f9117p = m4003b(f2);
        m4006e();
    }

    public void setTextAllCaps(boolean z) {
        this.f9094H = z;
        m4006e();
    }

    public void setTextBold(int i2) {
        this.f9093G = i2;
        m4006e();
    }

    public void setTextSelectColor(int i2) {
        this.f9091E = i2;
        m4006e();
    }

    public void setTextUnselectColor(int i2) {
        this.f9092F = i2;
        m4006e();
    }

    public void setTextsize(float f2) {
        this.f9090D = m4004c(f2);
        m4006e();
    }

    public SegmentTabLayout(Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 0);
    }

    public SegmentTabLayout(Context context, AttributeSet attributeSet, int i2) {
        super(context, attributeSet, i2);
        this.f9111j = new Rect();
        this.f9112k = new GradientDrawable();
        this.f9113l = new GradientDrawable();
        this.f9114m = new Paint(1);
        this.f9099M = new OvershootInterpolator(0.8f);
        this.f9100N = new float[8];
        this.f9101O = true;
        new Paint(1);
        new SparseArray();
        this.f9103Q = new C3251a(this);
        this.f9104R = new C3251a(this);
        setWillNotDraw(false);
        setClipChildren(false);
        setClipToPadding(false);
        this.f9105c = context;
        LinearLayout linearLayout = new LinearLayout(context);
        this.f9107f = linearLayout;
        addView(linearLayout);
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, R$styleable.SegmentTabLayout);
        this.f9118q = obtainStyledAttributes.getColor(R$styleable.SegmentTabLayout_tl_indicator_color, Color.parseColor("#222831"));
        this.f9119r = obtainStyledAttributes.getDimension(R$styleable.SegmentTabLayout_tl_indicator_height, -1.0f);
        this.f9120s = obtainStyledAttributes.getDimension(R$styleable.SegmentTabLayout_tl_indicator_corner_radius, -1.0f);
        this.f9121t = obtainStyledAttributes.getDimension(R$styleable.SegmentTabLayout_tl_indicator_margin_left, m4003b(0.0f));
        this.f9122u = obtainStyledAttributes.getDimension(R$styleable.SegmentTabLayout_tl_indicator_margin_top, 0.0f);
        this.f9123v = obtainStyledAttributes.getDimension(R$styleable.SegmentTabLayout_tl_indicator_margin_right, m4003b(0.0f));
        this.f9124w = obtainStyledAttributes.getDimension(R$styleable.SegmentTabLayout_tl_indicator_margin_bottom, 0.0f);
        this.f9126y = obtainStyledAttributes.getBoolean(R$styleable.SegmentTabLayout_tl_indicator_anim_enable, false);
        this.f9127z = obtainStyledAttributes.getBoolean(R$styleable.SegmentTabLayout_tl_indicator_bounce_enable, true);
        this.f9125x = obtainStyledAttributes.getInt(R$styleable.SegmentTabLayout_tl_indicator_anim_duration, -1);
        this.f9087A = obtainStyledAttributes.getColor(R$styleable.SegmentTabLayout_tl_divider_color, this.f9118q);
        this.f9088B = obtainStyledAttributes.getDimension(R$styleable.SegmentTabLayout_tl_divider_width, m4003b(1.0f));
        this.f9089C = obtainStyledAttributes.getDimension(R$styleable.SegmentTabLayout_tl_divider_padding, 0.0f);
        this.f9090D = obtainStyledAttributes.getDimension(R$styleable.SegmentTabLayout_tl_textsize, m4004c(13.0f));
        this.f9091E = obtainStyledAttributes.getColor(R$styleable.SegmentTabLayout_tl_textSelectColor, Color.parseColor("#ffffff"));
        this.f9092F = obtainStyledAttributes.getColor(R$styleable.SegmentTabLayout_tl_textUnselectColor, this.f9118q);
        this.f9093G = obtainStyledAttributes.getInt(R$styleable.SegmentTabLayout_tl_textBold, 0);
        this.f9094H = obtainStyledAttributes.getBoolean(R$styleable.SegmentTabLayout_tl_textAllCaps, false);
        this.f9116o = obtainStyledAttributes.getBoolean(R$styleable.SegmentTabLayout_tl_tab_space_equal, true);
        float dimension = obtainStyledAttributes.getDimension(R$styleable.SegmentTabLayout_tl_tab_width, m4003b(-1.0f));
        this.f9117p = dimension;
        this.f9115n = obtainStyledAttributes.getDimension(R$styleable.SegmentTabLayout_tl_tab_padding, (this.f9116o || dimension > 0.0f) ? m4003b(0.0f) : m4003b(10.0f));
        this.f9095I = obtainStyledAttributes.getColor(R$styleable.SegmentTabLayout_tl_bar_color, 0);
        this.f9096J = obtainStyledAttributes.getColor(R$styleable.SegmentTabLayout_tl_bar_stroke_color, this.f9118q);
        this.f9097K = obtainStyledAttributes.getDimension(R$styleable.SegmentTabLayout_tl_bar_stroke_width, m4003b(1.0f));
        obtainStyledAttributes.recycle();
        String attributeValue = attributeSet.getAttributeValue("http://schemas.android.com/apk/res/android", "layout_height");
        if (!attributeValue.equals(ChatMsgBean.SERVICE_ID) && !attributeValue.equals("-2")) {
            TypedArray obtainStyledAttributes2 = context.obtainStyledAttributes(attributeSet, new int[]{R.attr.layout_height});
            obtainStyledAttributes2.getDimensionPixelSize(0, -2);
            obtainStyledAttributes2.recycle();
        }
        ValueAnimator ofObject = ValueAnimator.ofObject(new C3252b(), this.f9104R, this.f9103Q);
        this.f9098L = ofObject;
        ofObject.addUpdateListener(this);
    }
}
