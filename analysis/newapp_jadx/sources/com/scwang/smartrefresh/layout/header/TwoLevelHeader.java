package com.scwang.smartrefresh.layout.header;

import android.animation.ValueAnimator;
import android.content.Context;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewGroup;
import android.widget.RelativeLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import com.scwang.smartrefresh.layout.R$styleable;
import com.scwang.smartrefresh.layout.SmartRefreshLayout;
import com.scwang.smartrefresh.layout.internal.InternalAbstract;
import p005b.p340x.p354b.p355a.C2891a;
import p005b.p340x.p354b.p355a.p356b.InterfaceC2897f;
import p005b.p340x.p354b.p355a.p356b.InterfaceC2898g;
import p005b.p340x.p354b.p355a.p356b.InterfaceC2899h;
import p005b.p340x.p354b.p355a.p356b.InterfaceC2900i;
import p005b.p340x.p354b.p355a.p357c.C2904c;
import p005b.p340x.p354b.p355a.p357c.EnumC2903b;

/* loaded from: classes2.dex */
public class TwoLevelHeader extends InternalAbstract implements InterfaceC2897f {

    /* renamed from: g */
    public int f10732g;

    /* renamed from: h */
    public float f10733h;

    /* renamed from: i */
    public float f10734i;

    /* renamed from: j */
    public float f10735j;

    /* renamed from: k */
    public float f10736k;

    /* renamed from: l */
    public boolean f10737l;

    /* renamed from: m */
    public boolean f10738m;

    /* renamed from: n */
    public int f10739n;

    /* renamed from: o */
    public int f10740o;

    /* renamed from: p */
    public InterfaceC2898g f10741p;

    /* renamed from: q */
    public InterfaceC2899h f10742q;

    public TwoLevelHeader(Context context) {
        this(context, null);
    }

    @Override // com.scwang.smartrefresh.layout.internal.InternalAbstract, p005b.p340x.p354b.p355a.p356b.InterfaceC2898g
    /* renamed from: d */
    public void mo3352d(boolean z, float f2, int i2, int i3, int i4) {
        InterfaceC2898g interfaceC2898g = this.f10741p;
        if (this.f10732g != i2 && interfaceC2898g != null) {
            this.f10732g = i2;
            C2904c spinnerStyle = interfaceC2898g.getSpinnerStyle();
            if (spinnerStyle == C2904c.f7953a) {
                interfaceC2898g.getView().setTranslationY(i2);
            } else if (spinnerStyle.f7961i) {
                View view = interfaceC2898g.getView();
                view.layout(view.getLeft(), view.getTop(), view.getRight(), Math.max(0, i2) + view.getTop());
            }
        }
        InterfaceC2898g interfaceC2898g2 = this.f10741p;
        InterfaceC2899h interfaceC2899h = this.f10742q;
        if (interfaceC2898g2 != null) {
            interfaceC2898g2.mo3352d(z, f2, i2, i3, i4);
        }
        if (z) {
            float f3 = this.f10733h;
            float f4 = this.f10735j;
            if (f3 < f4 && f2 >= f4 && this.f10737l) {
                ((SmartRefreshLayout.C4087m) interfaceC2899h).m4627d(EnumC2903b.ReleaseToTwoLevel);
            } else if (f3 >= f4 && f2 < this.f10736k) {
                ((SmartRefreshLayout.C4087m) interfaceC2899h).m4627d(EnumC2903b.PullDownToRefresh);
            } else if (f3 >= f4 && f2 < f4) {
                ((SmartRefreshLayout.C4087m) interfaceC2899h).m4627d(EnumC2903b.ReleaseToRefresh);
            }
            this.f10733h = f2;
        }
    }

    @Override // com.scwang.smartrefresh.layout.internal.InternalAbstract, p005b.p340x.p354b.p355a.p360f.InterfaceC2915f
    /* renamed from: e */
    public void mo3379e(@NonNull InterfaceC2900i interfaceC2900i, @NonNull EnumC2903b enumC2903b, @NonNull EnumC2903b enumC2903b2) {
        InterfaceC2898g interfaceC2898g = this.f10741p;
        if (interfaceC2898g != null) {
            interfaceC2898g.mo3379e(interfaceC2900i, enumC2903b, enumC2903b2);
            int ordinal = enumC2903b2.ordinal();
            if (ordinal == 1) {
                if (interfaceC2898g.getView().getAlpha() != 0.0f || interfaceC2898g.getView() == this) {
                    return;
                }
                interfaceC2898g.getView().setAlpha(1.0f);
                return;
            }
            if (ordinal != 8) {
                if (ordinal == 16 && interfaceC2898g.getView() != this) {
                    interfaceC2898g.getView().animate().alpha(1.0f).setDuration(this.f10739n / 2);
                    return;
                }
                return;
            }
            if (interfaceC2898g.getView() != this) {
                interfaceC2898g.getView().animate().alpha(0.0f).setDuration(this.f10739n / 2);
            }
            InterfaceC2899h interfaceC2899h = this.f10742q;
            if (interfaceC2899h != null) {
                SmartRefreshLayout.C4087m c4087m = (SmartRefreshLayout.C4087m) interfaceC2899h;
                C2891a c2891a = new C2891a(c4087m);
                ValueAnimator m4624a = c4087m.m4624a(SmartRefreshLayout.this.getMeasuredHeight());
                if (m4624a != null) {
                    if (m4624a == SmartRefreshLayout.this.reboundAnimator) {
                        m4624a.setDuration(r3.mFloorDuration);
                        m4624a.addListener(c2891a);
                        return;
                    }
                }
                c2891a.onAnimationEnd(null);
            }
        }
    }

    @Override // com.scwang.smartrefresh.layout.internal.InternalAbstract
    public boolean equals(Object obj) {
        InterfaceC2898g interfaceC2898g = this.f10741p;
        return (interfaceC2898g != null && interfaceC2898g.equals(obj)) || super.equals(obj);
    }

    @Override // com.scwang.smartrefresh.layout.internal.InternalAbstract, p005b.p340x.p354b.p355a.p356b.InterfaceC2898g
    /* renamed from: o */
    public void mo3356o(@NonNull InterfaceC2899h interfaceC2899h, int i2, int i3) {
        InterfaceC2898g interfaceC2898g = this.f10741p;
        if (interfaceC2898g == null) {
            return;
        }
        float f2 = ((i3 + i2) * 1.0f) / i2;
        float f3 = this.f10734i;
        if (f2 != f3 && this.f10740o == 0) {
            this.f10740o = i2;
            this.f10741p = null;
            SmartRefreshLayout.this.setHeaderMaxDragRate(f3);
            this.f10741p = interfaceC2898g;
        }
        if (this.f10742q == null && interfaceC2898g.getSpinnerStyle() == C2904c.f7953a && !isInEditMode()) {
            ViewGroup.MarginLayoutParams marginLayoutParams = (ViewGroup.MarginLayoutParams) interfaceC2898g.getView().getLayoutParams();
            marginLayoutParams.topMargin -= i2;
            interfaceC2898g.getView().setLayoutParams(marginLayoutParams);
        }
        this.f10740o = i2;
        this.f10742q = interfaceC2899h;
        SmartRefreshLayout.this.mFloorDuration = this.f10739n;
        boolean z = !this.f10738m;
        SmartRefreshLayout.C4087m c4087m = (SmartRefreshLayout.C4087m) interfaceC2899h;
        if (equals(SmartRefreshLayout.this.mRefreshHeader)) {
            SmartRefreshLayout.this.mHeaderNeedTouchEventWhenRefreshing = z;
        } else if (equals(SmartRefreshLayout.this.mRefreshFooter)) {
            SmartRefreshLayout.this.mFooterNeedTouchEventWhenLoading = z;
        }
        interfaceC2898g.mo3356o(interfaceC2899h, i2, i3);
    }

    @Override // android.view.ViewGroup, android.view.View
    public void onAttachedToWindow() {
        super.onAttachedToWindow();
        this.f10744e = C2904c.f7957e;
        if (this.f10741p == null) {
            m4631r(new ClassicsHeader(getContext()));
        }
    }

    @Override // android.view.ViewGroup, android.view.View
    public void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        this.f10744e = C2904c.f7955c;
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // android.view.View
    public void onFinishInflate() {
        super.onFinishInflate();
        int childCount = getChildCount();
        int i2 = 0;
        while (true) {
            if (i2 >= childCount) {
                break;
            }
            View childAt = getChildAt(i2);
            if (childAt instanceof InterfaceC2897f) {
                this.f10741p = (InterfaceC2897f) childAt;
                this.f10745f = (InterfaceC2898g) childAt;
                bringChildToFront(childAt);
                break;
            }
            i2++;
        }
        if (this.f10741p == null) {
            m4631r(new ClassicsHeader(getContext()));
        }
    }

    @Override // android.widget.RelativeLayout, android.view.View
    public void onMeasure(int i2, int i3) {
        InterfaceC2898g interfaceC2898g = this.f10741p;
        if (interfaceC2898g == null) {
            super.onMeasure(i2, i3);
        } else {
            if (View.MeasureSpec.getMode(i3) != Integer.MIN_VALUE) {
                super.onMeasure(i2, i3);
                return;
            }
            interfaceC2898g.getView().measure(i2, i3);
            super.setMeasuredDimension(View.resolveSize(super.getSuggestedMinimumWidth(), i2), interfaceC2898g.getView().getMeasuredHeight());
        }
    }

    /* renamed from: r */
    public TwoLevelHeader m4631r(InterfaceC2897f interfaceC2897f) {
        InterfaceC2898g interfaceC2898g = this.f10741p;
        if (interfaceC2898g != null) {
            removeView(interfaceC2898g.getView());
        }
        if (interfaceC2897f.getSpinnerStyle() == C2904c.f7955c) {
            addView(interfaceC2897f.getView(), 0, new RelativeLayout.LayoutParams(-1, -2));
        } else {
            addView(interfaceC2897f.getView(), getChildCount(), new RelativeLayout.LayoutParams(-1, -2));
        }
        this.f10741p = interfaceC2897f;
        this.f10745f = interfaceC2897f;
        return this;
    }

    public TwoLevelHeader(Context context, @Nullable AttributeSet attributeSet) {
        super(context, attributeSet, 0);
        this.f10733h = 0.0f;
        this.f10734i = 2.5f;
        this.f10735j = 1.9f;
        this.f10736k = 1.0f;
        this.f10737l = true;
        this.f10738m = true;
        this.f10739n = 1000;
        this.f10744e = C2904c.f7955c;
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, R$styleable.TwoLevelHeader);
        this.f10734i = obtainStyledAttributes.getFloat(R$styleable.TwoLevelHeader_srlMaxRage, this.f10734i);
        this.f10735j = obtainStyledAttributes.getFloat(R$styleable.TwoLevelHeader_srlFloorRage, this.f10735j);
        this.f10736k = obtainStyledAttributes.getFloat(R$styleable.TwoLevelHeader_srlRefreshRage, this.f10736k);
        this.f10739n = obtainStyledAttributes.getInt(R$styleable.TwoLevelHeader_srlFloorDuration, this.f10739n);
        this.f10737l = obtainStyledAttributes.getBoolean(R$styleable.TwoLevelHeader_srlEnableTwoLevel, this.f10737l);
        this.f10738m = obtainStyledAttributes.getBoolean(R$styleable.TwoLevelHeader_srlEnablePullToCloseTwoLevel, this.f10738m);
        obtainStyledAttributes.recycle();
    }
}
