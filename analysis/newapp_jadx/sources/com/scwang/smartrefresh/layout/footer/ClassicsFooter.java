package com.scwang.smartrefresh.layout.footer;

import android.content.Context;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import android.view.View;
import android.widget.ImageView;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.annotation.ColorInt;
import androidx.annotation.NonNull;
import com.scwang.smartrefresh.layout.R$id;
import com.scwang.smartrefresh.layout.R$layout;
import com.scwang.smartrefresh.layout.R$string;
import com.scwang.smartrefresh.layout.R$styleable;
import com.scwang.smartrefresh.layout.internal.InternalClassics;
import p005b.p340x.p354b.p355a.p356b.InterfaceC2896e;
import p005b.p340x.p354b.p355a.p356b.InterfaceC2900i;
import p005b.p340x.p354b.p355a.p357c.C2904c;
import p005b.p340x.p354b.p355a.p357c.EnumC2903b;
import p005b.p340x.p354b.p355a.p359e.C2907a;
import p005b.p340x.p354b.p355a.p359e.C2909c;
import p005b.p340x.p354b.p355a.p361g.InterpolatorC2917b;

/* loaded from: classes2.dex */
public class ClassicsFooter extends InternalClassics<ClassicsFooter> implements InterfaceC2896e {

    /* renamed from: A */
    public boolean f10684A;

    /* renamed from: t */
    public String f10685t;

    /* renamed from: u */
    public String f10686u;

    /* renamed from: v */
    public String f10687v;

    /* renamed from: w */
    public String f10688w;

    /* renamed from: x */
    public String f10689x;

    /* renamed from: y */
    public String f10690y;

    /* renamed from: z */
    public String f10691z;

    public ClassicsFooter(Context context) {
        this(context, null);
    }

    @Override // com.scwang.smartrefresh.layout.internal.InternalAbstract, p005b.p340x.p354b.p355a.p356b.InterfaceC2896e
    /* renamed from: a */
    public boolean mo3349a(boolean z) {
        if (this.f10684A == z) {
            return true;
        }
        this.f10684A = z;
        ImageView imageView = this.f10747h;
        if (z) {
            this.f10746g.setText(this.f10691z);
            imageView.setVisibility(8);
            return true;
        }
        this.f10746g.setText(this.f10685t);
        imageView.setVisibility(0);
        return true;
    }

    @Override // com.scwang.smartrefresh.layout.internal.InternalAbstract, p005b.p340x.p354b.p355a.p360f.InterfaceC2915f
    /* renamed from: e */
    public void mo3379e(@NonNull InterfaceC2900i interfaceC2900i, @NonNull EnumC2903b enumC2903b, @NonNull EnumC2903b enumC2903b2) {
        ImageView imageView = this.f10747h;
        if (this.f10684A) {
            return;
        }
        int ordinal = enumC2903b2.ordinal();
        if (ordinal == 0) {
            imageView.setVisibility(0);
        } else if (ordinal != 2) {
            if (ordinal == 6) {
                this.f10746g.setText(this.f10686u);
                imageView.animate().rotation(0.0f);
                return;
            }
            switch (ordinal) {
                case 10:
                case 12:
                    imageView.setVisibility(8);
                    this.f10746g.setText(this.f10687v);
                    break;
                case 11:
                    this.f10746g.setText(this.f10688w);
                    imageView.setVisibility(8);
                    break;
            }
        }
        this.f10746g.setText(this.f10685t);
        imageView.animate().rotation(180.0f);
    }

    @Override // com.scwang.smartrefresh.layout.internal.InternalClassics, com.scwang.smartrefresh.layout.internal.InternalAbstract, p005b.p340x.p354b.p355a.p356b.InterfaceC2898g
    /* renamed from: f */
    public void mo3353f(@NonNull InterfaceC2900i interfaceC2900i, int i2, int i3) {
        if (this.f10684A) {
            return;
        }
        super.mo3353f(interfaceC2900i, i2, i3);
    }

    @Override // com.scwang.smartrefresh.layout.internal.InternalClassics, com.scwang.smartrefresh.layout.internal.InternalAbstract, p005b.p340x.p354b.p355a.p356b.InterfaceC2898g
    /* renamed from: j */
    public int mo3354j(@NonNull InterfaceC2900i interfaceC2900i, boolean z) {
        if (this.f10684A) {
            return 0;
        }
        this.f10746g.setText(z ? this.f10689x : this.f10690y);
        return super.mo3354j(interfaceC2900i, z);
    }

    @Override // com.scwang.smartrefresh.layout.internal.InternalClassics, com.scwang.smartrefresh.layout.internal.InternalAbstract, p005b.p340x.p354b.p355a.p356b.InterfaceC2898g
    @Deprecated
    public void setPrimaryColors(@ColorInt int... iArr) {
        if (this.f10744e == C2904c.f7955c) {
            super.setPrimaryColors(iArr);
        }
    }

    public ClassicsFooter(Context context, AttributeSet attributeSet) {
        super(context, attributeSet, 0);
        this.f10684A = false;
        View.inflate(context, R$layout.srl_classics_footer, this);
        ImageView imageView = (ImageView) findViewById(R$id.srl_classics_arrow);
        this.f10747h = imageView;
        ImageView imageView2 = (ImageView) findViewById(R$id.srl_classics_progress);
        this.f10748i = imageView2;
        this.f10746g = (TextView) findViewById(R$id.srl_classics_title);
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, R$styleable.ClassicsFooter);
        RelativeLayout.LayoutParams layoutParams = (RelativeLayout.LayoutParams) imageView.getLayoutParams();
        RelativeLayout.LayoutParams layoutParams2 = (RelativeLayout.LayoutParams) imageView2.getLayoutParams();
        int dimensionPixelSize = obtainStyledAttributes.getDimensionPixelSize(R$styleable.ClassicsFooter_srlDrawableMarginRight, InterpolatorC2917b.m3382c(20.0f));
        layoutParams2.rightMargin = dimensionPixelSize;
        layoutParams.rightMargin = dimensionPixelSize;
        int i2 = R$styleable.ClassicsFooter_srlDrawableArrowSize;
        layoutParams.width = obtainStyledAttributes.getLayoutDimension(i2, layoutParams.width);
        layoutParams.height = obtainStyledAttributes.getLayoutDimension(i2, layoutParams.height);
        int i3 = R$styleable.ClassicsFooter_srlDrawableProgressSize;
        layoutParams2.width = obtainStyledAttributes.getLayoutDimension(i3, layoutParams2.width);
        layoutParams2.height = obtainStyledAttributes.getLayoutDimension(i3, layoutParams2.height);
        int i4 = R$styleable.ClassicsFooter_srlDrawableSize;
        layoutParams.width = obtainStyledAttributes.getLayoutDimension(i4, layoutParams.width);
        layoutParams.height = obtainStyledAttributes.getLayoutDimension(i4, layoutParams.height);
        layoutParams2.width = obtainStyledAttributes.getLayoutDimension(i4, layoutParams2.width);
        layoutParams2.height = obtainStyledAttributes.getLayoutDimension(i4, layoutParams2.height);
        this.f10755p = obtainStyledAttributes.getInt(R$styleable.ClassicsFooter_srlFinishDuration, this.f10755p);
        this.f10744e = C2904c.f7958f[obtainStyledAttributes.getInt(R$styleable.ClassicsFooter_srlClassicsSpinnerStyle, this.f10744e.f7959g)];
        int i5 = R$styleable.ClassicsFooter_srlDrawableArrow;
        if (obtainStyledAttributes.hasValue(i5)) {
            this.f10747h.setImageDrawable(obtainStyledAttributes.getDrawable(i5));
        } else if (this.f10747h.getDrawable() == null) {
            C2907a c2907a = new C2907a();
            this.f10750k = c2907a;
            c2907a.f7977c.setColor(-10066330);
            this.f10747h.setImageDrawable(this.f10750k);
        }
        int i6 = R$styleable.ClassicsFooter_srlDrawableProgress;
        if (obtainStyledAttributes.hasValue(i6)) {
            this.f10748i.setImageDrawable(obtainStyledAttributes.getDrawable(i6));
        } else if (this.f10748i.getDrawable() == null) {
            C2909c c2909c = new C2909c();
            this.f10751l = c2909c;
            c2909c.f7977c.setColor(-10066330);
            this.f10748i.setImageDrawable(this.f10751l);
        }
        if (obtainStyledAttributes.hasValue(R$styleable.ClassicsFooter_srlTextSizeTitle)) {
            this.f10746g.setTextSize(0, obtainStyledAttributes.getDimensionPixelSize(r3, InterpolatorC2917b.m3382c(16.0f)));
        }
        int i7 = R$styleable.ClassicsFooter_srlPrimaryColor;
        if (obtainStyledAttributes.hasValue(i7)) {
            m4632s(obtainStyledAttributes.getColor(i7, 0));
        }
        int i8 = R$styleable.ClassicsFooter_srlAccentColor;
        if (obtainStyledAttributes.hasValue(i8)) {
            mo4629r(obtainStyledAttributes.getColor(i8, 0));
        }
        int i9 = R$styleable.ClassicsFooter_srlTextPulling;
        if (obtainStyledAttributes.hasValue(i9)) {
            this.f10685t = obtainStyledAttributes.getString(i9);
        } else {
            this.f10685t = context.getString(R$string.srl_footer_pulling);
        }
        int i10 = R$styleable.ClassicsFooter_srlTextRelease;
        if (obtainStyledAttributes.hasValue(i10)) {
            this.f10686u = obtainStyledAttributes.getString(i10);
        } else {
            this.f10686u = context.getString(R$string.srl_footer_release);
        }
        int i11 = R$styleable.ClassicsFooter_srlTextLoading;
        if (obtainStyledAttributes.hasValue(i11)) {
            this.f10687v = obtainStyledAttributes.getString(i11);
        } else {
            this.f10687v = context.getString(R$string.srl_footer_loading);
        }
        int i12 = R$styleable.ClassicsFooter_srlTextRefreshing;
        if (obtainStyledAttributes.hasValue(i12)) {
            this.f10688w = obtainStyledAttributes.getString(i12);
        } else {
            this.f10688w = context.getString(R$string.srl_footer_refreshing);
        }
        int i13 = R$styleable.ClassicsFooter_srlTextFinish;
        if (obtainStyledAttributes.hasValue(i13)) {
            this.f10689x = obtainStyledAttributes.getString(i13);
        } else {
            this.f10689x = context.getString(R$string.srl_footer_finish);
        }
        int i14 = R$styleable.ClassicsFooter_srlTextFailed;
        if (obtainStyledAttributes.hasValue(i14)) {
            this.f10690y = obtainStyledAttributes.getString(i14);
        } else {
            this.f10690y = context.getString(R$string.srl_footer_failed);
        }
        int i15 = R$styleable.ClassicsFooter_srlTextNothing;
        if (obtainStyledAttributes.hasValue(i15)) {
            this.f10691z = obtainStyledAttributes.getString(i15);
        } else {
            this.f10691z = context.getString(R$string.srl_footer_nothing);
        }
        obtainStyledAttributes.recycle();
        imageView2.animate().setInterpolator(null);
        this.f10746g.setText(isInEditMode() ? this.f10687v : this.f10685t);
        if (isInEditMode()) {
            imageView.setVisibility(8);
        } else {
            imageView2.setVisibility(8);
        }
    }
}
