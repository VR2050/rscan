package com.scwang.smart.refresh.footer;

import android.content.Context;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import android.view.View;
import android.widget.ImageView;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.annotation.ColorInt;
import androidx.annotation.NonNull;
import com.scwang.smart.refresh.classics.ClassicsAbstract;
import com.scwang.smart.refresh.footer.classics.R$id;
import com.scwang.smart.refresh.footer.classics.R$layout;
import com.scwang.smart.refresh.footer.classics.R$string;
import com.scwang.smart.refresh.footer.classics.R$styleable;
import p005b.p340x.p341a.p342a.C2866b;
import p005b.p340x.p341a.p343b.p344a.C2867a;
import p005b.p340x.p341a.p343b.p347c.p348a.InterfaceC2873c;
import p005b.p340x.p341a.p343b.p347c.p348a.InterfaceC2876f;
import p005b.p340x.p341a.p343b.p347c.p349b.C2879c;
import p005b.p340x.p341a.p343b.p347c.p349b.EnumC2878b;
import p005b.p340x.p341a.p343b.p347c.p352e.InterpolatorC2889b;

/* loaded from: classes2.dex */
public class ClassicsFooter extends ClassicsAbstract<ClassicsFooter> implements InterfaceC2873c {

    /* renamed from: A */
    public boolean f10468A;

    /* renamed from: t */
    public String f10469t;

    /* renamed from: u */
    public String f10470u;

    /* renamed from: v */
    public String f10471v;

    /* renamed from: w */
    public String f10472w;

    /* renamed from: x */
    public String f10473x;

    /* renamed from: y */
    public String f10474y;

    /* renamed from: z */
    public String f10475z;

    public ClassicsFooter(Context context) {
        this(context, null);
    }

    @Override // com.scwang.smart.refresh.layout.simple.SimpleComponent, p005b.p340x.p341a.p343b.p347c.p348a.InterfaceC2873c
    /* renamed from: a */
    public boolean mo3321a(boolean z) {
        if (this.f10468A == z) {
            return true;
        }
        this.f10468A = z;
        ImageView imageView = this.f10456h;
        if (z) {
            this.f10455g.setText(this.f10475z);
            imageView.setVisibility(8);
            return true;
        }
        this.f10455g.setText(this.f10469t);
        imageView.setVisibility(0);
        return true;
    }

    @Override // com.scwang.smart.refresh.classics.ClassicsAbstract, com.scwang.smart.refresh.layout.simple.SimpleComponent, p005b.p340x.p341a.p343b.p347c.p348a.InterfaceC2871a
    /* renamed from: f */
    public int mo3318f(@NonNull InterfaceC2876f interfaceC2876f, boolean z) {
        super.mo3318f(interfaceC2876f, z);
        if (this.f10468A) {
            return 0;
        }
        this.f10455g.setText(z ? this.f10473x : this.f10474y);
        return this.f10464p;
    }

    @Override // com.scwang.smart.refresh.layout.simple.SimpleComponent, p005b.p340x.p341a.p343b.p347c.p350c.InterfaceC2885f
    /* renamed from: h */
    public void mo3328h(@NonNull InterfaceC2876f interfaceC2876f, @NonNull EnumC2878b enumC2878b, @NonNull EnumC2878b enumC2878b2) {
        ImageView imageView = this.f10456h;
        if (this.f10468A) {
            return;
        }
        int ordinal = enumC2878b2.ordinal();
        if (ordinal == 0) {
            imageView.setVisibility(0);
        } else if (ordinal != 2) {
            if (ordinal == 6) {
                this.f10455g.setText(this.f10470u);
                imageView.animate().rotation(0.0f);
                return;
            }
            switch (ordinal) {
                case 10:
                case 12:
                    imageView.setVisibility(8);
                    this.f10455g.setText(this.f10471v);
                    break;
                case 11:
                    this.f10455g.setText(this.f10472w);
                    imageView.setVisibility(8);
                    break;
            }
        }
        this.f10455g.setText(this.f10469t);
        imageView.animate().rotation(180.0f);
    }

    @Override // com.scwang.smart.refresh.classics.ClassicsAbstract, com.scwang.smart.refresh.layout.simple.SimpleComponent, p005b.p340x.p341a.p343b.p347c.p348a.InterfaceC2871a
    @Deprecated
    public void setPrimaryColors(@ColorInt int... iArr) {
        if (this.f10627e == C2879c.f7889c) {
            super.setPrimaryColors(iArr);
        }
    }

    public ClassicsFooter(Context context, AttributeSet attributeSet) {
        super(context, attributeSet, 0);
        this.f10468A = false;
        View.inflate(context, R$layout.srl_classics_footer, this);
        ImageView imageView = (ImageView) findViewById(R$id.srl_classics_arrow);
        this.f10456h = imageView;
        ImageView imageView2 = (ImageView) findViewById(R$id.srl_classics_progress);
        this.f10457i = imageView2;
        this.f10455g = (TextView) findViewById(R$id.srl_classics_title);
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, R$styleable.ClassicsFooter);
        RelativeLayout.LayoutParams layoutParams = (RelativeLayout.LayoutParams) imageView.getLayoutParams();
        RelativeLayout.LayoutParams layoutParams2 = (RelativeLayout.LayoutParams) imageView2.getLayoutParams();
        int dimensionPixelSize = obtainStyledAttributes.getDimensionPixelSize(R$styleable.ClassicsFooter_srlDrawableMarginRight, InterpolatorC2889b.m3333c(20.0f));
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
        this.f10464p = obtainStyledAttributes.getInt(R$styleable.ClassicsFooter_srlFinishDuration, this.f10464p);
        this.f10627e = C2879c.f7892f[obtainStyledAttributes.getInt(R$styleable.ClassicsFooter_srlClassicsSpinnerStyle, this.f10627e.f7893g)];
        int i5 = R$styleable.ClassicsFooter_srlDrawableArrow;
        if (obtainStyledAttributes.hasValue(i5)) {
            this.f10456h.setImageDrawable(obtainStyledAttributes.getDrawable(i5));
        } else if (this.f10456h.getDrawable() == null) {
            C2867a c2867a = new C2867a();
            this.f10459k = c2867a;
            c2867a.f7802c.setColor(-10066330);
            this.f10456h.setImageDrawable(this.f10459k);
        }
        int i6 = R$styleable.ClassicsFooter_srlDrawableProgress;
        if (obtainStyledAttributes.hasValue(i6)) {
            this.f10457i.setImageDrawable(obtainStyledAttributes.getDrawable(i6));
        } else if (this.f10457i.getDrawable() == null) {
            C2866b c2866b = new C2866b();
            this.f10460l = c2866b;
            c2866b.f7802c.setColor(-10066330);
            this.f10457i.setImageDrawable(this.f10460l);
        }
        if (obtainStyledAttributes.hasValue(R$styleable.ClassicsFooter_srlTextSizeTitle)) {
            this.f10455g.setTextSize(0, obtainStyledAttributes.getDimensionPixelSize(r3, InterpolatorC2889b.m3333c(16.0f)));
        }
        int i7 = R$styleable.ClassicsFooter_srlPrimaryColor;
        if (obtainStyledAttributes.hasValue(i7)) {
            m4599k(obtainStyledAttributes.getColor(i7, 0));
        }
        int i8 = R$styleable.ClassicsFooter_srlAccentColor;
        if (obtainStyledAttributes.hasValue(i8)) {
            mo4598j(obtainStyledAttributes.getColor(i8, 0));
        }
        int i9 = R$styleable.ClassicsFooter_srlTextPulling;
        if (obtainStyledAttributes.hasValue(i9)) {
            this.f10469t = obtainStyledAttributes.getString(i9);
        } else {
            this.f10469t = context.getString(R$string.srl_footer_pulling);
        }
        int i10 = R$styleable.ClassicsFooter_srlTextRelease;
        if (obtainStyledAttributes.hasValue(i10)) {
            this.f10470u = obtainStyledAttributes.getString(i10);
        } else {
            this.f10470u = context.getString(R$string.srl_footer_release);
        }
        int i11 = R$styleable.ClassicsFooter_srlTextLoading;
        if (obtainStyledAttributes.hasValue(i11)) {
            this.f10471v = obtainStyledAttributes.getString(i11);
        } else {
            this.f10471v = context.getString(R$string.srl_footer_loading);
        }
        int i12 = R$styleable.ClassicsFooter_srlTextRefreshing;
        if (obtainStyledAttributes.hasValue(i12)) {
            this.f10472w = obtainStyledAttributes.getString(i12);
        } else {
            this.f10472w = context.getString(R$string.srl_footer_refreshing);
        }
        int i13 = R$styleable.ClassicsFooter_srlTextFinish;
        if (obtainStyledAttributes.hasValue(i13)) {
            this.f10473x = obtainStyledAttributes.getString(i13);
        } else {
            this.f10473x = context.getString(R$string.srl_footer_finish);
        }
        int i14 = R$styleable.ClassicsFooter_srlTextFailed;
        if (obtainStyledAttributes.hasValue(i14)) {
            this.f10474y = obtainStyledAttributes.getString(i14);
        } else {
            this.f10474y = context.getString(R$string.srl_footer_failed);
        }
        int i15 = R$styleable.ClassicsFooter_srlTextNothing;
        if (obtainStyledAttributes.hasValue(i15)) {
            this.f10475z = obtainStyledAttributes.getString(i15);
        } else {
            this.f10475z = context.getString(R$string.srl_footer_nothing);
        }
        obtainStyledAttributes.recycle();
        imageView2.animate().setInterpolator(null);
        this.f10455g.setText(isInEditMode() ? this.f10471v : this.f10469t);
        if (isInEditMode()) {
            imageView.setVisibility(8);
        } else {
            imageView2.setVisibility(8);
        }
    }
}
