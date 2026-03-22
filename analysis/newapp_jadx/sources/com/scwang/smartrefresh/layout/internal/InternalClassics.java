package com.scwang.smartrefresh.layout.internal;

import android.content.Context;
import android.graphics.drawable.Animatable;
import android.graphics.drawable.BitmapDrawable;
import android.util.AttributeSet;
import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.annotation.ColorInt;
import androidx.annotation.NonNull;
import com.scwang.smartrefresh.layout.SmartRefreshLayout;
import com.scwang.smartrefresh.layout.internal.InternalClassics;
import com.yalantis.ucrop.view.CropImageView;
import p005b.p340x.p354b.p355a.p356b.InterfaceC2898g;
import p005b.p340x.p354b.p355a.p356b.InterfaceC2899h;
import p005b.p340x.p354b.p355a.p356b.InterfaceC2900i;
import p005b.p340x.p354b.p355a.p357c.C2904c;
import p005b.p340x.p354b.p355a.p359e.AbstractC2908b;
import p005b.p340x.p354b.p355a.p361g.InterpolatorC2917b;

/* loaded from: classes2.dex */
public abstract class InternalClassics<T extends InternalClassics> extends InternalAbstract implements InterfaceC2898g {

    /* renamed from: g */
    public TextView f10746g;

    /* renamed from: h */
    public ImageView f10747h;

    /* renamed from: i */
    public ImageView f10748i;

    /* renamed from: j */
    public InterfaceC2899h f10749j;

    /* renamed from: k */
    public AbstractC2908b f10750k;

    /* renamed from: l */
    public AbstractC2908b f10751l;

    /* renamed from: m */
    public boolean f10752m;

    /* renamed from: n */
    public boolean f10753n;

    /* renamed from: o */
    public int f10754o;

    /* renamed from: p */
    public int f10755p;

    /* renamed from: q */
    public int f10756q;

    /* renamed from: r */
    public int f10757r;

    /* renamed from: s */
    public int f10758s;

    public InternalClassics(Context context, AttributeSet attributeSet, int i2) {
        super(context, attributeSet, i2);
        this.f10755p = CropImageView.DEFAULT_IMAGE_TO_CROP_BOUNDS_ANIM_DURATION;
        this.f10756q = 20;
        this.f10757r = 20;
        this.f10758s = 0;
        this.f10744e = C2904c.f7953a;
    }

    @Override // com.scwang.smartrefresh.layout.internal.InternalAbstract, p005b.p340x.p354b.p355a.p356b.InterfaceC2898g
    /* renamed from: f */
    public void mo3353f(@NonNull InterfaceC2900i interfaceC2900i, int i2, int i3) {
        ImageView imageView = this.f10748i;
        if (imageView.getVisibility() != 0) {
            imageView.setVisibility(0);
            Object drawable = this.f10748i.getDrawable();
            if (drawable instanceof Animatable) {
                ((Animatable) drawable).start();
            } else {
                imageView.animate().rotation(36000.0f).setDuration(100000L);
            }
        }
    }

    @Override // com.scwang.smartrefresh.layout.internal.InternalAbstract, p005b.p340x.p354b.p355a.p356b.InterfaceC2898g
    /* renamed from: j */
    public int mo3354j(@NonNull InterfaceC2900i interfaceC2900i, boolean z) {
        ImageView imageView = this.f10748i;
        Object drawable = imageView.getDrawable();
        if (drawable instanceof Animatable) {
            Animatable animatable = (Animatable) drawable;
            if (animatable.isRunning()) {
                animatable.stop();
            }
        } else {
            imageView.animate().rotation(0.0f).setDuration(0L);
        }
        imageView.setVisibility(8);
        return this.f10755p;
    }

    @Override // com.scwang.smartrefresh.layout.internal.InternalAbstract, p005b.p340x.p354b.p355a.p356b.InterfaceC2898g
    /* renamed from: k */
    public void mo3355k(@NonNull InterfaceC2900i interfaceC2900i, int i2, int i3) {
        mo3353f(interfaceC2900i, i2, i3);
    }

    @Override // com.scwang.smartrefresh.layout.internal.InternalAbstract, p005b.p340x.p354b.p355a.p356b.InterfaceC2898g
    /* renamed from: o */
    public void mo3356o(@NonNull InterfaceC2899h interfaceC2899h, int i2, int i3) {
        this.f10749j = interfaceC2899h;
        ((SmartRefreshLayout.C4087m) interfaceC2899h).m4626c(this, this.f10754o);
    }

    @Override // android.view.ViewGroup, android.view.View
    public void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        ImageView imageView = this.f10747h;
        ImageView imageView2 = this.f10748i;
        imageView.animate().cancel();
        imageView2.animate().cancel();
        Object drawable = this.f10748i.getDrawable();
        if (drawable instanceof Animatable) {
            Animatable animatable = (Animatable) drawable;
            if (animatable.isRunning()) {
                animatable.stop();
            }
        }
    }

    @Override // android.widget.RelativeLayout, android.view.View
    public void onMeasure(int i2, int i3) {
        if (this.f10758s == 0) {
            this.f10756q = getPaddingTop();
            int paddingBottom = getPaddingBottom();
            this.f10757r = paddingBottom;
            if (this.f10756q == 0 || paddingBottom == 0) {
                int paddingLeft = getPaddingLeft();
                int paddingRight = getPaddingRight();
                int i4 = this.f10756q;
                if (i4 == 0) {
                    i4 = InterpolatorC2917b.m3382c(20.0f);
                }
                this.f10756q = i4;
                int i5 = this.f10757r;
                if (i5 == 0) {
                    i5 = InterpolatorC2917b.m3382c(20.0f);
                }
                this.f10757r = i5;
                setPadding(paddingLeft, this.f10756q, paddingRight, i5);
            }
            setClipToPadding(false);
        }
        if (View.MeasureSpec.getMode(i3) == 1073741824) {
            int size = View.MeasureSpec.getSize(i3);
            int i6 = this.f10758s;
            if (size < i6) {
                int i7 = (size - i6) / 2;
                setPadding(getPaddingLeft(), i7, getPaddingRight(), i7);
            } else {
                setPadding(getPaddingLeft(), 0, getPaddingRight(), 0);
            }
        } else {
            setPadding(getPaddingLeft(), this.f10756q, getPaddingRight(), this.f10757r);
        }
        super.onMeasure(i2, i3);
        if (this.f10758s == 0) {
            for (int i8 = 0; i8 < getChildCount(); i8++) {
                int measuredHeight = getChildAt(i8).getMeasuredHeight();
                if (this.f10758s < measuredHeight) {
                    this.f10758s = measuredHeight;
                }
            }
        }
    }

    /* renamed from: r */
    public T mo4629r(@ColorInt int i2) {
        this.f10752m = true;
        this.f10746g.setTextColor(i2);
        AbstractC2908b abstractC2908b = this.f10750k;
        if (abstractC2908b != null) {
            abstractC2908b.f7977c.setColor(i2);
            this.f10747h.invalidateDrawable(this.f10750k);
        }
        AbstractC2908b abstractC2908b2 = this.f10751l;
        if (abstractC2908b2 != null) {
            abstractC2908b2.f7977c.setColor(i2);
            this.f10748i.invalidateDrawable(this.f10751l);
        }
        return this;
    }

    /* renamed from: s */
    public T m4632s(@ColorInt int i2) {
        this.f10753n = true;
        this.f10754o = i2;
        InterfaceC2899h interfaceC2899h = this.f10749j;
        if (interfaceC2899h != null) {
            ((SmartRefreshLayout.C4087m) interfaceC2899h).m4626c(this, i2);
        }
        return this;
    }

    @Override // com.scwang.smartrefresh.layout.internal.InternalAbstract, p005b.p340x.p354b.p355a.p356b.InterfaceC2898g
    public void setPrimaryColors(@ColorInt int... iArr) {
        if (iArr.length > 0) {
            if (!(getBackground() instanceof BitmapDrawable) && !this.f10753n) {
                m4632s(iArr[0]);
                this.f10753n = false;
            }
            if (this.f10752m) {
                return;
            }
            if (iArr.length > 1) {
                mo4629r(iArr[1]);
            } else {
                mo4629r(iArr[0] == -1 ? -10066330 : -1);
            }
            this.f10752m = false;
        }
    }
}
