package com.scwang.smart.refresh.classics;

import android.content.Context;
import android.graphics.drawable.Animatable;
import android.graphics.drawable.BitmapDrawable;
import android.util.AttributeSet;
import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.annotation.ColorInt;
import androidx.annotation.NonNull;
import com.scwang.smart.refresh.classics.ClassicsAbstract;
import com.scwang.smart.refresh.layout.SmartRefreshLayout;
import com.scwang.smart.refresh.layout.simple.SimpleComponent;
import com.yalantis.ucrop.view.CropImageView;
import p005b.p340x.p341a.p342a.AbstractC2865a;
import p005b.p340x.p341a.p343b.p347c.p348a.InterfaceC2871a;
import p005b.p340x.p341a.p343b.p347c.p348a.InterfaceC2875e;
import p005b.p340x.p341a.p343b.p347c.p348a.InterfaceC2876f;
import p005b.p340x.p341a.p343b.p347c.p349b.C2879c;
import p005b.p340x.p341a.p343b.p347c.p352e.InterpolatorC2889b;

/* loaded from: classes2.dex */
public abstract class ClassicsAbstract<T extends ClassicsAbstract<?>> extends SimpleComponent implements InterfaceC2871a {

    /* renamed from: g */
    public TextView f10455g;

    /* renamed from: h */
    public ImageView f10456h;

    /* renamed from: i */
    public ImageView f10457i;

    /* renamed from: j */
    public InterfaceC2875e f10458j;

    /* renamed from: k */
    public AbstractC2865a f10459k;

    /* renamed from: l */
    public AbstractC2865a f10460l;

    /* renamed from: m */
    public boolean f10461m;

    /* renamed from: n */
    public boolean f10462n;

    /* renamed from: o */
    public int f10463o;

    /* renamed from: p */
    public int f10464p;

    /* renamed from: q */
    public int f10465q;

    /* renamed from: r */
    public int f10466r;

    /* renamed from: s */
    public int f10467s;

    public ClassicsAbstract(Context context, AttributeSet attributeSet, int i2) {
        super(context, attributeSet, i2);
        this.f10464p = CropImageView.DEFAULT_IMAGE_TO_CROP_BOUNDS_ANIM_DURATION;
        this.f10465q = 20;
        this.f10466r = 20;
        this.f10467s = 0;
        this.f10627e = C2879c.f7887a;
    }

    @Override // com.scwang.smart.refresh.layout.simple.SimpleComponent, p005b.p340x.p341a.p343b.p347c.p348a.InterfaceC2871a
    /* renamed from: e */
    public void mo3317e(@NonNull InterfaceC2876f interfaceC2876f, int i2, int i3) {
        mo3320i(interfaceC2876f, i2, i3);
    }

    @Override // com.scwang.smart.refresh.layout.simple.SimpleComponent, p005b.p340x.p341a.p343b.p347c.p348a.InterfaceC2871a
    /* renamed from: f */
    public int mo3318f(@NonNull InterfaceC2876f interfaceC2876f, boolean z) {
        ImageView imageView = this.f10457i;
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
        return this.f10464p;
    }

    @Override // com.scwang.smart.refresh.layout.simple.SimpleComponent, p005b.p340x.p341a.p343b.p347c.p348a.InterfaceC2871a
    /* renamed from: g */
    public void mo3319g(@NonNull InterfaceC2875e interfaceC2875e, int i2, int i3) {
        this.f10458j = interfaceC2875e;
        ((SmartRefreshLayout.C4074k) interfaceC2875e).m4622c(this, this.f10463o);
    }

    @Override // com.scwang.smart.refresh.layout.simple.SimpleComponent, p005b.p340x.p341a.p343b.p347c.p348a.InterfaceC2871a
    /* renamed from: i */
    public void mo3320i(@NonNull InterfaceC2876f interfaceC2876f, int i2, int i3) {
        ImageView imageView = this.f10457i;
        if (imageView.getVisibility() != 0) {
            imageView.setVisibility(0);
            Object drawable = this.f10457i.getDrawable();
            if (drawable instanceof Animatable) {
                ((Animatable) drawable).start();
            } else {
                imageView.animate().rotation(36000.0f).setDuration(100000L);
            }
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* renamed from: j */
    public T mo4598j(@ColorInt int i2) {
        this.f10461m = true;
        this.f10455g.setTextColor(i2);
        AbstractC2865a abstractC2865a = this.f10459k;
        if (abstractC2865a != null) {
            abstractC2865a.f7802c.setColor(i2);
            this.f10456h.invalidateDrawable(this.f10459k);
        }
        AbstractC2865a abstractC2865a2 = this.f10460l;
        if (abstractC2865a2 != null) {
            abstractC2865a2.f7802c.setColor(i2);
            this.f10457i.invalidateDrawable(this.f10460l);
        }
        return this;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* renamed from: k */
    public T m4599k(@ColorInt int i2) {
        this.f10462n = true;
        this.f10463o = i2;
        InterfaceC2875e interfaceC2875e = this.f10458j;
        if (interfaceC2875e != null) {
            ((SmartRefreshLayout.C4074k) interfaceC2875e).m4622c(this, i2);
        }
        return this;
    }

    @Override // android.view.ViewGroup, android.view.View
    public void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        ImageView imageView = this.f10456h;
        ImageView imageView2 = this.f10457i;
        imageView.animate().cancel();
        imageView2.animate().cancel();
        Object drawable = this.f10457i.getDrawable();
        if (drawable instanceof Animatable) {
            Animatable animatable = (Animatable) drawable;
            if (animatable.isRunning()) {
                animatable.stop();
            }
        }
    }

    @Override // android.widget.RelativeLayout, android.view.View
    public void onMeasure(int i2, int i3) {
        if (this.f10467s == 0) {
            this.f10465q = getPaddingTop();
            int paddingBottom = getPaddingBottom();
            this.f10466r = paddingBottom;
            if (this.f10465q == 0 || paddingBottom == 0) {
                int paddingLeft = getPaddingLeft();
                int paddingRight = getPaddingRight();
                int i4 = this.f10465q;
                if (i4 == 0) {
                    i4 = InterpolatorC2889b.m3333c(20.0f);
                }
                this.f10465q = i4;
                int i5 = this.f10466r;
                if (i5 == 0) {
                    i5 = InterpolatorC2889b.m3333c(20.0f);
                }
                this.f10466r = i5;
                setPadding(paddingLeft, this.f10465q, paddingRight, i5);
            }
            setClipToPadding(false);
        }
        if (View.MeasureSpec.getMode(i3) == 1073741824) {
            int size = View.MeasureSpec.getSize(i3);
            int i6 = this.f10467s;
            if (size < i6) {
                int i7 = (size - i6) / 2;
                setPadding(getPaddingLeft(), i7, getPaddingRight(), i7);
            } else {
                setPadding(getPaddingLeft(), 0, getPaddingRight(), 0);
            }
        } else {
            setPadding(getPaddingLeft(), this.f10465q, getPaddingRight(), this.f10466r);
        }
        super.onMeasure(i2, i3);
        if (this.f10467s == 0) {
            for (int i8 = 0; i8 < getChildCount(); i8++) {
                int measuredHeight = getChildAt(i8).getMeasuredHeight();
                if (this.f10467s < measuredHeight) {
                    this.f10467s = measuredHeight;
                }
            }
        }
    }

    @Override // com.scwang.smart.refresh.layout.simple.SimpleComponent, p005b.p340x.p341a.p343b.p347c.p348a.InterfaceC2871a
    public void setPrimaryColors(@ColorInt int... iArr) {
        if (iArr.length > 0) {
            if (!(getBackground() instanceof BitmapDrawable) && !this.f10462n) {
                m4599k(iArr[0]);
                this.f10462n = false;
            }
            if (this.f10461m) {
                return;
            }
            if (iArr.length > 1) {
                mo4598j(iArr[1]);
            }
            this.f10461m = false;
        }
    }
}
