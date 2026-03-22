package com.github.chrisbanes.photoview;

import android.content.Context;
import android.graphics.Matrix;
import android.graphics.RectF;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.util.AttributeSet;
import android.view.GestureDetector;
import android.view.View;
import android.widget.ImageView;
import androidx.appcompat.widget.AppCompatImageView;
import java.util.Objects;
import p005b.p190k.p195b.p196a.C1899k;
import p005b.p190k.p195b.p196a.InterfaceC1891c;
import p005b.p190k.p195b.p196a.InterfaceC1892d;
import p005b.p190k.p195b.p196a.InterfaceC1893e;
import p005b.p190k.p195b.p196a.InterfaceC1894f;
import p005b.p190k.p195b.p196a.InterfaceC1895g;
import p005b.p190k.p195b.p196a.InterfaceC1896h;
import p005b.p190k.p195b.p196a.InterfaceC1897i;
import p005b.p190k.p195b.p196a.ViewOnTouchListenerC1898j;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* loaded from: classes.dex */
public class PhotoView extends AppCompatImageView {

    /* renamed from: c */
    public ViewOnTouchListenerC1898j f9208c;

    /* renamed from: e */
    public ImageView.ScaleType f9209e;

    public PhotoView(Context context) {
        this(context, null);
    }

    public ViewOnTouchListenerC1898j getAttacher() {
        return this.f9208c;
    }

    public RectF getDisplayRect() {
        return this.f9208c.m1240c();
    }

    @Override // android.widget.ImageView
    public Matrix getImageMatrix() {
        return this.f9208c.f2971o;
    }

    public float getMaximumScale() {
        return this.f9208c.f2964h;
    }

    public float getMediumScale() {
        return this.f9208c.f2963g;
    }

    public float getMinimumScale() {
        return this.f9208c.f2962f;
    }

    public float getScale() {
        return this.f9208c.m1245h();
    }

    @Override // android.widget.ImageView
    public ImageView.ScaleType getScaleType() {
        return this.f9208c.f2958F;
    }

    public void setAllowParentInterceptOnEdge(boolean z) {
        this.f9208c.f2965i = z;
    }

    @Override // android.widget.ImageView
    public boolean setFrame(int i2, int i3, int i4, int i5) {
        boolean frame = super.setFrame(i2, i3, i4, i5);
        if (frame) {
            this.f9208c.m1248k();
        }
        return frame;
    }

    @Override // androidx.appcompat.widget.AppCompatImageView, android.widget.ImageView
    public void setImageDrawable(Drawable drawable) {
        super.setImageDrawable(drawable);
        ViewOnTouchListenerC1898j viewOnTouchListenerC1898j = this.f9208c;
        if (viewOnTouchListenerC1898j != null) {
            viewOnTouchListenerC1898j.m1248k();
        }
    }

    @Override // androidx.appcompat.widget.AppCompatImageView, android.widget.ImageView
    public void setImageResource(int i2) {
        super.setImageResource(i2);
        ViewOnTouchListenerC1898j viewOnTouchListenerC1898j = this.f9208c;
        if (viewOnTouchListenerC1898j != null) {
            viewOnTouchListenerC1898j.m1248k();
        }
    }

    @Override // androidx.appcompat.widget.AppCompatImageView, android.widget.ImageView
    public void setImageURI(Uri uri) {
        super.setImageURI(uri);
        ViewOnTouchListenerC1898j viewOnTouchListenerC1898j = this.f9208c;
        if (viewOnTouchListenerC1898j != null) {
            viewOnTouchListenerC1898j.m1248k();
        }
    }

    public void setMaximumScale(float f2) {
        ViewOnTouchListenerC1898j viewOnTouchListenerC1898j = this.f9208c;
        C4195m.m4777L(viewOnTouchListenerC1898j.f2962f, viewOnTouchListenerC1898j.f2963g, f2);
        viewOnTouchListenerC1898j.f2964h = f2;
    }

    public void setMediumScale(float f2) {
        ViewOnTouchListenerC1898j viewOnTouchListenerC1898j = this.f9208c;
        C4195m.m4777L(viewOnTouchListenerC1898j.f2962f, f2, viewOnTouchListenerC1898j.f2964h);
        viewOnTouchListenerC1898j.f2963g = f2;
    }

    public void setMinimumScale(float f2) {
        ViewOnTouchListenerC1898j viewOnTouchListenerC1898j = this.f9208c;
        C4195m.m4777L(f2, viewOnTouchListenerC1898j.f2963g, viewOnTouchListenerC1898j.f2964h);
        viewOnTouchListenerC1898j.f2962f = f2;
    }

    @Override // android.view.View
    public void setOnClickListener(View.OnClickListener onClickListener) {
        this.f9208c.setOnClickListener(onClickListener);
    }

    public void setOnDoubleTapListener(GestureDetector.OnDoubleTapListener onDoubleTapListener) {
        this.f9208c.setOnDoubleTapListener(onDoubleTapListener);
    }

    @Override // android.view.View
    public void setOnLongClickListener(View.OnLongClickListener onLongClickListener) {
        this.f9208c.setOnLongClickListener(onLongClickListener);
    }

    public void setOnMatrixChangeListener(InterfaceC1891c interfaceC1891c) {
        this.f9208c.setOnMatrixChangeListener(interfaceC1891c);
    }

    public void setOnOutsidePhotoTapListener(InterfaceC1892d interfaceC1892d) {
        this.f9208c.setOnOutsidePhotoTapListener(interfaceC1892d);
    }

    public void setOnPhotoTapListener(InterfaceC1893e interfaceC1893e) {
        this.f9208c.setOnPhotoTapListener(interfaceC1893e);
    }

    public void setOnScaleChangeListener(InterfaceC1894f interfaceC1894f) {
        this.f9208c.setOnScaleChangeListener(interfaceC1894f);
    }

    public void setOnSingleFlingListener(InterfaceC1895g interfaceC1895g) {
        this.f9208c.setOnSingleFlingListener(interfaceC1895g);
    }

    public void setOnViewDragListener(InterfaceC1896h interfaceC1896h) {
        this.f9208c.setOnViewDragListener(interfaceC1896h);
    }

    public void setOnViewTapListener(InterfaceC1897i interfaceC1897i) {
        this.f9208c.setOnViewTapListener(interfaceC1897i);
    }

    public void setRotationBy(float f2) {
        ViewOnTouchListenerC1898j viewOnTouchListenerC1898j = this.f9208c;
        viewOnTouchListenerC1898j.f2972p.postRotate(f2 % 360.0f);
        viewOnTouchListenerC1898j.m1238a();
    }

    public void setRotationTo(float f2) {
        ViewOnTouchListenerC1898j viewOnTouchListenerC1898j = this.f9208c;
        viewOnTouchListenerC1898j.f2972p.setRotate(f2 % 360.0f);
        viewOnTouchListenerC1898j.m1238a();
    }

    public void setScale(float f2) {
        this.f9208c.m1247j(f2, r0.f2967k.getRight() / 2, r0.f2967k.getBottom() / 2, false);
    }

    @Override // android.widget.ImageView
    public void setScaleType(ImageView.ScaleType scaleType) {
        ViewOnTouchListenerC1898j viewOnTouchListenerC1898j = this.f9208c;
        if (viewOnTouchListenerC1898j == null) {
            this.f9209e = scaleType;
            return;
        }
        Objects.requireNonNull(viewOnTouchListenerC1898j);
        boolean z = true;
        if (scaleType == null) {
            z = false;
        } else if (C1899k.f2997a[scaleType.ordinal()] == 1) {
            throw new IllegalStateException("Matrix scale type is not supported");
        }
        if (!z || scaleType == viewOnTouchListenerC1898j.f2958F) {
            return;
        }
        viewOnTouchListenerC1898j.f2958F = scaleType;
        viewOnTouchListenerC1898j.m1248k();
    }

    public void setZoomTransitionDuration(int i2) {
        this.f9208c.f2961e = i2;
    }

    public void setZoomable(boolean z) {
        ViewOnTouchListenerC1898j viewOnTouchListenerC1898j = this.f9208c;
        viewOnTouchListenerC1898j.f2957E = z;
        viewOnTouchListenerC1898j.m1248k();
    }

    public PhotoView(Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 0);
    }

    public PhotoView(Context context, AttributeSet attributeSet, int i2) {
        super(context, attributeSet, i2);
        this.f9208c = new ViewOnTouchListenerC1898j(this);
        super.setScaleType(ImageView.ScaleType.MATRIX);
        ImageView.ScaleType scaleType = this.f9209e;
        if (scaleType != null) {
            setScaleType(scaleType);
            this.f9209e = null;
        }
    }
}
