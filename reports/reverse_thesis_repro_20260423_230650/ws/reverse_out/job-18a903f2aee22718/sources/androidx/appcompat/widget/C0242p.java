package androidx.appcompat.widget;

import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.Bitmap;
import android.graphics.PorterDuff;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.util.AttributeSet;
import android.widget.ImageButton;
import d.AbstractC0502a;

/* JADX INFO: renamed from: androidx.appcompat.widget.p, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0242p extends ImageButton {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final C0231e f4150b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final C0243q f4151c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private boolean f4152d;

    public C0242p(Context context, AttributeSet attributeSet) {
        this(context, attributeSet, AbstractC0502a.f8814z);
    }

    @Override // android.widget.ImageView, android.view.View
    protected void drawableStateChanged() {
        super.drawableStateChanged();
        C0231e c0231e = this.f4150b;
        if (c0231e != null) {
            c0231e.b();
        }
        C0243q c0243q = this.f4151c;
        if (c0243q != null) {
            c0243q.c();
        }
    }

    public ColorStateList getSupportBackgroundTintList() {
        C0231e c0231e = this.f4150b;
        if (c0231e != null) {
            return c0231e.c();
        }
        return null;
    }

    public PorterDuff.Mode getSupportBackgroundTintMode() {
        C0231e c0231e = this.f4150b;
        if (c0231e != null) {
            return c0231e.d();
        }
        return null;
    }

    public ColorStateList getSupportImageTintList() {
        C0243q c0243q = this.f4151c;
        if (c0243q != null) {
            return c0243q.d();
        }
        return null;
    }

    public PorterDuff.Mode getSupportImageTintMode() {
        C0243q c0243q = this.f4151c;
        if (c0243q != null) {
            return c0243q.e();
        }
        return null;
    }

    @Override // android.widget.ImageView, android.view.View
    public boolean hasOverlappingRendering() {
        return this.f4151c.f() && super.hasOverlappingRendering();
    }

    @Override // android.view.View
    public void setBackgroundDrawable(Drawable drawable) {
        super.setBackgroundDrawable(drawable);
        C0231e c0231e = this.f4150b;
        if (c0231e != null) {
            c0231e.f(drawable);
        }
    }

    @Override // android.view.View
    public void setBackgroundResource(int i3) {
        super.setBackgroundResource(i3);
        C0231e c0231e = this.f4150b;
        if (c0231e != null) {
            c0231e.g(i3);
        }
    }

    @Override // android.widget.ImageView
    public void setImageBitmap(Bitmap bitmap) {
        super.setImageBitmap(bitmap);
        C0243q c0243q = this.f4151c;
        if (c0243q != null) {
            c0243q.c();
        }
    }

    @Override // android.widget.ImageView
    public void setImageDrawable(Drawable drawable) {
        C0243q c0243q = this.f4151c;
        if (c0243q != null && drawable != null && !this.f4152d) {
            c0243q.h(drawable);
        }
        super.setImageDrawable(drawable);
        C0243q c0243q2 = this.f4151c;
        if (c0243q2 != null) {
            c0243q2.c();
            if (this.f4152d) {
                return;
            }
            this.f4151c.b();
        }
    }

    @Override // android.widget.ImageView
    public void setImageLevel(int i3) {
        super.setImageLevel(i3);
        this.f4152d = true;
    }

    @Override // android.widget.ImageView
    public void setImageResource(int i3) {
        this.f4151c.i(i3);
    }

    @Override // android.widget.ImageView
    public void setImageURI(Uri uri) {
        super.setImageURI(uri);
        C0243q c0243q = this.f4151c;
        if (c0243q != null) {
            c0243q.c();
        }
    }

    public void setSupportBackgroundTintList(ColorStateList colorStateList) {
        C0231e c0231e = this.f4150b;
        if (c0231e != null) {
            c0231e.i(colorStateList);
        }
    }

    public void setSupportBackgroundTintMode(PorterDuff.Mode mode) {
        C0231e c0231e = this.f4150b;
        if (c0231e != null) {
            c0231e.j(mode);
        }
    }

    public void setSupportImageTintList(ColorStateList colorStateList) {
        C0243q c0243q = this.f4151c;
        if (c0243q != null) {
            c0243q.j(colorStateList);
        }
    }

    public void setSupportImageTintMode(PorterDuff.Mode mode) {
        C0243q c0243q = this.f4151c;
        if (c0243q != null) {
            c0243q.k(mode);
        }
    }

    public C0242p(Context context, AttributeSet attributeSet, int i3) {
        super(d0.b(context), attributeSet, i3);
        this.f4152d = false;
        c0.a(this, getContext());
        C0231e c0231e = new C0231e(this);
        this.f4150b = c0231e;
        c0231e.e(attributeSet, i3);
        C0243q c0243q = new C0243q(this);
        this.f4151c = c0243q;
        c0243q.g(attributeSet, i3);
    }
}
