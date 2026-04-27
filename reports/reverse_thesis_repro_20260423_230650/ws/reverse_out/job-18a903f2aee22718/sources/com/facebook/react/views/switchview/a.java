package com.facebook.react.views.switchview;

import android.R;
import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.RippleDrawable;
import androidx.appcompat.widget.b0;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class a extends b0 {

    /* JADX INFO: renamed from: V, reason: collision with root package name */
    private boolean f8036V;

    /* JADX INFO: renamed from: W, reason: collision with root package name */
    private Integer f8037W;

    /* JADX INFO: renamed from: a0, reason: collision with root package name */
    private Integer f8038a0;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(Context context) {
        super(context);
        j.f(context, "context");
        this.f8036V = true;
    }

    private final ColorStateList r(int i3) {
        return new ColorStateList(new int[][]{new int[]{R.attr.state_pressed}}, new int[]{i3});
    }

    public final void s(Drawable drawable, Integer num) {
        j.f(drawable, "drawable");
        if (num == null) {
            drawable.clearColorFilter();
        } else {
            drawable.setColorFilter(new PorterDuffColorFilter(num.intValue(), PorterDuff.Mode.MULTIPLY));
        }
    }

    @Override // android.view.View
    public void setBackgroundColor(int i3) {
        setBackground(new RippleDrawable(r(i3), new ColorDrawable(i3), null));
    }

    @Override // androidx.appcompat.widget.b0, android.widget.CompoundButton, android.widget.Checkable
    public void setChecked(boolean z3) {
        if (!this.f8036V || isChecked() == z3) {
            super.setChecked(isChecked());
            return;
        }
        this.f8036V = false;
        super.setChecked(z3);
        setTrackColor(z3);
    }

    public final void setOn(boolean z3) {
        if (isChecked() != z3) {
            super.setChecked(z3);
            setTrackColor(z3);
        }
        this.f8036V = true;
    }

    public final void setThumbColor(Integer num) {
        Drawable thumbDrawable = super.getThumbDrawable();
        j.e(thumbDrawable, "getThumbDrawable(...)");
        s(thumbDrawable, num);
        if (num == null || !(super.getBackground() instanceof RippleDrawable)) {
            return;
        }
        ColorStateList colorStateListR = r(num.intValue());
        Drawable background = super.getBackground();
        j.d(background, "null cannot be cast to non-null type android.graphics.drawable.RippleDrawable");
        ((RippleDrawable) background).setColor(colorStateListR);
    }

    public final void setTrackColor(Integer num) {
        Drawable trackDrawable = super.getTrackDrawable();
        j.e(trackDrawable, "getTrackDrawable(...)");
        s(trackDrawable, num);
    }

    public final void setTrackColorForFalse(Integer num) {
        if (j.b(num, this.f8037W)) {
            return;
        }
        this.f8037W = num;
        if (isChecked()) {
            return;
        }
        setTrackColor(this.f8037W);
    }

    public final void setTrackColorForTrue(Integer num) {
        if (j.b(num, this.f8038a0)) {
            return;
        }
        this.f8038a0 = num;
        if (isChecked()) {
            setTrackColor(this.f8038a0);
        }
    }

    private final void setTrackColor(boolean z3) {
        Integer num = this.f8038a0;
        if (num == null && this.f8037W == null) {
            return;
        }
        if (!z3) {
            num = this.f8037W;
        }
        setTrackColor(num);
    }
}
