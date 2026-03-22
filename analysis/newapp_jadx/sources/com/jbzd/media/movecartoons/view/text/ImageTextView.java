package com.jbzd.media.movecartoons.view.text;

import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.drawable.Drawable;
import android.util.AttributeSet;
import androidx.annotation.Nullable;
import androidx.appcompat.widget.AppCompatTextView;
import com.jbzd.media.movecartoons.R$styleable;

/* loaded from: classes2.dex */
public class ImageTextView extends AppCompatTextView {
    private static final int DIRECTION_HEIGHT = 1;
    private static final int DIRECTION_WIDTH = 0;
    private static final String TAG = ImageTextView.class.getSimpleName();
    private float drawableHeight;
    private float drawableWidth;

    public ImageTextView(Context context) {
        this(context, null);
    }

    private int getSize(Drawable drawable, int i2) {
        float f2 = this.drawableWidth;
        if (f2 > 0.0f) {
            float f3 = this.drawableHeight;
            if (f3 > 0.0f) {
                return i2 == 0 ? (int) f2 : (int) f3;
            }
        }
        return i2 == 0 ? drawable.getIntrinsicWidth() : drawable.getIntrinsicHeight();
    }

    @Override // androidx.appcompat.widget.AppCompatTextView, android.widget.TextView
    public void setCompoundDrawablesWithIntrinsicBounds(@Nullable Drawable drawable, @Nullable Drawable drawable2, @Nullable Drawable drawable3, @Nullable Drawable drawable4) {
        if (drawable != null) {
            drawable.setBounds(0, 0, getSize(drawable, 0), getSize(drawable, 1));
        }
        if (drawable3 != null) {
            drawable3.setBounds(0, 0, getSize(drawable3, 0), getSize(drawable3, 1));
        }
        if (drawable2 != null) {
            drawable2.setBounds(0, 0, getSize(drawable2, 0), getSize(drawable2, 1));
        }
        if (drawable4 != null) {
            drawable4.setBounds(0, 0, getSize(drawable4, 0), getSize(drawable4, 1));
        }
        setCompoundDrawables(drawable, drawable2, drawable3, drawable4);
    }

    public ImageTextView(Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 0);
    }

    public ImageTextView(Context context, @Nullable AttributeSet attributeSet, int i2) {
        super(context, attributeSet, i2);
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, R$styleable.ImageTextView);
        this.drawableWidth = obtainStyledAttributes.getDimension(1, 0.0f);
        this.drawableHeight = obtainStyledAttributes.getDimension(0, 0.0f);
        obtainStyledAttributes.recycle();
        if (this.drawableWidth <= 0.0f || this.drawableHeight <= 0.0f) {
            return;
        }
        Drawable[] compoundDrawables = getCompoundDrawables();
        setCompoundDrawablesWithIntrinsicBounds(compoundDrawables[0], compoundDrawables[1], compoundDrawables[2], compoundDrawables[3]);
    }
}
