package com.noober.background.drawable;

import android.R;
import android.content.res.TypedArray;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.StateListDrawable;
import androidx.annotation.AttrRes;
import com.noober.background.C4028R;

/* loaded from: classes2.dex */
public class ButtonDrawableCreator implements ICreateDrawable {
    private TypedArray buttonTa;
    private TypedArray typedArray;

    public ButtonDrawableCreator(TypedArray typedArray, TypedArray typedArray2) {
        this.typedArray = typedArray;
        this.buttonTa = typedArray2;
    }

    private void setSelectorDrawable(TypedArray typedArray, TypedArray typedArray2, StateListDrawable stateListDrawable, int i2, @AttrRes int i3) {
        int i4;
        Drawable drawable;
        try {
            i4 = typedArray2.getColor(i2, 0);
            if (i4 == 0) {
                try {
                    drawable = typedArray2.getDrawable(i2);
                } catch (Exception unused) {
                    drawable = typedArray2.getDrawable(i2);
                    if (drawable == null) {
                    }
                    stateListDrawable.addState(new int[]{i3}, drawable);
                    return;
                }
            } else {
                drawable = null;
            }
        } catch (Exception unused2) {
            i4 = 0;
        }
        if (drawable == null || i4 == 0) {
            stateListDrawable.addState(new int[]{i3}, drawable);
            return;
        }
        GradientDrawable drawable2 = DrawableFactory.getDrawable(typedArray);
        drawable2.setColor(i4);
        stateListDrawable.addState(new int[]{i3}, drawable2);
    }

    @Override // com.noober.background.drawable.ICreateDrawable
    public StateListDrawable create() {
        StateListDrawable stateListDrawable = new StateListDrawable();
        for (int i2 = 0; i2 < this.buttonTa.getIndexCount(); i2++) {
            int index = this.buttonTa.getIndex(i2);
            if (index == C4028R.styleable.background_button_drawable_bl_checked_button_drawable) {
                setSelectorDrawable(this.typedArray, this.buttonTa, stateListDrawable, index, R.attr.state_checked);
            } else if (index == C4028R.styleable.background_button_drawable_bl_unChecked_button_drawable) {
                setSelectorDrawable(this.typedArray, this.buttonTa, stateListDrawable, index, -16842912);
            }
        }
        return stateListDrawable;
    }
}
