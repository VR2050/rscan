package com.noober.background.drawable;

import android.R;
import android.content.res.TypedArray;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.StateListDrawable;
import androidx.annotation.AttrRes;
import androidx.annotation.StyleableRes;
import com.noober.background.C4028R;

/* loaded from: classes2.dex */
public class SelectorPre21DrawableCreator implements ICreateDrawable {
    private TypedArray typedArray;

    public SelectorPre21DrawableCreator(TypedArray typedArray) {
        this.typedArray = typedArray;
    }

    private void setSelectorDrawable(StateListDrawable stateListDrawable, @StyleableRes int i2, @StyleableRes int i3, @AttrRes int i4) {
        if (this.typedArray.hasValue(i2) || this.typedArray.hasValue(i3)) {
            GradientDrawable drawable = DrawableFactory.getDrawable(this.typedArray);
            if (this.typedArray.hasValue(i2)) {
                drawable.setColor(this.typedArray.getColor(i2, 0));
            }
            if (this.typedArray.hasValue(i3)) {
                drawable.setStroke(this.typedArray.getDimensionPixelSize(C4028R.styleable.background_bl_stroke_width, 0), this.typedArray.getColor(i3, 0), this.typedArray.getDimension(C4028R.styleable.background_bl_stroke_dashWidth, 0.0f), this.typedArray.getDimension(C4028R.styleable.background_bl_stroke_dashGap, 0.0f));
            }
            stateListDrawable.addState(new int[]{i4}, drawable);
        }
    }

    @Override // com.noober.background.drawable.ICreateDrawable
    public StateListDrawable create() {
        StateListDrawable stateListDrawable = new StateListDrawable();
        setSelectorDrawable(stateListDrawable, C4028R.styleable.background_bl_checkable_solid_color, C4028R.styleable.background_bl_checkable_stroke_color, R.attr.state_checkable);
        setSelectorDrawable(stateListDrawable, C4028R.styleable.background_bl_unCheckable_solid_color, C4028R.styleable.background_bl_unCheckable_stroke_color, -16842911);
        setSelectorDrawable(stateListDrawable, C4028R.styleable.background_bl_checked_solid_color, C4028R.styleable.background_bl_checked_stroke_color, R.attr.state_checked);
        setSelectorDrawable(stateListDrawable, C4028R.styleable.background_bl_unChecked_solid_color, C4028R.styleable.background_bl_unChecked_stroke_color, -16842912);
        setSelectorDrawable(stateListDrawable, C4028R.styleable.background_bl_enabled_solid_color, C4028R.styleable.background_bl_enabled_stroke_color, R.attr.state_enabled);
        setSelectorDrawable(stateListDrawable, C4028R.styleable.background_bl_unEnabled_solid_color, C4028R.styleable.background_bl_unEnabled_stroke_color, -16842910);
        setSelectorDrawable(stateListDrawable, C4028R.styleable.background_bl_selected_solid_color, C4028R.styleable.background_bl_selected_stroke_color, R.attr.state_selected);
        setSelectorDrawable(stateListDrawable, C4028R.styleable.background_bl_unSelected_solid_color, C4028R.styleable.background_bl_unSelected_stroke_color, -16842913);
        setSelectorDrawable(stateListDrawable, C4028R.styleable.background_bl_pressed_solid_color, C4028R.styleable.background_bl_pressed_stroke_color, R.attr.state_pressed);
        setSelectorDrawable(stateListDrawable, C4028R.styleable.background_bl_unPressed_solid_color, C4028R.styleable.background_bl_unPressed_stroke_color, -16842919);
        setSelectorDrawable(stateListDrawable, C4028R.styleable.background_bl_focused_solid_color, C4028R.styleable.background_bl_focused_stroke_color, R.attr.state_focused);
        setSelectorDrawable(stateListDrawable, C4028R.styleable.background_bl_unFocused_solid_color, C4028R.styleable.background_bl_unFocused_stroke_color, -16842908);
        return stateListDrawable;
    }
}
