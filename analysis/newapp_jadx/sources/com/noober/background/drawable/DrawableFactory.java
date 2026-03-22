package com.noober.background.drawable;

import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.TypedArray;
import android.graphics.drawable.AnimationDrawable;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.StateListDrawable;

/* loaded from: classes2.dex */
public class DrawableFactory {
    public static AnimationDrawable getAnimationDrawable(TypedArray typedArray) {
        return new AnimationDrawableCreator(typedArray).create();
    }

    public static StateListDrawable getButtonDrawable(TypedArray typedArray, TypedArray typedArray2) {
        return new ButtonDrawableCreator(typedArray, typedArray2).create();
    }

    public static GradientDrawable getDrawable(TypedArray typedArray) {
        return new GradientDrawableCreator(typedArray).create();
    }

    public static StateListDrawable getMultiSelectorDrawable(Context context, TypedArray typedArray, TypedArray typedArray2) {
        return new MultiSelectorDrawableCreator(context, typedArray, typedArray2).create();
    }

    public static ColorStateList getMultiTextColorSelectorColorCreator(Context context, TypedArray typedArray) {
        return new MultiTextColorSelectorColorCreator(context, typedArray).create();
    }

    public static StateListDrawable getPressDrawable(GradientDrawable gradientDrawable, TypedArray typedArray, TypedArray typedArray2) {
        return new PressDrawableCreator(gradientDrawable, typedArray, typedArray2).create();
    }

    public static StateListDrawable getSelectorDrawable(TypedArray typedArray, TypedArray typedArray2) {
        return new SelectorDrawableCreator(typedArray, typedArray2).create();
    }

    public static StateListDrawable getSelectorPre21Drawable(TypedArray typedArray) {
        return new SelectorPre21DrawableCreator(typedArray).create();
    }

    public static ColorStateList getTextSelectorColor(TypedArray typedArray) {
        return new ColorStateCreator(typedArray).create();
    }
}
