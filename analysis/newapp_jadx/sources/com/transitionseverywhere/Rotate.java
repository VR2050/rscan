package com.transitionseverywhere;

import android.animation.Animator;
import android.animation.ObjectAnimator;
import android.util.Property;
import android.view.View;
import android.view.ViewGroup;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.transition.Transition;
import androidx.transition.TransitionValues;

/* loaded from: classes2.dex */
public class Rotate extends Transition {
    @Override // androidx.transition.Transition
    public void captureEndValues(@NonNull TransitionValues transitionValues) {
        transitionValues.values.put("android:rotate:rotation", Float.valueOf(transitionValues.view.getRotation()));
    }

    @Override // androidx.transition.Transition
    public void captureStartValues(@NonNull TransitionValues transitionValues) {
        transitionValues.values.put("android:rotate:rotation", Float.valueOf(transitionValues.view.getRotation()));
    }

    @Override // androidx.transition.Transition
    @Nullable
    public Animator createAnimator(@NonNull ViewGroup viewGroup, @Nullable TransitionValues transitionValues, @Nullable TransitionValues transitionValues2) {
        if (transitionValues == null || transitionValues2 == null) {
            return null;
        }
        View view = transitionValues2.view;
        float floatValue = ((Float) transitionValues.values.get("android:rotate:rotation")).floatValue();
        float floatValue2 = ((Float) transitionValues2.values.get("android:rotate:rotation")).floatValue();
        if (floatValue == floatValue2) {
            return null;
        }
        view.setRotation(floatValue);
        return ObjectAnimator.ofFloat(view, (Property<View, Float>) View.ROTATION, floatValue, floatValue2);
    }
}
