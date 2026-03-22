package com.transitionseverywhere.extra;

import android.animation.Animator;
import android.animation.ObjectAnimator;
import android.animation.TypeConverter;
import android.annotation.TargetApi;
import android.graphics.PointF;
import android.util.Property;
import android.view.View;
import android.view.ViewGroup;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.transition.Transition;
import androidx.transition.TransitionValues;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@TargetApi(14)
/* loaded from: classes2.dex */
public class Translation extends Transition {

    /* renamed from: c */
    @Nullable
    public static final Property<View, PointF> f10891c = new C4155a(PointF.class, "translation");

    /* renamed from: com.transitionseverywhere.extra.Translation$a */
    public static class C4155a extends Property<View, PointF> {
        public C4155a(Class cls, String str) {
            super(cls, str);
        }

        @Override // android.util.Property
        public PointF get(@NonNull View view) {
            View view2 = view;
            return new PointF(view2.getTranslationX(), view2.getTranslationY());
        }

        @Override // android.util.Property
        public void set(@NonNull View view, @NonNull PointF pointF) {
            View view2 = view;
            PointF pointF2 = pointF;
            view2.setTranslationX(pointF2.x);
            view2.setTranslationY(pointF2.y);
        }
    }

    @Override // androidx.transition.Transition
    public void captureEndValues(@NonNull TransitionValues transitionValues) {
        captureValues(transitionValues);
    }

    @Override // androidx.transition.Transition
    public void captureStartValues(@NonNull TransitionValues transitionValues) {
        captureValues(transitionValues);
    }

    public final void captureValues(@NonNull TransitionValues transitionValues) {
        transitionValues.values.put("Translation:translationX", Float.valueOf(transitionValues.view.getTranslationX()));
        transitionValues.values.put("Translation:translationY", Float.valueOf(transitionValues.view.getTranslationY()));
    }

    @Override // androidx.transition.Transition
    @Nullable
    public Animator createAnimator(@NonNull ViewGroup viewGroup, @Nullable TransitionValues transitionValues, @Nullable TransitionValues transitionValues2) {
        if (transitionValues == null || transitionValues2 == null) {
            return null;
        }
        float floatValue = ((Float) transitionValues.values.get("Translation:translationX")).floatValue();
        float floatValue2 = ((Float) transitionValues.values.get("Translation:translationY")).floatValue();
        float floatValue3 = ((Float) transitionValues2.values.get("Translation:translationX")).floatValue();
        float floatValue4 = ((Float) transitionValues2.values.get("Translation:translationY")).floatValue();
        transitionValues2.view.setTranslationX(floatValue);
        transitionValues2.view.setTranslationY(floatValue2);
        Property<View, PointF> property = f10891c;
        if (property != null) {
            return ObjectAnimator.ofObject(transitionValues2.view, (Property<View, V>) property, (TypeConverter) null, getPathMotion().getPath(floatValue, floatValue2, floatValue3, floatValue4));
        }
        return C2354n.m2458b1(floatValue == floatValue3 ? null : ObjectAnimator.ofFloat(transitionValues2.view, (Property<View, Float>) View.TRANSLATION_X, floatValue, floatValue3), floatValue2 != floatValue4 ? ObjectAnimator.ofFloat(transitionValues2.view, (Property<View, Float>) View.TRANSLATION_Y, floatValue2, floatValue4) : null);
    }
}
