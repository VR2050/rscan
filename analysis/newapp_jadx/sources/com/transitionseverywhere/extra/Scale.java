package com.transitionseverywhere.extra;

import android.animation.Animator;
import android.animation.ObjectAnimator;
import android.util.Property;
import android.view.View;
import android.view.ViewGroup;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.transition.Transition;
import androidx.transition.TransitionListenerAdapter;
import androidx.transition.TransitionValues;
import androidx.transition.Visibility;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

/* loaded from: classes2.dex */
public class Scale extends Visibility {

    /* renamed from: com.transitionseverywhere.extra.Scale$a */
    public class C4154a extends TransitionListenerAdapter {

        /* renamed from: c */
        public final /* synthetic */ View f10888c;

        /* renamed from: e */
        public final /* synthetic */ float f10889e;

        /* renamed from: f */
        public final /* synthetic */ float f10890f;

        public C4154a(Scale scale, View view, float f2, float f3) {
            this.f10888c = view;
            this.f10889e = f2;
            this.f10890f = f3;
        }

        @Override // androidx.transition.TransitionListenerAdapter, androidx.transition.Transition.TransitionListener
        public void onTransitionEnd(@NonNull Transition transition) {
            this.f10888c.setScaleX(this.f10889e);
            this.f10888c.setScaleY(this.f10890f);
            transition.removeListener(this);
        }
    }

    @Nullable
    /* renamed from: a */
    public final Animator m4744a(@NonNull View view, float f2, float f3, @Nullable TransitionValues transitionValues) {
        float scaleX = view.getScaleX();
        float scaleY = view.getScaleY();
        float f4 = scaleX * f2;
        float f5 = scaleX * f3;
        float f6 = f2 * scaleY;
        float f7 = f3 * scaleY;
        if (transitionValues != null) {
            Float f8 = (Float) transitionValues.values.get("scale:scaleX");
            Float f9 = (Float) transitionValues.values.get("scale:scaleY");
            if (f8 != null && f8.floatValue() != scaleX) {
                f4 = f8.floatValue();
            }
            if (f9 != null && f9.floatValue() != scaleY) {
                f6 = f9.floatValue();
            }
        }
        view.setScaleX(f4);
        view.setScaleY(f6);
        Animator m2458b1 = C2354n.m2458b1(ObjectAnimator.ofFloat(view, (Property<View, Float>) View.SCALE_X, f4, f5), ObjectAnimator.ofFloat(view, (Property<View, Float>) View.SCALE_Y, f6, f7));
        addListener(new C4154a(this, view, scaleX, scaleY));
        return m2458b1;
    }

    @Override // androidx.transition.Visibility, androidx.transition.Transition
    public void captureStartValues(@NonNull TransitionValues transitionValues) {
        super.captureStartValues(transitionValues);
        transitionValues.values.put("scale:scaleX", Float.valueOf(transitionValues.view.getScaleX()));
        transitionValues.values.put("scale:scaleY", Float.valueOf(transitionValues.view.getScaleY()));
    }

    @Override // androidx.transition.Visibility
    @Nullable
    public Animator onAppear(@NonNull ViewGroup viewGroup, @NonNull View view, @Nullable TransitionValues transitionValues, @Nullable TransitionValues transitionValues2) {
        return m4744a(view, 0.0f, 1.0f, transitionValues);
    }

    @Override // androidx.transition.Visibility
    public Animator onDisappear(@NonNull ViewGroup viewGroup, @NonNull View view, @Nullable TransitionValues transitionValues, @Nullable TransitionValues transitionValues2) {
        return m4744a(view, 1.0f, 0.0f, transitionValues);
    }
}
