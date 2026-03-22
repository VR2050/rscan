package com.transitionseverywhere;

import android.graphics.drawable.ColorDrawable;
import android.util.Property;
import android.view.View;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.transition.Transition;
import androidx.transition.TransitionValues;
import p005b.p065a0.p066a.AbstractC1277b;
import p005b.p065a0.p066a.C1276a;

/* loaded from: classes2.dex */
public class Recolor extends Transition {

    /* renamed from: c */
    @NonNull
    public static final Property<TextView, Integer> f10886c = new C1276a(new C4152a(), null);

    /* renamed from: e */
    @NonNull
    public static final Property<ColorDrawable, Integer> f10887e = new C1276a(new C4153b(), null);

    /* renamed from: com.transitionseverywhere.Recolor$a */
    public static class C4152a extends AbstractC1277b<TextView> {
        @Override // p005b.p065a0.p066a.AbstractC1277b
        @NonNull
        /* renamed from: a */
        public Integer mo303a(TextView textView) {
            return 0;
        }

        @Override // p005b.p065a0.p066a.AbstractC1277b
        /* renamed from: b */
        public void mo304b(@NonNull TextView textView, int i2) {
            textView.setTextColor(i2);
        }

        @Override // android.util.Property
        @NonNull
        public Integer get(Object obj) {
            return 0;
        }
    }

    /* renamed from: com.transitionseverywhere.Recolor$b */
    public static class C4153b extends AbstractC1277b<ColorDrawable> {
        @Override // p005b.p065a0.p066a.AbstractC1277b
        @NonNull
        /* renamed from: a */
        public Integer mo303a(@NonNull ColorDrawable colorDrawable) {
            return Integer.valueOf(colorDrawable.getColor());
        }

        @Override // p005b.p065a0.p066a.AbstractC1277b
        /* renamed from: b */
        public void mo304b(@NonNull ColorDrawable colorDrawable, int i2) {
            colorDrawable.setColor(i2);
        }

        @Override // android.util.Property
        @NonNull
        public Integer get(@NonNull Object obj) {
            return Integer.valueOf(((ColorDrawable) obj).getColor());
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

    public final void captureValues(TransitionValues transitionValues) {
        transitionValues.values.put("android:recolor:background", transitionValues.view.getBackground());
        View view = transitionValues.view;
        if (view instanceof TextView) {
            transitionValues.values.put("android:recolor:textColor", Integer.valueOf(((TextView) view).getCurrentTextColor()));
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:13:0x0063  */
    @Override // androidx.transition.Transition
    @androidx.annotation.Nullable
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public android.animation.Animator createAnimator(@androidx.annotation.NonNull android.view.ViewGroup r10, @androidx.annotation.Nullable androidx.transition.TransitionValues r11, @androidx.annotation.Nullable androidx.transition.TransitionValues r12) {
        /*
            r9 = this;
            r10 = 0
            if (r11 == 0) goto L9c
            if (r12 != 0) goto L7
            goto L9c
        L7:
            android.view.View r0 = r12.view
            java.util.Map<java.lang.String, java.lang.Object> r1 = r11.values
            java.lang.String r2 = "android:recolor:background"
            java.lang.Object r1 = r1.get(r2)
            android.graphics.drawable.Drawable r1 = (android.graphics.drawable.Drawable) r1
            java.util.Map<java.lang.String, java.lang.Object> r3 = r12.values
            java.lang.Object r2 = r3.get(r2)
            android.graphics.drawable.Drawable r2 = (android.graphics.drawable.Drawable) r2
            boolean r3 = r1 instanceof android.graphics.drawable.ColorDrawable
            r4 = 1
            r5 = 0
            r6 = 2
            if (r3 == 0) goto L5e
            boolean r3 = r2 instanceof android.graphics.drawable.ColorDrawable
            if (r3 == 0) goto L5e
            android.graphics.drawable.ColorDrawable r1 = (android.graphics.drawable.ColorDrawable) r1
            android.graphics.drawable.ColorDrawable r2 = (android.graphics.drawable.ColorDrawable) r2
            int r3 = r1.getColor()
            int r7 = r2.getColor()
            if (r3 == r7) goto L5e
            int r3 = r2.getColor()
            android.graphics.drawable.Drawable r2 = r2.mutate()
            android.graphics.drawable.ColorDrawable r2 = (android.graphics.drawable.ColorDrawable) r2
            int r7 = r1.getColor()
            r2.setColor(r7)
            android.util.Property<android.graphics.drawable.ColorDrawable, java.lang.Integer> r7 = com.transitionseverywhere.Recolor.f10887e
            int[] r8 = new int[r6]
            int r1 = r1.getColor()
            r8[r5] = r1
            r8[r4] = r3
            android.animation.ObjectAnimator r1 = android.animation.ObjectAnimator.ofInt(r2, r7, r8)
            android.animation.ArgbEvaluator r2 = new android.animation.ArgbEvaluator
            r2.<init>()
            r1.setEvaluator(r2)
            goto L5f
        L5e:
            r1 = r10
        L5f:
            boolean r2 = r0 instanceof android.widget.TextView
            if (r2 == 0) goto L98
            android.widget.TextView r0 = (android.widget.TextView) r0
            java.util.Map<java.lang.String, java.lang.Object> r11 = r11.values
            java.lang.String r2 = "android:recolor:textColor"
            java.lang.Object r11 = r11.get(r2)
            java.lang.Integer r11 = (java.lang.Integer) r11
            int r11 = r11.intValue()
            java.util.Map<java.lang.String, java.lang.Object> r12 = r12.values
            java.lang.Object r12 = r12.get(r2)
            java.lang.Integer r12 = (java.lang.Integer) r12
            int r12 = r12.intValue()
            if (r11 == r12) goto L98
            r0.setTextColor(r12)
            android.util.Property<android.widget.TextView, java.lang.Integer> r10 = com.transitionseverywhere.Recolor.f10886c
            int[] r2 = new int[r6]
            r2[r5] = r11
            r2[r4] = r12
            android.animation.ObjectAnimator r10 = android.animation.ObjectAnimator.ofInt(r0, r10, r2)
            android.animation.ArgbEvaluator r11 = new android.animation.ArgbEvaluator
            r11.<init>()
            r10.setEvaluator(r11)
        L98:
            android.animation.Animator r10 = p005b.p199l.p200a.p201a.p250p1.C2354n.m2458b1(r1, r10)
        L9c:
            return r10
        */
        throw new UnsupportedOperationException("Method not decompiled: com.transitionseverywhere.Recolor.createAnimator(android.view.ViewGroup, androidx.transition.TransitionValues, androidx.transition.TransitionValues):android.animation.Animator");
    }
}
