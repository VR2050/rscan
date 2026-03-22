package com.transitionseverywhere;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.ValueAnimator;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.transition.Transition;
import androidx.transition.TransitionListenerAdapter;
import androidx.transition.TransitionValues;
import java.util.Map;
import java.util.Objects;

/* loaded from: classes2.dex */
public class ChangeText extends Transition {

    /* renamed from: c */
    public static final String[] f10861c = {"android:textchange:text", "android:textchange:textSelectionStart", "android:textchange:textSelectionEnd"};

    /* renamed from: com.transitionseverywhere.ChangeText$a */
    public class C4148a extends AnimatorListenerAdapter {

        /* renamed from: c */
        public final /* synthetic */ CharSequence f10862c;

        /* renamed from: e */
        public final /* synthetic */ TextView f10863e;

        /* renamed from: f */
        public final /* synthetic */ CharSequence f10864f;

        /* renamed from: g */
        public final /* synthetic */ int f10865g;

        /* renamed from: h */
        public final /* synthetic */ int f10866h;

        public C4148a(CharSequence charSequence, TextView textView, CharSequence charSequence2, int i2, int i3) {
            this.f10862c = charSequence;
            this.f10863e = textView;
            this.f10864f = charSequence2;
            this.f10865g = i2;
            this.f10866h = i3;
        }

        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
        public void onAnimationEnd(Animator animator) {
            if (this.f10862c.equals(this.f10863e.getText())) {
                this.f10863e.setText(this.f10864f);
                TextView textView = this.f10863e;
                if (textView instanceof EditText) {
                    ChangeText.m4743a(ChangeText.this, (EditText) textView, this.f10865g, this.f10866h);
                }
            }
        }
    }

    /* renamed from: com.transitionseverywhere.ChangeText$b */
    public class C4149b extends TransitionListenerAdapter {

        /* renamed from: c */
        public final /* synthetic */ TextView f10868c;

        /* renamed from: e */
        public final /* synthetic */ CharSequence f10869e;

        /* renamed from: f */
        public final /* synthetic */ int f10870f;

        /* renamed from: g */
        public final /* synthetic */ int f10871g;

        /* renamed from: h */
        public final /* synthetic */ CharSequence f10872h;

        /* renamed from: i */
        public final /* synthetic */ int f10873i;

        /* renamed from: j */
        public final /* synthetic */ int f10874j;

        public C4149b(TextView textView, CharSequence charSequence, int i2, int i3, int i4, CharSequence charSequence2, int i5, int i6) {
            this.f10868c = textView;
            this.f10869e = charSequence;
            this.f10870f = i2;
            this.f10871g = i3;
            this.f10872h = charSequence2;
            this.f10873i = i5;
            this.f10874j = i6;
        }

        @Override // androidx.transition.TransitionListenerAdapter, androidx.transition.Transition.TransitionListener
        public void onTransitionEnd(@NonNull Transition transition) {
            transition.removeListener(this);
        }

        @Override // androidx.transition.TransitionListenerAdapter, androidx.transition.Transition.TransitionListener
        public void onTransitionPause(@NonNull Transition transition) {
            ChangeText changeText = ChangeText.this;
            String[] strArr = ChangeText.f10861c;
            Objects.requireNonNull(changeText);
            this.f10868c.setText(this.f10869e);
            TextView textView = this.f10868c;
            if (textView instanceof EditText) {
                ChangeText.m4743a(ChangeText.this, (EditText) textView, this.f10870f, this.f10871g);
            }
            Objects.requireNonNull(ChangeText.this);
        }

        @Override // androidx.transition.TransitionListenerAdapter, androidx.transition.Transition.TransitionListener
        public void onTransitionResume(@NonNull Transition transition) {
            ChangeText changeText = ChangeText.this;
            String[] strArr = ChangeText.f10861c;
            Objects.requireNonNull(changeText);
            this.f10868c.setText(this.f10872h);
            TextView textView = this.f10868c;
            if (textView instanceof EditText) {
                ChangeText.m4743a(ChangeText.this, (EditText) textView, this.f10873i, this.f10874j);
            }
            Objects.requireNonNull(ChangeText.this);
        }
    }

    /* renamed from: a */
    public static void m4743a(ChangeText changeText, EditText editText, int i2, int i3) {
        Objects.requireNonNull(changeText);
        if (i2 < 0 || i3 < 0) {
            return;
        }
        editText.setSelection(i2, i3);
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
        View view = transitionValues.view;
        if (view instanceof TextView) {
            TextView textView = (TextView) view;
            transitionValues.values.put("android:textchange:text", textView.getText());
            if (textView instanceof EditText) {
                transitionValues.values.put("android:textchange:textSelectionStart", Integer.valueOf(textView.getSelectionStart()));
                transitionValues.values.put("android:textchange:textSelectionEnd", Integer.valueOf(textView.getSelectionEnd()));
            }
        }
    }

    @Override // androidx.transition.Transition
    @Nullable
    public Animator createAnimator(@NonNull ViewGroup viewGroup, @Nullable TransitionValues transitionValues, @Nullable TransitionValues transitionValues2) {
        int i2;
        int i3;
        int i4;
        int i5;
        if (transitionValues != null && transitionValues2 != null && (transitionValues.view instanceof TextView)) {
            View view = transitionValues2.view;
            if (view instanceof TextView) {
                TextView textView = (TextView) view;
                Map<String, Object> map = transitionValues.values;
                Map<String, Object> map2 = transitionValues2.values;
                String str = map.get("android:textchange:text") != null ? (CharSequence) map.get("android:textchange:text") : "";
                String str2 = map2.get("android:textchange:text") != null ? (CharSequence) map2.get("android:textchange:text") : "";
                if (textView instanceof EditText) {
                    int intValue = map.get("android:textchange:textSelectionStart") != null ? ((Integer) map.get("android:textchange:textSelectionStart")).intValue() : -1;
                    int intValue2 = map.get("android:textchange:textSelectionEnd") != null ? ((Integer) map.get("android:textchange:textSelectionEnd")).intValue() : intValue;
                    int intValue3 = map2.get("android:textchange:textSelectionStart") != null ? ((Integer) map2.get("android:textchange:textSelectionStart")).intValue() : -1;
                    i3 = map2.get("android:textchange:textSelectionEnd") != null ? ((Integer) map2.get("android:textchange:textSelectionEnd")).intValue() : intValue3;
                    i5 = intValue2;
                    i2 = intValue3;
                    i4 = intValue;
                } else {
                    i2 = -1;
                    i3 = -1;
                    i4 = -1;
                    i5 = -1;
                }
                if (str.equals(str2)) {
                    return null;
                }
                textView.setText(str);
                if (textView instanceof EditText) {
                    EditText editText = (EditText) textView;
                    if (i4 >= 0 && i5 >= 0) {
                        editText.setSelection(i4, i5);
                    }
                }
                ValueAnimator ofFloat = ValueAnimator.ofFloat(0.0f, 1.0f);
                ofFloat.addListener(new C4148a(str, textView, str2, i2, i3));
                addListener(new C4149b(textView, str2, i2, i3, 0, str, i4, i5));
                return ofFloat;
            }
        }
        return null;
    }

    @Override // androidx.transition.Transition
    @Nullable
    public String[] getTransitionProperties() {
        return f10861c;
    }
}
