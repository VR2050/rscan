package com.transitionseverywhere;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.animation.RectEvaluator;
import android.animation.ValueAnimator;
import android.annotation.TargetApi;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Rect;
import android.graphics.drawable.BitmapDrawable;
import android.util.Property;
import android.view.TextureView;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewOverlay;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.constraintlayout.motion.widget.Key;
import androidx.transition.Transition;
import androidx.transition.TransitionValues;
import java.util.Map;

@TargetApi(18)
/* loaded from: classes2.dex */
public class Crossfade extends Transition {

    /* renamed from: c */
    public static RectEvaluator f10876c;

    /* renamed from: e */
    public int f10877e = 1;

    /* renamed from: f */
    public int f10878f = 1;

    /* renamed from: com.transitionseverywhere.Crossfade$a */
    public class C4150a implements ValueAnimator.AnimatorUpdateListener {

        /* renamed from: c */
        public final /* synthetic */ View f10879c;

        /* renamed from: e */
        public final /* synthetic */ BitmapDrawable f10880e;

        public C4150a(Crossfade crossfade, View view, BitmapDrawable bitmapDrawable) {
            this.f10879c = view;
            this.f10880e = bitmapDrawable;
        }

        @Override // android.animation.ValueAnimator.AnimatorUpdateListener
        public void onAnimationUpdate(ValueAnimator valueAnimator) {
            this.f10879c.invalidate(this.f10880e.getBounds());
        }
    }

    /* renamed from: com.transitionseverywhere.Crossfade$b */
    public class C4151b extends AnimatorListenerAdapter {

        /* renamed from: c */
        public final /* synthetic */ boolean f10881c;

        /* renamed from: e */
        public final /* synthetic */ View f10882e;

        /* renamed from: f */
        public final /* synthetic */ BitmapDrawable f10883f;

        /* renamed from: g */
        public final /* synthetic */ BitmapDrawable f10884g;

        public C4151b(boolean z, View view, BitmapDrawable bitmapDrawable, BitmapDrawable bitmapDrawable2) {
            this.f10881c = z;
            this.f10882e = view;
            this.f10883f = bitmapDrawable;
            this.f10884g = bitmapDrawable2;
        }

        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
        public void onAnimationEnd(Animator animator) {
            ViewOverlay overlay = this.f10881c ? ((ViewGroup) this.f10882e.getParent()).getOverlay() : this.f10882e.getOverlay();
            overlay.remove(this.f10883f);
            if (Crossfade.this.f10877e == 1) {
                overlay.remove(this.f10884g);
            }
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
        View view = transitionValues.view;
        if (view.getWidth() <= 0 || view.getHeight() <= 0) {
            return;
        }
        Rect rect = new Rect(0, 0, view.getWidth(), view.getHeight());
        if (this.f10877e != 1) {
            rect.offset(view.getLeft(), view.getTop());
        }
        transitionValues.values.put("android:crossfade:bounds", rect);
        Bitmap createBitmap = Bitmap.createBitmap(view.getWidth(), view.getHeight(), Bitmap.Config.ARGB_8888);
        if (view instanceof TextureView) {
            createBitmap = ((TextureView) view).getBitmap();
        } else {
            view.draw(new Canvas(createBitmap));
        }
        transitionValues.values.put("android:crossfade:bitmap", createBitmap);
        BitmapDrawable bitmapDrawable = new BitmapDrawable(view.getResources(), createBitmap);
        bitmapDrawable.setBounds(rect);
        transitionValues.values.put("android:crossfade:drawable", bitmapDrawable);
    }

    @Override // androidx.transition.Transition
    @Nullable
    public Animator createAnimator(@NonNull ViewGroup viewGroup, @Nullable TransitionValues transitionValues, @Nullable TransitionValues transitionValues2) {
        ObjectAnimator objectAnimator = null;
        if (transitionValues != null && transitionValues2 != null) {
            if (f10876c == null) {
                f10876c = new RectEvaluator();
            }
            boolean z = this.f10877e != 1;
            View view = transitionValues2.view;
            Map<String, Object> map = transitionValues.values;
            Map<String, Object> map2 = transitionValues2.values;
            Rect rect = (Rect) map.get("android:crossfade:bounds");
            Rect rect2 = (Rect) map2.get("android:crossfade:bounds");
            if (rect != null && rect2 != null) {
                Bitmap bitmap = (Bitmap) map.get("android:crossfade:bitmap");
                Bitmap bitmap2 = (Bitmap) map2.get("android:crossfade:bitmap");
                BitmapDrawable bitmapDrawable = (BitmapDrawable) map.get("android:crossfade:drawable");
                BitmapDrawable bitmapDrawable2 = (BitmapDrawable) map2.get("android:crossfade:drawable");
                if (bitmapDrawable != null && bitmapDrawable2 != null && !bitmap.sameAs(bitmap2)) {
                    ViewOverlay overlay = z ? ((ViewGroup) view.getParent()).getOverlay() : view.getOverlay();
                    if (this.f10877e == 1) {
                        overlay.add(bitmapDrawable2);
                    }
                    overlay.add(bitmapDrawable);
                    ObjectAnimator ofInt = this.f10877e == 2 ? ObjectAnimator.ofInt(bitmapDrawable, Key.ALPHA, 255, 0, 0) : ObjectAnimator.ofInt(bitmapDrawable, Key.ALPHA, 0);
                    ofInt.addUpdateListener(new C4150a(this, view, bitmapDrawable));
                    int i2 = this.f10877e;
                    if (i2 == 2) {
                        objectAnimator = ObjectAnimator.ofFloat(view, (Property<View, Float>) View.ALPHA, 0.0f, 0.0f, 1.0f);
                    } else if (i2 == 0) {
                        objectAnimator = ObjectAnimator.ofFloat(view, (Property<View, Float>) View.ALPHA, 0.0f, 1.0f);
                    }
                    ObjectAnimator objectAnimator2 = objectAnimator;
                    ofInt.addListener(new C4151b(z, view, bitmapDrawable, bitmapDrawable2));
                    AnimatorSet animatorSet = new AnimatorSet();
                    animatorSet.playTogether(ofInt);
                    if (objectAnimator2 != null) {
                        animatorSet.playTogether(objectAnimator2);
                    }
                    if (this.f10878f == 1 && !rect.equals(rect2)) {
                        animatorSet.playTogether(ObjectAnimator.ofObject(bitmapDrawable, "bounds", f10876c, rect, rect2));
                        if (this.f10878f == 1) {
                            animatorSet.playTogether(ObjectAnimator.ofObject(bitmapDrawable2, "bounds", f10876c, rect, rect2));
                        }
                    }
                    return animatorSet;
                }
            }
        }
        return null;
    }
}
