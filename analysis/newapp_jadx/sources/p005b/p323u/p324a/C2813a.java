package p005b.p323u.p324a;

import android.animation.ValueAnimator;
import com.mikhaellopez.circularprogressbar.CircularProgressBar;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: b.u.a.a */
/* loaded from: classes2.dex */
public final class C2813a implements ValueAnimator.AnimatorUpdateListener {

    /* renamed from: c */
    public final /* synthetic */ CircularProgressBar f7653c;

    public C2813a(CircularProgressBar circularProgressBar) {
        this.f7653c = circularProgressBar;
    }

    @Override // android.animation.ValueAnimator.AnimatorUpdateListener
    public final void onAnimationUpdate(ValueAnimator animation) {
        Intrinsics.checkExpressionValueIsNotNull(animation, "animation");
        Object animatedValue = animation.getAnimatedValue();
        if (!(animatedValue instanceof Float)) {
            animatedValue = null;
        }
        Float f2 = (Float) animatedValue;
        if (f2 != null) {
            float floatValue = f2.floatValue();
            if (this.f7653c.getIndeterminateMode()) {
                this.f7653c.setProgressIndeterminateMode(floatValue);
            } else {
                this.f7653c.setProgress(floatValue);
            }
            if (this.f7653c.getIndeterminateMode()) {
                float f3 = (floatValue * 360) / 100;
                CircularProgressBar circularProgressBar = this.f7653c;
                if (!circularProgressBar.m4562e(circularProgressBar.progressDirectionIndeterminateMode)) {
                    f3 = -f3;
                }
                circularProgressBar.setStartAngleIndeterminateMode(f3 + 270.0f);
            }
        }
    }
}
