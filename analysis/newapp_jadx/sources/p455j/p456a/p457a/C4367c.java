package p455j.p456a.p457a;

import android.animation.ValueAnimator;
import moe.codeest.enviews.ENPlayView;

/* renamed from: j.a.a.c */
/* loaded from: classes3.dex */
public class C4367c implements ValueAnimator.AnimatorUpdateListener {

    /* renamed from: c */
    public final /* synthetic */ ENPlayView f11295c;

    public C4367c(ENPlayView eNPlayView) {
        this.f11295c = eNPlayView;
    }

    @Override // android.animation.ValueAnimator.AnimatorUpdateListener
    public void onAnimationUpdate(ValueAnimator valueAnimator) {
        this.f11295c.f12786n = 1.0f - valueAnimator.getAnimatedFraction();
        this.f11295c.invalidate();
    }
}
