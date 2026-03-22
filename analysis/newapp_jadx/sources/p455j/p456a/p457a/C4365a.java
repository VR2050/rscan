package p455j.p456a.p457a;

import android.animation.ValueAnimator;
import moe.codeest.enviews.ENDownloadView;

/* renamed from: j.a.a.a */
/* loaded from: classes3.dex */
public class C4365a implements ValueAnimator.AnimatorUpdateListener {

    /* renamed from: c */
    public final /* synthetic */ ENDownloadView f11293c;

    public C4365a(ENDownloadView eNDownloadView) {
        this.f11293c = eNDownloadView;
    }

    @Override // android.animation.ValueAnimator.AnimatorUpdateListener
    public void onAnimationUpdate(ValueAnimator valueAnimator) {
        this.f11293c.f12766q = valueAnimator.getAnimatedFraction();
        ENDownloadView eNDownloadView = this.f11293c;
        int i2 = eNDownloadView.f12758i;
        eNDownloadView.invalidate();
    }
}
