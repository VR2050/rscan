package p005b.p067b.p068a.p069a.p070a.p072h;

import android.animation.Animator;
import android.animation.ObjectAnimator;
import android.view.View;
import android.view.animation.DecelerateInterpolator;
import androidx.constraintlayout.motion.widget.Key;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* renamed from: b.b.a.a.a.h.c */
/* loaded from: classes.dex */
public final class C1287c implements InterfaceC1286b {

    /* renamed from: a */
    public final float f1006a;

    public C1287c(float f2, int i2) {
        this.f1006a = (i2 & 1) != 0 ? 0.5f : f2;
    }

    @Override // p005b.p067b.p068a.p069a.p070a.p072h.InterfaceC1286b
    @NotNull
    /* renamed from: a */
    public Animator[] mo307a(@NotNull View view) {
        Intrinsics.checkNotNullParameter(view, "view");
        ObjectAnimator scaleX = ObjectAnimator.ofFloat(view, Key.SCALE_X, this.f1006a, 1.0f);
        scaleX.setDuration(300L);
        scaleX.setInterpolator(new DecelerateInterpolator());
        ObjectAnimator scaleY = ObjectAnimator.ofFloat(view, Key.SCALE_Y, this.f1006a, 1.0f);
        scaleY.setDuration(300L);
        scaleY.setInterpolator(new DecelerateInterpolator());
        Intrinsics.checkNotNullExpressionValue(scaleX, "scaleX");
        Intrinsics.checkNotNullExpressionValue(scaleY, "scaleY");
        return new Animator[]{scaleX, scaleY};
    }
}
