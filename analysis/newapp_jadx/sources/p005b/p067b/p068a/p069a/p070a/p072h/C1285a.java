package p005b.p067b.p068a.p069a.p070a.p072h;

import android.animation.Animator;
import android.animation.ObjectAnimator;
import android.view.View;
import android.view.animation.LinearInterpolator;
import androidx.constraintlayout.motion.widget.Key;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* renamed from: b.b.a.a.a.h.a */
/* loaded from: classes.dex */
public final class C1285a implements InterfaceC1286b {

    /* renamed from: a */
    public final float f1005a;

    public C1285a(float f2, int i2) {
        this.f1005a = (i2 & 1) != 0 ? 0.0f : f2;
    }

    @Override // p005b.p067b.p068a.p069a.p070a.p072h.InterfaceC1286b
    @NotNull
    /* renamed from: a */
    public Animator[] mo307a(@NotNull View view) {
        Intrinsics.checkNotNullParameter(view, "view");
        ObjectAnimator animator = ObjectAnimator.ofFloat(view, Key.ALPHA, this.f1005a, 1.0f);
        animator.setDuration(300L);
        animator.setInterpolator(new LinearInterpolator());
        Intrinsics.checkNotNullExpressionValue(animator, "animator");
        return new Animator[]{animator};
    }
}
