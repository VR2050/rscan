package p005b.p067b.p068a.p069a.p070a.p072h;

import android.animation.Animator;
import android.animation.ObjectAnimator;
import android.view.View;
import android.view.animation.DecelerateInterpolator;
import androidx.constraintlayout.motion.widget.Key;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* renamed from: b.b.a.a.a.h.e */
/* loaded from: classes.dex */
public final class C1289e implements InterfaceC1286b {
    @Override // p005b.p067b.p068a.p069a.p070a.p072h.InterfaceC1286b
    @NotNull
    /* renamed from: a */
    public Animator[] mo307a(@NotNull View view) {
        Intrinsics.checkNotNullParameter(view, "view");
        ObjectAnimator animator = ObjectAnimator.ofFloat(view, Key.TRANSLATION_X, -view.getRootView().getWidth(), 0.0f);
        animator.setDuration(400L);
        animator.setInterpolator(new DecelerateInterpolator(1.8f));
        Intrinsics.checkNotNullExpressionValue(animator, "animator");
        return new Animator[]{animator};
    }
}
