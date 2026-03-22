package com.angcyo.tablayout;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import com.angcyo.tablayout.DslTabLayout;
import kotlin.Metadata;
import org.jetbrains.annotations.Nullable;

@Metadata(m5310d1 = {"\u0000\u0019\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002*\u0001\u0000\b\n\u0018\u00002\u00020\u0001J\u0012\u0010\u0002\u001a\u00020\u00032\b\u0010\u0004\u001a\u0004\u0018\u00010\u0005H\u0016J\u0012\u0010\u0006\u001a\u00020\u00032\b\u0010\u0004\u001a\u0004\u0018\u00010\u0005H\u0016¨\u0006\u0007"}, m5311d2 = {"com/angcyo/tablayout/DslTabLayout$_scrollAnimator$2$1$2", "Landroid/animation/AnimatorListenerAdapter;", "onAnimationCancel", "", "animation", "Landroid/animation/Animator;", "onAnimationEnd", "TabLayout_release"}, m5312k = 1, m5313mv = {1, 6, 0}, m5315xi = 48)
/* renamed from: b.e.a.r */
/* loaded from: classes.dex */
public final class C1521r extends AnimatorListenerAdapter {

    /* renamed from: c */
    public final /* synthetic */ DslTabLayout f1648c;

    public C1521r(DslTabLayout dslTabLayout) {
        this.f1648c = dslTabLayout;
    }

    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
    public void onAnimationCancel(@Nullable Animator animation) {
        this.f1648c.m3864b(1.0f);
        this.f1648c.m3863a();
    }

    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
    public void onAnimationEnd(@Nullable Animator animation) {
        this.f1648c.m3863a();
    }
}
