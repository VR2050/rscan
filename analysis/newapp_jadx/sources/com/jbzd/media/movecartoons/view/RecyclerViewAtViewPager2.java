package com.jbzd.media.movecartoons.view;

import android.content.Context;
import android.util.AttributeSet;
import androidx.recyclerview.widget.RecyclerView;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00006\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0010\b\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0005\u0018\u00002\u00020\u0001B\u0011\b\u0016\u0012\u0006\u0010\u0014\u001a\u00020\u0013¢\u0006\u0004\b\u0015\u0010\u0016B\u001b\b\u0016\u0012\u0006\u0010\u0014\u001a\u00020\u0013\u0012\b\u0010\u0018\u001a\u0004\u0018\u00010\u0017¢\u0006\u0004\b\u0015\u0010\u0019B#\b\u0016\u0012\u0006\u0010\u0014\u001a\u00020\u0013\u0012\b\u0010\u0018\u001a\u0004\u0018\u00010\u0017\u0012\u0006\u0010\u001a\u001a\u00020\f¢\u0006\u0004\b\u0015\u0010\u001bJ\u0017\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0005\u0010\u0006J\u0017\u0010\t\u001a\u00020\b2\u0006\u0010\u0007\u001a\u00020\u0004H\u0016¢\u0006\u0004\b\t\u0010\nR\u0016\u0010\u0007\u001a\u00020\u00048\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0007\u0010\u000bR\u0016\u0010\r\u001a\u00020\f8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\r\u0010\u000eR\"\u0010\u000f\u001a\u00020\u00048\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u000f\u0010\u000b\u001a\u0004\b\u000f\u0010\u0010\"\u0004\b\u0011\u0010\nR\u0016\u0010\u0012\u001a\u00020\f8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0012\u0010\u000e¨\u0006\u001c"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/view/RecyclerViewAtViewPager2;", "Landroidx/recyclerview/widget/RecyclerView;", "Landroid/view/MotionEvent;", "ev", "", "dispatchTouchEvent", "(Landroid/view/MotionEvent;)Z", "disallowIntercept", "", "requestDisallowInterceptTouchEvent", "(Z)V", "Z", "", "startX", "I", "isDispatch", "()Z", "setDispatch", "startY", "Landroid/content/Context;", "context", "<init>", "(Landroid/content/Context;)V", "Landroid/util/AttributeSet;", "attrs", "(Landroid/content/Context;Landroid/util/AttributeSet;)V", "defStyleAttr", "(Landroid/content/Context;Landroid/util/AttributeSet;I)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class RecyclerViewAtViewPager2 extends RecyclerView {
    private boolean disallowIntercept;
    private boolean isDispatch;
    private int startX;
    private int startY;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public RecyclerViewAtViewPager2(@NotNull Context context) {
        super(context);
        Intrinsics.checkNotNullParameter(context, "context");
        this.isDispatch = true;
    }

    public void _$_clearFindViewByIdCache() {
    }

    /* JADX WARN: Code restructure failed: missing block: B:10:0x0017, code lost:
    
        if (r0 != 3) goto L22;
     */
    @Override // android.view.ViewGroup, android.view.View
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean dispatchTouchEvent(@org.jetbrains.annotations.NotNull android.view.MotionEvent r6) {
        /*
            r5 = this;
            java.lang.String r0 = "ev"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r6, r0)
            boolean r0 = r5.isDispatch
            if (r0 == 0) goto L77
            int r0 = r6.getAction()
            r1 = 1
            if (r0 == 0) goto L62
            r2 = 0
            if (r0 == r1) goto L5a
            r1 = 2
            if (r0 == r1) goto L1a
            r1 = 3
            if (r0 == r1) goto L5a
            goto L77
        L1a:
            float r0 = r6.getX()
            int r0 = (int) r0
            float r1 = r6.getY()
            int r1 = (int) r1
            int r3 = r5.startX
            int r3 = r0 - r3
            int r3 = java.lang.Math.abs(r3)
            int r4 = r5.startY
            int r1 = r1 - r4
            int r1 = java.lang.Math.abs(r1)
            if (r3 <= r1) goto L52
            boolean r1 = r5.disallowIntercept
            if (r1 == 0) goto L43
            android.view.ViewParent r0 = r5.getParent()
            boolean r1 = r5.disallowIntercept
            r0.requestDisallowInterceptTouchEvent(r1)
            goto L77
        L43:
            android.view.ViewParent r1 = r5.getParent()
            int r2 = r5.startX
            int r2 = r2 - r0
            boolean r0 = r5.canScrollHorizontally(r2)
            r1.requestDisallowInterceptTouchEvent(r0)
            goto L77
        L52:
            android.view.ViewParent r0 = r5.getParent()
            r0.requestDisallowInterceptTouchEvent(r2)
            goto L77
        L5a:
            android.view.ViewParent r0 = r5.getParent()
            r0.requestDisallowInterceptTouchEvent(r2)
            goto L77
        L62:
            float r0 = r6.getX()
            int r0 = (int) r0
            r5.startX = r0
            float r0 = r6.getY()
            int r0 = (int) r0
            r5.startY = r0
            android.view.ViewParent r0 = r5.getParent()
            r0.requestDisallowInterceptTouchEvent(r1)
        L77:
            boolean r6 = super.dispatchTouchEvent(r6)
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.jbzd.media.movecartoons.view.RecyclerViewAtViewPager2.dispatchTouchEvent(android.view.MotionEvent):boolean");
    }

    /* renamed from: isDispatch, reason: from getter */
    public final boolean getIsDispatch() {
        return this.isDispatch;
    }

    @Override // androidx.recyclerview.widget.RecyclerView, android.view.ViewGroup, android.view.ViewParent
    public void requestDisallowInterceptTouchEvent(boolean disallowIntercept) {
        this.disallowIntercept = disallowIntercept;
        super.requestDisallowInterceptTouchEvent(disallowIntercept);
    }

    public final void setDispatch(boolean z) {
        this.isDispatch = z;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public RecyclerViewAtViewPager2(@NotNull Context context, @Nullable AttributeSet attributeSet) {
        super(context, attributeSet);
        Intrinsics.checkNotNullParameter(context, "context");
        this.isDispatch = true;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public RecyclerViewAtViewPager2(@NotNull Context context, @Nullable AttributeSet attributeSet, int i2) {
        super(context, attributeSet, i2);
        Intrinsics.checkNotNullParameter(context, "context");
        this.isDispatch = true;
    }
}
