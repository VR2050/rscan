package com.android.p394db.swipemenulayout;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.PointF;
import android.util.AttributeSet;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewConfiguration;
import android.view.ViewGroup;
import android.widget.Scroller;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.Metadata;
import kotlin.TypeCastException;
import kotlin.collections.IntIterator;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.RangesKt___RangesKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p310s.p311a.C2743m;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000v\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0010\u0007\n\u0002\b\f\n\u0002\u0018\u0002\n\u0002\b\f\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\b\b\u0016\u0018\u0000 a2\u00020\u0001:\u0002/\u0012B\u0011\b\u0016\u0012\u0006\u0010[\u001a\u00020Z¢\u0006\u0004\b\\\u0010]B\u001b\b\u0016\u0012\u0006\u0010[\u001a\u00020Z\u0012\b\u0010\t\u001a\u0004\u0018\u00010\b¢\u0006\u0004\b\\\u0010^B#\b\u0016\u0012\u0006\u0010[\u001a\u00020Z\u0012\b\u0010\t\u001a\u0004\u0018\u00010\b\u0012\u0006\u0010_\u001a\u00020\u0002¢\u0006\u0004\b\\\u0010`J\u001f\u0010\u0006\u001a\u00020\u00052\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0004\u001a\u00020\u0002H\u0014¢\u0006\u0004\b\u0006\u0010\u0007J\u0019\u0010\u000b\u001a\u00020\n2\b\u0010\t\u001a\u0004\u0018\u00010\bH\u0016¢\u0006\u0004\b\u000b\u0010\fJ7\u0010\u0013\u001a\u00020\u00052\u0006\u0010\u000e\u001a\u00020\r2\u0006\u0010\u000f\u001a\u00020\u00022\u0006\u0010\u0010\u001a\u00020\u00022\u0006\u0010\u0011\u001a\u00020\u00022\u0006\u0010\u0012\u001a\u00020\u0002H\u0014¢\u0006\u0004\b\u0013\u0010\u0014J\u0019\u0010\u0017\u001a\u00020\r2\b\u0010\u0016\u001a\u0004\u0018\u00010\u0015H\u0016¢\u0006\u0004\b\u0017\u0010\u0018J\u0019\u0010\u0019\u001a\u00020\r2\b\u0010\u0016\u001a\u0004\u0018\u00010\u0015H\u0016¢\u0006\u0004\b\u0019\u0010\u0018J\u000f\u0010\u001a\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\u001a\u0010\u001bJ\u000f\u0010\u001c\u001a\u00020\u0005H\u0014¢\u0006\u0004\b\u001c\u0010\u001bJ\u000f\u0010\u001d\u001a\u00020\u0005H\u0014¢\u0006\u0004\b\u001d\u0010\u001bJ\r\u0010\u001f\u001a\u00020\u001e¢\u0006\u0004\b\u001f\u0010 J\u0015\u0010\"\u001a\u00020\u00052\u0006\u0010!\u001a\u00020\u001e¢\u0006\u0004\b\"\u0010#J\u0015\u0010%\u001a\u00020\u00052\u0006\u0010$\u001a\u00020\r¢\u0006\u0004\b%\u0010&J\u0015\u0010(\u001a\u00020\u00052\u0006\u0010'\u001a\u00020\r¢\u0006\u0004\b(\u0010&J\u000f\u0010)\u001a\u0004\u0018\u00010\u0000¢\u0006\u0004\b)\u0010*J\u000f\u0010,\u001a\u0004\u0018\u00010+¢\u0006\u0004\b,\u0010-J\u0017\u0010/\u001a\u00020\u00052\u0006\u0010.\u001a\u00020+H\u0002¢\u0006\u0004\b/\u00100R\u0016\u0010'\u001a\u00020\r8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b1\u00102R\u0016\u00105\u001a\u00020\u00028\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b3\u00104R\u0016\u00107\u001a\u00020\u00028\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b6\u00104R\u0018\u0010;\u001a\u0004\u0018\u0001088\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b9\u0010:R\u0016\u0010=\u001a\u00020\u00028\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b<\u00104R\u0018\u0010@\u001a\u0004\u0018\u00010>8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u000f\u0010?R\u0016\u0010!\u001a\u00020\u001e8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0010\u0010AR\u0016\u0010B\u001a\u00020\u001e8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0011\u0010AR\u0016\u0010D\u001a\u00020\u00028\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\bC\u00104R\u0018\u0010H\u001a\u0004\u0018\u00010E8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\bF\u0010GR\u0018\u0010J\u001a\u0004\u0018\u0001088\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\bI\u0010:R\u0018\u0010L\u001a\u0004\u0018\u00010>8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\bK\u0010?R\u0018\u0010P\u001a\u0004\u0018\u00010M8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\bN\u0010OR\u0016\u0010R\u001a\u00020\r8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\bQ\u00102R\u001c\u0010V\u001a\b\u0012\u0004\u0012\u00020>0S8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\bT\u0010UR\u0018\u0010X\u001a\u0004\u0018\u00010>8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\bW\u0010?R\u0016\u0010$\u001a\u00020\r8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\bY\u00102¨\u0006b"}, m5311d2 = {"Lcom/android/db/swipemenulayout/SwipeMenuLayout;", "Landroid/view/ViewGroup;", "", "widthMeasureSpec", "heightMeasureSpec", "", "onMeasure", "(II)V", "Landroid/util/AttributeSet;", "attrs", "Landroid/view/ViewGroup$LayoutParams;", "generateLayoutParams", "(Landroid/util/AttributeSet;)Landroid/view/ViewGroup$LayoutParams;", "", "changed", "l", "t", "r", "b", "onLayout", "(ZIIII)V", "Landroid/view/MotionEvent;", "ev", "dispatchTouchEvent", "(Landroid/view/MotionEvent;)Z", "onInterceptTouchEvent", "computeScroll", "()V", "onDetachedFromWindow", "onAttachedToWindow", "", "getFraction", "()F", "mFraction", "setFraction", "(F)V", "mCanLeftSwipe", "setCanLeftSwipe", "(Z)V", "mCanRightSwipe", "setCanRightSwipe", "getViewCache", "()Lcom/android/db/swipemenulayout/SwipeMenuLayout;", "Lcom/android/db/swipemenulayout/SwipeMenuLayout$b;", "getStateCache", "()Lcom/android/db/swipemenulayout/SwipeMenuLayout$b;", "result", "a", "(Lcom/android/db/swipemenulayout/SwipeMenuLayout$b;)V", "u", "Z", "s", "I", "mScaledTouchSlop", "p", "mRightViewResID", "Landroid/graphics/PointF;", "n", "Landroid/graphics/PointF;", "mLastP", "q", "mLeftViewResID", "Landroid/view/View;", "Landroid/view/View;", "mLeftView", "F", "finallyDistanceX", "o", "mContentViewResID", "Landroid/widget/Scroller;", "i", "Landroid/widget/Scroller;", "mScroller", C2743m.f7506a, "mFirstP", "j", "mContentView", "Landroid/view/ViewGroup$MarginLayoutParams;", "h", "Landroid/view/ViewGroup$MarginLayoutParams;", "mContentViewLp", "w", "isSwiping", "Ljava/util/ArrayList;", "g", "Ljava/util/ArrayList;", "mMatchParentChildren", "k", "mRightView", "v", "Landroid/content/Context;", "context", "<init>", "(Landroid/content/Context;)V", "(Landroid/content/Context;Landroid/util/AttributeSet;)V", "defStyleAttr", "(Landroid/content/Context;Landroid/util/AttributeSet;I)V", "f", "swipemenulayout_release"}, m5312k = 1, m5313mv = {1, 4, 0})
/* loaded from: classes.dex */
public class SwipeMenuLayout extends ViewGroup {

    /* renamed from: c */
    @SuppressLint({"StaticFieldLeak"})
    public static SwipeMenuLayout f8719c;

    /* renamed from: e */
    public static EnumC3199b f8720e;

    /* renamed from: g, reason: from kotlin metadata */
    public final ArrayList<View> mMatchParentChildren;

    /* renamed from: h, reason: from kotlin metadata */
    public ViewGroup.MarginLayoutParams mContentViewLp;

    /* renamed from: i, reason: from kotlin metadata */
    public Scroller mScroller;

    /* renamed from: j, reason: from kotlin metadata */
    public View mContentView;

    /* renamed from: k, reason: from kotlin metadata */
    public View mRightView;

    /* renamed from: l, reason: from kotlin metadata */
    public View mLeftView;

    /* renamed from: m, reason: from kotlin metadata */
    public PointF mFirstP;

    /* renamed from: n, reason: from kotlin metadata */
    public PointF mLastP;

    /* renamed from: o, reason: from kotlin metadata */
    public int mContentViewResID;

    /* renamed from: p, reason: from kotlin metadata */
    public int mRightViewResID;

    /* renamed from: q, reason: from kotlin metadata */
    public int mLeftViewResID;

    /* renamed from: r, reason: from kotlin metadata */
    public float finallyDistanceX;

    /* renamed from: s, reason: from kotlin metadata */
    public int mScaledTouchSlop;

    /* renamed from: t, reason: from kotlin metadata */
    public float mFraction;

    /* renamed from: u, reason: from kotlin metadata */
    public boolean mCanRightSwipe;

    /* renamed from: v, reason: from kotlin metadata */
    public boolean mCanLeftSwipe;

    /* renamed from: w, reason: from kotlin metadata */
    public boolean isSwiping;

    /* renamed from: com.android.db.swipemenulayout.SwipeMenuLayout$b */
    public enum EnumC3199b {
        LEFT_OPEN,
        RIGHT_OPEN,
        CLOSE
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public SwipeMenuLayout(@NotNull Context context) {
        this(context, null);
        Intrinsics.checkParameterIsNotNull(context, "context");
    }

    /* renamed from: a */
    public final void m3859a(EnumC3199b result) {
        int ordinal = result.ordinal();
        if (ordinal == 0) {
            Scroller scroller = this.mScroller;
            if (scroller != null) {
                int scrollX = getScrollX();
                View view = this.mLeftView;
                scroller.startScroll(scrollX, 0, (view != null ? view.getLeft() : 0) - getScrollX(), 0);
            }
            f8719c = this;
            f8720e = result;
        } else if (ordinal != 1) {
            Scroller scroller2 = this.mScroller;
            if (scroller2 != null) {
                scroller2.startScroll(getScrollX(), 0, -getScrollX(), 0);
            }
            f8719c = null;
            f8720e = null;
        } else {
            f8719c = this;
            Scroller scroller3 = this.mScroller;
            if (scroller3 != null) {
                int scrollX2 = getScrollX();
                View view2 = this.mRightView;
                int right = view2 != null ? view2.getRight() : 0;
                View view3 = this.mContentView;
                int right2 = right - (view3 != null ? view3.getRight() : 0);
                ViewGroup.MarginLayoutParams marginLayoutParams = this.mContentViewLp;
                scroller3.startScroll(scrollX2, 0, (right2 - (marginLayoutParams != null ? marginLayoutParams.rightMargin : 0)) - getScrollX(), 0);
            }
            f8720e = result;
        }
        invalidate();
    }

    @Override // android.view.View
    public void computeScroll() {
        Scroller scroller = this.mScroller;
        if (scroller == null || !scroller.computeScrollOffset()) {
            return;
        }
        scrollTo(scroller.getCurrX(), scroller.getCurrY());
        invalidate();
    }

    @Override // android.view.ViewGroup, android.view.View
    public boolean dispatchTouchEvent(@Nullable MotionEvent ev) {
        View view;
        View view2;
        SwipeMenuLayout swipeMenuLayout;
        EnumC3199b enumC3199b = EnumC3199b.CLOSE;
        Integer valueOf = ev != null ? Integer.valueOf(ev.getAction()) : null;
        if (valueOf != null && valueOf.intValue() == 0) {
            this.isSwiping = false;
            if (this.mLastP == null) {
                this.mLastP = new PointF();
            }
            PointF pointF = this.mLastP;
            if (pointF != null) {
                pointF.set(ev.getRawX(), ev.getRawY());
            }
            if (this.mFirstP == null) {
                this.mFirstP = new PointF();
            }
            PointF pointF2 = this.mFirstP;
            if (pointF2 != null) {
                pointF2.set(ev.getRawX(), ev.getRawY());
            }
            SwipeMenuLayout swipeMenuLayout2 = f8719c;
            if (swipeMenuLayout2 != null) {
                if ((!Intrinsics.areEqual(swipeMenuLayout2, this)) && (swipeMenuLayout = f8719c) != null) {
                    swipeMenuLayout.m3859a(enumC3199b);
                }
                swipeMenuLayout2.getParent().requestDisallowInterceptTouchEvent(true);
            }
        } else {
            if (valueOf != null && valueOf.intValue() == 2) {
                PointF pointF3 = this.mLastP;
                float rawX = (pointF3 != null ? pointF3.x : 0.0f) - ev.getRawX();
                PointF pointF4 = this.mLastP;
                float rawY = (pointF4 != null ? pointF4.y : 0.0f) - ev.getRawY();
                if (Math.abs(rawY) > this.mScaledTouchSlop && Math.abs(rawY) > Math.abs(rawX)) {
                    return super.dispatchTouchEvent(ev);
                }
                scrollBy((int) rawX, 0);
                if (getScrollX() < 0) {
                    if (!this.mCanRightSwipe || this.mLeftView == null) {
                        scrollTo(0, 0);
                    } else {
                        int scrollX = getScrollX();
                        View view3 = this.mLeftView;
                        if (scrollX < (view3 != null ? view3.getLeft() : 0)) {
                            View view4 = this.mLeftView;
                            scrollTo(view4 != null ? view4.getLeft() : 0, 0);
                        }
                    }
                } else if (getScrollX() > 0) {
                    if (!this.mCanLeftSwipe || this.mRightView == null) {
                        scrollTo(0, 0);
                    } else {
                        int scrollX2 = getScrollX();
                        View view5 = this.mRightView;
                        int right = view5 != null ? view5.getRight() : 0;
                        View view6 = this.mContentView;
                        int right2 = right - (view6 != null ? view6.getRight() : 0);
                        ViewGroup.MarginLayoutParams marginLayoutParams = this.mContentViewLp;
                        if (scrollX2 > right2 - (marginLayoutParams != null ? marginLayoutParams.rightMargin : 0)) {
                            View view7 = this.mRightView;
                            int right3 = view7 != null ? view7.getRight() : 0;
                            View view8 = this.mContentView;
                            int right4 = right3 - (view8 != null ? view8.getRight() : 0);
                            ViewGroup.MarginLayoutParams marginLayoutParams2 = this.mContentViewLp;
                            scrollTo(right4 - (marginLayoutParams2 != null ? marginLayoutParams2.rightMargin : 0), 0);
                        }
                    }
                }
                if (Math.abs(rawX) > this.mScaledTouchSlop) {
                    getParent().requestDisallowInterceptTouchEvent(true);
                }
                PointF pointF5 = this.mLastP;
                if (pointF5 != null) {
                    pointF5.set(ev.getRawX(), ev.getRawY());
                }
            } else if ((valueOf != null && valueOf.intValue() == 1) || (valueOf != null && valueOf.intValue() == 3)) {
                PointF pointF6 = this.mFirstP;
                float rawX2 = (pointF6 != null ? pointF6.x : 0.0f) - ev.getRawX();
                this.finallyDistanceX = rawX2;
                float abs = Math.abs(rawX2);
                int i2 = this.mScaledTouchSlop;
                if (abs > i2) {
                    this.isSwiping = true;
                }
                if (i2 >= Math.abs(this.finallyDistanceX)) {
                    EnumC3199b enumC3199b2 = f8720e;
                    if (enumC3199b2 != null) {
                        enumC3199b = enumC3199b2;
                    }
                } else {
                    float f2 = this.finallyDistanceX;
                    float f3 = 0;
                    if (f2 < f3) {
                        if (getScrollX() < 0 && (view2 = this.mLeftView) != null && Math.abs(view2.getWidth() * this.mFraction) < Math.abs(getScrollX())) {
                            enumC3199b = EnumC3199b.LEFT_OPEN;
                        } else if (getScrollX() > 0) {
                            View view9 = this.mRightView;
                        }
                    } else if (f2 > f3) {
                        if (getScrollX() <= 0 || (view = this.mRightView) == null || Math.abs(view.getWidth() * this.mFraction) >= Math.abs(getScrollX())) {
                            getScrollX();
                        } else {
                            enumC3199b = EnumC3199b.RIGHT_OPEN;
                        }
                    }
                }
                m3859a(enumC3199b);
            }
        }
        return super.dispatchTouchEvent(ev);
    }

    @Override // android.view.ViewGroup
    @NotNull
    public ViewGroup.LayoutParams generateLayoutParams(@Nullable AttributeSet attrs) {
        return new ViewGroup.MarginLayoutParams(getContext(), attrs);
    }

    /* renamed from: getFraction, reason: from getter */
    public final float getMFraction() {
        return this.mFraction;
    }

    @Nullable
    public final EnumC3199b getStateCache() {
        return f8720e;
    }

    @Nullable
    public final SwipeMenuLayout getViewCache() {
        return f8719c;
    }

    @Override // android.view.ViewGroup, android.view.View
    public void onAttachedToWindow() {
        super.onAttachedToWindow();
        SwipeMenuLayout swipeMenuLayout = f8719c;
        if (swipeMenuLayout != null) {
            EnumC3199b enumC3199b = f8720e;
            if (enumC3199b == null) {
                enumC3199b = EnumC3199b.CLOSE;
            }
            swipeMenuLayout.m3859a(enumC3199b);
        }
    }

    @Override // android.view.ViewGroup, android.view.View
    public void onDetachedFromWindow() {
        SwipeMenuLayout swipeMenuLayout = f8719c;
        if (swipeMenuLayout != null) {
            swipeMenuLayout.m3859a(EnumC3199b.CLOSE);
        }
        super.onDetachedFromWindow();
    }

    @Override // android.view.ViewGroup
    public boolean onInterceptTouchEvent(@Nullable MotionEvent ev) {
        Integer valueOf = ev != null ? Integer.valueOf(ev.getAction()) : null;
        if (valueOf == null || valueOf.intValue() != 0) {
            if (valueOf != null && valueOf.intValue() == 2) {
                if (Math.abs(this.finallyDistanceX) > this.mScaledTouchSlop) {
                    return true;
                }
            } else if (((valueOf != null && valueOf.intValue() == 1) || (valueOf != null && valueOf.intValue() == 3)) && this.isSwiping) {
                this.isSwiping = false;
                this.finallyDistanceX = 0.0f;
                return true;
            }
        }
        return super.onInterceptTouchEvent(ev);
    }

    @Override // android.view.ViewGroup, android.view.View
    public void onLayout(boolean changed, int l2, int t, int r, int b2) {
        int childCount = getChildCount();
        int paddingLeft = getPaddingLeft();
        int paddingTop = getPaddingTop();
        for (int i2 = 0; i2 < childCount; i2++) {
            View child = getChildAt(i2);
            if (this.mLeftView == null) {
                Intrinsics.checkExpressionValueIsNotNull(child, "child");
                if (child.getId() == this.mLeftViewResID) {
                    this.mLeftView = child;
                    if (child != null) {
                        child.setClickable(true);
                    }
                }
            }
            if (this.mRightView == null) {
                Intrinsics.checkExpressionValueIsNotNull(child, "child");
                if (child.getId() == this.mRightViewResID) {
                    this.mRightView = child;
                    if (child != null) {
                        child.setClickable(true);
                    }
                }
            }
            if (this.mContentView == null) {
                Intrinsics.checkExpressionValueIsNotNull(child, "child");
                if (child.getId() == this.mContentViewResID) {
                    this.mContentView = child;
                    if (child != null) {
                        child.setClickable(true);
                    }
                }
            }
        }
        View view = this.mContentView;
        if (view != null) {
            int measuredWidth = view.getMeasuredWidth();
            int measuredHeight = view.getMeasuredHeight();
            ViewGroup.LayoutParams layoutParams = view.getLayoutParams();
            if (layoutParams == null) {
                throw new TypeCastException("null cannot be cast to non-null type android.view.ViewGroup.MarginLayoutParams");
            }
            ViewGroup.MarginLayoutParams marginLayoutParams = (ViewGroup.MarginLayoutParams) layoutParams;
            int i3 = marginLayoutParams.topMargin + paddingTop;
            int i4 = marginLayoutParams.leftMargin;
            this.mContentViewLp = marginLayoutParams;
            view.layout(paddingLeft + i4, i3, paddingLeft + i4 + measuredWidth, measuredHeight + i3);
        }
        View view2 = this.mLeftView;
        if (view2 != null) {
            int measuredWidth2 = view2.getMeasuredWidth();
            int measuredHeight2 = view2.getMeasuredHeight();
            ViewGroup.LayoutParams layoutParams2 = view2.getLayoutParams();
            if (layoutParams2 == null) {
                throw new TypeCastException("null cannot be cast to non-null type android.view.ViewGroup.MarginLayoutParams");
            }
            ViewGroup.MarginLayoutParams marginLayoutParams2 = (ViewGroup.MarginLayoutParams) layoutParams2;
            int i5 = marginLayoutParams2.topMargin + paddingTop;
            int i6 = (0 - measuredWidth2) + marginLayoutParams2.leftMargin;
            int i7 = marginLayoutParams2.rightMargin;
            view2.layout(i6 + i7, i5, 0 - i7, measuredHeight2 + i5);
        }
        View view3 = this.mRightView;
        if (view3 != null) {
            int measuredWidth3 = view3.getMeasuredWidth();
            int measuredHeight3 = view3.getMeasuredHeight();
            View view4 = this.mContentView;
            int right = view4 != null ? view4.getRight() : -1;
            ViewGroup.MarginLayoutParams marginLayoutParams3 = this.mContentViewLp;
            int i8 = marginLayoutParams3 != null ? marginLayoutParams3.rightMargin : 0;
            ViewGroup.LayoutParams layoutParams3 = view3.getLayoutParams();
            if (layoutParams3 == null) {
                throw new TypeCastException("null cannot be cast to non-null type android.view.ViewGroup.MarginLayoutParams");
            }
            ViewGroup.MarginLayoutParams marginLayoutParams4 = (ViewGroup.MarginLayoutParams) layoutParams3;
            int i9 = paddingTop + marginLayoutParams4.topMargin;
            int i10 = right + i8 + marginLayoutParams4.leftMargin;
            view3.layout(i10, i9, measuredWidth3 + i10, measuredHeight3 + i9);
        }
    }

    @Override // android.view.View
    public void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        super.onMeasure(widthMeasureSpec, heightMeasureSpec);
        setClickable(true);
        int childCount = getChildCount();
        boolean z = (View.MeasureSpec.getMode(widthMeasureSpec) == 1073741824 && View.MeasureSpec.getMode(heightMeasureSpec) == 1073741824) ? false : true;
        this.mMatchParentChildren.clear();
        int i2 = 0;
        int i3 = 0;
        int i4 = 0;
        for (int i5 = 0; i5 < childCount; i5++) {
            View child = getChildAt(i5);
            Intrinsics.checkExpressionValueIsNotNull(child, "child");
            if (child.getVisibility() != 8) {
                int i6 = i2;
                int i7 = i3;
                measureChildWithMargins(child, widthMeasureSpec, 0, heightMeasureSpec, 0);
                ViewGroup.LayoutParams layoutParams = child.getLayoutParams();
                if (layoutParams == null) {
                    throw new TypeCastException("null cannot be cast to non-null type android.view.ViewGroup.MarginLayoutParams");
                }
                ViewGroup.MarginLayoutParams marginLayoutParams = (ViewGroup.MarginLayoutParams) layoutParams;
                i3 = Math.max(i7, child.getMeasuredWidth() + marginLayoutParams.leftMargin + marginLayoutParams.rightMargin);
                i4 = Math.max(i4, child.getMeasuredHeight() + marginLayoutParams.topMargin + marginLayoutParams.bottomMargin);
                i2 = View.combineMeasuredStates(i6, child.getMeasuredState());
                if (z && (marginLayoutParams.width == -1 || marginLayoutParams.height == -1)) {
                    this.mMatchParentChildren.add(child);
                }
            }
        }
        int i8 = i2;
        setMeasuredDimension(View.resolveSizeAndState(Math.max(i3, getSuggestedMinimumWidth()), widthMeasureSpec, i8), View.resolveSizeAndState(Math.max(i4, getSuggestedMinimumHeight()), heightMeasureSpec, i8 << 16));
        int size = this.mMatchParentChildren.size();
        if (size > 1) {
            for (int i9 = 0; i9 < size; i9++) {
                View child2 = this.mMatchParentChildren.get(i9);
                Intrinsics.checkExpressionValueIsNotNull(child2, "child");
                ViewGroup.LayoutParams layoutParams2 = child2.getLayoutParams();
                if (layoutParams2 == null) {
                    throw new TypeCastException("null cannot be cast to non-null type android.view.ViewGroup.MarginLayoutParams");
                }
                ViewGroup.MarginLayoutParams marginLayoutParams2 = (ViewGroup.MarginLayoutParams) layoutParams2;
                int i10 = marginLayoutParams2.width;
                int makeMeasureSpec = i10 == -1 ? View.MeasureSpec.makeMeasureSpec(Math.max(0, (getMeasuredWidth() - marginLayoutParams2.leftMargin) - marginLayoutParams2.rightMargin), 1073741824) : ViewGroup.getChildMeasureSpec(widthMeasureSpec, marginLayoutParams2.leftMargin + marginLayoutParams2.rightMargin, i10);
                int i11 = marginLayoutParams2.height;
                child2.measure(makeMeasureSpec, i11 == -1 ? View.MeasureSpec.makeMeasureSpec(Math.max(0, (getMeasuredHeight() - marginLayoutParams2.topMargin) - marginLayoutParams2.bottomMargin), 1073741824) : ViewGroup.getChildMeasureSpec(heightMeasureSpec, marginLayoutParams2.topMargin + marginLayoutParams2.bottomMargin, i11));
            }
        }
    }

    public final void setCanLeftSwipe(boolean mCanLeftSwipe) {
        this.mCanLeftSwipe = mCanLeftSwipe;
    }

    public final void setCanRightSwipe(boolean mCanRightSwipe) {
        this.mCanRightSwipe = mCanRightSwipe;
    }

    public final void setFraction(float mFraction) {
        this.mFraction = mFraction;
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public SwipeMenuLayout(@NotNull Context context, @Nullable AttributeSet attributeSet) {
        this(context, attributeSet, 0);
        Intrinsics.checkParameterIsNotNull(context, "context");
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public SwipeMenuLayout(@NotNull Context context, @Nullable AttributeSet attributeSet, int i2) {
        super(context, attributeSet, i2);
        Intrinsics.checkParameterIsNotNull(context, "context");
        this.mMatchParentChildren = new ArrayList<>(1);
        this.mFraction = 0.5f;
        this.mCanRightSwipe = true;
        this.mCanLeftSwipe = true;
        ViewConfiguration viewConfiguration = ViewConfiguration.get(context);
        Intrinsics.checkExpressionValueIsNotNull(viewConfiguration, "ViewConfiguration.get(context)");
        this.mScaledTouchSlop = viewConfiguration.getScaledTouchSlop();
        this.mScroller = new Scroller(context);
        TypedArray typedArray = context.getTheme().obtainStyledAttributes(attributeSet, R$styleable.SwipeMenuLayout, i2, 0);
        try {
            try {
                Intrinsics.checkExpressionValueIsNotNull(typedArray, "typedArray");
                Iterator<Integer> it = RangesKt___RangesKt.until(0, typedArray.getIndexCount()).iterator();
                while (it.hasNext()) {
                    int index = typedArray.getIndex(((IntIterator) it).nextInt());
                    int i3 = R$styleable.SwipeMenuLayout_leftView;
                    if (index == i3) {
                        this.mLeftViewResID = typedArray.getResourceId(i3, -1);
                    } else {
                        int i4 = R$styleable.SwipeMenuLayout_rightView;
                        if (index == i4) {
                            this.mRightViewResID = typedArray.getResourceId(i4, -1);
                        } else {
                            int i5 = R$styleable.SwipeMenuLayout_contentView;
                            if (index == i5) {
                                this.mContentViewResID = typedArray.getResourceId(i5, -1);
                            } else {
                                int i6 = R$styleable.SwipeMenuLayout_canLeftSwipe;
                                if (index == i6) {
                                    this.mCanLeftSwipe = typedArray.getBoolean(i6, true);
                                } else {
                                    int i7 = R$styleable.SwipeMenuLayout_canRightSwipe;
                                    if (index == i7) {
                                        this.mCanRightSwipe = typedArray.getBoolean(i7, true);
                                    } else {
                                        int i8 = R$styleable.SwipeMenuLayout_fraction;
                                        if (index == i8) {
                                            this.mFraction = typedArray.getFloat(i8, 0.5f);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            } catch (Exception e2) {
                e2.printStackTrace();
            }
        } finally {
            typedArray.recycle();
        }
    }
}
