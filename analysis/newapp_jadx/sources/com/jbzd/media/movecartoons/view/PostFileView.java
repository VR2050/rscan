package com.jbzd.media.movecartoons.view;

import android.content.Context;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewGroup;
import com.jbzd.media.movecartoons.R$styleable;
import java.util.Objects;
import kotlin.Metadata;
import kotlin.jvm.JvmOverloads;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.RangesKt___RangesKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00008\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\b\n\u0002\b\t\n\u0002\u0010\u0002\n\u0002\b\u0010\n\u0002\u0010\u000b\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0005\u0018\u00002\u00020\u0001B'\b\u0007\u0012\u0006\u0010+\u001a\u00020*\u0012\n\b\u0002\u0010%\u001a\u0004\u0018\u00010$\u0012\b\b\u0002\u0010,\u001a\u00020\u0002¢\u0006\u0004\b-\u0010.J\u001f\u0010\u0005\u001a\u00020\u00022\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0004\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0005\u0010\u0006J'\u0010\n\u001a\u00020\u00022\u0006\u0010\u0007\u001a\u00020\u00022\u0006\u0010\b\u001a\u00020\u00022\u0006\u0010\t\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\n\u0010\u000bJ\u000f\u0010\r\u001a\u00020\fH\u0002¢\u0006\u0004\b\r\u0010\u000eJ\u000f\u0010\u000f\u001a\u00020\fH\u0002¢\u0006\u0004\b\u000f\u0010\u000eJ\u000f\u0010\u0010\u001a\u00020\fH\u0002¢\u0006\u0004\b\u0010\u0010\u000eJ/\u0010\u0015\u001a\u00020\f2\u0006\u0010\u0011\u001a\u00020\u00022\u0006\u0010\u0012\u001a\u00020\u00022\u0006\u0010\u0013\u001a\u00020\u00022\u0006\u0010\u0014\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0015\u0010\u0016J/\u0010\u0017\u001a\u00020\f2\u0006\u0010\u0011\u001a\u00020\u00022\u0006\u0010\u0012\u001a\u00020\u00022\u0006\u0010\u0013\u001a\u00020\u00022\u0006\u0010\u0014\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0017\u0010\u0016J/\u0010\u0018\u001a\u00020\f2\u0006\u0010\u0011\u001a\u00020\u00022\u0006\u0010\u0012\u001a\u00020\u00022\u0006\u0010\u0013\u001a\u00020\u00022\u0006\u0010\u0014\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0018\u0010\u0016J\u001f\u0010\u001b\u001a\u00020\f2\u0006\u0010\u0019\u001a\u00020\u00022\u0006\u0010\u001a\u001a\u00020\u0002H\u0014¢\u0006\u0004\b\u001b\u0010\u001cJ7\u0010\u001f\u001a\u00020\f2\u0006\u0010\u001e\u001a\u00020\u001d2\u0006\u0010\u0011\u001a\u00020\u00022\u0006\u0010\u0012\u001a\u00020\u00022\u0006\u0010\u0013\u001a\u00020\u00022\u0006\u0010\u0014\u001a\u00020\u0002H\u0014¢\u0006\u0004\b\u001f\u0010 J\u000f\u0010\"\u001a\u00020!H\u0014¢\u0006\u0004\b\"\u0010#J\u0019\u0010&\u001a\u00020!2\b\u0010%\u001a\u0004\u0018\u00010$H\u0016¢\u0006\u0004\b&\u0010'R\u0016\u0010(\u001a\u00020\u00028\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b(\u0010)¨\u0006/"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/view/PostFileView;", "Landroid/view/ViewGroup;", "", "measureSpec", "defaultSize", "getMeasureSize", "(II)I", "specSize", "padding", "dimen", "getPostSize", "(III)I", "", "measureSingleChild", "()V", "measureDoubleChild", "measureMultipleChild", "left", "top", "right", "bottom", "layoutSingle", "(IIII)V", "layoutDouble", "layoutMultipleChild", "widthMeasureSpec", "heightMeasureSpec", "onMeasure", "(II)V", "", "changed", "onLayout", "(ZIIII)V", "Landroid/view/ViewGroup$LayoutParams;", "generateDefaultLayoutParams", "()Landroid/view/ViewGroup$LayoutParams;", "Landroid/util/AttributeSet;", "attrs", "generateLayoutParams", "(Landroid/util/AttributeSet;)Landroid/view/ViewGroup$LayoutParams;", "contentPadding", "I", "Landroid/content/Context;", "context", "defStyleAttr", "<init>", "(Landroid/content/Context;Landroid/util/AttributeSet;I)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class PostFileView extends ViewGroup {
    private final int contentPadding;

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    @JvmOverloads
    public PostFileView(@NotNull Context context) {
        this(context, null, 0, 6, null);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    @JvmOverloads
    public PostFileView(@NotNull Context context, @Nullable AttributeSet attributeSet) {
        this(context, attributeSet, 0, 4, null);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    public /* synthetic */ PostFileView(Context context, AttributeSet attributeSet, int i2, int i3, DefaultConstructorMarker defaultConstructorMarker) {
        this(context, (i3 & 2) != 0 ? null : attributeSet, (i3 & 4) != 0 ? 0 : i2);
    }

    private final int getMeasureSize(int measureSpec, int defaultSize) {
        return View.MeasureSpec.getMode(measureSpec) == 1073741824 ? View.MeasureSpec.getSize(measureSpec) : defaultSize;
    }

    private final int getPostSize(int specSize, int padding, int dimen) {
        int coerceAtLeast = RangesKt___RangesKt.coerceAtLeast(0, specSize - padding);
        if (dimen <= 0) {
            dimen = coerceAtLeast;
        }
        return View.MeasureSpec.makeMeasureSpec(dimen, 1073741824);
    }

    private final void layoutDouble(int left, int top, int right, int bottom) {
        View childAt = getChildAt(0);
        childAt.layout(getPaddingLeft(), getPaddingTop(), childAt.getMeasuredWidth(), bottom - getPaddingBottom());
        getChildAt(1).layout(childAt.getMeasuredWidth() + this.contentPadding, getPaddingTop(), right - getPaddingRight(), bottom - getPaddingBottom());
    }

    private final void layoutMultipleChild(int left, int top, int right, int bottom) {
        View childAt = getChildAt(0);
        childAt.layout(getPaddingLeft(), getPaddingTop(), childAt.getMeasuredWidth(), bottom - getPaddingBottom());
        View childAt2 = getChildAt(1);
        childAt2.layout(childAt.getMeasuredWidth() + this.contentPadding, getPaddingTop(), right - getPaddingRight(), childAt2.getMeasuredHeight() + top);
        int childCount = getChildCount();
        int i2 = 2;
        if (2 >= childCount) {
            return;
        }
        while (true) {
            int i3 = i2 + 1;
            getChildAt(i2).layout(childAt.getMeasuredWidth() + this.contentPadding, getPaddingTop() + childAt2.getMeasuredHeight() + this.contentPadding, right - getPaddingRight(), bottom - getPaddingBottom());
            if (i3 >= childCount) {
                return;
            } else {
                i2 = i3;
            }
        }
    }

    private final void layoutSingle(int left, int top, int right, int bottom) {
        getChildAt(0).layout(getPaddingStart(), getPaddingTop(), right - getPaddingRight(), bottom - getPaddingBottom());
    }

    private final void measureDoubleChild() {
        View childAt = getChildAt(0);
        View childAt2 = getChildAt(1);
        ViewGroup.LayoutParams layoutParams = childAt.getLayoutParams();
        Objects.requireNonNull(layoutParams, "null cannot be cast to non-null type android.view.ViewGroup.MarginLayoutParams");
        int postSize = getPostSize(getMeasuredHeight(), getPaddingBottom() + getPaddingTop(), ((ViewGroup.MarginLayoutParams) layoutParams).height);
        childAt.measure(postSize, postSize);
        childAt2.measure(postSize, postSize);
    }

    private final void measureMultipleChild() {
        View childAt = getChildAt(0);
        ViewGroup.LayoutParams layoutParams = childAt.getLayoutParams();
        Objects.requireNonNull(layoutParams, "null cannot be cast to non-null type android.view.ViewGroup.MarginLayoutParams");
        ViewGroup.MarginLayoutParams marginLayoutParams = (ViewGroup.MarginLayoutParams) layoutParams;
        int postSize = getPostSize(getMeasuredHeight(), getPaddingBottom() + getPaddingTop(), marginLayoutParams.height);
        childAt.measure(postSize, postSize);
        int postSize2 = getPostSize((getMeasuredHeight() - this.contentPadding) / 2, getPaddingTop() + getPaddingBottom(), marginLayoutParams.height);
        int childCount = getChildCount();
        int i2 = 1;
        if (1 >= childCount) {
            return;
        }
        while (true) {
            int i3 = i2 + 1;
            getChildAt(i2).measure(postSize, postSize2);
            if (i3 >= childCount) {
                return;
            } else {
                i2 = i3;
            }
        }
    }

    private final void measureSingleChild() {
        View childAt = getChildAt(0);
        ViewGroup.LayoutParams layoutParams = childAt.getLayoutParams();
        Objects.requireNonNull(layoutParams, "null cannot be cast to non-null type android.view.ViewGroup.MarginLayoutParams");
        ViewGroup.MarginLayoutParams marginLayoutParams = (ViewGroup.MarginLayoutParams) layoutParams;
        childAt.measure(getPostSize(getMeasuredWidth(), getPaddingRight() + getPaddingLeft(), marginLayoutParams.width), getPostSize(getMeasuredHeight(), getPaddingBottom() + getPaddingTop(), marginLayoutParams.height));
    }

    public void _$_clearFindViewByIdCache() {
    }

    @Override // android.view.ViewGroup
    @NotNull
    public ViewGroup.LayoutParams generateDefaultLayoutParams() {
        return new ViewGroup.MarginLayoutParams(-1, -2);
    }

    @Override // android.view.ViewGroup
    @NotNull
    public ViewGroup.LayoutParams generateLayoutParams(@Nullable AttributeSet attrs) {
        return new ViewGroup.MarginLayoutParams(getContext(), attrs);
    }

    @Override // android.view.ViewGroup, android.view.View
    public void onLayout(boolean changed, int left, int top, int right, int bottom) {
        int childCount = getChildCount();
        if (childCount == 1) {
            layoutSingle(left, top, right, bottom);
        } else if (childCount != 2) {
            layoutMultipleChild(left, top, right, bottom);
        } else {
            layoutDouble(left, top, right, bottom);
        }
    }

    @Override // android.view.View
    public void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        int childCount = getChildCount();
        if (childCount == 0) {
            setMeasuredDimension(widthMeasureSpec, ViewGroup.resolveSize(Math.max(getPaddingBottom() + getPaddingTop(), getSuggestedMinimumHeight()), heightMeasureSpec));
            return;
        }
        int size = (View.MeasureSpec.getSize(widthMeasureSpec) - getPaddingLeft()) - getPaddingRight();
        int paddingBottom = getPaddingBottom() + getPaddingTop() + ((size - (childCount > 1 ? this.contentPadding : 0)) / 2);
        getMeasureSize(heightMeasureSpec, paddingBottom);
        setMeasuredDimension(View.MeasureSpec.makeMeasureSpec(size, 1073741824), View.MeasureSpec.makeMeasureSpec(getMeasureSize(heightMeasureSpec, paddingBottom), 1073741824));
        if (childCount == 1) {
            measureSingleChild();
        } else if (childCount != 2) {
            measureMultipleChild();
        } else {
            measureDoubleChild();
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    @JvmOverloads
    public PostFileView(@NotNull Context context, @Nullable AttributeSet attributeSet, int i2) {
        super(context, attributeSet, i2);
        Intrinsics.checkNotNullParameter(context, "context");
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, R$styleable.PostFileView);
        Intrinsics.checkNotNullExpressionValue(obtainStyledAttributes, "context.obtainStyledAttributes(attrs, R.styleable.PostFileView)");
        this.contentPadding = obtainStyledAttributes.getDimensionPixelSize(0, 0);
        obtainStyledAttributes.recycle();
    }
}
