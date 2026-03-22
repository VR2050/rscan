package com.jbzd.media.movecartoons.view.decoration;

import android.content.Context;
import android.graphics.Rect;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewGroup;
import androidx.recyclerview.widget.RecyclerView;
import androidx.recyclerview.widget.StaggeredGridLayoutManager;
import java.lang.reflect.Field;

/* loaded from: classes2.dex */
public class FullStaggeredGridLayoutManager extends StaggeredGridLayoutManager {
    private static final int CHILD_HEIGHT = 1;
    private static final int CHILD_WIDTH = 0;
    private static final int DEFAULT_CHILD_SIZE = 100;
    private static boolean canMakeInsetsDirty = true;
    private static Field insetsDirtyField;
    private int[] childColumnDimensions;
    private final int[] childDimensions;
    private int childSize;
    private boolean hasChildSize;
    private int spanCount;
    private final Rect tmpRect;

    public FullStaggeredGridLayoutManager(Context context, AttributeSet attributeSet, int i2, int i3) {
        super(context, attributeSet, i2, i3);
        this.spanCount = 0;
        this.childDimensions = new int[2];
        this.childSize = 100;
        this.tmpRect = new Rect();
    }

    private void initChildDimensions(int i2, int i3, boolean z) {
        int[] iArr = this.childDimensions;
        if (iArr[0] == 0 && iArr[1] == 0) {
            if (z) {
                iArr[0] = i2;
                iArr[1] = this.childSize;
            } else {
                iArr[0] = this.childSize;
                iArr[1] = i3;
            }
        }
    }

    private void logMeasureWarning(int i2) {
    }

    private static void makeInsetsDirty(RecyclerView.LayoutParams layoutParams) {
        if (canMakeInsetsDirty) {
            try {
                if (insetsDirtyField == null) {
                    Field declaredField = RecyclerView.LayoutParams.class.getDeclaredField("mInsetsDirty");
                    insetsDirtyField = declaredField;
                    declaredField.setAccessible(true);
                }
                insetsDirtyField.set(layoutParams, Boolean.TRUE);
            } catch (IllegalAccessException unused) {
                onMakeInsertDirtyFailed();
            } catch (NoSuchFieldException unused2) {
                onMakeInsertDirtyFailed();
            }
        }
    }

    public static int makeUnspecifiedSpec() {
        return View.MeasureSpec.makeMeasureSpec(0, 0);
    }

    private void measureChild(RecyclerView.Recycler recycler, int i2, int i3, int i4, int[] iArr) {
        try {
            View viewForPosition = recycler.getViewForPosition(i2);
            RecyclerView.LayoutParams layoutParams = (RecyclerView.LayoutParams) viewForPosition.getLayoutParams();
            int paddingRight = getPaddingRight() + getPaddingLeft();
            int paddingBottom = getPaddingBottom() + getPaddingTop();
            int i5 = ((ViewGroup.MarginLayoutParams) layoutParams).leftMargin + ((ViewGroup.MarginLayoutParams) layoutParams).rightMargin;
            int i6 = ((ViewGroup.MarginLayoutParams) layoutParams).topMargin + ((ViewGroup.MarginLayoutParams) layoutParams).bottomMargin;
            makeInsetsDirty(layoutParams);
            calculateItemDecorationsForChild(viewForPosition, this.tmpRect);
            viewForPosition.measure(RecyclerView.LayoutManager.getChildMeasureSpec(i3, paddingRight + i5 + getLeftDecorationWidth(viewForPosition) + getRightDecorationWidth(viewForPosition), ((ViewGroup.MarginLayoutParams) layoutParams).width, canScrollHorizontally()), RecyclerView.LayoutManager.getChildMeasureSpec(i4, paddingBottom + i6 + getBottomDecorationHeight(viewForPosition) + getTopDecorationHeight(viewForPosition), ((ViewGroup.MarginLayoutParams) layoutParams).height, canScrollVertically()));
            iArr[0] = getDecoratedMeasuredWidth(viewForPosition) + ((ViewGroup.MarginLayoutParams) layoutParams).leftMargin + ((ViewGroup.MarginLayoutParams) layoutParams).rightMargin;
            iArr[1] = getDecoratedMeasuredHeight(viewForPosition) + ((ViewGroup.MarginLayoutParams) layoutParams).bottomMargin + ((ViewGroup.MarginLayoutParams) layoutParams).topMargin;
            makeInsetsDirty(layoutParams);
            recycler.recycleView(viewForPosition);
        } catch (IndexOutOfBoundsException unused) {
        }
    }

    private static void onMakeInsertDirtyFailed() {
        canMakeInsetsDirty = false;
    }

    public void clearChildSize() {
        this.hasChildSize = false;
        setChildSize(100);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void onMeasure(RecyclerView.Recycler recycler, RecyclerView.State state, int i2, int i3) {
        int i4;
        boolean z;
        int i5;
        int i6;
        int i7;
        int i8;
        int i9;
        int i10;
        int mode = View.MeasureSpec.getMode(i2);
        int mode2 = View.MeasureSpec.getMode(i3);
        int size = View.MeasureSpec.getSize(i2);
        int size2 = View.MeasureSpec.getSize(i3);
        char c2 = 1;
        boolean z2 = mode != 0;
        boolean z3 = mode2 != 0;
        boolean z4 = mode == 1073741824;
        boolean z5 = mode2 == 1073741824;
        int makeUnspecifiedSpec = makeUnspecifiedSpec();
        if (z4 && z5) {
            super.onMeasure(recycler, state, i2, i3);
            return;
        }
        boolean z6 = getOrientation() == 1;
        initChildDimensions(size, size2, z6);
        recycler.clear();
        int itemCount = state.getItemCount();
        int itemCount2 = getItemCount();
        this.childColumnDimensions = new int[itemCount2];
        int i11 = 0;
        int i12 = 0;
        int i13 = 0;
        while (true) {
            if (i12 >= itemCount2) {
                i4 = itemCount2;
                break;
            }
            if (!z6) {
                i4 = itemCount2;
                int i14 = itemCount;
                z = z6;
                int i15 = i11;
                int i16 = i12;
                if (this.hasChildSize) {
                    i5 = i16;
                    i6 = i14;
                    i7 = i15;
                } else if (i16 < i14) {
                    i6 = i14;
                    i7 = i15;
                    i5 = i16;
                    measureChild(recycler, i16, makeUnspecifiedSpec, size2, this.childDimensions);
                } else {
                    i6 = i14;
                    i7 = i15;
                    i5 = i16;
                    logMeasureWarning(i5);
                }
                int[] iArr = this.childDimensions;
                int i17 = i13 + iArr[0];
                int i18 = i5 == 0 ? iArr[1] : i7;
                if (z2 && i17 >= size) {
                    i13 = i17;
                    break;
                }
                i13 = i17;
                i11 = i18;
                i12 = i5 + 1;
                itemCount = i6;
                itemCount2 = i4;
                z6 = z;
                c2 = 1;
            } else {
                if (this.hasChildSize) {
                    i8 = i11;
                    i4 = itemCount2;
                    i9 = itemCount;
                    z = z6;
                    i10 = i12;
                } else if (i12 < itemCount) {
                    i8 = i11;
                    i4 = itemCount2;
                    i9 = itemCount;
                    z = z6;
                    measureChild(recycler, i12, size, makeUnspecifiedSpec, this.childDimensions);
                    i10 = i12;
                } else {
                    i8 = i11;
                    i4 = itemCount2;
                    i9 = itemCount;
                    z = z6;
                    i10 = i12;
                    logMeasureWarning(i10);
                }
                int[] iArr2 = this.childColumnDimensions;
                int[] iArr3 = this.childDimensions;
                iArr2[i10] = iArr3[c2];
                if (i10 == 0) {
                    i13 = iArr3[0];
                }
                int i19 = i8;
                if (z3 && i19 >= size2) {
                    break;
                }
                i11 = i19;
                i5 = i10;
                i6 = i9;
                i12 = i5 + 1;
                itemCount = i6;
                itemCount2 = i4;
                z6 = z;
                c2 = 1;
            }
        }
        int[] iArr4 = new int[this.spanCount];
        int i20 = i4;
        for (int i21 = 0; i21 < i20; i21++) {
            int i22 = this.spanCount;
            int i23 = i21 % i22;
            if (i21 < i22) {
                iArr4[i23] = iArr4[i23] + this.childColumnDimensions[i21];
            } else if (i23 < i22) {
                int i24 = iArr4[0];
                int i25 = 0;
                for (int i26 = 0; i26 < this.spanCount; i26++) {
                    if (i24 > iArr4[i26]) {
                        i24 = iArr4[i26];
                        i25 = i26;
                    }
                }
                iArr4[i25] = iArr4[i25] + this.childColumnDimensions[i21];
            }
        }
        for (int i27 = 0; i27 < this.spanCount; i27++) {
            int i28 = 0;
            while (i28 < (this.spanCount - i27) - 1) {
                int i29 = i28 + 1;
                if (iArr4[i28] < iArr4[i29]) {
                    int i30 = iArr4[i28];
                    iArr4[i28] = iArr4[i29];
                    iArr4[i29] = i30;
                }
                i28 = i29;
            }
        }
        int i31 = iArr4[0];
        if (!z4) {
            int paddingRight = getPaddingRight() + getPaddingLeft() + i13;
            size = z2 ? Math.min(paddingRight, size) : paddingRight;
        }
        if (!z5) {
            int paddingBottom = getPaddingBottom() + getPaddingTop() + i31;
            size2 = z3 ? Math.min(paddingBottom, size2) : paddingBottom;
        }
        setMeasuredDimension(size, size2);
    }

    public void setChildSize(int i2) {
        this.hasChildSize = true;
        if (this.childSize != i2) {
            this.childSize = i2;
            requestLayout();
        }
    }

    @Override // androidx.recyclerview.widget.StaggeredGridLayoutManager
    public void setOrientation(int i2) {
        if (this.childDimensions != null && getOrientation() != i2) {
            int[] iArr = this.childDimensions;
            iArr[0] = 0;
            iArr[1] = 0;
        }
        super.setOrientation(i2);
    }

    public FullStaggeredGridLayoutManager(int i2, int i3) {
        super(i2, i3);
        this.spanCount = 0;
        this.childDimensions = new int[2];
        this.childSize = 100;
        this.tmpRect = new Rect();
        this.spanCount = i2;
    }
}
