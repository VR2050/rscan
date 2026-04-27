package im.uwrkaxlmjj.ui.components.recyclerview.manager;

import android.content.Context;
import android.graphics.Rect;
import android.view.View;
import androidx.core.view.ViewCompat;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.blankj.utilcode.util.LogUtils;
import java.lang.reflect.Field;

/* JADX INFO: loaded from: classes5.dex */
public class FullyLinearLayoutManager extends LinearLayoutManager {
    private static final int CHILD_HEIGHT = 1;
    private static final int CHILD_WIDTH = 0;
    private static final int DEFAULT_CHILD_SIZE = 100;
    private static boolean canMakeInsetsDirty = true;
    private static Field insetsDirtyField = null;
    private final int[] childDimensions;
    private int childSize;
    private boolean hasChildSize;
    private int overScrollMode;
    private final Rect tmpRect;
    private final RecyclerView view;

    public FullyLinearLayoutManager(Context context) {
        super(context);
        this.childDimensions = new int[2];
        this.childSize = 100;
        this.overScrollMode = 0;
        this.tmpRect = new Rect();
        this.view = null;
    }

    public FullyLinearLayoutManager(Context context, int orientation, boolean reverseLayout) {
        super(context, orientation, reverseLayout);
        this.childDimensions = new int[2];
        this.childSize = 100;
        this.overScrollMode = 0;
        this.tmpRect = new Rect();
        this.view = null;
    }

    public FullyLinearLayoutManager(RecyclerView view) {
        super(view.getContext());
        this.childDimensions = new int[2];
        this.childSize = 100;
        this.overScrollMode = 0;
        this.tmpRect = new Rect();
        this.view = view;
        this.overScrollMode = ViewCompat.getOverScrollMode(view);
    }

    public FullyLinearLayoutManager(RecyclerView view, int orientation, boolean reverseLayout) {
        super(view.getContext(), orientation, reverseLayout);
        this.childDimensions = new int[2];
        this.childSize = 100;
        this.overScrollMode = 0;
        this.tmpRect = new Rect();
        this.view = view;
        this.overScrollMode = ViewCompat.getOverScrollMode(view);
    }

    public void setOverScrollMode(int overScrollMode) {
        if (overScrollMode < 0 || overScrollMode > 2) {
            throw new IllegalArgumentException("Unknown overscroll mode: " + overScrollMode);
        }
        RecyclerView recyclerView = this.view;
        if (recyclerView == null) {
            throw new IllegalStateException("view == null");
        }
        this.overScrollMode = overScrollMode;
        ViewCompat.setOverScrollMode(recyclerView, overScrollMode);
    }

    public static int makeUnspecifiedSpec() {
        return View.MeasureSpec.makeMeasureSpec(0, 0);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void onMeasure(RecyclerView.Recycler recycler, RecyclerView.State state, int widthSpec, int heightSpec) {
        boolean vertical;
        int width;
        int height;
        int adapterItemCount;
        int i;
        int stateItemCount;
        int stateItemCount2;
        int i2;
        int widthMode = View.MeasureSpec.getMode(widthSpec);
        int heightMode = View.MeasureSpec.getMode(heightSpec);
        int widthSize = View.MeasureSpec.getSize(widthSpec);
        int heightSize = View.MeasureSpec.getSize(heightSpec);
        int i3 = 1;
        boolean hasWidthSize = widthMode != 0;
        boolean hasHeightSize = heightMode != 0;
        boolean exactWidth = widthMode == 1073741824;
        boolean exactHeight = heightMode == 1073741824;
        int unspecified = makeUnspecifiedSpec();
        if (exactWidth && exactHeight) {
            super.onMeasure(recycler, state, widthSpec, heightSpec);
            return;
        }
        boolean vertical2 = getOrientation() == 1;
        initChildDimensions(widthSize, heightSize, vertical2);
        recycler.clear();
        int stateItemCount3 = state.getItemCount();
        int adapterItemCount2 = getItemCount();
        int i4 = 0;
        int width2 = 0;
        int height2 = 0;
        while (true) {
            if (i4 >= adapterItemCount2) {
                vertical = vertical2;
                break;
            }
            if (vertical2) {
                if (this.hasChildSize) {
                    adapterItemCount = adapterItemCount2;
                    stateItemCount2 = stateItemCount3;
                    vertical = vertical2;
                    i2 = i4;
                } else if (i4 < stateItemCount3) {
                    adapterItemCount = adapterItemCount2;
                    stateItemCount2 = stateItemCount3;
                    vertical = vertical2;
                    measureChild(recycler, i4, widthSize, unspecified, this.childDimensions);
                    i2 = i4;
                } else {
                    adapterItemCount = adapterItemCount2;
                    stateItemCount2 = stateItemCount3;
                    vertical = vertical2;
                    i2 = i4;
                    logMeasureWarning(i2);
                }
                int[] iArr = this.childDimensions;
                int height3 = height2 + iArr[i3];
                if (i2 == 0) {
                    width2 = iArr[0];
                }
                if (!hasHeightSize || height3 < heightSize) {
                    height2 = height3;
                    i = i2;
                    stateItemCount = stateItemCount2;
                    i4 = i + 1;
                    stateItemCount3 = stateItemCount;
                    adapterItemCount2 = adapterItemCount;
                    vertical2 = vertical;
                    i3 = 1;
                } else {
                    height2 = height3;
                    break;
                }
            } else {
                adapterItemCount = adapterItemCount2;
                int stateItemCount4 = stateItemCount3;
                vertical = vertical2;
                int i5 = i4;
                if (this.hasChildSize) {
                    i = i5;
                    stateItemCount = stateItemCount4;
                } else if (i5 < stateItemCount4) {
                    stateItemCount = stateItemCount4;
                    i = i5;
                    measureChild(recycler, i5, unspecified, heightSize, this.childDimensions);
                } else {
                    stateItemCount = stateItemCount4;
                    i = i5;
                    logMeasureWarning(i);
                }
                int[] iArr2 = this.childDimensions;
                int width3 = width2 + iArr2[0];
                if (i == 0) {
                    height2 = iArr2[1];
                }
                if (!hasWidthSize || width3 < widthSize) {
                    width2 = width3;
                    i4 = i + 1;
                    stateItemCount3 = stateItemCount;
                    adapterItemCount2 = adapterItemCount;
                    vertical2 = vertical;
                    i3 = 1;
                } else {
                    width2 = width3;
                    break;
                }
            }
        }
        if (exactWidth) {
            width = widthSize;
        } else {
            int width4 = getPaddingLeft();
            width = width2 + width4 + getPaddingRight();
            if (hasWidthSize) {
                width = Math.min(width, widthSize);
            }
        }
        if (exactHeight) {
            height = heightSize;
        } else {
            int height4 = getPaddingTop();
            height = height2 + height4 + getPaddingBottom();
            if (hasHeightSize) {
                height = Math.min(height, heightSize);
            }
        }
        setMeasuredDimension(width, height);
        if (this.view != null && this.overScrollMode == 1) {
            boolean fit = (vertical && (!hasHeightSize || height < heightSize)) || (!vertical && (!hasWidthSize || width < widthSize));
            ViewCompat.setOverScrollMode(this.view, fit ? 2 : 0);
        }
    }

    private void logMeasureWarning(int child) {
        LogUtils.dTag("LinearLayoutManager", "Can't measure child #" + child + ", previously used dimensions will be reused.To remove this message either use #setChildSize() method or don't run RecyclerView animations");
    }

    private void initChildDimensions(int width, int height, boolean vertical) {
        int[] iArr = this.childDimensions;
        if (iArr[0] != 0 || iArr[1] != 0) {
            return;
        }
        if (vertical) {
            iArr[0] = width;
            iArr[1] = this.childSize;
        } else {
            iArr[0] = this.childSize;
            iArr[1] = height;
        }
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager
    public void setOrientation(int orientation) {
        if (this.childDimensions != null && getOrientation() != orientation) {
            int[] iArr = this.childDimensions;
            iArr[0] = 0;
            iArr[1] = 0;
        }
        super.setOrientation(orientation);
    }

    public void clearChildSize() {
        this.hasChildSize = false;
        setChildSize(100);
    }

    public void setChildSize(int childSize) {
        this.hasChildSize = true;
        if (this.childSize != childSize) {
            this.childSize = childSize;
            requestLayout();
        }
    }

    private void measureChild(RecyclerView.Recycler recycler, int position, int widthSize, int heightSize, int[] dimensions) {
        try {
            View child = recycler.getViewForPosition(position);
            RecyclerView.LayoutParams p = (RecyclerView.LayoutParams) child.getLayoutParams();
            int hPadding = getPaddingLeft() + getPaddingRight();
            int vPadding = getPaddingTop() + getPaddingBottom();
            int hMargin = p.leftMargin + p.rightMargin;
            int vMargin = p.topMargin + p.bottomMargin;
            makeInsetsDirty(p);
            calculateItemDecorationsForChild(child, this.tmpRect);
            int hDecoration = getRightDecorationWidth(child) + getLeftDecorationWidth(child);
            int vDecoration = getTopDecorationHeight(child) + getBottomDecorationHeight(child);
            int childWidthSpec = getChildMeasureSpec(widthSize, hPadding + hMargin + hDecoration, p.width, canScrollHorizontally());
            int childHeightSpec = getChildMeasureSpec(heightSize, vPadding + vMargin + vDecoration, p.height, canScrollVertically());
            child.measure(childWidthSpec, childHeightSpec);
            dimensions[0] = getDecoratedMeasuredWidth(child) + p.leftMargin + p.rightMargin;
            dimensions[1] = getDecoratedMeasuredHeight(child) + p.bottomMargin + p.topMargin;
            makeInsetsDirty(p);
            recycler.recycleView(child);
        } catch (IndexOutOfBoundsException e) {
            LogUtils.dTag("LinearLayoutManager doesn't work well with animations. Consider switching them off", e);
        }
    }

    private static void makeInsetsDirty(RecyclerView.LayoutParams p) {
        if (!canMakeInsetsDirty) {
            return;
        }
        try {
            if (insetsDirtyField == null) {
                Field declaredField = RecyclerView.LayoutParams.class.getDeclaredField("mInsetsDirty");
                insetsDirtyField = declaredField;
                declaredField.setAccessible(true);
            }
            insetsDirtyField.set(p, true);
        } catch (IllegalAccessException e) {
            onMakeInsertDirtyFailed();
        } catch (NoSuchFieldException e2) {
            onMakeInsertDirtyFailed();
        }
    }

    private static void onMakeInsertDirtyFailed() {
        canMakeInsetsDirty = false;
        LogUtils.dTag("LinearLayoutManager", "Can't make LayoutParams insets dirty, decorations measurements might be incorrect");
    }
}
