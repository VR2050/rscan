package im.uwrkaxlmjj.ui.hui.decoration;

import android.graphics.Canvas;
import android.graphics.Rect;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.view.View;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.ui.actionbar.Theme;

/* JADX INFO: loaded from: classes5.dex */
public class TopBottomDecoration extends BaseItemDecoration<TopBottomDecoration> {
    private int mBottomOffset;
    private int mColor;
    private float mCornerRadius;
    private float[] mCornerRadiusArr;
    private Drawable mDrawable;
    private int mFirstRowPosition;
    private boolean mIsDpValue;
    private int mItemBgColor;
    private int mLastRowPosition;
    private boolean mRoundCornerBottom;
    private boolean mRoundCornerTop;
    private int mTopOffset;

    public TopBottomDecoration() {
        this(10, 10);
    }

    public TopBottomDecoration(int topOffset, int bottomOffset) {
        this(topOffset, bottomOffset, true);
    }

    public TopBottomDecoration(int topOffset, int bottomOffset, boolean isDpValue) {
        this.mTopOffset = topOffset;
        this.mBottomOffset = bottomOffset;
        this.mIsDpValue = isDpValue;
    }

    public TopBottomDecoration(int topOffset, int bottomOffset, float conerRadius, boolean isDpValue, int color, int itemBgColor) {
        this.mTopOffset = topOffset;
        this.mBottomOffset = bottomOffset;
        this.mIsDpValue = isDpValue;
        this.mRoundCornerTop = true;
        this.mRoundCornerBottom = true;
        this.mCornerRadius = isDpValue ? AndroidUtilities.dp(conerRadius) : conerRadius;
        setOffsetColor(color);
        setItemBgColor(itemBgColor);
    }

    public static TopBottomDecoration getDefaultTopBottomCornerBg(int topOffset, int bottomOffset, float conerRadius) {
        return new TopBottomDecoration(topOffset, bottomOffset, conerRadius, true, Theme.getColor(Theme.key_windowBackgroundGray), Theme.getColor(Theme.key_windowBackgroundWhite));
    }

    @Override // androidx.recyclerview.widget.RecyclerView.ItemDecoration
    public void getItemOffsets(Rect outRect, View view, RecyclerView parent, RecyclerView.State state) {
        super.getItemOffsets(outRect, view, parent, state);
        int position = parent.getChildAdapterPosition(view);
        boolean isHorizontal = isHorizontal(parent);
        int iDp = this.mTopOffset;
        if (iDp != 0 && position == 0) {
            if (isHorizontal) {
                if (this.mIsDpValue) {
                    iDp = AndroidUtilities.dp(iDp);
                }
                outRect.left = iDp;
            } else {
                if (this.mIsDpValue) {
                    iDp = AndroidUtilities.dp(iDp);
                }
                outRect.top = iDp;
            }
        }
        if (this.mBottomOffset != 0 && parent.getAdapter() != null && position == parent.getAdapter().getItemCount() - 1) {
            if (isHorizontal) {
                outRect.right = this.mIsDpValue ? AndroidUtilities.dp(this.mBottomOffset) : this.mBottomOffset;
            } else {
                outRect.bottom = this.mIsDpValue ? AndroidUtilities.dp(this.mBottomOffset) : this.mBottomOffset;
            }
        }
    }

    @Override // androidx.recyclerview.widget.RecyclerView.ItemDecoration
    public void onDraw(Canvas c, RecyclerView parent, RecyclerView.State state) {
        super.onDraw(c, parent, state);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.ItemDecoration
    public void onDrawOver(Canvas c, RecyclerView parent, RecyclerView.State state) {
        RecyclerView.Adapter adapter;
        int left;
        int i;
        RecyclerView recyclerView = parent;
        super.onDrawOver(c, parent, state);
        RecyclerView.Adapter adapter2 = parent.getAdapter();
        if (this.mDrawable != null && adapter2 != null) {
            int left2 = parent.getPaddingLeft();
            int width = parent.getWidth() - parent.getPaddingRight();
            int childCount = parent.getChildCount();
            int itemCount = adapter2.getItemCount();
            boolean isHorizontal = isHorizontal(recyclerView);
            int i2 = 0;
            while (i2 < childCount) {
                View child = recyclerView.getChildAt(i2);
                if (child == null) {
                    adapter = adapter2;
                    left = left2;
                } else {
                    int childPosition = recyclerView.getChildAdapterPosition(child);
                    if (adapter2 != null && this.mExcludeViewTypeList.contains(Integer.valueOf(adapter2.getItemViewType(childPosition)))) {
                        adapter = adapter2;
                        left = left2;
                    } else {
                        if (!this.mRoundCornerTop || childPosition != this.mFirstRowPosition) {
                            adapter = adapter2;
                            left = left2;
                            if (this.mRoundCornerBottom && (((i = this.mLastRowPosition) > 0 && childPosition == i) || (this.mLastRowPosition <= 0 && childPosition == itemCount - 1))) {
                                float[] fArr = this.mCornerRadiusArr;
                                if (fArr != null && fArr.length == 4) {
                                    child.setBackground(Theme.createRoundRectDrawable(fArr[0], fArr[1], fArr[2], fArr[3], this.mItemBgColor));
                                } else {
                                    float f = this.mCornerRadius;
                                    if (f != 0.0f) {
                                        if (isHorizontal) {
                                            child.setBackground(Theme.createRoundRectDrawable(0.0f, f, 0.0f, f, this.mItemBgColor));
                                        } else {
                                            child.setBackground(Theme.createRoundRectDrawable(0.0f, 0.0f, f, f, this.mItemBgColor));
                                        }
                                    }
                                }
                            } else {
                                int i3 = this.mItemBgColor;
                                if (i3 != 0) {
                                    child.setBackgroundColor(i3);
                                }
                            }
                        } else {
                            float[] fArr2 = this.mCornerRadiusArr;
                            if (fArr2 == null || fArr2.length != 4) {
                                adapter = adapter2;
                                left = left2;
                                float f2 = this.mCornerRadius;
                                if (f2 != 0.0f) {
                                    if (itemCount == 1) {
                                        child.setBackground(Theme.createRoundRectDrawable(f2, f2, f2, f2, this.mItemBgColor));
                                    } else if (isHorizontal) {
                                        child.setBackground(Theme.createRoundRectDrawable(f2, 0.0f, f2, 0.0f, this.mItemBgColor));
                                    } else {
                                        child.setBackground(Theme.createRoundRectDrawable(f2, f2, 0.0f, 0.0f, this.mItemBgColor));
                                    }
                                }
                            } else {
                                float f3 = fArr2[0];
                                float f4 = fArr2[1];
                                adapter = adapter2;
                                float f5 = fArr2[2];
                                float f6 = fArr2[3];
                                left = left2;
                                int left3 = this.mItemBgColor;
                                child.setBackground(Theme.createRoundRectDrawable(f3, f4, f5, f6, left3));
                            }
                        }
                    }
                }
                i2++;
                recyclerView = parent;
                adapter2 = adapter;
                left2 = left;
            }
        }
    }

    public TopBottomDecoration setOffsetColor(int offsetColor) {
        if (this.mColor != offsetColor) {
            this.mColor = offsetColor;
            this.mDrawable = new ColorDrawable(this.mColor);
        }
        return this;
    }

    public TopBottomDecoration setItemBgColor(int itemBgColor) {
        this.mItemBgColor = itemBgColor;
        return this;
    }

    public TopBottomDecoration setDrawable(Drawable drawable) {
        this.mDrawable = drawable;
        return this;
    }

    public TopBottomDecoration setTopOffset(int topOffset) {
        this.mTopOffset = topOffset;
        return this;
    }

    public TopBottomDecoration setBottomOffset(int bottomOffset) {
        this.mBottomOffset = bottomOffset;
        return this;
    }

    public TopBottomDecoration setIsDpValue(boolean isDpValue) {
        this.mIsDpValue = isDpValue;
        return this;
    }

    public TopBottomDecoration setRoundCornerTop(boolean roundCornerTop) {
        this.mRoundCornerTop = roundCornerTop;
        return this;
    }

    public TopBottomDecoration setRoundCornerBottom(boolean roundCornerBottom) {
        this.mRoundCornerBottom = roundCornerBottom;
        return this;
    }

    public TopBottomDecoration setCornerRadius(float cornerRadius) {
        this.mCornerRadius = cornerRadius;
        return this;
    }

    public TopBottomDecoration setCornerRadiusArr(float[] cornerRadiusArr) {
        this.mCornerRadiusArr = cornerRadiusArr;
        return this;
    }

    public TopBottomDecoration setFirstRowPosition(int firstRowPosition) {
        this.mFirstRowPosition = firstRowPosition;
        return this;
    }

    public TopBottomDecoration setLastRowPosition(int lastRowPosition) {
        this.mLastRowPosition = lastRowPosition;
        return this;
    }
}
