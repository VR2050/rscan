package im.uwrkaxlmjj.ui.bottom;

import android.content.Context;
import android.content.res.TypedArray;
import android.os.Bundle;
import android.os.Parcelable;
import android.util.AttributeSet;
import android.view.View;
import android.widget.LinearLayout;
import androidx.viewpager.widget.ViewPager;
import com.blankj.utilcode.util.LogUtils;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.R;
import java.util.ArrayList;
import java.util.List;

/* JADX INFO: loaded from: classes5.dex */
public class BottomBarLayout extends LinearLayout implements ViewPager.OnPageChangeListener {
    private static final String STATE_INSTANCE = "instance_state";
    private static final String STATE_ITEM = "state_item";
    private int mChildCount;
    private int mCurrentItem;
    private List<BottomBarItem> mItemViews;
    private boolean mSmoothScroll;
    private ViewPager mViewPager;
    private OnItemLongClickListner onItemLongClickListner;
    private OnItemSelectedListener onItemSelectedListener;

    public interface OnItemLongClickListner {
        void onItemLongClick(BottomBarItem bottomBarItem, int i, int i2);
    }

    public interface OnItemSelectedListener {
        void onItemSelected(BottomBarItem bottomBarItem, int i, int i2);
    }

    public BottomBarLayout(Context context) {
        this(context, null);
    }

    public BottomBarLayout(Context context, AttributeSet attrs) {
        this(context, attrs, 0);
    }

    public BottomBarLayout(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        this.mItemViews = new ArrayList();
        TypedArray ta = context.obtainStyledAttributes(attrs, R.styleable.BottomBarLayout);
        this.mSmoothScroll = ta.getBoolean(0, false);
        ta.recycle();
    }

    @Override // android.view.View
    protected void onFinishInflate() {
        super.onFinishInflate();
        initBottomItem();
    }

    @Override // android.widget.LinearLayout
    public void setOrientation(int orientation) {
        super.setOrientation(orientation);
    }

    public void setViewPager(ViewPager viewPager) {
        this.mViewPager = viewPager;
        LogUtils.e("setViewPager");
        init();
    }

    private void initBottomItem() {
        this.mChildCount = getChildCount();
        for (int i = 0; i < this.mChildCount; i++) {
            if (getChildAt(i) instanceof BottomBarItem) {
                BottomBarItem bottomBarItem = (BottomBarItem) getChildAt(i);
                this.mItemViews.add(bottomBarItem);
                bottomBarItem.setOnClickListener(new MyOnClickListener(i));
                bottomBarItem.setOnLongClickListener(new MyOnLongClickListener(i));
            }
        }
    }

    private void init() {
        this.mItemViews.clear();
        int childCount = getChildCount();
        this.mChildCount = childCount;
        if (childCount == 0) {
            return;
        }
        if (this.mViewPager != null) {
            LogUtils.e("mViewPager.getAdapter().getCount()=" + this.mViewPager.getAdapter().getCount());
            LogUtils.e("mChildCount=" + this.mChildCount);
        }
        initBottomItem();
        if (this.mCurrentItem < this.mItemViews.size()) {
            this.mItemViews.get(this.mCurrentItem).refreshTab(true);
        }
        ViewPager viewPager = this.mViewPager;
        if (viewPager != null) {
            viewPager.addOnPageChangeListener(this);
        }
    }

    public void addItem(BottomBarItem item) {
        LinearLayout.LayoutParams layoutParams = new LinearLayout.LayoutParams(0, -2);
        layoutParams.weight = 1.0f;
        item.setLayoutParams(layoutParams);
        addView(item);
        LogUtils.e("addItem1111");
        init();
    }

    public void addItem(BottomBarItem item, int index) {
        LinearLayout.LayoutParams layoutParams = new LinearLayout.LayoutParams(0, -2);
        layoutParams.weight = 1.0f;
        item.setLayoutParams(layoutParams);
        addView(item, index);
        LogUtils.e("addItem2222");
        init();
    }

    public void removeItem(int position) {
        if (position >= 0 && position < this.mItemViews.size()) {
            BottomBarItem item = this.mItemViews.get(position);
            if (this.mItemViews.contains(item)) {
                resetState();
                removeViewAt(position);
                LogUtils.e("removeItem");
                init();
            }
        }
    }

    @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
    public void onPageScrolled(int position, float positionOffset, int positionOffsetPixels) {
    }

    @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
    public void onPageSelected(int position) {
        resetState();
        this.mItemViews.get(position).refreshTab(true);
        OnItemSelectedListener onItemSelectedListener = this.onItemSelectedListener;
        if (onItemSelectedListener != null) {
            onItemSelectedListener.onItemSelected(getBottomItem(position), this.mCurrentItem, position);
        }
        this.mCurrentItem = position;
    }

    @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
    public void onPageScrollStateChanged(int state) {
    }

    private class MyOnClickListener implements View.OnClickListener {
        private int currentIndex;

        public MyOnClickListener(int i) {
            this.currentIndex = i;
        }

        @Override // android.view.View.OnClickListener
        public void onClick(View v) {
            if (BottomBarLayout.this.mViewPager != null) {
                if (this.currentIndex == BottomBarLayout.this.mCurrentItem) {
                    if (BottomBarLayout.this.onItemSelectedListener != null) {
                        BottomBarLayout.this.onItemSelectedListener.onItemSelected(BottomBarLayout.this.getBottomItem(this.currentIndex), BottomBarLayout.this.mCurrentItem, this.currentIndex);
                        return;
                    }
                    return;
                } else {
                    try {
                        BottomBarLayout.this.mViewPager.setCurrentItem(this.currentIndex, BottomBarLayout.this.mSmoothScroll);
                        return;
                    } catch (Exception e) {
                        FileLog.e(e);
                        return;
                    }
                }
            }
            if (BottomBarLayout.this.onItemSelectedListener != null) {
                BottomBarLayout.this.onItemSelectedListener.onItemSelected(BottomBarLayout.this.getBottomItem(this.currentIndex), BottomBarLayout.this.mCurrentItem, this.currentIndex);
            }
            BottomBarLayout.this.updateTabState(this.currentIndex);
        }
    }

    private class MyOnLongClickListener implements View.OnLongClickListener {
        private int currentIndex;

        public MyOnLongClickListener(int currentIndex) {
            this.currentIndex = currentIndex;
        }

        @Override // android.view.View.OnLongClickListener
        public boolean onLongClick(View v) {
            if (BottomBarLayout.this.mViewPager != null && BottomBarLayout.this.onItemLongClickListner != null) {
                BottomBarLayout.this.onItemLongClickListner.onItemLongClick(BottomBarLayout.this.getBottomItem(this.currentIndex), BottomBarLayout.this.mCurrentItem, this.currentIndex);
                return false;
            }
            return false;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateTabState(int position) {
        resetState();
        this.mCurrentItem = position;
        this.mItemViews.get(position).refreshTab(true);
    }

    private void resetState() {
        if (this.mCurrentItem < this.mItemViews.size()) {
            this.mItemViews.get(this.mCurrentItem).refreshTab(false);
        }
    }

    public void setCurrentItem(int currentItem) {
        ViewPager viewPager = this.mViewPager;
        if (viewPager != null) {
            viewPager.setCurrentItem(currentItem, this.mSmoothScroll);
            return;
        }
        OnItemSelectedListener onItemSelectedListener = this.onItemSelectedListener;
        if (onItemSelectedListener != null) {
            onItemSelectedListener.onItemSelected(getBottomItem(currentItem), this.mCurrentItem, currentItem);
        }
        updateTabState(currentItem);
    }

    public void setUnread(int position, int unreadNum) {
        this.mItemViews.get(position).setUnreadNum(unreadNum);
    }

    public void setMsg(int position, String msg) {
        this.mItemViews.get(position).setMsg(msg);
    }

    public void hideMsg(int position) {
        this.mItemViews.get(position).hideMsg();
    }

    public void showNotify(int position) {
        this.mItemViews.get(position).showNotify();
    }

    public void hideNotify(int position) {
        this.mItemViews.get(position).hideNotify();
    }

    public int getCurrentItem() {
        return this.mCurrentItem;
    }

    public void setSmoothScroll(boolean smoothScroll) {
        this.mSmoothScroll = smoothScroll;
    }

    public BottomBarItem getBottomItem(int position) {
        return this.mItemViews.get(position);
    }

    @Override // android.view.View
    protected Parcelable onSaveInstanceState() {
        Bundle bundle = new Bundle();
        bundle.putParcelable(STATE_INSTANCE, super.onSaveInstanceState());
        bundle.putInt(STATE_ITEM, this.mCurrentItem);
        return bundle;
    }

    @Override // android.view.View
    protected void onRestoreInstanceState(Parcelable state) {
        if (state instanceof Bundle) {
            Bundle bundle = (Bundle) state;
            this.mCurrentItem = bundle.getInt(STATE_ITEM);
            resetState();
            this.mItemViews.get(this.mCurrentItem).refreshTab(true);
            super.onRestoreInstanceState(bundle.getParcelable(STATE_INSTANCE));
            return;
        }
        super.onRestoreInstanceState(state);
    }

    public void setOnItemSelectedListener(OnItemSelectedListener onItemSelectedListener) {
        this.onItemSelectedListener = onItemSelectedListener;
    }

    public void setOnItemLongClickListner(OnItemLongClickListner onItemLongClickListner) {
        this.onItemLongClickListner = onItemLongClickListner;
    }
}
