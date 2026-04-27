package com.scwang.smartrefresh.layout.impl;

import android.animation.ValueAnimator;
import android.graphics.PointF;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AbsListView;
import android.widget.FrameLayout;
import androidx.core.view.NestedScrollingChild;
import androidx.core.view.NestedScrollingParent;
import androidx.legacy.widget.Space;
import androidx.viewpager.widget.ViewPager;
import com.scwang.smartrefresh.layout.api.RefreshContent;
import com.scwang.smartrefresh.layout.api.RefreshKernel;
import com.scwang.smartrefresh.layout.api.ScrollBoundaryDecider;
import com.scwang.smartrefresh.layout.listener.CoordinatorLayoutListener;
import com.scwang.smartrefresh.layout.util.DesignUtil;
import com.scwang.smartrefresh.layout.util.SmartUtil;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;

/* JADX INFO: loaded from: classes3.dex */
public class RefreshContentWrapper implements RefreshContent, CoordinatorLayoutListener, ValueAnimator.AnimatorUpdateListener {
    protected View mContentView;
    protected View mFixedFooter;
    protected View mFixedHeader;
    protected View mOriginalContentView;
    protected View mScrollableView;
    protected int mLastSpinner = 0;
    protected boolean mEnableRefresh = true;
    protected boolean mEnableLoadMore = true;
    protected ScrollBoundaryDeciderAdapter mBoundaryAdapter = new ScrollBoundaryDeciderAdapter();

    public RefreshContentWrapper(View view) {
        this.mScrollableView = view;
        this.mOriginalContentView = view;
        this.mContentView = view;
    }

    protected void findScrollableView(View content, RefreshKernel kernel) {
        View scrollableView = null;
        boolean isInEditMode = this.mContentView.isInEditMode();
        while (true) {
            if (scrollableView != null && (!(scrollableView instanceof NestedScrollingParent) || (scrollableView instanceof NestedScrollingChild))) {
                break;
            }
            content = findScrollableViewInternal(content, scrollableView == null);
            if (content == scrollableView) {
                break;
            }
            if (!isInEditMode) {
                DesignUtil.checkCoordinatorLayout(content, kernel, this);
            }
            scrollableView = content;
        }
        if (scrollableView != null) {
            this.mScrollableView = scrollableView;
        }
    }

    @Override // com.scwang.smartrefresh.layout.listener.CoordinatorLayoutListener
    public void onCoordinatorUpdate(boolean enableRefresh, boolean enableLoadMore) {
        this.mEnableRefresh = enableRefresh;
        this.mEnableLoadMore = enableLoadMore;
    }

    protected View findScrollableViewInternal(View content, boolean selfAble) {
        View scrollableView = null;
        Queue<View> views = new LinkedList<>();
        List<View> list = (List) views;
        list.add(content);
        while (list.size() > 0 && scrollableView == null) {
            View view = views.poll();
            if (view != null) {
                if ((selfAble || view != content) && SmartUtil.isContentView(view)) {
                    scrollableView = view;
                } else if (view instanceof ViewGroup) {
                    ViewGroup group = (ViewGroup) view;
                    for (int j = 0; j < group.getChildCount(); j++) {
                        list.add(group.getChildAt(j));
                    }
                }
            }
        }
        return scrollableView == null ? content : scrollableView;
    }

    protected View findScrollableViewByPoint(View content, PointF event, View orgScrollableView) {
        if ((content instanceof ViewGroup) && event != null) {
            ViewGroup viewGroup = (ViewGroup) content;
            int childCount = viewGroup.getChildCount();
            PointF point = new PointF();
            for (int i = childCount; i > 0; i--) {
                View child = viewGroup.getChildAt(i - 1);
                if (SmartUtil.isTransformedTouchPointInView(viewGroup, child, event.x, event.y, point)) {
                    if ((child instanceof ViewPager) || !SmartUtil.isContentView(child)) {
                        event.offset(point.x, point.y);
                        View child2 = findScrollableViewByPoint(child, event, orgScrollableView);
                        event.offset(-point.x, -point.y);
                        return child2;
                    }
                    return child;
                }
            }
        }
        return orgScrollableView;
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshContent
    public View getView() {
        return this.mContentView;
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshContent
    public View getScrollableView() {
        return this.mScrollableView;
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshContent
    public void moveSpinner(int spinner, int headerTranslationViewId, int footerTranslationViewId) {
        View footerTranslationView;
        View headerTranslationView;
        boolean translated = false;
        if (headerTranslationViewId != -1 && (headerTranslationView = this.mOriginalContentView.findViewById(headerTranslationViewId)) != null) {
            if (spinner > 0) {
                translated = true;
                headerTranslationView.setTranslationY(spinner);
            } else if (headerTranslationView.getTranslationY() > 0.0f) {
                headerTranslationView.setTranslationY(0.0f);
            }
        }
        if (footerTranslationViewId != -1 && (footerTranslationView = this.mOriginalContentView.findViewById(footerTranslationViewId)) != null) {
            if (spinner < 0) {
                translated = true;
                footerTranslationView.setTranslationY(spinner);
            } else if (footerTranslationView.getTranslationY() < 0.0f) {
                footerTranslationView.setTranslationY(0.0f);
            }
        }
        if (!translated) {
            this.mOriginalContentView.setTranslationY(spinner);
        } else {
            this.mOriginalContentView.setTranslationY(0.0f);
        }
        View view = this.mFixedHeader;
        if (view != null) {
            view.setTranslationY(Math.max(0, spinner));
        }
        View view2 = this.mFixedFooter;
        if (view2 != null) {
            view2.setTranslationY(Math.min(0, spinner));
        }
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshContent
    public boolean canRefresh() {
        return this.mEnableRefresh && this.mBoundaryAdapter.canRefresh(this.mContentView);
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshContent
    public boolean canLoadMore() {
        return this.mEnableLoadMore && this.mBoundaryAdapter.canLoadMore(this.mContentView);
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshContent
    public void onActionDown(MotionEvent e) {
        PointF point = new PointF(e.getX(), e.getY());
        point.offset(-this.mContentView.getLeft(), -this.mContentView.getTop());
        View view = this.mScrollableView;
        View view2 = this.mContentView;
        if (view != view2) {
            this.mScrollableView = findScrollableViewByPoint(view2, point, view);
        }
        if (this.mScrollableView == this.mContentView) {
            this.mBoundaryAdapter.mActionEvent = null;
        } else {
            this.mBoundaryAdapter.mActionEvent = point;
        }
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshContent
    public void setUpComponent(RefreshKernel kernel, View fixedHeader, View fixedFooter) {
        findScrollableView(this.mContentView, kernel);
        if (fixedHeader != null || fixedFooter != null) {
            this.mFixedHeader = fixedHeader;
            this.mFixedFooter = fixedFooter;
            ViewGroup frameLayout = new FrameLayout(this.mContentView.getContext());
            int index = kernel.getRefreshLayout().getLayout().indexOfChild(this.mContentView);
            kernel.getRefreshLayout().getLayout().removeView(this.mContentView);
            frameLayout.addView(this.mContentView, 0, new ViewGroup.LayoutParams(-1, -1));
            ViewGroup.LayoutParams layoutParams = this.mContentView.getLayoutParams();
            kernel.getRefreshLayout().getLayout().addView(frameLayout, index, layoutParams);
            this.mContentView = frameLayout;
            if (fixedHeader != null) {
                fixedHeader.setTag("fixed-top");
                ViewGroup.LayoutParams lp = fixedHeader.getLayoutParams();
                ViewGroup parent = (ViewGroup) fixedHeader.getParent();
                int index2 = parent.indexOfChild(fixedHeader);
                parent.removeView(fixedHeader);
                lp.height = SmartUtil.measureViewHeight(fixedHeader);
                parent.addView(new Space(this.mContentView.getContext()), index2, lp);
                frameLayout.addView(fixedHeader, 1, lp);
            }
            if (fixedFooter != null) {
                fixedFooter.setTag("fixed-bottom");
                ViewGroup.LayoutParams lp2 = fixedFooter.getLayoutParams();
                ViewGroup parent2 = (ViewGroup) fixedFooter.getParent();
                int index3 = parent2.indexOfChild(fixedFooter);
                parent2.removeView(fixedFooter);
                FrameLayout.LayoutParams flp = new FrameLayout.LayoutParams(lp2);
                lp2.height = SmartUtil.measureViewHeight(fixedFooter);
                parent2.addView(new Space(this.mContentView.getContext()), index3, lp2);
                flp.gravity = 80;
                frameLayout.addView(fixedFooter, 1, flp);
            }
        }
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshContent
    public void setScrollBoundaryDecider(ScrollBoundaryDecider boundary) {
        if (boundary instanceof ScrollBoundaryDeciderAdapter) {
            this.mBoundaryAdapter = (ScrollBoundaryDeciderAdapter) boundary;
        } else {
            this.mBoundaryAdapter.boundary = boundary;
        }
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshContent
    public void setEnableLoadMoreWhenContentNotFull(boolean enable) {
        this.mBoundaryAdapter.mEnableLoadMoreWhenContentNotFull = enable;
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshContent
    public ValueAnimator.AnimatorUpdateListener scrollContentWhenFinished(int spinner) {
        View view = this.mScrollableView;
        if (view != null && spinner != 0) {
            if ((spinner < 0 && SmartUtil.canScrollVertically(view, 1)) || (spinner > 0 && SmartUtil.canScrollVertically(this.mScrollableView, -1))) {
                this.mLastSpinner = spinner;
                return this;
            }
            return null;
        }
        return null;
    }

    @Override // android.animation.ValueAnimator.AnimatorUpdateListener
    public void onAnimationUpdate(ValueAnimator animation) {
        int value = ((Integer) animation.getAnimatedValue()).intValue();
        try {
            float dy = (value - this.mLastSpinner) * this.mScrollableView.getScaleY();
            if (this.mScrollableView instanceof AbsListView) {
                SmartUtil.scrollListBy((AbsListView) this.mScrollableView, (int) dy);
            } else {
                this.mScrollableView.scrollBy(0, (int) dy);
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
        this.mLastSpinner = value;
    }
}
