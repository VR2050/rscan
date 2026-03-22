package com.jbzd.media.movecartoons.view.layoutmanagergroup.viewpager;

import android.content.Context;
import android.view.View;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.PagerSnapHelper;
import androidx.recyclerview.widget.RecyclerView;

/* loaded from: classes2.dex */
public class ViewPagerLayoutManager extends LinearLayoutManager {
    private static final String TAG = "ViewPagerLayoutManager";
    private RecyclerView.OnChildAttachStateChangeListener mChildAttachStateChangeListener;
    private int mDrift;
    private OnViewPagerListener mOnViewPagerListener;
    private PagerSnapHelper mPagerSnapHelper;

    public ViewPagerLayoutManager(Context context, int i2) {
        super(context, i2, false);
        this.mChildAttachStateChangeListener = new RecyclerView.OnChildAttachStateChangeListener() { // from class: com.jbzd.media.movecartoons.view.layoutmanagergroup.viewpager.ViewPagerLayoutManager.1
            @Override // androidx.recyclerview.widget.RecyclerView.OnChildAttachStateChangeListener
            public void onChildViewAttachedToWindow(View view) {
                if (ViewPagerLayoutManager.this.mOnViewPagerListener == null || ViewPagerLayoutManager.this.getChildCount() != 1) {
                    return;
                }
                ViewPagerLayoutManager.this.mOnViewPagerListener.onInitComplete();
            }

            @Override // androidx.recyclerview.widget.RecyclerView.OnChildAttachStateChangeListener
            public void onChildViewDetachedFromWindow(View view) {
                if (ViewPagerLayoutManager.this.mDrift >= 0) {
                    if (ViewPagerLayoutManager.this.mOnViewPagerListener != null) {
                        ViewPagerLayoutManager.this.mOnViewPagerListener.onPageRelease(true, ViewPagerLayoutManager.this.getPosition(view));
                    }
                } else if (ViewPagerLayoutManager.this.mOnViewPagerListener != null) {
                    ViewPagerLayoutManager.this.mOnViewPagerListener.onPageRelease(false, ViewPagerLayoutManager.this.getPosition(view));
                }
            }
        };
        init();
    }

    private void init() {
        this.mPagerSnapHelper = new PagerSnapHelper();
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void onAttachedToWindow(RecyclerView recyclerView) {
        super.onAttachedToWindow(recyclerView);
        this.mPagerSnapHelper.attachToRecyclerView(recyclerView);
        recyclerView.addOnChildAttachStateChangeListener(this.mChildAttachStateChangeListener);
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void onLayoutChildren(RecyclerView.Recycler recycler, RecyclerView.State state) {
        super.onLayoutChildren(recycler, state);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void onScrollStateChanged(int i2) {
        View findSnapView;
        if (i2 == 0) {
            View findSnapView2 = this.mPagerSnapHelper.findSnapView(this);
            if (findSnapView2 != null) {
                int position = getPosition(findSnapView2);
                if (this.mOnViewPagerListener == null || getChildCount() != 1) {
                    return;
                }
                this.mOnViewPagerListener.onPageSelected(position, position == getItemCount() - 1);
                return;
            }
            return;
        }
        if (i2 != 1) {
            if (i2 == 2 && (findSnapView = this.mPagerSnapHelper.findSnapView(this)) != null) {
                getPosition(findSnapView);
                return;
            }
            return;
        }
        View findSnapView3 = this.mPagerSnapHelper.findSnapView(this);
        if (findSnapView3 != null) {
            getPosition(findSnapView3);
        }
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public int scrollHorizontallyBy(int i2, RecyclerView.Recycler recycler, RecyclerView.State state) {
        this.mDrift = i2;
        return super.scrollHorizontallyBy(i2, recycler, state);
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public int scrollVerticallyBy(int i2, RecyclerView.Recycler recycler, RecyclerView.State state) {
        this.mDrift = i2;
        return super.scrollVerticallyBy(i2, recycler, state);
    }

    public void setOnViewPagerListener(OnViewPagerListener onViewPagerListener) {
        this.mOnViewPagerListener = onViewPagerListener;
    }

    public ViewPagerLayoutManager(Context context, int i2, boolean z) {
        super(context, i2, z);
        this.mChildAttachStateChangeListener = new RecyclerView.OnChildAttachStateChangeListener() { // from class: com.jbzd.media.movecartoons.view.layoutmanagergroup.viewpager.ViewPagerLayoutManager.1
            @Override // androidx.recyclerview.widget.RecyclerView.OnChildAttachStateChangeListener
            public void onChildViewAttachedToWindow(View view) {
                if (ViewPagerLayoutManager.this.mOnViewPagerListener == null || ViewPagerLayoutManager.this.getChildCount() != 1) {
                    return;
                }
                ViewPagerLayoutManager.this.mOnViewPagerListener.onInitComplete();
            }

            @Override // androidx.recyclerview.widget.RecyclerView.OnChildAttachStateChangeListener
            public void onChildViewDetachedFromWindow(View view) {
                if (ViewPagerLayoutManager.this.mDrift >= 0) {
                    if (ViewPagerLayoutManager.this.mOnViewPagerListener != null) {
                        ViewPagerLayoutManager.this.mOnViewPagerListener.onPageRelease(true, ViewPagerLayoutManager.this.getPosition(view));
                    }
                } else if (ViewPagerLayoutManager.this.mOnViewPagerListener != null) {
                    ViewPagerLayoutManager.this.mOnViewPagerListener.onPageRelease(false, ViewPagerLayoutManager.this.getPosition(view));
                }
            }
        };
        init();
    }
}
