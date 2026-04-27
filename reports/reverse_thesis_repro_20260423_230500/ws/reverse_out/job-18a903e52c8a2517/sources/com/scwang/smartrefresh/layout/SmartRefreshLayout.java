package com.scwang.smartrefresh.layout;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.ValueAnimator;
import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.os.Build;
import android.os.Handler;
import android.util.AttributeSet;
import android.view.MotionEvent;
import android.view.VelocityTracker;
import android.view.View;
import android.view.ViewConfiguration;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.view.animation.AnimationUtils;
import android.view.animation.Interpolator;
import android.widget.Scroller;
import android.widget.TextView;
import android.widget.Toast;
import androidx.core.content.ContextCompat;
import androidx.core.view.NestedScrollingChildHelper;
import androidx.core.view.NestedScrollingParent;
import androidx.core.view.NestedScrollingParentHelper;
import com.google.firebase.remoteconfig.FirebaseRemoteConfig;
import com.scwang.smartrefresh.layout.api.DefaultRefreshFooterCreator;
import com.scwang.smartrefresh.layout.api.DefaultRefreshHeaderCreator;
import com.scwang.smartrefresh.layout.api.DefaultRefreshInitializer;
import com.scwang.smartrefresh.layout.api.RefreshContent;
import com.scwang.smartrefresh.layout.api.RefreshFooter;
import com.scwang.smartrefresh.layout.api.RefreshHeader;
import com.scwang.smartrefresh.layout.api.RefreshInternal;
import com.scwang.smartrefresh.layout.api.RefreshKernel;
import com.scwang.smartrefresh.layout.api.RefreshLayout;
import com.scwang.smartrefresh.layout.api.ScrollBoundaryDecider;
import com.scwang.smartrefresh.layout.constant.DimensionStatus;
import com.scwang.smartrefresh.layout.constant.RefreshState;
import com.scwang.smartrefresh.layout.constant.SpinnerStyle;
import com.scwang.smartrefresh.layout.footer.BallPulseFooter;
import com.scwang.smartrefresh.layout.header.BezierRadarHeader;
import com.scwang.smartrefresh.layout.impl.RefreshContentWrapper;
import com.scwang.smartrefresh.layout.impl.RefreshFooterWrapper;
import com.scwang.smartrefresh.layout.impl.RefreshHeaderWrapper;
import com.scwang.smartrefresh.layout.listener.OnLoadMoreListener;
import com.scwang.smartrefresh.layout.listener.OnMultiPurposeListener;
import com.scwang.smartrefresh.layout.listener.OnRefreshListener;
import com.scwang.smartrefresh.layout.listener.OnRefreshLoadMoreListener;
import com.scwang.smartrefresh.layout.listener.OnStateChangedListener;
import com.scwang.smartrefresh.layout.util.SmartUtil;

/* JADX INFO: loaded from: classes3.dex */
public class SmartRefreshLayout extends ViewGroup implements RefreshLayout, NestedScrollingParent {
    protected Runnable animationRunnable;
    protected boolean mAttachedToWindow;
    protected int mCurrentVelocity;
    protected boolean mDisableContentWhenLoading;
    protected boolean mDisableContentWhenRefresh;
    protected char mDragDirection;
    protected float mDragRate;
    protected boolean mEnableAutoLoadMore;
    protected boolean mEnableClipFooterWhenFixedBehind;
    protected boolean mEnableClipHeaderWhenFixedBehind;
    protected boolean mEnableFooterFollowWhenNoMoreData;
    protected boolean mEnableFooterTranslationContent;
    protected boolean mEnableHeaderTranslationContent;
    protected boolean mEnableLoadMore;
    protected boolean mEnableLoadMoreWhenContentNotFull;
    protected boolean mEnableNestedScrolling;
    protected boolean mEnableOverScrollBounce;
    protected boolean mEnableOverScrollDrag;
    protected boolean mEnablePreviewInEditMode;
    protected boolean mEnablePureScrollMode;
    protected boolean mEnableRefresh;
    protected boolean mEnableScrollContentWhenLoaded;
    protected boolean mEnableScrollContentWhenRefreshed;
    protected MotionEvent mFalsifyEvent;
    protected int mFixedFooterViewId;
    protected int mFixedHeaderViewId;
    protected int mFloorDuration;
    protected int mFooterBackgroundColor;
    protected int mFooterHeight;
    protected DimensionStatus mFooterHeightStatus;
    protected int mFooterInsetStart;
    protected boolean mFooterLocked;
    protected float mFooterMaxDragRate;
    protected boolean mFooterNeedTouchEventWhenLoading;
    protected boolean mFooterNoMoreData;
    protected boolean mFooterNoMoreDataEffective;
    protected int mFooterTranslationViewId;
    protected float mFooterTriggerRate;
    protected Handler mHandler;
    protected int mHeaderBackgroundColor;
    protected int mHeaderHeight;
    protected DimensionStatus mHeaderHeightStatus;
    protected int mHeaderInsetStart;
    protected float mHeaderMaxDragRate;
    protected boolean mHeaderNeedTouchEventWhenRefreshing;
    protected int mHeaderTranslationViewId;
    protected float mHeaderTriggerRate;
    protected boolean mIsBeingDragged;
    protected RefreshKernel mKernel;
    protected long mLastOpenTime;
    protected int mLastSpinner;
    protected float mLastTouchX;
    protected float mLastTouchY;
    protected OnLoadMoreListener mLoadMoreListener;
    protected boolean mManualFooterTranslationContent;
    protected boolean mManualHeaderTranslationContent;
    protected boolean mManualLoadMore;
    protected int mMaximumVelocity;
    protected int mMinimumVelocity;
    protected NestedScrollingChildHelper mNestedChild;
    protected boolean mNestedInProgress;
    protected NestedScrollingParentHelper mNestedParent;
    protected OnMultiPurposeListener mOnMultiPurposeListener;
    protected Paint mPaint;
    protected int[] mParentOffsetInWindow;
    protected int[] mPrimaryColors;
    protected int mReboundDuration;
    protected Interpolator mReboundInterpolator;
    protected RefreshContent mRefreshContent;
    protected RefreshInternal mRefreshFooter;
    protected RefreshInternal mRefreshHeader;
    protected OnRefreshListener mRefreshListener;
    protected int mScreenHeightPixels;
    protected ScrollBoundaryDecider mScrollBoundaryDecider;
    protected Scroller mScroller;
    protected int mSpinner;
    protected RefreshState mState;
    protected boolean mSuperDispatchTouchEvent;
    protected int mTotalUnconsumed;
    protected int mTouchSlop;
    protected int mTouchSpinner;
    protected float mTouchX;
    protected float mTouchY;
    protected VelocityTracker mVelocityTracker;
    protected boolean mVerticalPermit;
    protected RefreshState mViceState;
    protected ValueAnimator reboundAnimator;
    protected static DefaultRefreshFooterCreator sFooterCreator = null;
    protected static DefaultRefreshHeaderCreator sHeaderCreator = null;
    protected static DefaultRefreshInitializer sRefreshInitializer = null;
    protected static ViewGroup.MarginLayoutParams sDefaultMarginLP = new ViewGroup.MarginLayoutParams(-1, -1);

    public SmartRefreshLayout(Context context) {
        this(context, null);
    }

    public SmartRefreshLayout(Context context, AttributeSet attrs) {
        super(context, attrs);
        this.mFloorDuration = 300;
        this.mReboundDuration = 300;
        this.mDragRate = 0.5f;
        this.mDragDirection = 'n';
        this.mFixedHeaderViewId = -1;
        this.mFixedFooterViewId = -1;
        this.mHeaderTranslationViewId = -1;
        this.mFooterTranslationViewId = -1;
        this.mEnableRefresh = true;
        this.mEnableLoadMore = false;
        this.mEnableClipHeaderWhenFixedBehind = true;
        this.mEnableClipFooterWhenFixedBehind = true;
        this.mEnableHeaderTranslationContent = true;
        this.mEnableFooterTranslationContent = true;
        this.mEnableFooterFollowWhenNoMoreData = false;
        this.mEnablePreviewInEditMode = true;
        this.mEnableOverScrollBounce = true;
        this.mEnableOverScrollDrag = false;
        this.mEnableAutoLoadMore = true;
        this.mEnablePureScrollMode = false;
        this.mEnableScrollContentWhenLoaded = true;
        this.mEnableScrollContentWhenRefreshed = true;
        this.mEnableLoadMoreWhenContentNotFull = true;
        this.mEnableNestedScrolling = true;
        this.mDisableContentWhenRefresh = false;
        this.mDisableContentWhenLoading = false;
        this.mFooterNoMoreData = false;
        this.mFooterNoMoreDataEffective = false;
        this.mManualLoadMore = false;
        this.mManualHeaderTranslationContent = false;
        this.mManualFooterTranslationContent = false;
        this.mParentOffsetInWindow = new int[2];
        this.mNestedChild = new NestedScrollingChildHelper(this);
        this.mNestedParent = new NestedScrollingParentHelper(this);
        this.mHeaderHeightStatus = DimensionStatus.DefaultUnNotify;
        this.mFooterHeightStatus = DimensionStatus.DefaultUnNotify;
        this.mHeaderMaxDragRate = 2.5f;
        this.mFooterMaxDragRate = 2.5f;
        this.mHeaderTriggerRate = 1.0f;
        this.mFooterTriggerRate = 1.0f;
        this.mKernel = new RefreshKernelImpl();
        this.mState = RefreshState.None;
        this.mViceState = RefreshState.None;
        this.mLastOpenTime = 0L;
        this.mHeaderBackgroundColor = 0;
        this.mFooterBackgroundColor = 0;
        this.mFooterLocked = false;
        this.mVerticalPermit = false;
        this.mFalsifyEvent = null;
        ViewConfiguration configuration = ViewConfiguration.get(context);
        this.mHandler = new Handler();
        this.mScroller = new Scroller(context);
        this.mVelocityTracker = VelocityTracker.obtain();
        this.mScreenHeightPixels = context.getResources().getDisplayMetrics().heightPixels;
        this.mReboundInterpolator = new SmartUtil(SmartUtil.INTERPOLATOR_VISCOUS_FLUID);
        this.mTouchSlop = configuration.getScaledTouchSlop();
        this.mMinimumVelocity = configuration.getScaledMinimumFlingVelocity();
        this.mMaximumVelocity = configuration.getScaledMaximumFlingVelocity();
        this.mFooterHeight = SmartUtil.dp2px(60.0f);
        this.mHeaderHeight = SmartUtil.dp2px(100.0f);
        TypedArray ta = context.obtainStyledAttributes(attrs, R.styleable.SmartRefreshLayout);
        if (!ta.hasValue(R.styleable.SmartRefreshLayout_android_clipToPadding)) {
            super.setClipToPadding(false);
        }
        if (!ta.hasValue(R.styleable.SmartRefreshLayout_android_clipChildren)) {
            super.setClipChildren(false);
        }
        DefaultRefreshInitializer defaultRefreshInitializer = sRefreshInitializer;
        if (defaultRefreshInitializer != null) {
            defaultRefreshInitializer.initialize(context, this);
        }
        this.mDragRate = ta.getFloat(R.styleable.SmartRefreshLayout_srlDragRate, this.mDragRate);
        this.mHeaderMaxDragRate = ta.getFloat(R.styleable.SmartRefreshLayout_srlHeaderMaxDragRate, this.mHeaderMaxDragRate);
        this.mFooterMaxDragRate = ta.getFloat(R.styleable.SmartRefreshLayout_srlFooterMaxDragRate, this.mFooterMaxDragRate);
        this.mHeaderTriggerRate = ta.getFloat(R.styleable.SmartRefreshLayout_srlHeaderTriggerRate, this.mHeaderTriggerRate);
        this.mFooterTriggerRate = ta.getFloat(R.styleable.SmartRefreshLayout_srlFooterTriggerRate, this.mFooterTriggerRate);
        this.mEnableRefresh = ta.getBoolean(R.styleable.SmartRefreshLayout_srlEnableRefresh, this.mEnableRefresh);
        this.mReboundDuration = ta.getInt(R.styleable.SmartRefreshLayout_srlReboundDuration, this.mReboundDuration);
        this.mEnableLoadMore = ta.getBoolean(R.styleable.SmartRefreshLayout_srlEnableLoadMore, this.mEnableLoadMore);
        this.mHeaderHeight = ta.getDimensionPixelOffset(R.styleable.SmartRefreshLayout_srlHeaderHeight, this.mHeaderHeight);
        this.mFooterHeight = ta.getDimensionPixelOffset(R.styleable.SmartRefreshLayout_srlFooterHeight, this.mFooterHeight);
        this.mHeaderInsetStart = ta.getDimensionPixelOffset(R.styleable.SmartRefreshLayout_srlHeaderInsetStart, this.mHeaderInsetStart);
        this.mFooterInsetStart = ta.getDimensionPixelOffset(R.styleable.SmartRefreshLayout_srlFooterInsetStart, this.mFooterInsetStart);
        this.mDisableContentWhenRefresh = ta.getBoolean(R.styleable.SmartRefreshLayout_srlDisableContentWhenRefresh, this.mDisableContentWhenRefresh);
        this.mDisableContentWhenLoading = ta.getBoolean(R.styleable.SmartRefreshLayout_srlDisableContentWhenLoading, this.mDisableContentWhenLoading);
        this.mEnableHeaderTranslationContent = ta.getBoolean(R.styleable.SmartRefreshLayout_srlEnableHeaderTranslationContent, this.mEnableHeaderTranslationContent);
        this.mEnableFooterTranslationContent = ta.getBoolean(R.styleable.SmartRefreshLayout_srlEnableFooterTranslationContent, this.mEnableFooterTranslationContent);
        this.mEnablePreviewInEditMode = ta.getBoolean(R.styleable.SmartRefreshLayout_srlEnablePreviewInEditMode, this.mEnablePreviewInEditMode);
        this.mEnableAutoLoadMore = ta.getBoolean(R.styleable.SmartRefreshLayout_srlEnableAutoLoadMore, this.mEnableAutoLoadMore);
        this.mEnableOverScrollBounce = ta.getBoolean(R.styleable.SmartRefreshLayout_srlEnableOverScrollBounce, this.mEnableOverScrollBounce);
        this.mEnablePureScrollMode = ta.getBoolean(R.styleable.SmartRefreshLayout_srlEnablePureScrollMode, this.mEnablePureScrollMode);
        this.mEnableScrollContentWhenLoaded = ta.getBoolean(R.styleable.SmartRefreshLayout_srlEnableScrollContentWhenLoaded, this.mEnableScrollContentWhenLoaded);
        this.mEnableScrollContentWhenRefreshed = ta.getBoolean(R.styleable.SmartRefreshLayout_srlEnableScrollContentWhenRefreshed, this.mEnableScrollContentWhenRefreshed);
        this.mEnableLoadMoreWhenContentNotFull = ta.getBoolean(R.styleable.SmartRefreshLayout_srlEnableLoadMoreWhenContentNotFull, this.mEnableLoadMoreWhenContentNotFull);
        this.mEnableFooterFollowWhenNoMoreData = ta.getBoolean(R.styleable.SmartRefreshLayout_srlEnableFooterFollowWhenLoadFinished, this.mEnableFooterFollowWhenNoMoreData);
        this.mEnableFooterFollowWhenNoMoreData = ta.getBoolean(R.styleable.SmartRefreshLayout_srlEnableFooterFollowWhenNoMoreData, this.mEnableFooterFollowWhenNoMoreData);
        this.mEnableClipHeaderWhenFixedBehind = ta.getBoolean(R.styleable.SmartRefreshLayout_srlEnableClipHeaderWhenFixedBehind, this.mEnableClipHeaderWhenFixedBehind);
        this.mEnableClipFooterWhenFixedBehind = ta.getBoolean(R.styleable.SmartRefreshLayout_srlEnableClipFooterWhenFixedBehind, this.mEnableClipFooterWhenFixedBehind);
        this.mEnableOverScrollDrag = ta.getBoolean(R.styleable.SmartRefreshLayout_srlEnableOverScrollDrag, this.mEnableOverScrollDrag);
        this.mFixedHeaderViewId = ta.getResourceId(R.styleable.SmartRefreshLayout_srlFixedHeaderViewId, this.mFixedHeaderViewId);
        this.mFixedFooterViewId = ta.getResourceId(R.styleable.SmartRefreshLayout_srlFixedFooterViewId, this.mFixedFooterViewId);
        this.mHeaderTranslationViewId = ta.getResourceId(R.styleable.SmartRefreshLayout_srlHeaderTranslationViewId, this.mHeaderTranslationViewId);
        this.mFooterTranslationViewId = ta.getResourceId(R.styleable.SmartRefreshLayout_srlFooterTranslationViewId, this.mFooterTranslationViewId);
        boolean z = ta.getBoolean(R.styleable.SmartRefreshLayout_srlEnableNestedScrolling, this.mEnableNestedScrolling);
        this.mEnableNestedScrolling = z;
        this.mNestedChild.setNestedScrollingEnabled(z);
        this.mManualLoadMore = this.mManualLoadMore || ta.hasValue(R.styleable.SmartRefreshLayout_srlEnableLoadMore);
        this.mManualHeaderTranslationContent = this.mManualHeaderTranslationContent || ta.hasValue(R.styleable.SmartRefreshLayout_srlEnableHeaderTranslationContent);
        this.mManualFooterTranslationContent = this.mManualFooterTranslationContent || ta.hasValue(R.styleable.SmartRefreshLayout_srlEnableFooterTranslationContent);
        this.mHeaderHeightStatus = ta.hasValue(R.styleable.SmartRefreshLayout_srlHeaderHeight) ? DimensionStatus.XmlLayoutUnNotify : this.mHeaderHeightStatus;
        this.mFooterHeightStatus = ta.hasValue(R.styleable.SmartRefreshLayout_srlFooterHeight) ? DimensionStatus.XmlLayoutUnNotify : this.mFooterHeightStatus;
        int accentColor = ta.getColor(R.styleable.SmartRefreshLayout_srlAccentColor, 0);
        int primaryColor = ta.getColor(R.styleable.SmartRefreshLayout_srlPrimaryColor, 0);
        if (primaryColor != 0) {
            if (accentColor != 0) {
                this.mPrimaryColors = new int[]{primaryColor, accentColor};
            } else {
                this.mPrimaryColors = new int[]{primaryColor};
            }
        } else if (accentColor != 0) {
            this.mPrimaryColors = new int[]{0, accentColor};
        }
        if (this.mEnablePureScrollMode && !this.mManualLoadMore && !this.mEnableLoadMore) {
            this.mEnableLoadMore = true;
        }
        ta.recycle();
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // android.view.View
    public void onFinishInflate() {
        super.onFinishInflate();
        int count = super.getChildCount();
        if (count > 3) {
            throw new RuntimeException("最多只支持3个子View，Most only support three sub view");
        }
        int contentLevel = 0;
        int indexContent = -1;
        int i = 0;
        while (true) {
            if (i >= count) {
                break;
            }
            View view = super.getChildAt(i);
            if (SmartUtil.isContentView(view) && (contentLevel < 2 || i == 1)) {
                indexContent = i;
                contentLevel = 2;
            } else if (!(view instanceof RefreshInternal) && contentLevel < 1) {
                indexContent = i;
                contentLevel = i > 0 ? 1 : 0;
            }
            i++;
        }
        int indexHeader = -1;
        int indexFooter = -1;
        if (indexContent >= 0) {
            this.mRefreshContent = new RefreshContentWrapper(super.getChildAt(indexContent));
            if (indexContent == 1) {
                indexHeader = 0;
                if (count == 3) {
                    indexFooter = 2;
                }
            } else if (count == 2) {
                indexFooter = 1;
            }
        }
        for (int i2 = 0; i2 < count; i2++) {
            View childAt = super.getChildAt(i2);
            if (i2 == indexHeader || (i2 != indexFooter && indexHeader == -1 && this.mRefreshHeader == null && (childAt instanceof RefreshHeader))) {
                this.mRefreshHeader = childAt instanceof RefreshHeader ? (RefreshHeader) childAt : new RefreshHeaderWrapper(childAt);
            } else if (i2 == indexFooter || (indexFooter == -1 && (childAt instanceof RefreshFooter))) {
                this.mEnableLoadMore = this.mEnableLoadMore || !this.mManualLoadMore;
                this.mRefreshFooter = childAt instanceof RefreshFooter ? (RefreshFooter) childAt : new RefreshFooterWrapper(childAt);
            }
        }
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onAttachedToWindow() {
        RefreshInternal refreshInternal;
        super.onAttachedToWindow();
        boolean z = true;
        this.mAttachedToWindow = true;
        if (!isInEditMode()) {
            if (this.mRefreshHeader == null) {
                DefaultRefreshHeaderCreator defaultRefreshHeaderCreator = sHeaderCreator;
                if (defaultRefreshHeaderCreator != null) {
                    setRefreshHeader(defaultRefreshHeaderCreator.createRefreshHeader(getContext(), this));
                } else {
                    setRefreshHeader(new BezierRadarHeader(getContext()));
                }
            }
            if (this.mRefreshFooter == null) {
                DefaultRefreshFooterCreator defaultRefreshFooterCreator = sFooterCreator;
                if (defaultRefreshFooterCreator != null) {
                    setRefreshFooter(defaultRefreshFooterCreator.createRefreshFooter(getContext(), this));
                } else {
                    boolean old = this.mEnableLoadMore;
                    setRefreshFooter(new BallPulseFooter(getContext()));
                    this.mEnableLoadMore = old;
                }
            } else {
                if (!this.mEnableLoadMore && this.mManualLoadMore) {
                    z = false;
                }
                this.mEnableLoadMore = z;
            }
            if (this.mRefreshContent == null) {
                int len = getChildCount();
                for (int i = 0; i < len; i++) {
                    View view = getChildAt(i);
                    RefreshInternal refreshInternal2 = this.mRefreshHeader;
                    if ((refreshInternal2 == null || view != refreshInternal2.getView()) && ((refreshInternal = this.mRefreshFooter) == null || view != refreshInternal.getView())) {
                        this.mRefreshContent = new RefreshContentWrapper(view);
                    }
                }
            }
            if (this.mRefreshContent == null) {
                int padding = SmartUtil.dp2px(20.0f);
                TextView errorView = new TextView(getContext());
                errorView.setTextColor(-39424);
                errorView.setGravity(17);
                errorView.setTextSize(20.0f);
                errorView.setText(R.string.srl_content_empty);
                super.addView(errorView, 0, new LayoutParams(-1, -1));
                RefreshContentWrapper refreshContentWrapper = new RefreshContentWrapper(errorView);
                this.mRefreshContent = refreshContentWrapper;
                refreshContentWrapper.getView().setPadding(padding, padding, padding, padding);
            }
            View fixedHeaderView = findViewById(this.mFixedHeaderViewId);
            View fixedFooterView = findViewById(this.mFixedFooterViewId);
            this.mRefreshContent.setScrollBoundaryDecider(this.mScrollBoundaryDecider);
            this.mRefreshContent.setEnableLoadMoreWhenContentNotFull(this.mEnableLoadMoreWhenContentNotFull);
            this.mRefreshContent.setUpComponent(this.mKernel, fixedHeaderView, fixedFooterView);
            if (this.mSpinner != 0) {
                notifyStateChanged(RefreshState.None);
                RefreshContent refreshContent = this.mRefreshContent;
                this.mSpinner = 0;
                refreshContent.moveSpinner(0, this.mHeaderTranslationViewId, this.mFooterTranslationViewId);
            }
        }
        int[] iArr = this.mPrimaryColors;
        if (iArr != null) {
            RefreshInternal refreshInternal3 = this.mRefreshHeader;
            if (refreshInternal3 != null) {
                refreshInternal3.setPrimaryColors(iArr);
            }
            RefreshInternal refreshInternal4 = this.mRefreshFooter;
            if (refreshInternal4 != null) {
                refreshInternal4.setPrimaryColors(this.mPrimaryColors);
            }
        }
        RefreshContent refreshContent2 = this.mRefreshContent;
        if (refreshContent2 != null) {
            super.bringChildToFront(refreshContent2.getView());
        }
        RefreshInternal refreshInternal5 = this.mRefreshHeader;
        if (refreshInternal5 != null && refreshInternal5.getSpinnerStyle().front) {
            super.bringChildToFront(this.mRefreshHeader.getView());
        }
        RefreshInternal refreshInternal6 = this.mRefreshFooter;
        if (refreshInternal6 != null && refreshInternal6.getSpinnerStyle().front) {
            super.bringChildToFront(this.mRefreshFooter.getView());
        }
    }

    @Override // android.view.View
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        int len;
        int minimumHeight = 0;
        boolean needPreview = isInEditMode() && this.mEnablePreviewInEditMode;
        int i = 0;
        int len2 = super.getChildCount();
        while (i < len2) {
            View child = super.getChildAt(i);
            if (child.getVisibility() == 8) {
                len = len2;
            } else if (child.getTag(R.string.srl_component_falsify) == child) {
                len = len2;
            } else {
                RefreshInternal refreshInternal = this.mRefreshHeader;
                if (refreshInternal == null || refreshInternal.getView() != child) {
                    len = len2;
                } else {
                    View headerView = this.mRefreshHeader.getView();
                    ViewGroup.LayoutParams lp = headerView.getLayoutParams();
                    ViewGroup.MarginLayoutParams mlp = lp instanceof ViewGroup.MarginLayoutParams ? (ViewGroup.MarginLayoutParams) lp : sDefaultMarginLP;
                    int widthSpec = ViewGroup.getChildMeasureSpec(widthMeasureSpec, mlp.leftMargin + mlp.rightMargin, lp.width);
                    int height = this.mHeaderHeight;
                    if (this.mHeaderHeightStatus.ordinal < DimensionStatus.XmlLayoutUnNotify.ordinal) {
                        if (lp.height > 0) {
                            height = lp.height + mlp.bottomMargin + mlp.topMargin;
                            if (this.mHeaderHeightStatus.canReplaceWith(DimensionStatus.XmlExactUnNotify)) {
                                this.mHeaderHeight = lp.height + mlp.bottomMargin + mlp.topMargin;
                                this.mHeaderHeightStatus = DimensionStatus.XmlExactUnNotify;
                            }
                        } else if (lp.height == -2 && (this.mRefreshHeader.getSpinnerStyle() != SpinnerStyle.MatchLayout || !this.mHeaderHeightStatus.notified)) {
                            int maxHeight = Math.max((View.MeasureSpec.getSize(heightMeasureSpec) - mlp.bottomMargin) - mlp.topMargin, 0);
                            headerView.measure(widthSpec, View.MeasureSpec.makeMeasureSpec(maxHeight, Integer.MIN_VALUE));
                            int measuredHeight = headerView.getMeasuredHeight();
                            if (measuredHeight > 0) {
                                height = -1;
                                if (measuredHeight != maxHeight && this.mHeaderHeightStatus.canReplaceWith(DimensionStatus.XmlWrapUnNotify)) {
                                    this.mHeaderHeight = mlp.bottomMargin + measuredHeight + mlp.topMargin;
                                    this.mHeaderHeightStatus = DimensionStatus.XmlWrapUnNotify;
                                }
                            }
                        }
                    }
                    if (this.mRefreshHeader.getSpinnerStyle() == SpinnerStyle.MatchLayout) {
                        height = View.MeasureSpec.getSize(heightMeasureSpec);
                    } else if (this.mRefreshHeader.getSpinnerStyle().scale && !needPreview) {
                        height = Math.max(0, isEnableRefreshOrLoadMore(this.mEnableRefresh) ? this.mSpinner : 0);
                    }
                    if (height != -1) {
                        headerView.measure(widthSpec, View.MeasureSpec.makeMeasureSpec(Math.max((height - mlp.bottomMargin) - mlp.topMargin, 0), 1073741824));
                    }
                    if (!this.mHeaderHeightStatus.notified) {
                        this.mHeaderHeightStatus = this.mHeaderHeightStatus.notified();
                        RefreshInternal refreshInternal2 = this.mRefreshHeader;
                        RefreshKernel refreshKernel = this.mKernel;
                        int i2 = this.mHeaderHeight;
                        len = len2;
                        refreshInternal2.onInitialized(refreshKernel, i2, (int) (this.mHeaderMaxDragRate * i2));
                    } else {
                        len = len2;
                    }
                    if (needPreview && isEnableRefreshOrLoadMore(this.mEnableRefresh)) {
                        minimumHeight += headerView.getMeasuredHeight();
                    }
                }
                RefreshInternal refreshInternal3 = this.mRefreshFooter;
                if (refreshInternal3 != null && refreshInternal3.getView() == child) {
                    View footerView = this.mRefreshFooter.getView();
                    ViewGroup.LayoutParams lp2 = footerView.getLayoutParams();
                    ViewGroup.MarginLayoutParams mlp2 = lp2 instanceof ViewGroup.MarginLayoutParams ? (ViewGroup.MarginLayoutParams) lp2 : sDefaultMarginLP;
                    int widthSpec2 = ViewGroup.getChildMeasureSpec(widthMeasureSpec, mlp2.leftMargin + mlp2.rightMargin, lp2.width);
                    int height2 = this.mFooterHeight;
                    if (this.mFooterHeightStatus.ordinal < DimensionStatus.XmlLayoutUnNotify.ordinal) {
                        if (lp2.height > 0) {
                            height2 = lp2.height + mlp2.topMargin + mlp2.bottomMargin;
                            if (this.mFooterHeightStatus.canReplaceWith(DimensionStatus.XmlExactUnNotify)) {
                                this.mFooterHeight = lp2.height + mlp2.topMargin + mlp2.bottomMargin;
                                this.mFooterHeightStatus = DimensionStatus.XmlExactUnNotify;
                            }
                        } else if (lp2.height == -2 && (this.mRefreshFooter.getSpinnerStyle() != SpinnerStyle.MatchLayout || !this.mFooterHeightStatus.notified)) {
                            int maxHeight2 = Math.max((View.MeasureSpec.getSize(heightMeasureSpec) - mlp2.bottomMargin) - mlp2.topMargin, 0);
                            footerView.measure(widthSpec2, View.MeasureSpec.makeMeasureSpec(maxHeight2, Integer.MIN_VALUE));
                            int measuredHeight2 = footerView.getMeasuredHeight();
                            if (measuredHeight2 > 0) {
                                height2 = -1;
                                if (measuredHeight2 != maxHeight2 && this.mFooterHeightStatus.canReplaceWith(DimensionStatus.XmlWrapUnNotify)) {
                                    this.mFooterHeight = mlp2.topMargin + measuredHeight2 + mlp2.bottomMargin;
                                    this.mFooterHeightStatus = DimensionStatus.XmlWrapUnNotify;
                                }
                            }
                        }
                    }
                    if (this.mRefreshFooter.getSpinnerStyle() == SpinnerStyle.MatchLayout) {
                        height2 = View.MeasureSpec.getSize(heightMeasureSpec);
                    } else if (this.mRefreshFooter.getSpinnerStyle().scale && !needPreview) {
                        height2 = Math.max(0, isEnableRefreshOrLoadMore(this.mEnableLoadMore) ? -this.mSpinner : 0);
                    }
                    if (height2 != -1) {
                        footerView.measure(widthSpec2, View.MeasureSpec.makeMeasureSpec(Math.max((height2 - mlp2.bottomMargin) - mlp2.topMargin, 0), 1073741824));
                    }
                    if (!this.mFooterHeightStatus.notified) {
                        this.mFooterHeightStatus = this.mFooterHeightStatus.notified();
                        RefreshInternal refreshInternal4 = this.mRefreshFooter;
                        RefreshKernel refreshKernel2 = this.mKernel;
                        int i3 = this.mFooterHeight;
                        refreshInternal4.onInitialized(refreshKernel2, i3, (int) (this.mFooterMaxDragRate * i3));
                    }
                    if (needPreview && isEnableRefreshOrLoadMore(this.mEnableLoadMore)) {
                        minimumHeight += footerView.getMeasuredHeight();
                    }
                }
                RefreshContent refreshContent = this.mRefreshContent;
                if (refreshContent != null && refreshContent.getView() == child) {
                    View contentView = this.mRefreshContent.getView();
                    ViewGroup.LayoutParams lp3 = contentView.getLayoutParams();
                    ViewGroup.MarginLayoutParams mlp3 = lp3 instanceof ViewGroup.MarginLayoutParams ? (ViewGroup.MarginLayoutParams) lp3 : sDefaultMarginLP;
                    boolean showHeader = this.mRefreshHeader != null && isEnableRefreshOrLoadMore(this.mEnableRefresh) && isEnableTranslationContent(this.mEnableHeaderTranslationContent, this.mRefreshHeader);
                    boolean showFooter = this.mRefreshFooter != null && isEnableRefreshOrLoadMore(this.mEnableLoadMore) && isEnableTranslationContent(this.mEnableFooterTranslationContent, this.mRefreshFooter);
                    int widthSpec3 = ViewGroup.getChildMeasureSpec(widthMeasureSpec, getPaddingLeft() + getPaddingRight() + mlp3.leftMargin + mlp3.rightMargin, lp3.width);
                    int heightSpec = ViewGroup.getChildMeasureSpec(heightMeasureSpec, getPaddingTop() + getPaddingBottom() + mlp3.topMargin + mlp3.bottomMargin + ((needPreview && showHeader) ? this.mHeaderHeight : 0) + ((needPreview && showFooter) ? this.mFooterHeight : 0), lp3.height);
                    contentView.measure(widthSpec3, heightSpec);
                    minimumHeight += contentView.getMeasuredHeight();
                }
            }
            i++;
            len2 = len;
        }
        super.setMeasuredDimension(View.resolveSize(super.getSuggestedMinimumWidth(), widthMeasureSpec), View.resolveSize(minimumHeight, heightMeasureSpec));
        this.mLastTouchX = getMeasuredWidth() / 2.0f;
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onLayout(boolean changed, int l, int t, int r, int b) {
        View thisView;
        int paddingLeft;
        int bottom;
        View thisView2 = this;
        int paddingLeft2 = thisView2.getPaddingLeft();
        int paddingTop = thisView2.getPaddingTop();
        thisView2.getPaddingBottom();
        int i = 0;
        int len = super.getChildCount();
        while (i < len) {
            View child = super.getChildAt(i);
            if (child.getVisibility() == 8) {
                thisView = thisView2;
                paddingLeft = paddingLeft2;
            } else if (child.getTag(R.string.srl_component_falsify) == child) {
                thisView = thisView2;
                paddingLeft = paddingLeft2;
            } else {
                RefreshContent refreshContent = this.mRefreshContent;
                if (refreshContent == null || refreshContent.getView() != child) {
                    paddingLeft = paddingLeft2;
                } else {
                    boolean isPreviewMode = thisView2.isInEditMode() && this.mEnablePreviewInEditMode && isEnableRefreshOrLoadMore(this.mEnableRefresh) && this.mRefreshHeader != null;
                    View contentView = this.mRefreshContent.getView();
                    ViewGroup.LayoutParams lp = contentView.getLayoutParams();
                    ViewGroup.MarginLayoutParams mlp = lp instanceof ViewGroup.MarginLayoutParams ? (ViewGroup.MarginLayoutParams) lp : sDefaultMarginLP;
                    int left = mlp.leftMargin + paddingLeft2;
                    int top = mlp.topMargin + paddingTop;
                    int right = left + contentView.getMeasuredWidth();
                    int bottom2 = top + contentView.getMeasuredHeight();
                    if (isPreviewMode) {
                        paddingLeft = paddingLeft2;
                        if (isEnableTranslationContent(this.mEnableHeaderTranslationContent, this.mRefreshHeader)) {
                            int i2 = this.mHeaderHeight;
                            top += i2;
                            bottom = bottom2 + i2;
                        }
                        contentView.layout(left, top, right, bottom);
                    } else {
                        paddingLeft = paddingLeft2;
                    }
                    bottom = bottom2;
                    contentView.layout(left, top, right, bottom);
                }
                RefreshInternal refreshInternal = this.mRefreshHeader;
                if (refreshInternal != null && refreshInternal.getView() == child) {
                    boolean isPreviewMode2 = thisView2.isInEditMode() && this.mEnablePreviewInEditMode && isEnableRefreshOrLoadMore(this.mEnableRefresh);
                    View headerView = this.mRefreshHeader.getView();
                    ViewGroup.LayoutParams lp2 = headerView.getLayoutParams();
                    ViewGroup.MarginLayoutParams mlp2 = lp2 instanceof ViewGroup.MarginLayoutParams ? (ViewGroup.MarginLayoutParams) lp2 : sDefaultMarginLP;
                    int left2 = mlp2.leftMargin;
                    int top2 = mlp2.topMargin + this.mHeaderInsetStart;
                    int right2 = headerView.getMeasuredWidth() + left2;
                    int bottom3 = headerView.getMeasuredHeight() + top2;
                    if (!isPreviewMode2 && this.mRefreshHeader.getSpinnerStyle() == SpinnerStyle.Translate) {
                        int i3 = this.mHeaderHeight;
                        top2 -= i3;
                        bottom3 -= i3;
                    }
                    headerView.layout(left2, top2, right2, bottom3);
                }
                RefreshInternal refreshInternal2 = this.mRefreshFooter;
                if (refreshInternal2 == null || refreshInternal2.getView() != child) {
                    thisView = thisView2;
                } else {
                    boolean isPreviewMode3 = thisView2.isInEditMode() && this.mEnablePreviewInEditMode && isEnableRefreshOrLoadMore(this.mEnableLoadMore);
                    View footerView = this.mRefreshFooter.getView();
                    ViewGroup.LayoutParams lp3 = footerView.getLayoutParams();
                    ViewGroup.MarginLayoutParams mlp3 = lp3 instanceof ViewGroup.MarginLayoutParams ? (ViewGroup.MarginLayoutParams) lp3 : sDefaultMarginLP;
                    SpinnerStyle style = this.mRefreshFooter.getSpinnerStyle();
                    int left3 = mlp3.leftMargin;
                    int top3 = (mlp3.topMargin + thisView2.getMeasuredHeight()) - this.mFooterInsetStart;
                    if (!this.mFooterNoMoreData || !this.mFooterNoMoreDataEffective || !this.mEnableFooterFollowWhenNoMoreData || this.mRefreshContent == null || this.mRefreshFooter.getSpinnerStyle() != SpinnerStyle.Translate || !isEnableRefreshOrLoadMore(this.mEnableLoadMore)) {
                        thisView = thisView2;
                    } else {
                        View contentView2 = this.mRefreshContent.getView();
                        ViewGroup.LayoutParams clp = contentView2.getLayoutParams();
                        thisView = thisView2;
                        int topMargin = clp instanceof ViewGroup.MarginLayoutParams ? ((ViewGroup.MarginLayoutParams) clp).topMargin : 0;
                        top3 = paddingTop + paddingTop + topMargin + contentView2.getMeasuredHeight();
                    }
                    if (style == SpinnerStyle.MatchLayout) {
                        top3 = mlp3.topMargin - this.mFooterInsetStart;
                    } else if (isPreviewMode3 || style == SpinnerStyle.FixedFront || style == SpinnerStyle.FixedBehind) {
                        top3 -= this.mFooterHeight;
                    } else if (style.scale && this.mSpinner < 0) {
                        top3 -= Math.max(isEnableRefreshOrLoadMore(this.mEnableLoadMore) ? -this.mSpinner : 0, 0);
                    }
                    int right3 = footerView.getMeasuredWidth() + left3;
                    footerView.layout(left3, top3, right3, footerView.getMeasuredHeight() + top3);
                }
            }
            i++;
            thisView2 = thisView;
            paddingLeft2 = paddingLeft;
        }
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        this.mAttachedToWindow = false;
        this.mKernel.moveSpinner(0, true);
        notifyStateChanged(RefreshState.None);
        Handler handler = this.mHandler;
        if (handler != null) {
            handler.removeCallbacksAndMessages(null);
        }
        this.mManualLoadMore = true;
        this.animationRunnable = null;
        if (this.reboundAnimator != null) {
            Animator animator = this.reboundAnimator;
            animator.removeAllListeners();
            this.reboundAnimator.removeAllUpdateListeners();
            this.reboundAnimator.cancel();
            this.reboundAnimator = null;
        }
        this.mFooterLocked = false;
    }

    @Override // android.view.ViewGroup
    protected boolean drawChild(Canvas canvas, View child, long drawingTime) {
        Paint paint;
        Paint paint2;
        RefreshContent refreshContent = this.mRefreshContent;
        View contentView = refreshContent != null ? refreshContent.getView() : null;
        RefreshInternal refreshInternal = this.mRefreshHeader;
        if (refreshInternal != null && refreshInternal.getView() == child) {
            if (!isEnableRefreshOrLoadMore(this.mEnableRefresh) || (!this.mEnablePreviewInEditMode && isInEditMode())) {
                return true;
            }
            if (contentView != null) {
                int bottom = Math.max(contentView.getTop() + contentView.getPaddingTop() + this.mSpinner, child.getTop());
                int i = this.mHeaderBackgroundColor;
                if (i != 0 && (paint2 = this.mPaint) != null) {
                    paint2.setColor(i);
                    if (this.mRefreshHeader.getSpinnerStyle().scale) {
                        bottom = child.getBottom();
                    } else if (this.mRefreshHeader.getSpinnerStyle() == SpinnerStyle.Translate) {
                        bottom = child.getBottom() + this.mSpinner;
                    }
                    canvas.drawRect(0.0f, child.getTop(), getWidth(), bottom, this.mPaint);
                }
                if (this.mEnableClipHeaderWhenFixedBehind && this.mRefreshHeader.getSpinnerStyle() == SpinnerStyle.FixedBehind) {
                    canvas.save();
                    canvas.clipRect(child.getLeft(), child.getTop(), child.getRight(), bottom);
                    boolean ret = super.drawChild(canvas, child, drawingTime);
                    canvas.restore();
                    return ret;
                }
            }
        }
        RefreshInternal refreshInternal2 = this.mRefreshFooter;
        if (refreshInternal2 != null && refreshInternal2.getView() == child) {
            if (!isEnableRefreshOrLoadMore(this.mEnableLoadMore) || (!this.mEnablePreviewInEditMode && isInEditMode())) {
                return true;
            }
            if (contentView != null) {
                int top = Math.min((contentView.getBottom() - contentView.getPaddingBottom()) + this.mSpinner, child.getBottom());
                int i2 = this.mFooterBackgroundColor;
                if (i2 != 0 && (paint = this.mPaint) != null) {
                    paint.setColor(i2);
                    if (this.mRefreshFooter.getSpinnerStyle().scale) {
                        top = child.getTop();
                    } else if (this.mRefreshFooter.getSpinnerStyle() == SpinnerStyle.Translate) {
                        top = child.getTop() + this.mSpinner;
                    }
                    canvas.drawRect(0.0f, top, getWidth(), child.getBottom(), this.mPaint);
                }
                if (this.mEnableClipFooterWhenFixedBehind && this.mRefreshFooter.getSpinnerStyle() == SpinnerStyle.FixedBehind) {
                    canvas.save();
                    canvas.clipRect(child.getLeft(), top, child.getRight(), child.getBottom());
                    boolean ret2 = super.drawChild(canvas, child, drawingTime);
                    canvas.restore();
                    return ret2;
                }
            }
        }
        return super.drawChild(canvas, child, drawingTime);
    }

    @Override // android.view.View
    public void computeScroll() {
        float velocity;
        this.mScroller.getCurrY();
        if (this.mScroller.computeScrollOffset()) {
            int finalY = this.mScroller.getFinalY();
            if ((finalY < 0 && ((this.mEnableRefresh || this.mEnableOverScrollDrag) && this.mRefreshContent.canRefresh())) || (finalY > 0 && ((this.mEnableLoadMore || this.mEnableOverScrollDrag) && this.mRefreshContent.canLoadMore()))) {
                if (this.mVerticalPermit) {
                    if (Build.VERSION.SDK_INT < 14) {
                        velocity = ((this.mScroller.getCurrY() - finalY) * 1.0f) / Math.max(this.mScroller.getDuration() - this.mScroller.timePassed(), 1);
                    } else {
                        velocity = this.mScroller.getCurrVelocity();
                        if (finalY > 0) {
                            velocity = -velocity;
                        }
                    }
                    animSpinnerBounce(velocity);
                }
                this.mScroller.forceFinished(true);
                return;
            }
            this.mVerticalPermit = true;
            invalidate();
        }
    }

    @Override // android.view.ViewGroup, android.view.View
    public boolean dispatchTouchEvent(MotionEvent e) {
        char c;
        RefreshInternal refreshInternal;
        RefreshInternal refreshInternal2;
        int action = e.getActionMasked();
        boolean pointerUp = action == 6;
        int skipIndex = pointerUp ? e.getActionIndex() : -1;
        int count = e.getPointerCount();
        float sumX = 0.0f;
        float sumY = 0.0f;
        for (int i = 0; i < count; i++) {
            if (skipIndex != i) {
                sumX += e.getX(i);
                sumY += e.getY(i);
            }
        }
        int div = pointerUp ? count - 1 : count;
        float touchX = sumX / div;
        float touchY = sumY / div;
        if ((action == 6 || action == 5) && this.mIsBeingDragged) {
            this.mTouchY += touchY - this.mLastTouchY;
        }
        this.mLastTouchX = touchX;
        this.mLastTouchY = touchY;
        if (this.mNestedInProgress) {
            int totalUnconsumed = this.mTotalUnconsumed;
            boolean ret = super.dispatchTouchEvent(e);
            if (action == 2 && totalUnconsumed == this.mTotalUnconsumed) {
                int offsetX = (int) this.mLastTouchX;
                int offsetMax = getWidth();
                float percentX = this.mLastTouchX / (offsetMax != 0 ? offsetMax : 1);
                if (!isEnableRefreshOrLoadMore(this.mEnableRefresh) || this.mSpinner <= 0 || (refreshInternal2 = this.mRefreshHeader) == null || !refreshInternal2.isSupportHorizontalDrag()) {
                    if (isEnableRefreshOrLoadMore(this.mEnableLoadMore) && this.mSpinner < 0 && (refreshInternal = this.mRefreshFooter) != null && refreshInternal.isSupportHorizontalDrag()) {
                        this.mRefreshFooter.onHorizontalDrag(percentX, offsetX, offsetMax);
                    }
                } else {
                    this.mRefreshHeader.onHorizontalDrag(percentX, offsetX, offsetMax);
                }
            }
            return ret;
        }
        if (!isEnabled() || ((!this.mEnableRefresh && !this.mEnableLoadMore && !this.mEnableOverScrollDrag) || ((this.mHeaderNeedTouchEventWhenRefreshing && ((this.mState.isOpening || this.mState.isFinishing) && this.mState.isHeader)) || (this.mFooterNeedTouchEventWhenLoading && ((this.mState.isOpening || this.mState.isFinishing) && this.mState.isFooter))))) {
            return super.dispatchTouchEvent(e);
        }
        if (!interceptAnimatorByAction(action) && !this.mState.isFinishing) {
            if ((this.mState == RefreshState.Loading && this.mDisableContentWhenLoading) || (this.mState == RefreshState.Refreshing && this.mDisableContentWhenRefresh)) {
                return false;
            }
            if (action == 0) {
                this.mCurrentVelocity = 0;
                this.mVelocityTracker.addMovement(e);
                this.mScroller.forceFinished(true);
                this.mTouchX = touchX;
                this.mTouchY = touchY;
                this.mLastSpinner = 0;
                this.mTouchSpinner = this.mSpinner;
                this.mIsBeingDragged = false;
                this.mSuperDispatchTouchEvent = super.dispatchTouchEvent(e);
                if (this.mState == RefreshState.TwoLevel && this.mTouchY < (getMeasuredHeight() * 5) / 6) {
                    this.mDragDirection = 'h';
                    return this.mSuperDispatchTouchEvent;
                }
                RefreshContent refreshContent = this.mRefreshContent;
                if (refreshContent != null) {
                    refreshContent.onActionDown(e);
                    return true;
                }
                return true;
            }
            if (action == 1) {
                this.mVelocityTracker.addMovement(e);
                this.mVelocityTracker.computeCurrentVelocity(1000, this.mMaximumVelocity);
                this.mCurrentVelocity = (int) this.mVelocityTracker.getYVelocity();
                startFlingIfNeed(0.0f);
            } else {
                if (action == 2) {
                    float dx = touchX - this.mTouchX;
                    float dy = touchY - this.mTouchY;
                    this.mVelocityTracker.addMovement(e);
                    if (!this.mIsBeingDragged && (c = this.mDragDirection) != 'h' && this.mRefreshContent != null) {
                        if (c != 'v' && (Math.abs(dy) < this.mTouchSlop || Math.abs(dx) >= Math.abs(dy))) {
                            if (Math.abs(dx) >= this.mTouchSlop && Math.abs(dx) > Math.abs(dy) && this.mDragDirection != 'v') {
                                this.mDragDirection = 'h';
                            }
                        } else {
                            this.mDragDirection = 'v';
                            if (dy <= 0.0f || (this.mSpinner >= 0 && ((!this.mEnableOverScrollDrag && !this.mEnableRefresh) || !this.mRefreshContent.canRefresh()))) {
                                if (dy < 0.0f && (this.mSpinner > 0 || ((this.mEnableOverScrollDrag || this.mEnableLoadMore) && ((this.mState == RefreshState.Loading && this.mFooterLocked) || this.mRefreshContent.canLoadMore())))) {
                                    this.mIsBeingDragged = true;
                                    this.mTouchY = this.mTouchSlop + touchY;
                                }
                            } else {
                                this.mIsBeingDragged = true;
                                this.mTouchY = touchY - this.mTouchSlop;
                            }
                            if (this.mIsBeingDragged) {
                                dy = touchY - this.mTouchY;
                                if (this.mSuperDispatchTouchEvent) {
                                    e.setAction(3);
                                    super.dispatchTouchEvent(e);
                                }
                                RefreshKernel refreshKernel = this.mKernel;
                                int i2 = this.mSpinner;
                                refreshKernel.setState((i2 > 0 || (i2 == 0 && dy > 0.0f)) ? RefreshState.PullDownToRefresh : RefreshState.PullUpToLoad);
                                ViewParent parent = getParent();
                                if (parent instanceof ViewGroup) {
                                    ((ViewGroup) parent).requestDisallowInterceptTouchEvent(true);
                                }
                            }
                        }
                    }
                    if (this.mIsBeingDragged) {
                        int spinner = ((int) dy) + this.mTouchSpinner;
                        if ((this.mViceState.isHeader && (spinner < 0 || this.mLastSpinner < 0)) || (this.mViceState.isFooter && (spinner > 0 || this.mLastSpinner > 0))) {
                            this.mLastSpinner = spinner;
                            long time = e.getEventTime();
                            if (this.mFalsifyEvent == null) {
                                MotionEvent motionEventObtain = MotionEvent.obtain(time, time, 0, this.mTouchX + dx, this.mTouchY, 0);
                                this.mFalsifyEvent = motionEventObtain;
                                super.dispatchTouchEvent(motionEventObtain);
                            }
                            MotionEvent em = MotionEvent.obtain(time, time, 2, this.mTouchX + dx, this.mTouchY + spinner, 0);
                            super.dispatchTouchEvent(em);
                            if (this.mFooterLocked && dy > this.mTouchSlop && this.mSpinner < 0) {
                                this.mFooterLocked = false;
                            }
                            if (spinner > 0 && ((this.mEnableOverScrollDrag || this.mEnableRefresh) && this.mRefreshContent.canRefresh())) {
                                this.mLastTouchY = touchY;
                                this.mTouchY = touchY;
                                this.mTouchSpinner = 0;
                                this.mKernel.setState(RefreshState.PullDownToRefresh);
                                spinner = 0;
                            } else if (spinner < 0 && ((this.mEnableOverScrollDrag || this.mEnableLoadMore) && this.mRefreshContent.canLoadMore())) {
                                this.mLastTouchY = touchY;
                                this.mTouchY = touchY;
                                this.mTouchSpinner = 0;
                                this.mKernel.setState(RefreshState.PullUpToLoad);
                                spinner = 0;
                            }
                            if ((this.mViceState.isHeader && spinner < 0) || (this.mViceState.isFooter && spinner > 0)) {
                                if (this.mSpinner != 0) {
                                    moveSpinnerInfinitely(0.0f);
                                    return true;
                                }
                                return true;
                            }
                            if (this.mFalsifyEvent != null) {
                                this.mFalsifyEvent = null;
                                em.setAction(3);
                                super.dispatchTouchEvent(em);
                            }
                            em.recycle();
                        }
                        moveSpinnerInfinitely(spinner);
                        return true;
                    }
                    if (this.mFooterLocked && dy > this.mTouchSlop && this.mSpinner < 0) {
                        this.mFooterLocked = false;
                    }
                } else if (action != 3) {
                }
                return super.dispatchTouchEvent(e);
            }
            this.mVelocityTracker.clear();
            this.mDragDirection = 'n';
            MotionEvent motionEvent = this.mFalsifyEvent;
            if (motionEvent != null) {
                motionEvent.recycle();
                this.mFalsifyEvent = null;
                long time2 = e.getEventTime();
                MotionEvent ec = MotionEvent.obtain(time2, time2, action, this.mTouchX, touchY, 0);
                super.dispatchTouchEvent(ec);
                ec.recycle();
            }
            overSpinner();
            if (this.mIsBeingDragged) {
                this.mIsBeingDragged = false;
                return true;
            }
            return super.dispatchTouchEvent(e);
        }
        return false;
    }

    protected boolean startFlingIfNeed(float flingVelocity) {
        float velocity = flingVelocity == 0.0f ? this.mCurrentVelocity : flingVelocity;
        if (Build.VERSION.SDK_INT > 27 && this.mRefreshContent != null) {
            getScaleY();
            View contentView = this.mRefreshContent.getView();
            if (getScaleY() == -1.0f && contentView.getScaleY() == -1.0f) {
                velocity = -velocity;
            }
        }
        float scaleY = Math.abs(velocity);
        if (scaleY > this.mMinimumVelocity) {
            if (this.mSpinner * velocity < 0.0f) {
                if (this.mState == RefreshState.Refreshing || this.mState == RefreshState.Loading || (this.mSpinner < 0 && this.mFooterNoMoreData)) {
                    this.animationRunnable = new FlingRunnable(velocity).start();
                    return true;
                }
                if (this.mState.isReleaseToOpening) {
                    return true;
                }
            }
            if ((velocity < 0.0f && ((this.mEnableOverScrollBounce && (this.mEnableLoadMore || this.mEnableOverScrollDrag)) || ((this.mState == RefreshState.Loading && this.mSpinner >= 0) || (this.mEnableAutoLoadMore && isEnableRefreshOrLoadMore(this.mEnableLoadMore))))) || (velocity > 0.0f && ((this.mEnableOverScrollBounce && this.mEnableRefresh) || this.mEnableOverScrollDrag || (this.mState == RefreshState.Refreshing && this.mSpinner <= 0)))) {
                this.mVerticalPermit = false;
                this.mScroller.fling(0, 0, 0, (int) (-velocity), 0, 0, -2147483647, Integer.MAX_VALUE);
                this.mScroller.computeScrollOffset();
                invalidate();
            }
        }
        return false;
    }

    protected boolean interceptAnimatorByAction(int action) {
        if (action == 0) {
            if (this.reboundAnimator != null) {
                if (this.mState.isFinishing || this.mState == RefreshState.TwoLevelReleased) {
                    return true;
                }
                if (this.mState == RefreshState.PullDownCanceled) {
                    this.mKernel.setState(RefreshState.PullDownToRefresh);
                } else if (this.mState == RefreshState.PullUpCanceled) {
                    this.mKernel.setState(RefreshState.PullUpToLoad);
                }
                this.reboundAnimator.cancel();
                this.reboundAnimator = null;
            }
            this.animationRunnable = null;
        }
        return this.reboundAnimator != null;
    }

    protected void notifyStateChanged(RefreshState state) {
        RefreshState oldState = this.mState;
        if (oldState != state) {
            this.mState = state;
            this.mViceState = state;
            OnStateChangedListener refreshHeader = this.mRefreshHeader;
            OnStateChangedListener refreshFooter = this.mRefreshFooter;
            OnStateChangedListener refreshListener = this.mOnMultiPurposeListener;
            if (refreshHeader != null) {
                refreshHeader.onStateChanged(this, oldState, state);
            }
            if (refreshFooter != null) {
                refreshFooter.onStateChanged(this, oldState, state);
            }
            if (refreshListener != null) {
                refreshListener.onStateChanged(this, oldState, state);
            }
            if (state == RefreshState.LoadFinish) {
                this.mFooterLocked = false;
                return;
            }
            return;
        }
        RefreshState refreshState = this.mViceState;
        RefreshState refreshState2 = this.mState;
        if (refreshState != refreshState2) {
            this.mViceState = refreshState2;
        }
    }

    protected void setStateDirectLoading(boolean triggerLoadMoreEvent) {
        if (this.mState != RefreshState.Loading) {
            this.mLastOpenTime = System.currentTimeMillis();
            this.mFooterLocked = true;
            notifyStateChanged(RefreshState.Loading);
            OnLoadMoreListener onLoadMoreListener = this.mLoadMoreListener;
            if (onLoadMoreListener != null) {
                if (triggerLoadMoreEvent) {
                    onLoadMoreListener.onLoadMore(this);
                }
            } else if (this.mOnMultiPurposeListener == null) {
                finishLoadMore(2000);
            }
            RefreshInternal refreshInternal = this.mRefreshFooter;
            if (refreshInternal != null) {
                int i = this.mFooterHeight;
                refreshInternal.onStartAnimator(this, i, (int) (this.mFooterMaxDragRate * i));
            }
            if (this.mOnMultiPurposeListener != null && (this.mRefreshFooter instanceof RefreshFooter)) {
                OnLoadMoreListener listener = this.mOnMultiPurposeListener;
                if (triggerLoadMoreEvent) {
                    listener.onLoadMore(this);
                }
                OnMultiPurposeListener onMultiPurposeListener = this.mOnMultiPurposeListener;
                RefreshFooter refreshFooter = (RefreshFooter) this.mRefreshFooter;
                int i2 = this.mFooterHeight;
                onMultiPurposeListener.onFooterStartAnimator(refreshFooter, i2, (int) (this.mFooterMaxDragRate * i2));
            }
        }
    }

    protected void setStateLoading(final boolean notify) {
        AnimatorListenerAdapter listener = new AnimatorListenerAdapter() { // from class: com.scwang.smartrefresh.layout.SmartRefreshLayout.1
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                SmartRefreshLayout.this.setStateDirectLoading(notify);
            }
        };
        notifyStateChanged(RefreshState.LoadReleased);
        ValueAnimator animator = this.mKernel.animSpinner(-this.mFooterHeight);
        if (animator != null) {
            animator.addListener(listener);
        }
        RefreshInternal refreshInternal = this.mRefreshFooter;
        if (refreshInternal != null) {
            int i = this.mFooterHeight;
            refreshInternal.onReleased(this, i, (int) (this.mFooterMaxDragRate * i));
        }
        OnMultiPurposeListener onMultiPurposeListener = this.mOnMultiPurposeListener;
        if (onMultiPurposeListener != null) {
            RefreshInternal refreshInternal2 = this.mRefreshFooter;
            if (refreshInternal2 instanceof RefreshFooter) {
                int i2 = this.mFooterHeight;
                onMultiPurposeListener.onFooterReleased((RefreshFooter) refreshInternal2, i2, (int) (this.mFooterMaxDragRate * i2));
            }
        }
        if (animator == null) {
            listener.onAnimationEnd(null);
        }
    }

    protected void setStateRefreshing(final boolean notify) {
        AnimatorListenerAdapter listener = new AnimatorListenerAdapter() { // from class: com.scwang.smartrefresh.layout.SmartRefreshLayout.2
            /* JADX WARN: Type inference fix 'apply assigned field type' failed
            java.lang.UnsupportedOperationException: ArgType.getObject(), call class: class jadx.core.dex.instructions.args.ArgType$PrimitiveArg
            	at jadx.core.dex.instructions.args.ArgType.getObject(ArgType.java:593)
            	at jadx.core.dex.attributes.nodes.ClassTypeVarsAttr.getTypeVarsMapFor(ClassTypeVarsAttr.java:35)
            	at jadx.core.dex.nodes.utils.TypeUtils.replaceClassGenerics(TypeUtils.java:177)
            	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.insertExplicitUseCast(FixTypesVisitor.java:397)
            	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.tryFieldTypeWithNewCasts(FixTypesVisitor.java:359)
            	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.applyFieldType(FixTypesVisitor.java:309)
            	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.visit(FixTypesVisitor.java:94)
             */
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                SmartRefreshLayout.this.mLastOpenTime = System.currentTimeMillis();
                SmartRefreshLayout.this.notifyStateChanged(RefreshState.Refreshing);
                if (SmartRefreshLayout.this.mRefreshListener != null) {
                    if (notify) {
                        SmartRefreshLayout.this.mRefreshListener.onRefresh(SmartRefreshLayout.this);
                    }
                } else if (SmartRefreshLayout.this.mOnMultiPurposeListener == null) {
                    SmartRefreshLayout.this.finishRefresh(3000);
                }
                if (SmartRefreshLayout.this.mRefreshHeader != null) {
                    RefreshInternal refreshInternal = SmartRefreshLayout.this.mRefreshHeader;
                    SmartRefreshLayout smartRefreshLayout = SmartRefreshLayout.this;
                    refreshInternal.onStartAnimator(smartRefreshLayout, smartRefreshLayout.mHeaderHeight, (int) (SmartRefreshLayout.this.mHeaderMaxDragRate * SmartRefreshLayout.this.mHeaderHeight));
                }
                if (SmartRefreshLayout.this.mOnMultiPurposeListener != null && (SmartRefreshLayout.this.mRefreshHeader instanceof RefreshHeader)) {
                    if (notify) {
                        SmartRefreshLayout.this.mOnMultiPurposeListener.onRefresh(SmartRefreshLayout.this);
                    }
                    SmartRefreshLayout.this.mOnMultiPurposeListener.onHeaderStartAnimator((RefreshHeader) SmartRefreshLayout.this.mRefreshHeader, SmartRefreshLayout.this.mHeaderHeight, (int) (SmartRefreshLayout.this.mHeaderMaxDragRate * SmartRefreshLayout.this.mHeaderHeight));
                }
            }
        };
        notifyStateChanged(RefreshState.RefreshReleased);
        ValueAnimator animator = this.mKernel.animSpinner(this.mHeaderHeight);
        if (animator != null) {
            animator.addListener(listener);
        }
        RefreshInternal refreshInternal = this.mRefreshHeader;
        if (refreshInternal != null) {
            int i = this.mHeaderHeight;
            refreshInternal.onReleased(this, i, (int) (this.mHeaderMaxDragRate * i));
        }
        OnMultiPurposeListener onMultiPurposeListener = this.mOnMultiPurposeListener;
        if (onMultiPurposeListener != null) {
            RefreshInternal refreshInternal2 = this.mRefreshHeader;
            if (refreshInternal2 instanceof RefreshHeader) {
                int i2 = this.mHeaderHeight;
                onMultiPurposeListener.onHeaderReleased((RefreshHeader) refreshInternal2, i2, (int) (this.mHeaderMaxDragRate * i2));
            }
        }
        if (animator == null) {
            listener.onAnimationEnd(null);
        }
    }

    protected void setViceState(RefreshState state) {
        if (this.mState.isDragging && this.mState.isHeader != state.isHeader) {
            notifyStateChanged(RefreshState.None);
        }
        if (this.mViceState != state) {
            this.mViceState = state;
        }
    }

    protected boolean isEnableTranslationContent(boolean enable, RefreshInternal internal) {
        return enable || this.mEnablePureScrollMode || internal == null || internal.getSpinnerStyle() == SpinnerStyle.FixedBehind;
    }

    protected boolean isEnableRefreshOrLoadMore(boolean enable) {
        return enable && !this.mEnablePureScrollMode;
    }

    protected class FlingRunnable implements Runnable {
        int mOffset;
        float mVelocity;
        int mFrame = 0;
        int mFrameDelay = 10;
        float mDamping = 0.98f;
        long mStartTime = 0;
        long mLastTime = AnimationUtils.currentAnimationTimeMillis();

        FlingRunnable(float velocity) {
            this.mVelocity = velocity;
            this.mOffset = SmartRefreshLayout.this.mSpinner;
        }

        /* JADX WARN: Removed duplicated region for block: B:17:0x0034  */
        /* JADX WARN: Removed duplicated region for block: B:27:0x0058  */
        /* JADX WARN: Removed duplicated region for block: B:33:0x0075  */
        /* JADX WARN: Removed duplicated region for block: B:36:0x0084  */
        /* JADX WARN: Removed duplicated region for block: B:52:0x00d8 A[EDGE_INSN: B:52:0x00d8->B:50:0x00d8 BREAK  A[LOOP:0: B:34:0x0080->B:49:0x00d4], SYNTHETIC] */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public java.lang.Runnable start() {
            /*
                Method dump skipped, instruction units count: 233
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: com.scwang.smartrefresh.layout.SmartRefreshLayout.FlingRunnable.start():java.lang.Runnable");
        }

        @Override // java.lang.Runnable
        public void run() {
            if (SmartRefreshLayout.this.animationRunnable == this && !SmartRefreshLayout.this.mState.isFinishing) {
                long now = AnimationUtils.currentAnimationTimeMillis();
                long span = now - this.mLastTime;
                float fPow = (float) (((double) this.mVelocity) * Math.pow(this.mDamping, (now - this.mStartTime) / (1000.0f / this.mFrameDelay)));
                this.mVelocity = fPow;
                float velocity = fPow * ((span * 1.0f) / 1000.0f);
                if (Math.abs(velocity) > 1.0f) {
                    this.mLastTime = now;
                    this.mOffset = (int) (this.mOffset + velocity);
                    if (SmartRefreshLayout.this.mSpinner * this.mOffset > 0) {
                        SmartRefreshLayout.this.mKernel.moveSpinner(this.mOffset, true);
                        SmartRefreshLayout.this.mHandler.postDelayed(this, this.mFrameDelay);
                        return;
                    }
                    SmartRefreshLayout.this.animationRunnable = null;
                    SmartRefreshLayout.this.mKernel.moveSpinner(0, true);
                    SmartUtil.fling(SmartRefreshLayout.this.mRefreshContent.getScrollableView(), (int) (-this.mVelocity));
                    if (SmartRefreshLayout.this.mFooterLocked && velocity > 0.0f) {
                        SmartRefreshLayout.this.mFooterLocked = false;
                        return;
                    }
                    return;
                }
                SmartRefreshLayout.this.animationRunnable = null;
            }
        }
    }

    protected class BounceRunnable implements Runnable {
        int mSmoothDistance;
        float mVelocity;
        int mFrame = 0;
        int mFrameDelay = 10;
        float mOffset = 0.0f;
        long mLastTime = AnimationUtils.currentAnimationTimeMillis();

        BounceRunnable(float velocity, int smoothDistance) {
            this.mVelocity = velocity;
            this.mSmoothDistance = smoothDistance;
            SmartRefreshLayout.this.mHandler.postDelayed(this, this.mFrameDelay);
            if (velocity > 0.0f) {
                SmartRefreshLayout.this.mKernel.setState(RefreshState.PullDownToRefresh);
            } else {
                SmartRefreshLayout.this.mKernel.setState(RefreshState.PullUpToLoad);
            }
        }

        @Override // java.lang.Runnable
        public void run() {
            if (SmartRefreshLayout.this.animationRunnable == this && !SmartRefreshLayout.this.mState.isFinishing) {
                if (Math.abs(SmartRefreshLayout.this.mSpinner) >= Math.abs(this.mSmoothDistance)) {
                    if (this.mSmoothDistance != 0) {
                        double d = this.mVelocity;
                        this.mFrame = this.mFrame + 1;
                        this.mVelocity = (float) (d * Math.pow(0.44999998807907104d, r4 * 2));
                    } else {
                        double d2 = this.mVelocity;
                        this.mFrame = this.mFrame + 1;
                        this.mVelocity = (float) (d2 * Math.pow(0.8500000238418579d, r4 * 2));
                    }
                } else {
                    double d3 = this.mVelocity;
                    this.mFrame = this.mFrame + 1;
                    this.mVelocity = (float) (d3 * Math.pow(0.949999988079071d, r4 * 2));
                }
                long now = AnimationUtils.currentAnimationTimeMillis();
                float t = ((now - this.mLastTime) * 1.0f) / 1000.0f;
                float velocity = this.mVelocity * t;
                if (Math.abs(velocity) >= 1.0f) {
                    this.mLastTime = now;
                    float f = this.mOffset + velocity;
                    this.mOffset = f;
                    SmartRefreshLayout.this.moveSpinnerInfinitely(f);
                    SmartRefreshLayout.this.mHandler.postDelayed(this, this.mFrameDelay);
                    return;
                }
                if (SmartRefreshLayout.this.mViceState.isDragging && SmartRefreshLayout.this.mViceState.isHeader) {
                    SmartRefreshLayout.this.mKernel.setState(RefreshState.PullDownCanceled);
                } else if (SmartRefreshLayout.this.mViceState.isDragging && SmartRefreshLayout.this.mViceState.isFooter) {
                    SmartRefreshLayout.this.mKernel.setState(RefreshState.PullUpCanceled);
                }
                SmartRefreshLayout.this.animationRunnable = null;
                if (Math.abs(SmartRefreshLayout.this.mSpinner) >= Math.abs(this.mSmoothDistance)) {
                    int duration = Math.min(Math.max((int) SmartUtil.px2dp(Math.abs(SmartRefreshLayout.this.mSpinner - this.mSmoothDistance)), 30), 100) * 10;
                    SmartRefreshLayout smartRefreshLayout = SmartRefreshLayout.this;
                    smartRefreshLayout.animSpinner(this.mSmoothDistance, 0, smartRefreshLayout.mReboundInterpolator, duration);
                }
            }
        }
    }

    protected ValueAnimator animSpinner(int endSpinner, int startDelay, Interpolator interpolator, int duration) {
        if (this.mSpinner == endSpinner) {
            return null;
        }
        ValueAnimator valueAnimator = this.reboundAnimator;
        if (valueAnimator != null) {
            valueAnimator.cancel();
        }
        this.animationRunnable = null;
        ValueAnimator valueAnimatorOfInt = ValueAnimator.ofInt(this.mSpinner, endSpinner);
        this.reboundAnimator = valueAnimatorOfInt;
        valueAnimatorOfInt.setDuration(duration);
        this.reboundAnimator.setInterpolator(interpolator);
        this.reboundAnimator.addListener(new AnimatorListenerAdapter() { // from class: com.scwang.smartrefresh.layout.SmartRefreshLayout.3
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                SmartRefreshLayout.this.reboundAnimator = null;
                if (SmartRefreshLayout.this.mSpinner == 0 && SmartRefreshLayout.this.mState != RefreshState.None && !SmartRefreshLayout.this.mState.isOpening && !SmartRefreshLayout.this.mState.isDragging) {
                    SmartRefreshLayout.this.notifyStateChanged(RefreshState.None);
                } else if (SmartRefreshLayout.this.mState != SmartRefreshLayout.this.mViceState) {
                    SmartRefreshLayout smartRefreshLayout = SmartRefreshLayout.this;
                    smartRefreshLayout.setViceState(smartRefreshLayout.mState);
                }
            }
        });
        this.reboundAnimator.addUpdateListener(new ValueAnimator.AnimatorUpdateListener() { // from class: com.scwang.smartrefresh.layout.SmartRefreshLayout.4
            @Override // android.animation.ValueAnimator.AnimatorUpdateListener
            public void onAnimationUpdate(ValueAnimator animation) {
                SmartRefreshLayout.this.mKernel.moveSpinner(((Integer) animation.getAnimatedValue()).intValue(), false);
            }
        });
        this.reboundAnimator.setStartDelay(startDelay);
        this.reboundAnimator.start();
        return this.reboundAnimator;
    }

    protected void animSpinnerBounce(float velocity) {
        if (this.reboundAnimator == null) {
            if (velocity > 0.0f && (this.mState == RefreshState.Refreshing || this.mState == RefreshState.TwoLevel)) {
                this.animationRunnable = new BounceRunnable(velocity, this.mHeaderHeight);
                return;
            }
            if (velocity < 0.0f && (this.mState == RefreshState.Loading || ((this.mEnableFooterFollowWhenNoMoreData && this.mFooterNoMoreData && this.mFooterNoMoreDataEffective && isEnableRefreshOrLoadMore(this.mEnableLoadMore)) || (this.mEnableAutoLoadMore && !this.mFooterNoMoreData && isEnableRefreshOrLoadMore(this.mEnableLoadMore) && this.mState != RefreshState.Refreshing)))) {
                this.animationRunnable = new BounceRunnable(velocity, -this.mFooterHeight);
            } else if (this.mSpinner == 0 && this.mEnableOverScrollBounce) {
                this.animationRunnable = new BounceRunnable(velocity, 0);
            }
        }
    }

    protected void overSpinner() {
        if (this.mState == RefreshState.TwoLevel) {
            if (this.mCurrentVelocity > -1000 && this.mSpinner > getMeasuredHeight() / 2) {
                ValueAnimator animator = this.mKernel.animSpinner(getMeasuredHeight());
                if (animator != null) {
                    animator.setDuration(this.mFloorDuration);
                    return;
                }
                return;
            }
            if (this.mIsBeingDragged) {
                this.mKernel.finishTwoLevel();
                return;
            }
            return;
        }
        if (this.mState == RefreshState.Loading || (this.mEnableFooterFollowWhenNoMoreData && this.mFooterNoMoreData && this.mFooterNoMoreDataEffective && this.mSpinner < 0 && isEnableRefreshOrLoadMore(this.mEnableLoadMore))) {
            int i = this.mSpinner;
            int i2 = this.mFooterHeight;
            if (i < (-i2)) {
                this.mKernel.animSpinner(-i2);
                return;
            } else {
                if (i > 0) {
                    this.mKernel.animSpinner(0);
                    return;
                }
                return;
            }
        }
        if (this.mState == RefreshState.Refreshing) {
            int i3 = this.mSpinner;
            int i4 = this.mHeaderHeight;
            if (i3 > i4) {
                this.mKernel.animSpinner(i4);
                return;
            } else {
                if (i3 < 0) {
                    this.mKernel.animSpinner(0);
                    return;
                }
                return;
            }
        }
        if (this.mState == RefreshState.PullDownToRefresh) {
            this.mKernel.setState(RefreshState.PullDownCanceled);
            return;
        }
        if (this.mState == RefreshState.PullUpToLoad) {
            this.mKernel.setState(RefreshState.PullUpCanceled);
            return;
        }
        if (this.mState == RefreshState.ReleaseToRefresh) {
            this.mKernel.setState(RefreshState.Refreshing);
            return;
        }
        if (this.mState == RefreshState.ReleaseToLoad) {
            this.mKernel.setState(RefreshState.Loading);
            return;
        }
        if (this.mState == RefreshState.ReleaseToTwoLevel) {
            this.mKernel.setState(RefreshState.TwoLevelReleased);
            return;
        }
        if (this.mState == RefreshState.RefreshReleased) {
            if (this.reboundAnimator == null) {
                this.mKernel.animSpinner(this.mHeaderHeight);
            }
        } else if (this.mState == RefreshState.LoadReleased) {
            if (this.reboundAnimator == null) {
                this.mKernel.animSpinner(-this.mFooterHeight);
            }
        } else if (this.mSpinner != 0) {
            this.mKernel.animSpinner(0);
        }
    }

    protected void moveSpinnerInfinitely(float spinner) {
        float spinner2;
        if (this.mNestedInProgress && !this.mEnableLoadMoreWhenContentNotFull && spinner < 0.0f && !this.mRefreshContent.canLoadMore()) {
            spinner2 = 0.0f;
        } else {
            spinner2 = spinner;
        }
        if (spinner2 > this.mScreenHeightPixels * 5 && getTag() == null) {
            Toast.makeText(getContext(), "你这么死拉，臣妾做不到啊！", 0).show();
            setTag("你这么死拉，臣妾做不到啊！");
        }
        if (this.mState == RefreshState.TwoLevel && spinner2 > 0.0f) {
            this.mKernel.moveSpinner(Math.min((int) spinner2, getMeasuredHeight()), true);
        } else if (this.mState != RefreshState.Refreshing || spinner2 < 0.0f) {
            if (spinner2 < 0.0f && (this.mState == RefreshState.Loading || ((this.mEnableFooterFollowWhenNoMoreData && this.mFooterNoMoreData && this.mFooterNoMoreDataEffective && isEnableRefreshOrLoadMore(this.mEnableLoadMore)) || (this.mEnableAutoLoadMore && !this.mFooterNoMoreData && isEnableRefreshOrLoadMore(this.mEnableLoadMore))))) {
                int i = this.mFooterHeight;
                if (spinner2 > (-i)) {
                    this.mKernel.moveSpinner((int) spinner2, true);
                } else {
                    double M = (this.mFooterMaxDragRate - 1.0f) * i;
                    int iMax = Math.max((this.mScreenHeightPixels * 4) / 3, getHeight());
                    int i2 = this.mFooterHeight;
                    double H = iMax - i2;
                    double x = -Math.min(0.0f, (i2 + spinner2) * this.mDragRate);
                    double y = -Math.min((1.0d - Math.pow(100.0d, (-x) / (H == FirebaseRemoteConfig.DEFAULT_VALUE_FOR_DOUBLE ? 1.0d : H))) * M, x);
                    this.mKernel.moveSpinner(((int) y) - this.mFooterHeight, true);
                }
            } else if (spinner2 >= 0.0f) {
                double M2 = this.mHeaderMaxDragRate * this.mHeaderHeight;
                double H2 = Math.max(this.mScreenHeightPixels / 2, getHeight());
                double x2 = Math.max(0.0f, this.mDragRate * spinner2);
                double y2 = Math.min((1.0d - Math.pow(100.0d, (-x2) / (H2 == FirebaseRemoteConfig.DEFAULT_VALUE_FOR_DOUBLE ? 1.0d : H2))) * M2, x2);
                this.mKernel.moveSpinner((int) y2, true);
            } else {
                double M3 = this.mFooterMaxDragRate * this.mFooterHeight;
                double H3 = Math.max(this.mScreenHeightPixels / 2, getHeight());
                double x3 = -Math.min(0.0f, this.mDragRate * spinner2);
                double y3 = -Math.min((1.0d - Math.pow(100.0d, (-x3) / (H3 == FirebaseRemoteConfig.DEFAULT_VALUE_FOR_DOUBLE ? 1.0d : H3))) * M3, x3);
                this.mKernel.moveSpinner((int) y3, true);
            }
        } else {
            int i3 = this.mHeaderHeight;
            if (spinner2 < i3) {
                this.mKernel.moveSpinner((int) spinner2, true);
            } else {
                double M4 = (this.mHeaderMaxDragRate - 1.0f) * i3;
                int iMax2 = Math.max((this.mScreenHeightPixels * 4) / 3, getHeight());
                int i4 = this.mHeaderHeight;
                double H4 = iMax2 - i4;
                double x4 = Math.max(0.0f, (spinner2 - i4) * this.mDragRate);
                double y4 = Math.min((1.0d - Math.pow(100.0d, (-x4) / (H4 == FirebaseRemoteConfig.DEFAULT_VALUE_FOR_DOUBLE ? 1.0d : H4))) * M4, x4);
                this.mKernel.moveSpinner(((int) y4) + this.mHeaderHeight, true);
            }
        }
        if (this.mEnableAutoLoadMore && !this.mFooterNoMoreData && isEnableRefreshOrLoadMore(this.mEnableLoadMore) && spinner2 < 0.0f && this.mState != RefreshState.Refreshing && this.mState != RefreshState.Loading && this.mState != RefreshState.LoadFinish) {
            if (this.mDisableContentWhenLoading) {
                this.animationRunnable = null;
                this.mKernel.animSpinner(-this.mFooterHeight);
            }
            setStateDirectLoading(false);
            this.mHandler.postDelayed(new Runnable() { // from class: com.scwang.smartrefresh.layout.SmartRefreshLayout.5
                @Override // java.lang.Runnable
                public void run() {
                    if (SmartRefreshLayout.this.mLoadMoreListener != null) {
                        SmartRefreshLayout.this.mLoadMoreListener.onLoadMore(SmartRefreshLayout.this);
                    } else if (SmartRefreshLayout.this.mOnMultiPurposeListener == null) {
                        SmartRefreshLayout.this.finishLoadMore(2000);
                    }
                    OnLoadMoreListener listener = SmartRefreshLayout.this.mOnMultiPurposeListener;
                    if (listener != null) {
                        listener.onLoadMore(SmartRefreshLayout.this);
                    }
                }
            }, this.mReboundDuration);
        }
    }

    @Override // android.view.ViewGroup
    public ViewGroup.LayoutParams generateLayoutParams(AttributeSet attrs) {
        return new LayoutParams(getContext(), attrs);
    }

    public static class LayoutParams extends ViewGroup.MarginLayoutParams {
        public int backgroundColor;
        public SpinnerStyle spinnerStyle;

        public LayoutParams(Context context, AttributeSet attrs) {
            super(context, attrs);
            this.backgroundColor = 0;
            this.spinnerStyle = null;
            TypedArray ta = context.obtainStyledAttributes(attrs, R.styleable.SmartRefreshLayout_Layout);
            this.backgroundColor = ta.getColor(R.styleable.SmartRefreshLayout_Layout_layout_srlBackgroundColor, this.backgroundColor);
            if (ta.hasValue(R.styleable.SmartRefreshLayout_Layout_layout_srlSpinnerStyle)) {
                this.spinnerStyle = SpinnerStyle.values[ta.getInt(R.styleable.SmartRefreshLayout_Layout_layout_srlSpinnerStyle, SpinnerStyle.Translate.ordinal)];
            }
            ta.recycle();
        }

        public LayoutParams(int width, int height) {
            super(width, height);
            this.backgroundColor = 0;
            this.spinnerStyle = null;
        }
    }

    @Override // android.view.ViewGroup, androidx.core.view.NestedScrollingParent
    public int getNestedScrollAxes() {
        return this.mNestedParent.getNestedScrollAxes();
    }

    @Override // android.view.ViewGroup, android.view.ViewParent, androidx.core.view.NestedScrollingParent
    public boolean onStartNestedScroll(View child, View target, int nestedScrollAxes) {
        boolean z = true;
        boolean accepted = isEnabled() && isNestedScrollingEnabled() && (nestedScrollAxes & 2) != 0;
        if (!accepted || (!this.mEnableOverScrollDrag && !this.mEnableRefresh && !this.mEnableLoadMore)) {
            z = false;
        }
        boolean accepted2 = z;
        return accepted2;
    }

    @Override // android.view.ViewGroup, android.view.ViewParent, androidx.core.view.NestedScrollingParent
    public void onNestedScrollAccepted(View child, View target, int axes) {
        this.mNestedParent.onNestedScrollAccepted(child, target, axes);
        this.mNestedChild.startNestedScroll(axes & 2);
        this.mTotalUnconsumed = this.mSpinner;
        this.mNestedInProgress = true;
        interceptAnimatorByAction(0);
    }

    @Override // android.view.ViewGroup, android.view.ViewParent, androidx.core.view.NestedScrollingParent
    public void onNestedPreScroll(View target, int dx, int dy, int[] consumed) {
        int consumedY = 0;
        int i = this.mTotalUnconsumed;
        if (dy * i > 0) {
            if (Math.abs(dy) > Math.abs(this.mTotalUnconsumed)) {
                consumedY = this.mTotalUnconsumed;
                this.mTotalUnconsumed = 0;
            } else {
                consumedY = dy;
                this.mTotalUnconsumed -= dy;
            }
            moveSpinnerInfinitely(this.mTotalUnconsumed);
        } else if (dy > 0 && this.mFooterLocked) {
            consumedY = dy;
            int i2 = i - dy;
            this.mTotalUnconsumed = i2;
            moveSpinnerInfinitely(i2);
        }
        this.mNestedChild.dispatchNestedPreScroll(dx, dy - consumedY, consumed, null);
        consumed[1] = consumed[1] + consumedY;
    }

    @Override // android.view.ViewGroup, android.view.ViewParent, androidx.core.view.NestedScrollingParent
    public void onNestedScroll(View target, int dxConsumed, int dyConsumed, int dxUnconsumed, int dyUnconsumed) {
        ScrollBoundaryDecider scrollBoundaryDecider;
        ScrollBoundaryDecider scrollBoundaryDecider2;
        boolean scrolled = this.mNestedChild.dispatchNestedScroll(dxConsumed, dyConsumed, dxUnconsumed, dyUnconsumed, this.mParentOffsetInWindow);
        int dy = this.mParentOffsetInWindow[1] + dyUnconsumed;
        if ((dy < 0 && ((this.mEnableRefresh || this.mEnableOverScrollDrag) && (this.mTotalUnconsumed != 0 || (scrollBoundaryDecider2 = this.mScrollBoundaryDecider) == null || scrollBoundaryDecider2.canRefresh(this.mRefreshContent.getView())))) || (dy > 0 && ((this.mEnableLoadMore || this.mEnableOverScrollDrag) && (this.mTotalUnconsumed != 0 || (scrollBoundaryDecider = this.mScrollBoundaryDecider) == null || scrollBoundaryDecider.canLoadMore(this.mRefreshContent.getView()))))) {
            if (this.mViceState == RefreshState.None || this.mViceState.isOpening) {
                this.mKernel.setState(dy > 0 ? RefreshState.PullUpToLoad : RefreshState.PullDownToRefresh);
                if (!scrolled) {
                    ViewParent parent = getParent();
                    if (parent instanceof ViewGroup) {
                        ((ViewGroup) parent).requestDisallowInterceptTouchEvent(true);
                    }
                }
            }
            int i = this.mTotalUnconsumed - dy;
            this.mTotalUnconsumed = i;
            moveSpinnerInfinitely(i);
        }
        if (this.mFooterLocked && dyConsumed < 0) {
            this.mFooterLocked = false;
        }
    }

    @Override // android.view.ViewGroup, android.view.ViewParent, androidx.core.view.NestedScrollingParent
    public boolean onNestedPreFling(View target, float velocityX, float velocityY) {
        return (this.mFooterLocked && velocityY > 0.0f) || startFlingIfNeed(-velocityY) || this.mNestedChild.dispatchNestedPreFling(velocityX, velocityY);
    }

    @Override // android.view.ViewGroup, android.view.ViewParent, androidx.core.view.NestedScrollingParent
    public boolean onNestedFling(View target, float velocityX, float velocityY, boolean consumed) {
        return this.mNestedChild.dispatchNestedFling(velocityX, velocityY, consumed);
    }

    @Override // android.view.ViewGroup, android.view.ViewParent, androidx.core.view.NestedScrollingParent
    public void onStopNestedScroll(View target) {
        this.mNestedParent.onStopNestedScroll(target);
        this.mNestedInProgress = false;
        this.mTotalUnconsumed = 0;
        overSpinner();
        this.mNestedChild.stopNestedScroll();
    }

    @Override // android.view.View
    public void setNestedScrollingEnabled(boolean enabled) {
        this.mEnableNestedScrolling = enabled;
        this.mNestedChild.setNestedScrollingEnabled(enabled);
    }

    @Override // android.view.View
    public boolean isNestedScrollingEnabled() {
        return this.mEnableNestedScrolling && (this.mEnableOverScrollDrag || this.mEnableRefresh || this.mEnableLoadMore);
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public RefreshLayout setHeaderHeight(float heightDp) {
        int height = SmartUtil.dp2px(heightDp);
        if (height != this.mHeaderHeight && this.mHeaderHeightStatus.canReplaceWith(DimensionStatus.CodeExact)) {
            this.mHeaderHeight = height;
            if (this.mRefreshHeader != null && this.mAttachedToWindow && this.mHeaderHeightStatus.notified) {
                SpinnerStyle style = this.mRefreshHeader.getSpinnerStyle();
                if (style != SpinnerStyle.MatchLayout && !style.scale) {
                    View headerView = this.mRefreshHeader.getView();
                    ViewGroup.LayoutParams lp = headerView.getLayoutParams();
                    ViewGroup.MarginLayoutParams mlp = lp instanceof ViewGroup.MarginLayoutParams ? (ViewGroup.MarginLayoutParams) lp : sDefaultMarginLP;
                    int widthSpec = View.MeasureSpec.makeMeasureSpec(headerView.getMeasuredWidth(), 1073741824);
                    headerView.measure(widthSpec, View.MeasureSpec.makeMeasureSpec(Math.max((this.mHeaderHeight - mlp.bottomMargin) - mlp.topMargin, 0), 1073741824));
                    int left = mlp.leftMargin;
                    int top = (mlp.topMargin + this.mHeaderInsetStart) - (style == SpinnerStyle.Translate ? this.mHeaderHeight : 0);
                    headerView.layout(left, top, headerView.getMeasuredWidth() + left, headerView.getMeasuredHeight() + top);
                }
                this.mHeaderHeightStatus = DimensionStatus.CodeExact;
                RefreshInternal refreshInternal = this.mRefreshHeader;
                RefreshKernel refreshKernel = this.mKernel;
                int i = this.mHeaderHeight;
                refreshInternal.onInitialized(refreshKernel, i, (int) (this.mHeaderMaxDragRate * i));
            } else {
                this.mHeaderHeightStatus = DimensionStatus.CodeExactUnNotify;
            }
        }
        return this;
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public RefreshLayout setFooterHeight(float heightDp) {
        int height = SmartUtil.dp2px(heightDp);
        if (height != this.mFooterHeight && this.mFooterHeightStatus.canReplaceWith(DimensionStatus.CodeExact)) {
            this.mFooterHeight = height;
            if (this.mRefreshFooter != null && this.mAttachedToWindow && this.mFooterHeightStatus.notified) {
                SpinnerStyle style = this.mRefreshFooter.getSpinnerStyle();
                if (style != SpinnerStyle.MatchLayout && !style.scale) {
                    View footerView = this.mRefreshFooter.getView();
                    ViewGroup.LayoutParams lp = footerView.getLayoutParams();
                    ViewGroup.MarginLayoutParams mlp = lp instanceof ViewGroup.MarginLayoutParams ? (ViewGroup.MarginLayoutParams) lp : sDefaultMarginLP;
                    int widthSpec = View.MeasureSpec.makeMeasureSpec(footerView.getMeasuredWidth(), 1073741824);
                    footerView.measure(widthSpec, View.MeasureSpec.makeMeasureSpec(Math.max((this.mFooterHeight - mlp.bottomMargin) - mlp.topMargin, 0), 1073741824));
                    int left = mlp.leftMargin;
                    int top = ((mlp.topMargin + getMeasuredHeight()) - this.mFooterInsetStart) - (style != SpinnerStyle.Translate ? this.mFooterHeight : 0);
                    footerView.layout(left, top, footerView.getMeasuredWidth() + left, footerView.getMeasuredHeight() + top);
                }
                this.mFooterHeightStatus = DimensionStatus.CodeExact;
                RefreshInternal refreshInternal = this.mRefreshFooter;
                RefreshKernel refreshKernel = this.mKernel;
                int i = this.mFooterHeight;
                refreshInternal.onInitialized(refreshKernel, i, (int) (this.mFooterMaxDragRate * i));
            } else {
                this.mFooterHeightStatus = DimensionStatus.CodeExactUnNotify;
            }
        }
        return this;
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public RefreshLayout setHeaderInsetStart(float insetDp) {
        this.mHeaderInsetStart = SmartUtil.dp2px(insetDp);
        return this;
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public RefreshLayout setFooterInsetStart(float insetDp) {
        this.mFooterInsetStart = SmartUtil.dp2px(insetDp);
        return this;
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public RefreshLayout setDragRate(float rate) {
        this.mDragRate = rate;
        return this;
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public RefreshLayout setHeaderMaxDragRate(float rate) {
        this.mHeaderMaxDragRate = rate;
        RefreshInternal refreshInternal = this.mRefreshHeader;
        if (refreshInternal != null && this.mAttachedToWindow) {
            RefreshKernel refreshKernel = this.mKernel;
            int i = this.mHeaderHeight;
            refreshInternal.onInitialized(refreshKernel, i, (int) (i * rate));
        } else {
            this.mHeaderHeightStatus = this.mHeaderHeightStatus.unNotify();
        }
        return this;
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public RefreshLayout setFooterMaxDragRate(float rate) {
        this.mFooterMaxDragRate = rate;
        RefreshInternal refreshInternal = this.mRefreshFooter;
        if (refreshInternal != null && this.mAttachedToWindow) {
            RefreshKernel refreshKernel = this.mKernel;
            int i = this.mFooterHeight;
            refreshInternal.onInitialized(refreshKernel, i, (int) (i * rate));
        } else {
            this.mFooterHeightStatus = this.mFooterHeightStatus.unNotify();
        }
        return this;
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public RefreshLayout setHeaderTriggerRate(float rate) {
        this.mHeaderTriggerRate = rate;
        return this;
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public RefreshLayout setFooterTriggerRate(float rate) {
        this.mFooterTriggerRate = rate;
        return this;
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public RefreshLayout setReboundInterpolator(Interpolator interpolator) {
        this.mReboundInterpolator = interpolator;
        return this;
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public RefreshLayout setReboundDuration(int duration) {
        this.mReboundDuration = duration;
        return this;
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public RefreshLayout setEnableLoadMore(boolean enabled) {
        this.mManualLoadMore = true;
        this.mEnableLoadMore = enabled;
        return this;
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public RefreshLayout setEnableRefresh(boolean enabled) {
        this.mEnableRefresh = enabled;
        return this;
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public RefreshLayout setEnableHeaderTranslationContent(boolean enabled) {
        this.mEnableHeaderTranslationContent = enabled;
        this.mManualHeaderTranslationContent = true;
        return this;
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public RefreshLayout setEnableFooterTranslationContent(boolean enabled) {
        this.mEnableFooterTranslationContent = enabled;
        this.mManualFooterTranslationContent = true;
        return this;
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public RefreshLayout setEnableAutoLoadMore(boolean enabled) {
        this.mEnableAutoLoadMore = enabled;
        return this;
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public RefreshLayout setEnableOverScrollBounce(boolean enabled) {
        this.mEnableOverScrollBounce = enabled;
        return this;
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public RefreshLayout setEnablePureScrollMode(boolean enabled) {
        this.mEnablePureScrollMode = enabled;
        return this;
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public RefreshLayout setEnableScrollContentWhenLoaded(boolean enabled) {
        this.mEnableScrollContentWhenLoaded = enabled;
        return this;
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public RefreshLayout setEnableScrollContentWhenRefreshed(boolean enabled) {
        this.mEnableScrollContentWhenRefreshed = enabled;
        return this;
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public RefreshLayout setEnableLoadMoreWhenContentNotFull(boolean enabled) {
        this.mEnableLoadMoreWhenContentNotFull = enabled;
        RefreshContent refreshContent = this.mRefreshContent;
        if (refreshContent != null) {
            refreshContent.setEnableLoadMoreWhenContentNotFull(enabled);
        }
        return this;
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public RefreshLayout setEnableOverScrollDrag(boolean enabled) {
        this.mEnableOverScrollDrag = enabled;
        return this;
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    @Deprecated
    public RefreshLayout setEnableFooterFollowWhenLoadFinished(boolean enabled) {
        this.mEnableFooterFollowWhenNoMoreData = enabled;
        return this;
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public RefreshLayout setEnableFooterFollowWhenNoMoreData(boolean enabled) {
        this.mEnableFooterFollowWhenNoMoreData = enabled;
        return this;
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public RefreshLayout setEnableClipHeaderWhenFixedBehind(boolean enabled) {
        this.mEnableClipHeaderWhenFixedBehind = enabled;
        return this;
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public RefreshLayout setEnableClipFooterWhenFixedBehind(boolean enabled) {
        this.mEnableClipFooterWhenFixedBehind = enabled;
        return this;
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public RefreshLayout setEnableNestedScroll(boolean enabled) {
        setNestedScrollingEnabled(enabled);
        return this;
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public RefreshLayout setDisableContentWhenRefresh(boolean disable) {
        this.mDisableContentWhenRefresh = disable;
        return this;
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public RefreshLayout setDisableContentWhenLoading(boolean disable) {
        this.mDisableContentWhenLoading = disable;
        return this;
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public RefreshLayout setRefreshHeader(RefreshHeader header) {
        return setRefreshHeader(header, -1, -2);
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public RefreshLayout setRefreshHeader(RefreshHeader header, int width, int height) {
        RefreshInternal refreshInternal;
        RefreshInternal refreshInternal2 = this.mRefreshHeader;
        if (refreshInternal2 != null) {
            super.removeView(refreshInternal2.getView());
        }
        this.mRefreshHeader = header;
        this.mHeaderBackgroundColor = 0;
        this.mHeaderNeedTouchEventWhenRefreshing = false;
        this.mHeaderHeightStatus = this.mHeaderHeightStatus.unNotify();
        if (!this.mRefreshHeader.getSpinnerStyle().front) {
            super.addView(this.mRefreshHeader.getView(), 0, new LayoutParams(width, height));
        } else {
            super.addView(this.mRefreshHeader.getView(), getChildCount(), new LayoutParams(width, height));
        }
        int[] iArr = this.mPrimaryColors;
        if (iArr != null && (refreshInternal = this.mRefreshHeader) != null) {
            refreshInternal.setPrimaryColors(iArr);
        }
        return this;
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public RefreshLayout setRefreshFooter(RefreshFooter footer) {
        return setRefreshFooter(footer, -1, -2);
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public RefreshLayout setRefreshFooter(RefreshFooter footer, int width, int height) {
        RefreshInternal refreshInternal;
        RefreshInternal refreshInternal2 = this.mRefreshFooter;
        if (refreshInternal2 != null) {
            super.removeView(refreshInternal2.getView());
        }
        this.mRefreshFooter = footer;
        this.mFooterLocked = false;
        this.mFooterBackgroundColor = 0;
        this.mFooterNoMoreDataEffective = false;
        this.mFooterNeedTouchEventWhenLoading = false;
        this.mFooterHeightStatus = this.mFooterHeightStatus.unNotify();
        this.mEnableLoadMore = !this.mManualLoadMore || this.mEnableLoadMore;
        if (!this.mRefreshFooter.getSpinnerStyle().front) {
            super.addView(this.mRefreshFooter.getView(), 0, new LayoutParams(width, height));
        } else {
            super.addView(this.mRefreshFooter.getView(), getChildCount(), new LayoutParams(width, height));
        }
        int[] iArr = this.mPrimaryColors;
        if (iArr != null && (refreshInternal = this.mRefreshFooter) != null) {
            refreshInternal.setPrimaryColors(iArr);
        }
        return this;
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public RefreshLayout setRefreshContent(View content) {
        return setRefreshContent(content, -1, -1);
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public RefreshLayout setRefreshContent(View content, int width, int height) {
        RefreshContent refreshContent = this.mRefreshContent;
        if (refreshContent != null) {
            super.removeView(refreshContent.getView());
        }
        super.addView(content, getChildCount(), new LayoutParams(width, height));
        this.mRefreshContent = new RefreshContentWrapper(content);
        if (this.mAttachedToWindow) {
            View fixedHeaderView = findViewById(this.mFixedHeaderViewId);
            View fixedFooterView = findViewById(this.mFixedFooterViewId);
            this.mRefreshContent.setScrollBoundaryDecider(this.mScrollBoundaryDecider);
            this.mRefreshContent.setEnableLoadMoreWhenContentNotFull(this.mEnableLoadMoreWhenContentNotFull);
            this.mRefreshContent.setUpComponent(this.mKernel, fixedHeaderView, fixedFooterView);
        }
        RefreshInternal refreshInternal = this.mRefreshHeader;
        if (refreshInternal != null && refreshInternal.getSpinnerStyle().front) {
            super.bringChildToFront(this.mRefreshHeader.getView());
        }
        RefreshInternal refreshInternal2 = this.mRefreshFooter;
        if (refreshInternal2 != null && refreshInternal2.getSpinnerStyle().front) {
            super.bringChildToFront(this.mRefreshFooter.getView());
        }
        return this;
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public RefreshFooter getRefreshFooter() {
        RefreshInternal refreshInternal = this.mRefreshFooter;
        if (refreshInternal instanceof RefreshFooter) {
            return (RefreshFooter) refreshInternal;
        }
        return null;
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public RefreshHeader getRefreshHeader() {
        RefreshInternal refreshInternal = this.mRefreshHeader;
        if (refreshInternal instanceof RefreshHeader) {
            return (RefreshHeader) refreshInternal;
        }
        return null;
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public RefreshState getState() {
        return this.mState;
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public ViewGroup getLayout() {
        return this;
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public RefreshLayout setOnRefreshListener(OnRefreshListener listener) {
        this.mRefreshListener = listener;
        return this;
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public RefreshLayout setOnLoadMoreListener(OnLoadMoreListener listener) {
        this.mLoadMoreListener = listener;
        this.mEnableLoadMore = this.mEnableLoadMore || !(this.mManualLoadMore || listener == null);
        return this;
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public RefreshLayout setOnRefreshLoadMoreListener(OnRefreshLoadMoreListener listener) {
        this.mRefreshListener = listener;
        this.mLoadMoreListener = listener;
        this.mEnableLoadMore = this.mEnableLoadMore || !(this.mManualLoadMore || listener == null);
        return this;
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public RefreshLayout setOnMultiPurposeListener(OnMultiPurposeListener listener) {
        this.mOnMultiPurposeListener = listener;
        return this;
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public RefreshLayout setPrimaryColors(int... primaryColors) {
        RefreshInternal refreshInternal = this.mRefreshHeader;
        if (refreshInternal != null) {
            refreshInternal.setPrimaryColors(primaryColors);
        }
        RefreshInternal refreshInternal2 = this.mRefreshFooter;
        if (refreshInternal2 != null) {
            refreshInternal2.setPrimaryColors(primaryColors);
        }
        this.mPrimaryColors = primaryColors;
        return this;
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public RefreshLayout setPrimaryColorsId(int... primaryColorId) {
        int[] colors = new int[primaryColorId.length];
        for (int i = 0; i < primaryColorId.length; i++) {
            colors[i] = ContextCompat.getColor(getContext(), primaryColorId[i]);
        }
        setPrimaryColors(colors);
        return this;
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public RefreshLayout setScrollBoundaryDecider(ScrollBoundaryDecider boundary) {
        this.mScrollBoundaryDecider = boundary;
        RefreshContent refreshContent = this.mRefreshContent;
        if (refreshContent != null) {
            refreshContent.setScrollBoundaryDecider(boundary);
        }
        return this;
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public RefreshLayout setNoMoreData(boolean noMoreData) {
        if (this.mState == RefreshState.Refreshing && noMoreData) {
            finishRefreshWithNoMoreData();
        } else if (this.mState == RefreshState.Loading && noMoreData) {
            finishLoadMoreWithNoMoreData();
        } else if (this.mFooterNoMoreData != noMoreData) {
            this.mFooterNoMoreData = noMoreData;
            RefreshInternal refreshInternal = this.mRefreshFooter;
            if (refreshInternal instanceof RefreshFooter) {
                if (((RefreshFooter) refreshInternal).setNoMoreData(noMoreData)) {
                    this.mFooterNoMoreDataEffective = true;
                    if (this.mFooterNoMoreData && this.mEnableFooterFollowWhenNoMoreData && this.mSpinner > 0 && this.mRefreshFooter.getSpinnerStyle() == SpinnerStyle.Translate && isEnableRefreshOrLoadMore(this.mEnableLoadMore) && isEnableTranslationContent(this.mEnableRefresh, this.mRefreshHeader)) {
                        this.mRefreshFooter.getView().setTranslationY(this.mSpinner);
                    }
                } else {
                    this.mFooterNoMoreDataEffective = false;
                    String msg = "Footer:" + this.mRefreshFooter + " NoMoreData is not supported.(不支持NoMoreData，请使用[ClassicsFooter]或者[自定义Footer并实现setNoMoreData方法且返回true])";
                    Throwable e = new RuntimeException(msg);
                    e.printStackTrace();
                }
            }
        }
        return this;
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public RefreshLayout resetNoMoreData() {
        return setNoMoreData(false);
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public RefreshLayout finishRefresh() {
        return finishRefresh(true);
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public RefreshLayout finishLoadMore() {
        return finishLoadMore(true);
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public RefreshLayout finishRefresh(int delayed) {
        return finishRefresh(delayed, true, Boolean.FALSE);
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public RefreshLayout finishRefresh(boolean success) {
        if (!success) {
            return finishRefresh(0, false, null);
        }
        long passTime = System.currentTimeMillis() - this.mLastOpenTime;
        int delayed = Math.min(Math.max(0, 300 - ((int) passTime)), 300) << 16;
        return finishRefresh(delayed, true, Boolean.FALSE);
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public RefreshLayout finishRefresh(int delayed, final boolean success, final Boolean noMoreData) {
        final int more = delayed >> 16;
        int delay = (delayed << 16) >> 16;
        Runnable runnable = new Runnable() { // from class: com.scwang.smartrefresh.layout.SmartRefreshLayout.6
            int count = 0;

            @Override // java.lang.Runnable
            public void run() {
                if (this.count == 0) {
                    if (SmartRefreshLayout.this.mState == RefreshState.None && SmartRefreshLayout.this.mViceState == RefreshState.Refreshing) {
                        SmartRefreshLayout.this.mViceState = RefreshState.None;
                    } else if (SmartRefreshLayout.this.reboundAnimator != null && SmartRefreshLayout.this.mState.isHeader && (SmartRefreshLayout.this.mState.isDragging || SmartRefreshLayout.this.mState == RefreshState.RefreshReleased)) {
                        ValueAnimator animator = SmartRefreshLayout.this.reboundAnimator;
                        SmartRefreshLayout.this.reboundAnimator = null;
                        animator.cancel();
                        SmartRefreshLayout.this.mKernel.setState(RefreshState.None);
                    } else if (SmartRefreshLayout.this.mState == RefreshState.Refreshing && SmartRefreshLayout.this.mRefreshHeader != null && SmartRefreshLayout.this.mRefreshContent != null) {
                        this.count++;
                        SmartRefreshLayout.this.mHandler.postDelayed(this, more);
                        SmartRefreshLayout.this.notifyStateChanged(RefreshState.RefreshFinish);
                        if (noMoreData == Boolean.FALSE) {
                            SmartRefreshLayout.this.setNoMoreData(false);
                        }
                    }
                    if (noMoreData == Boolean.TRUE) {
                        SmartRefreshLayout.this.setNoMoreData(true);
                        return;
                    }
                    return;
                }
                int startDelay = SmartRefreshLayout.this.mRefreshHeader.onFinish(SmartRefreshLayout.this, success);
                if (SmartRefreshLayout.this.mOnMultiPurposeListener != null && (SmartRefreshLayout.this.mRefreshHeader instanceof RefreshHeader)) {
                    SmartRefreshLayout.this.mOnMultiPurposeListener.onHeaderFinish((RefreshHeader) SmartRefreshLayout.this.mRefreshHeader, success);
                }
                if (startDelay < Integer.MAX_VALUE) {
                    if (SmartRefreshLayout.this.mIsBeingDragged || SmartRefreshLayout.this.mNestedInProgress) {
                        long time = System.currentTimeMillis();
                        if (SmartRefreshLayout.this.mIsBeingDragged) {
                            SmartRefreshLayout smartRefreshLayout = SmartRefreshLayout.this;
                            smartRefreshLayout.mTouchY = smartRefreshLayout.mLastTouchY;
                            SmartRefreshLayout.this.mTouchSpinner = 0;
                            SmartRefreshLayout.this.mIsBeingDragged = false;
                            SmartRefreshLayout smartRefreshLayout2 = SmartRefreshLayout.this;
                            SmartRefreshLayout.super.dispatchTouchEvent(MotionEvent.obtain(time, time, 0, smartRefreshLayout2.mLastTouchX, (SmartRefreshLayout.this.mLastTouchY + SmartRefreshLayout.this.mSpinner) - (SmartRefreshLayout.this.mTouchSlop * 2), 0));
                            SmartRefreshLayout smartRefreshLayout3 = SmartRefreshLayout.this;
                            SmartRefreshLayout.super.dispatchTouchEvent(MotionEvent.obtain(time, time, 2, smartRefreshLayout3.mLastTouchX, SmartRefreshLayout.this.mLastTouchY + SmartRefreshLayout.this.mSpinner, 0));
                        }
                        if (SmartRefreshLayout.this.mNestedInProgress) {
                            SmartRefreshLayout.this.mTotalUnconsumed = 0;
                            SmartRefreshLayout smartRefreshLayout4 = SmartRefreshLayout.this;
                            SmartRefreshLayout.super.dispatchTouchEvent(MotionEvent.obtain(time, time, 1, smartRefreshLayout4.mLastTouchX, SmartRefreshLayout.this.mLastTouchY, 0));
                            SmartRefreshLayout.this.mNestedInProgress = false;
                            SmartRefreshLayout.this.mTouchSpinner = 0;
                        }
                    }
                    if (SmartRefreshLayout.this.mSpinner <= 0) {
                        if (SmartRefreshLayout.this.mSpinner < 0) {
                            SmartRefreshLayout smartRefreshLayout5 = SmartRefreshLayout.this;
                            smartRefreshLayout5.animSpinner(0, startDelay, smartRefreshLayout5.mReboundInterpolator, SmartRefreshLayout.this.mReboundDuration);
                            return;
                        } else {
                            SmartRefreshLayout.this.mKernel.moveSpinner(0, false);
                            SmartRefreshLayout.this.mKernel.setState(RefreshState.None);
                            return;
                        }
                    }
                    ValueAnimator.AnimatorUpdateListener updateListener = null;
                    SmartRefreshLayout smartRefreshLayout6 = SmartRefreshLayout.this;
                    ValueAnimator valueAnimator = smartRefreshLayout6.animSpinner(0, startDelay, smartRefreshLayout6.mReboundInterpolator, SmartRefreshLayout.this.mReboundDuration);
                    if (SmartRefreshLayout.this.mEnableScrollContentWhenRefreshed) {
                        updateListener = SmartRefreshLayout.this.mRefreshContent.scrollContentWhenFinished(SmartRefreshLayout.this.mSpinner);
                    }
                    if (valueAnimator != null && updateListener != null) {
                        valueAnimator.addUpdateListener(updateListener);
                    }
                }
            }
        };
        if (delay > 0) {
            this.mHandler.postDelayed(runnable, delay);
        } else {
            runnable.run();
        }
        return this;
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public RefreshLayout finishRefreshWithNoMoreData() {
        long passTime = System.currentTimeMillis() - this.mLastOpenTime;
        return finishRefresh(Math.min(Math.max(0, 300 - ((int) passTime)), 300) << 16, true, Boolean.TRUE);
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public RefreshLayout finishLoadMore(int delayed) {
        return finishLoadMore(delayed, true, false);
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public RefreshLayout finishLoadMore(boolean success) {
        long passTime = System.currentTimeMillis() - this.mLastOpenTime;
        return finishLoadMore(success ? Math.min(Math.max(0, 300 - ((int) passTime)), 300) << 16 : 0, success, false);
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public RefreshLayout finishLoadMore(int delayed, boolean success, boolean noMoreData) {
        int more = delayed >> 16;
        int delay = (delayed << 16) >> 16;
        Runnable runnable = new AnonymousClass7(more, noMoreData, success);
        if (delay > 0) {
            this.mHandler.postDelayed(runnable, delay);
        } else {
            runnable.run();
        }
        return this;
    }

    /* JADX INFO: renamed from: com.scwang.smartrefresh.layout.SmartRefreshLayout$7, reason: invalid class name */
    class AnonymousClass7 implements Runnable {
        int count = 0;
        final /* synthetic */ int val$more;
        final /* synthetic */ boolean val$noMoreData;
        final /* synthetic */ boolean val$success;

        AnonymousClass7(int i, boolean z, boolean z2) {
            this.val$more = i;
            this.val$noMoreData = z;
            this.val$success = z2;
        }

        @Override // java.lang.Runnable
        public void run() {
            if (this.count != 0) {
                int startDelay = SmartRefreshLayout.this.mRefreshFooter.onFinish(SmartRefreshLayout.this, this.val$success);
                if (SmartRefreshLayout.this.mOnMultiPurposeListener != null && (SmartRefreshLayout.this.mRefreshFooter instanceof RefreshFooter)) {
                    SmartRefreshLayout.this.mOnMultiPurposeListener.onFooterFinish((RefreshFooter) SmartRefreshLayout.this.mRefreshFooter, this.val$success);
                }
                if (startDelay < Integer.MAX_VALUE) {
                    boolean needHoldFooter = this.val$noMoreData && SmartRefreshLayout.this.mEnableFooterFollowWhenNoMoreData && SmartRefreshLayout.this.mSpinner < 0 && SmartRefreshLayout.this.mRefreshContent.canLoadMore();
                    final int offset = SmartRefreshLayout.this.mSpinner - (needHoldFooter ? Math.max(SmartRefreshLayout.this.mSpinner, -SmartRefreshLayout.this.mFooterHeight) : 0);
                    if (SmartRefreshLayout.this.mIsBeingDragged || SmartRefreshLayout.this.mNestedInProgress) {
                        long time = System.currentTimeMillis();
                        if (SmartRefreshLayout.this.mIsBeingDragged) {
                            SmartRefreshLayout smartRefreshLayout = SmartRefreshLayout.this;
                            smartRefreshLayout.mTouchY = smartRefreshLayout.mLastTouchY;
                            SmartRefreshLayout smartRefreshLayout2 = SmartRefreshLayout.this;
                            smartRefreshLayout2.mTouchSpinner = smartRefreshLayout2.mSpinner - offset;
                            SmartRefreshLayout.this.mIsBeingDragged = false;
                            int offsetY = SmartRefreshLayout.this.mEnableFooterTranslationContent ? offset : 0;
                            SmartRefreshLayout smartRefreshLayout3 = SmartRefreshLayout.this;
                            SmartRefreshLayout.super.dispatchTouchEvent(MotionEvent.obtain(time, time, 0, smartRefreshLayout3.mLastTouchX, SmartRefreshLayout.this.mLastTouchY + offsetY + (SmartRefreshLayout.this.mTouchSlop * 2), 0));
                            SmartRefreshLayout smartRefreshLayout4 = SmartRefreshLayout.this;
                            SmartRefreshLayout.super.dispatchTouchEvent(MotionEvent.obtain(time, time, 2, smartRefreshLayout4.mLastTouchX, SmartRefreshLayout.this.mLastTouchY + offsetY, 0));
                        }
                        if (SmartRefreshLayout.this.mNestedInProgress) {
                            SmartRefreshLayout.this.mTotalUnconsumed = 0;
                            SmartRefreshLayout smartRefreshLayout5 = SmartRefreshLayout.this;
                            SmartRefreshLayout.super.dispatchTouchEvent(MotionEvent.obtain(time, time, 1, smartRefreshLayout5.mLastTouchX, SmartRefreshLayout.this.mLastTouchY, 0));
                            SmartRefreshLayout.this.mNestedInProgress = false;
                            SmartRefreshLayout.this.mTouchSpinner = 0;
                        }
                    }
                    SmartRefreshLayout.this.mHandler.postDelayed(new Runnable() { // from class: com.scwang.smartrefresh.layout.SmartRefreshLayout.7.1
                        @Override // java.lang.Runnable
                        public void run() {
                            ValueAnimator.AnimatorUpdateListener updateListener = null;
                            if (SmartRefreshLayout.this.mEnableScrollContentWhenLoaded && offset < 0) {
                                updateListener = SmartRefreshLayout.this.mRefreshContent.scrollContentWhenFinished(SmartRefreshLayout.this.mSpinner);
                            }
                            if (updateListener != null) {
                                updateListener.onAnimationUpdate(ValueAnimator.ofInt(0, 0));
                            }
                            ValueAnimator animator = null;
                            AnimatorListenerAdapter listenerAdapter = new AnimatorListenerAdapter() { // from class: com.scwang.smartrefresh.layout.SmartRefreshLayout.7.1.1
                                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                                public void onAnimationEnd(Animator animation) {
                                    SmartRefreshLayout.this.mFooterLocked = false;
                                    if (AnonymousClass7.this.val$noMoreData) {
                                        SmartRefreshLayout.this.setNoMoreData(true);
                                    }
                                    if (SmartRefreshLayout.this.mState == RefreshState.LoadFinish) {
                                        SmartRefreshLayout.this.notifyStateChanged(RefreshState.None);
                                    }
                                }
                            };
                            if (SmartRefreshLayout.this.mSpinner > 0) {
                                animator = SmartRefreshLayout.this.mKernel.animSpinner(0);
                            } else if (updateListener != null || SmartRefreshLayout.this.mSpinner == 0) {
                                if (SmartRefreshLayout.this.reboundAnimator != null) {
                                    SmartRefreshLayout.this.reboundAnimator.cancel();
                                    SmartRefreshLayout.this.reboundAnimator = null;
                                }
                                SmartRefreshLayout.this.mKernel.moveSpinner(0, false);
                                SmartRefreshLayout.this.mKernel.setState(RefreshState.None);
                            } else if (AnonymousClass7.this.val$noMoreData && SmartRefreshLayout.this.mEnableFooterFollowWhenNoMoreData) {
                                if (SmartRefreshLayout.this.mSpinner >= (-SmartRefreshLayout.this.mFooterHeight)) {
                                    SmartRefreshLayout.this.notifyStateChanged(RefreshState.None);
                                } else {
                                    animator = SmartRefreshLayout.this.mKernel.animSpinner(-SmartRefreshLayout.this.mFooterHeight);
                                }
                            } else {
                                animator = SmartRefreshLayout.this.mKernel.animSpinner(0);
                            }
                            if (animator != null) {
                                animator.addListener(listenerAdapter);
                            } else {
                                listenerAdapter.onAnimationEnd(null);
                            }
                        }
                    }, SmartRefreshLayout.this.mSpinner < 0 ? startDelay : 0L);
                    return;
                }
                return;
            }
            if (SmartRefreshLayout.this.mState == RefreshState.None && SmartRefreshLayout.this.mViceState == RefreshState.Loading) {
                SmartRefreshLayout.this.mViceState = RefreshState.None;
            } else if (SmartRefreshLayout.this.reboundAnimator != null && ((SmartRefreshLayout.this.mState.isDragging || SmartRefreshLayout.this.mState == RefreshState.LoadReleased) && SmartRefreshLayout.this.mState.isFooter)) {
                ValueAnimator animator = SmartRefreshLayout.this.reboundAnimator;
                SmartRefreshLayout.this.reboundAnimator = null;
                animator.cancel();
                SmartRefreshLayout.this.mKernel.setState(RefreshState.None);
            } else if (SmartRefreshLayout.this.mState == RefreshState.Loading && SmartRefreshLayout.this.mRefreshFooter != null && SmartRefreshLayout.this.mRefreshContent != null) {
                this.count++;
                SmartRefreshLayout.this.mHandler.postDelayed(this, this.val$more);
                SmartRefreshLayout.this.notifyStateChanged(RefreshState.LoadFinish);
                return;
            }
            if (this.val$noMoreData) {
                SmartRefreshLayout.this.setNoMoreData(true);
            }
        }
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public RefreshLayout finishLoadMoreWithNoMoreData() {
        long passTime = System.currentTimeMillis() - this.mLastOpenTime;
        return finishLoadMore(Math.min(Math.max(0, 300 - ((int) passTime)), 300) << 16, true, true);
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public RefreshLayout closeHeaderOrFooter() {
        if (this.mState == RefreshState.Refreshing) {
            finishRefresh();
        } else if (this.mState == RefreshState.Loading) {
            finishLoadMore();
        } else if (this.mSpinner != 0) {
            animSpinner(0, 0, this.mReboundInterpolator, this.mReboundDuration);
        }
        return this;
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public boolean autoRefresh() {
        int i = this.mAttachedToWindow ? 0 : 400;
        int i2 = this.mReboundDuration;
        float f = (this.mHeaderMaxDragRate / 2.0f) + 0.5f;
        int i3 = this.mHeaderHeight;
        float f2 = f * i3 * 1.0f;
        if (i3 == 0) {
            i3 = 1;
        }
        return autoRefresh(i, i2, f2 / i3, false);
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    @Deprecated
    public boolean autoRefresh(int delayed) {
        int i = this.mReboundDuration;
        float f = (this.mHeaderMaxDragRate / 2.0f) + 0.5f;
        int i2 = this.mHeaderHeight;
        float f2 = f * i2 * 1.0f;
        if (i2 == 0) {
            i2 = 1;
        }
        return autoRefresh(delayed, i, f2 / i2, false);
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public boolean autoRefreshAnimationOnly() {
        int i = this.mAttachedToWindow ? 0 : 400;
        int i2 = this.mReboundDuration;
        float f = (this.mHeaderMaxDragRate / 2.0f) + 0.5f;
        int i3 = this.mHeaderHeight;
        float f2 = f * i3 * 1.0f;
        if (i3 == 0) {
            i3 = 1;
        }
        return autoRefresh(i, i2, f2 / i3, true);
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public boolean autoRefresh(int delayed, final int duration, final float dragRate, final boolean animationOnly) {
        if (this.mState == RefreshState.None && isEnableRefreshOrLoadMore(this.mEnableRefresh)) {
            Runnable runnable = new Runnable() { // from class: com.scwang.smartrefresh.layout.SmartRefreshLayout.8
                @Override // java.lang.Runnable
                public void run() {
                    if (SmartRefreshLayout.this.mViceState != RefreshState.Refreshing) {
                        return;
                    }
                    if (SmartRefreshLayout.this.reboundAnimator != null) {
                        SmartRefreshLayout.this.reboundAnimator.cancel();
                    }
                    View thisView = SmartRefreshLayout.this;
                    SmartRefreshLayout.this.mLastTouchX = thisView.getMeasuredWidth() / 2.0f;
                    SmartRefreshLayout.this.mKernel.setState(RefreshState.PullDownToRefresh);
                    SmartRefreshLayout smartRefreshLayout = SmartRefreshLayout.this;
                    smartRefreshLayout.reboundAnimator = ValueAnimator.ofInt(smartRefreshLayout.mSpinner, (int) (SmartRefreshLayout.this.mHeaderHeight * dragRate));
                    SmartRefreshLayout.this.reboundAnimator.setDuration(duration);
                    SmartRefreshLayout.this.reboundAnimator.setInterpolator(new SmartUtil(SmartUtil.INTERPOLATOR_VISCOUS_FLUID));
                    SmartRefreshLayout.this.reboundAnimator.addUpdateListener(new ValueAnimator.AnimatorUpdateListener() { // from class: com.scwang.smartrefresh.layout.SmartRefreshLayout.8.1
                        @Override // android.animation.ValueAnimator.AnimatorUpdateListener
                        public void onAnimationUpdate(ValueAnimator animation) {
                            if (SmartRefreshLayout.this.reboundAnimator != null) {
                                SmartRefreshLayout.this.mKernel.moveSpinner(((Integer) animation.getAnimatedValue()).intValue(), true);
                            }
                        }
                    });
                    SmartRefreshLayout.this.reboundAnimator.addListener(new AnimatorListenerAdapter() { // from class: com.scwang.smartrefresh.layout.SmartRefreshLayout.8.2
                        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                        public void onAnimationEnd(Animator animation) {
                            if (SmartRefreshLayout.this.reboundAnimator != null) {
                                SmartRefreshLayout.this.reboundAnimator = null;
                                if (SmartRefreshLayout.this.mState != RefreshState.ReleaseToRefresh) {
                                    SmartRefreshLayout.this.mKernel.setState(RefreshState.ReleaseToRefresh);
                                }
                                SmartRefreshLayout.this.setStateRefreshing(!animationOnly);
                            }
                        }
                    });
                    SmartRefreshLayout.this.reboundAnimator.start();
                }
            };
            setViceState(RefreshState.Refreshing);
            if (delayed > 0) {
                this.mHandler.postDelayed(runnable, delayed);
                return true;
            }
            runnable.run();
            return true;
        }
        return false;
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public boolean autoLoadMore() {
        int i = this.mReboundDuration;
        int i2 = this.mFooterHeight;
        float f = i2 * ((this.mFooterMaxDragRate / 2.0f) + 0.5f) * 1.0f;
        if (i2 == 0) {
            i2 = 1;
        }
        return autoLoadMore(0, i, f / i2, false);
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public boolean autoLoadMoreAnimationOnly() {
        int i = this.mReboundDuration;
        int i2 = this.mFooterHeight;
        float f = i2 * ((this.mFooterMaxDragRate / 2.0f) + 0.5f) * 1.0f;
        if (i2 == 0) {
            i2 = 1;
        }
        return autoLoadMore(0, i, f / i2, true);
    }

    @Override // com.scwang.smartrefresh.layout.api.RefreshLayout
    public boolean autoLoadMore(int delayed, final int duration, final float dragRate, final boolean animationOnly) {
        if (this.mState == RefreshState.None && isEnableRefreshOrLoadMore(this.mEnableLoadMore) && !this.mFooterNoMoreData) {
            Runnable runnable = new Runnable() { // from class: com.scwang.smartrefresh.layout.SmartRefreshLayout.9
                @Override // java.lang.Runnable
                public void run() {
                    if (SmartRefreshLayout.this.mViceState != RefreshState.Loading) {
                        return;
                    }
                    if (SmartRefreshLayout.this.reboundAnimator != null) {
                        SmartRefreshLayout.this.reboundAnimator.cancel();
                    }
                    View thisView = SmartRefreshLayout.this;
                    SmartRefreshLayout.this.mLastTouchX = thisView.getMeasuredWidth() / 2.0f;
                    SmartRefreshLayout.this.mKernel.setState(RefreshState.PullUpToLoad);
                    SmartRefreshLayout smartRefreshLayout = SmartRefreshLayout.this;
                    smartRefreshLayout.reboundAnimator = ValueAnimator.ofInt(smartRefreshLayout.mSpinner, -((int) (SmartRefreshLayout.this.mFooterHeight * dragRate)));
                    SmartRefreshLayout.this.reboundAnimator.setDuration(duration);
                    SmartRefreshLayout.this.reboundAnimator.setInterpolator(new SmartUtil(SmartUtil.INTERPOLATOR_VISCOUS_FLUID));
                    SmartRefreshLayout.this.reboundAnimator.addUpdateListener(new ValueAnimator.AnimatorUpdateListener() { // from class: com.scwang.smartrefresh.layout.SmartRefreshLayout.9.1
                        @Override // android.animation.ValueAnimator.AnimatorUpdateListener
                        public void onAnimationUpdate(ValueAnimator animation) {
                            if (SmartRefreshLayout.this.reboundAnimator != null) {
                                SmartRefreshLayout.this.mKernel.moveSpinner(((Integer) animation.getAnimatedValue()).intValue(), true);
                            }
                        }
                    });
                    SmartRefreshLayout.this.reboundAnimator.addListener(new AnimatorListenerAdapter() { // from class: com.scwang.smartrefresh.layout.SmartRefreshLayout.9.2
                        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                        public void onAnimationEnd(Animator animation) {
                            if (SmartRefreshLayout.this.reboundAnimator != null) {
                                SmartRefreshLayout.this.reboundAnimator = null;
                                if (SmartRefreshLayout.this.mState != RefreshState.ReleaseToLoad) {
                                    SmartRefreshLayout.this.mKernel.setState(RefreshState.ReleaseToLoad);
                                }
                                SmartRefreshLayout.this.setStateLoading(!animationOnly);
                            }
                        }
                    });
                    SmartRefreshLayout.this.reboundAnimator.start();
                }
            };
            setViceState(RefreshState.Loading);
            if (delayed > 0) {
                this.mHandler.postDelayed(runnable, delayed);
                return true;
            }
            runnable.run();
            return true;
        }
        return false;
    }

    public static void setDefaultRefreshHeaderCreator(DefaultRefreshHeaderCreator creator) {
        sHeaderCreator = creator;
    }

    public static void setDefaultRefreshFooterCreator(DefaultRefreshFooterCreator creator) {
        sFooterCreator = creator;
    }

    public static void setDefaultRefreshInitializer(DefaultRefreshInitializer initializer) {
        sRefreshInitializer = initializer;
    }

    public class RefreshKernelImpl implements RefreshKernel {
        public RefreshKernelImpl() {
        }

        @Override // com.scwang.smartrefresh.layout.api.RefreshKernel
        public RefreshLayout getRefreshLayout() {
            return SmartRefreshLayout.this;
        }

        @Override // com.scwang.smartrefresh.layout.api.RefreshKernel
        public RefreshContent getRefreshContent() {
            return SmartRefreshLayout.this.mRefreshContent;
        }

        @Override // com.scwang.smartrefresh.layout.api.RefreshKernel
        public RefreshKernel setState(RefreshState state) {
            switch (AnonymousClass10.$SwitchMap$com$scwang$smartrefresh$layout$constant$RefreshState[state.ordinal()]) {
                case 1:
                    if (SmartRefreshLayout.this.mState != RefreshState.None && SmartRefreshLayout.this.mSpinner == 0) {
                        SmartRefreshLayout.this.notifyStateChanged(RefreshState.None);
                    } else if (SmartRefreshLayout.this.mSpinner != 0) {
                        animSpinner(0);
                    }
                    break;
                case 2:
                    if (!SmartRefreshLayout.this.mState.isOpening) {
                        SmartRefreshLayout smartRefreshLayout = SmartRefreshLayout.this;
                        if (smartRefreshLayout.isEnableRefreshOrLoadMore(smartRefreshLayout.mEnableRefresh)) {
                            SmartRefreshLayout.this.notifyStateChanged(RefreshState.PullDownToRefresh);
                        }
                    }
                    SmartRefreshLayout.this.setViceState(RefreshState.PullDownToRefresh);
                    break;
                case 3:
                    SmartRefreshLayout smartRefreshLayout2 = SmartRefreshLayout.this;
                    if (smartRefreshLayout2.isEnableRefreshOrLoadMore(smartRefreshLayout2.mEnableLoadMore) && !SmartRefreshLayout.this.mState.isOpening && !SmartRefreshLayout.this.mState.isFinishing && (!SmartRefreshLayout.this.mFooterNoMoreData || !SmartRefreshLayout.this.mEnableFooterFollowWhenNoMoreData || !SmartRefreshLayout.this.mFooterNoMoreDataEffective)) {
                        SmartRefreshLayout.this.notifyStateChanged(RefreshState.PullUpToLoad);
                    } else {
                        SmartRefreshLayout.this.setViceState(RefreshState.PullUpToLoad);
                    }
                    break;
                case 4:
                    if (!SmartRefreshLayout.this.mState.isOpening) {
                        SmartRefreshLayout smartRefreshLayout3 = SmartRefreshLayout.this;
                        if (smartRefreshLayout3.isEnableRefreshOrLoadMore(smartRefreshLayout3.mEnableRefresh)) {
                            SmartRefreshLayout.this.notifyStateChanged(RefreshState.PullDownCanceled);
                            setState(RefreshState.None);
                        }
                    }
                    SmartRefreshLayout.this.setViceState(RefreshState.PullDownCanceled);
                    break;
                case 5:
                    SmartRefreshLayout smartRefreshLayout4 = SmartRefreshLayout.this;
                    if (smartRefreshLayout4.isEnableRefreshOrLoadMore(smartRefreshLayout4.mEnableLoadMore) && !SmartRefreshLayout.this.mState.isOpening && (!SmartRefreshLayout.this.mFooterNoMoreData || !SmartRefreshLayout.this.mEnableFooterFollowWhenNoMoreData || !SmartRefreshLayout.this.mFooterNoMoreDataEffective)) {
                        SmartRefreshLayout.this.notifyStateChanged(RefreshState.PullUpCanceled);
                        setState(RefreshState.None);
                    } else {
                        SmartRefreshLayout.this.setViceState(RefreshState.PullUpCanceled);
                    }
                    break;
                case 6:
                    if (!SmartRefreshLayout.this.mState.isOpening) {
                        SmartRefreshLayout smartRefreshLayout5 = SmartRefreshLayout.this;
                        if (smartRefreshLayout5.isEnableRefreshOrLoadMore(smartRefreshLayout5.mEnableRefresh)) {
                            SmartRefreshLayout.this.notifyStateChanged(RefreshState.ReleaseToRefresh);
                        }
                    }
                    SmartRefreshLayout.this.setViceState(RefreshState.ReleaseToRefresh);
                    break;
                case 7:
                    SmartRefreshLayout smartRefreshLayout6 = SmartRefreshLayout.this;
                    if (smartRefreshLayout6.isEnableRefreshOrLoadMore(smartRefreshLayout6.mEnableLoadMore) && !SmartRefreshLayout.this.mState.isOpening && !SmartRefreshLayout.this.mState.isFinishing && (!SmartRefreshLayout.this.mFooterNoMoreData || !SmartRefreshLayout.this.mEnableFooterFollowWhenNoMoreData || !SmartRefreshLayout.this.mFooterNoMoreDataEffective)) {
                        SmartRefreshLayout.this.notifyStateChanged(RefreshState.ReleaseToLoad);
                    } else {
                        SmartRefreshLayout.this.setViceState(RefreshState.ReleaseToLoad);
                    }
                    break;
                case 8:
                    if (!SmartRefreshLayout.this.mState.isOpening) {
                        SmartRefreshLayout smartRefreshLayout7 = SmartRefreshLayout.this;
                        if (smartRefreshLayout7.isEnableRefreshOrLoadMore(smartRefreshLayout7.mEnableRefresh)) {
                            SmartRefreshLayout.this.notifyStateChanged(RefreshState.ReleaseToTwoLevel);
                        }
                    }
                    SmartRefreshLayout.this.setViceState(RefreshState.ReleaseToTwoLevel);
                    break;
                case 9:
                    if (!SmartRefreshLayout.this.mState.isOpening) {
                        SmartRefreshLayout smartRefreshLayout8 = SmartRefreshLayout.this;
                        if (smartRefreshLayout8.isEnableRefreshOrLoadMore(smartRefreshLayout8.mEnableRefresh)) {
                            SmartRefreshLayout.this.notifyStateChanged(RefreshState.RefreshReleased);
                        }
                    }
                    SmartRefreshLayout.this.setViceState(RefreshState.RefreshReleased);
                    break;
                case 10:
                    if (!SmartRefreshLayout.this.mState.isOpening) {
                        SmartRefreshLayout smartRefreshLayout9 = SmartRefreshLayout.this;
                        if (smartRefreshLayout9.isEnableRefreshOrLoadMore(smartRefreshLayout9.mEnableLoadMore)) {
                            SmartRefreshLayout.this.notifyStateChanged(RefreshState.LoadReleased);
                        }
                    }
                    SmartRefreshLayout.this.setViceState(RefreshState.LoadReleased);
                    break;
                case 11:
                    SmartRefreshLayout.this.setStateRefreshing(true);
                    break;
                case 12:
                    SmartRefreshLayout.this.setStateLoading(true);
                    break;
                case 13:
                    if (SmartRefreshLayout.this.mState == RefreshState.Refreshing) {
                        SmartRefreshLayout.this.notifyStateChanged(RefreshState.RefreshFinish);
                    }
                    break;
                case 14:
                    if (SmartRefreshLayout.this.mState == RefreshState.Loading) {
                        SmartRefreshLayout.this.notifyStateChanged(RefreshState.LoadFinish);
                    }
                    break;
                case 15:
                    SmartRefreshLayout.this.notifyStateChanged(RefreshState.TwoLevelReleased);
                    break;
                case 16:
                    SmartRefreshLayout.this.notifyStateChanged(RefreshState.TwoLevelFinish);
                    break;
                case 17:
                    SmartRefreshLayout.this.notifyStateChanged(RefreshState.TwoLevel);
                    break;
            }
            return null;
        }

        @Override // com.scwang.smartrefresh.layout.api.RefreshKernel
        public RefreshKernel startTwoLevel(boolean open) {
            if (open) {
                AnimatorListenerAdapter listener = new AnimatorListenerAdapter() { // from class: com.scwang.smartrefresh.layout.SmartRefreshLayout.RefreshKernelImpl.1
                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationEnd(Animator animation) {
                        SmartRefreshLayout.this.mKernel.setState(RefreshState.TwoLevel);
                    }
                };
                View thisView = SmartRefreshLayout.this;
                ValueAnimator animator = animSpinner(thisView.getMeasuredHeight());
                if (animator != null && animator == SmartRefreshLayout.this.reboundAnimator) {
                    animator.setDuration(SmartRefreshLayout.this.mFloorDuration);
                    animator.addListener(listener);
                } else {
                    listener.onAnimationEnd(null);
                }
            } else if (animSpinner(0) == null) {
                SmartRefreshLayout.this.notifyStateChanged(RefreshState.None);
            }
            return this;
        }

        @Override // com.scwang.smartrefresh.layout.api.RefreshKernel
        public RefreshKernel finishTwoLevel() {
            if (SmartRefreshLayout.this.mState == RefreshState.TwoLevel) {
                SmartRefreshLayout.this.mKernel.setState(RefreshState.TwoLevelFinish);
                if (SmartRefreshLayout.this.mSpinner == 0) {
                    moveSpinner(0, false);
                    SmartRefreshLayout.this.notifyStateChanged(RefreshState.None);
                } else {
                    animSpinner(0).setDuration(SmartRefreshLayout.this.mFloorDuration);
                }
            }
            return this;
        }

        @Override // com.scwang.smartrefresh.layout.api.RefreshKernel
        public RefreshKernel moveSpinner(int spinner, boolean isDragging) {
            int maxDragHeight;
            if (SmartRefreshLayout.this.mSpinner == spinner && ((SmartRefreshLayout.this.mRefreshHeader == null || !SmartRefreshLayout.this.mRefreshHeader.isSupportHorizontalDrag()) && (SmartRefreshLayout.this.mRefreshFooter == null || !SmartRefreshLayout.this.mRefreshFooter.isSupportHorizontalDrag()))) {
                return this;
            }
            View thisView = SmartRefreshLayout.this;
            int oldSpinner = SmartRefreshLayout.this.mSpinner;
            SmartRefreshLayout.this.mSpinner = spinner;
            if (isDragging && (SmartRefreshLayout.this.mViceState.isDragging || SmartRefreshLayout.this.mViceState.isOpening)) {
                if (SmartRefreshLayout.this.mSpinner <= SmartRefreshLayout.this.mHeaderHeight * SmartRefreshLayout.this.mHeaderTriggerRate) {
                    if ((-SmartRefreshLayout.this.mSpinner) > SmartRefreshLayout.this.mFooterHeight * SmartRefreshLayout.this.mFooterTriggerRate && !SmartRefreshLayout.this.mFooterNoMoreData) {
                        SmartRefreshLayout.this.mKernel.setState(RefreshState.ReleaseToLoad);
                    } else if (SmartRefreshLayout.this.mSpinner < 0 && !SmartRefreshLayout.this.mFooterNoMoreData) {
                        SmartRefreshLayout.this.mKernel.setState(RefreshState.PullUpToLoad);
                    } else if (SmartRefreshLayout.this.mSpinner > 0) {
                        SmartRefreshLayout.this.mKernel.setState(RefreshState.PullDownToRefresh);
                    }
                } else if (SmartRefreshLayout.this.mState != RefreshState.ReleaseToTwoLevel) {
                    SmartRefreshLayout.this.mKernel.setState(RefreshState.ReleaseToRefresh);
                }
            }
            if (SmartRefreshLayout.this.mRefreshContent != null) {
                int tSpinner = 0;
                boolean changed = false;
                if (spinner >= 0 && SmartRefreshLayout.this.mRefreshHeader != null) {
                    SmartRefreshLayout smartRefreshLayout = SmartRefreshLayout.this;
                    if (smartRefreshLayout.isEnableTranslationContent(smartRefreshLayout.mEnableHeaderTranslationContent, SmartRefreshLayout.this.mRefreshHeader)) {
                        changed = true;
                        tSpinner = spinner;
                    } else if (oldSpinner < 0) {
                        changed = true;
                        tSpinner = 0;
                    }
                }
                if (spinner <= 0 && SmartRefreshLayout.this.mRefreshFooter != null) {
                    SmartRefreshLayout smartRefreshLayout2 = SmartRefreshLayout.this;
                    if (smartRefreshLayout2.isEnableTranslationContent(smartRefreshLayout2.mEnableFooterTranslationContent, SmartRefreshLayout.this.mRefreshFooter)) {
                        changed = true;
                        tSpinner = spinner;
                    } else if (oldSpinner > 0) {
                        changed = true;
                        tSpinner = 0;
                    }
                }
                if (changed) {
                    SmartRefreshLayout.this.mRefreshContent.moveSpinner(tSpinner, SmartRefreshLayout.this.mHeaderTranslationViewId, SmartRefreshLayout.this.mFooterTranslationViewId);
                    if (SmartRefreshLayout.this.mFooterNoMoreData && SmartRefreshLayout.this.mFooterNoMoreDataEffective && SmartRefreshLayout.this.mEnableFooterFollowWhenNoMoreData && (SmartRefreshLayout.this.mRefreshFooter instanceof RefreshFooter) && SmartRefreshLayout.this.mRefreshFooter.getSpinnerStyle() == SpinnerStyle.Translate) {
                        SmartRefreshLayout smartRefreshLayout3 = SmartRefreshLayout.this;
                        if (smartRefreshLayout3.isEnableRefreshOrLoadMore(smartRefreshLayout3.mEnableLoadMore)) {
                            SmartRefreshLayout.this.mRefreshFooter.getView().setTranslationY(Math.max(0, tSpinner));
                        }
                    }
                    boolean header = SmartRefreshLayout.this.mEnableClipHeaderWhenFixedBehind && SmartRefreshLayout.this.mRefreshHeader != null && SmartRefreshLayout.this.mRefreshHeader.getSpinnerStyle() == SpinnerStyle.FixedBehind;
                    boolean header2 = header || SmartRefreshLayout.this.mHeaderBackgroundColor != 0;
                    boolean footer = SmartRefreshLayout.this.mEnableClipFooterWhenFixedBehind && SmartRefreshLayout.this.mRefreshFooter != null && SmartRefreshLayout.this.mRefreshFooter.getSpinnerStyle() == SpinnerStyle.FixedBehind;
                    boolean footer2 = footer || SmartRefreshLayout.this.mFooterBackgroundColor != 0;
                    if ((header2 && (tSpinner >= 0 || oldSpinner > 0)) || (footer2 && (tSpinner <= 0 || oldSpinner < 0))) {
                        thisView.invalidate();
                    }
                }
            }
            if ((spinner >= 0 || oldSpinner > 0) && SmartRefreshLayout.this.mRefreshHeader != null) {
                int offset = Math.max(spinner, 0);
                int headerHeight = SmartRefreshLayout.this.mHeaderHeight;
                int maxDragHeight2 = (int) (SmartRefreshLayout.this.mHeaderHeight * SmartRefreshLayout.this.mHeaderMaxDragRate);
                float percent = (offset * 1.0f) / (SmartRefreshLayout.this.mHeaderHeight == 0 ? 1 : SmartRefreshLayout.this.mHeaderHeight);
                SmartRefreshLayout smartRefreshLayout4 = SmartRefreshLayout.this;
                if (smartRefreshLayout4.isEnableRefreshOrLoadMore(smartRefreshLayout4.mEnableRefresh) || (SmartRefreshLayout.this.mState == RefreshState.RefreshFinish && !isDragging)) {
                    if (oldSpinner == SmartRefreshLayout.this.mSpinner) {
                        maxDragHeight = maxDragHeight2;
                    } else {
                        if (SmartRefreshLayout.this.mRefreshHeader.getSpinnerStyle() == SpinnerStyle.Translate) {
                            SmartRefreshLayout.this.mRefreshHeader.getView().setTranslationY(SmartRefreshLayout.this.mSpinner);
                            if (SmartRefreshLayout.this.mHeaderBackgroundColor != 0 && SmartRefreshLayout.this.mPaint != null) {
                                SmartRefreshLayout smartRefreshLayout5 = SmartRefreshLayout.this;
                                if (!smartRefreshLayout5.isEnableTranslationContent(smartRefreshLayout5.mEnableHeaderTranslationContent, SmartRefreshLayout.this.mRefreshHeader)) {
                                    thisView.invalidate();
                                }
                            }
                        } else if (SmartRefreshLayout.this.mRefreshHeader.getSpinnerStyle().scale) {
                            View headerView = SmartRefreshLayout.this.mRefreshHeader.getView();
                            ViewGroup.LayoutParams lp = headerView.getLayoutParams();
                            ViewGroup.MarginLayoutParams mlp = lp instanceof ViewGroup.MarginLayoutParams ? (ViewGroup.MarginLayoutParams) lp : SmartRefreshLayout.sDefaultMarginLP;
                            int widthSpec = View.MeasureSpec.makeMeasureSpec(headerView.getMeasuredWidth(), 1073741824);
                            headerView.measure(widthSpec, View.MeasureSpec.makeMeasureSpec(Math.max((SmartRefreshLayout.this.mSpinner - mlp.bottomMargin) - mlp.topMargin, 0), 1073741824));
                            int left = mlp.leftMargin;
                            int top = mlp.topMargin + SmartRefreshLayout.this.mHeaderInsetStart;
                            headerView.layout(left, top, headerView.getMeasuredWidth() + left, top + headerView.getMeasuredHeight());
                        }
                        maxDragHeight = maxDragHeight2;
                        SmartRefreshLayout.this.mRefreshHeader.onMoving(isDragging, percent, offset, headerHeight, maxDragHeight2);
                    }
                    if (isDragging && SmartRefreshLayout.this.mRefreshHeader.isSupportHorizontalDrag()) {
                        int offsetX = (int) SmartRefreshLayout.this.mLastTouchX;
                        int offsetMax = thisView.getWidth();
                        float percentX = SmartRefreshLayout.this.mLastTouchX / (offsetMax == 0 ? 1 : offsetMax);
                        SmartRefreshLayout.this.mRefreshHeader.onHorizontalDrag(percentX, offsetX, offsetMax);
                    }
                } else {
                    maxDragHeight = maxDragHeight2;
                }
                if (oldSpinner != SmartRefreshLayout.this.mSpinner && SmartRefreshLayout.this.mOnMultiPurposeListener != null && (SmartRefreshLayout.this.mRefreshHeader instanceof RefreshHeader)) {
                    SmartRefreshLayout.this.mOnMultiPurposeListener.onHeaderMoving((RefreshHeader) SmartRefreshLayout.this.mRefreshHeader, isDragging, percent, offset, headerHeight, maxDragHeight);
                }
            }
            if ((spinner <= 0 || oldSpinner < 0) && SmartRefreshLayout.this.mRefreshFooter != null) {
                int offset2 = -Math.min(spinner, 0);
                int footerHeight = SmartRefreshLayout.this.mFooterHeight;
                int maxDragHeight3 = (int) (SmartRefreshLayout.this.mFooterHeight * SmartRefreshLayout.this.mFooterMaxDragRate);
                float percent2 = (offset2 * 1.0f) / (SmartRefreshLayout.this.mFooterHeight == 0 ? 1 : SmartRefreshLayout.this.mFooterHeight);
                SmartRefreshLayout smartRefreshLayout6 = SmartRefreshLayout.this;
                if (smartRefreshLayout6.isEnableRefreshOrLoadMore(smartRefreshLayout6.mEnableLoadMore) || (SmartRefreshLayout.this.mState == RefreshState.LoadFinish && !isDragging)) {
                    if (oldSpinner != SmartRefreshLayout.this.mSpinner) {
                        if (SmartRefreshLayout.this.mRefreshFooter.getSpinnerStyle() == SpinnerStyle.Translate) {
                            SmartRefreshLayout.this.mRefreshFooter.getView().setTranslationY(SmartRefreshLayout.this.mSpinner);
                            if (SmartRefreshLayout.this.mFooterBackgroundColor != 0 && SmartRefreshLayout.this.mPaint != null) {
                                SmartRefreshLayout smartRefreshLayout7 = SmartRefreshLayout.this;
                                if (!smartRefreshLayout7.isEnableTranslationContent(smartRefreshLayout7.mEnableFooterTranslationContent, SmartRefreshLayout.this.mRefreshFooter)) {
                                    thisView.invalidate();
                                }
                            }
                        } else if (SmartRefreshLayout.this.mRefreshFooter.getSpinnerStyle().scale) {
                            View footerView = SmartRefreshLayout.this.mRefreshFooter.getView();
                            ViewGroup.LayoutParams lp2 = footerView.getLayoutParams();
                            ViewGroup.MarginLayoutParams mlp2 = lp2 instanceof ViewGroup.MarginLayoutParams ? (ViewGroup.MarginLayoutParams) lp2 : SmartRefreshLayout.sDefaultMarginLP;
                            int widthSpec2 = View.MeasureSpec.makeMeasureSpec(footerView.getMeasuredWidth(), 1073741824);
                            footerView.measure(widthSpec2, View.MeasureSpec.makeMeasureSpec(Math.max(((-SmartRefreshLayout.this.mSpinner) - mlp2.bottomMargin) - mlp2.topMargin, 0), 1073741824));
                            int left2 = mlp2.leftMargin;
                            int bottom = (mlp2.topMargin + thisView.getMeasuredHeight()) - SmartRefreshLayout.this.mFooterInsetStart;
                            footerView.layout(left2, bottom - footerView.getMeasuredHeight(), footerView.getMeasuredWidth() + left2, bottom);
                        }
                        SmartRefreshLayout.this.mRefreshFooter.onMoving(isDragging, percent2, offset2, footerHeight, maxDragHeight3);
                    }
                    if (isDragging && SmartRefreshLayout.this.mRefreshFooter.isSupportHorizontalDrag()) {
                        int offsetX2 = (int) SmartRefreshLayout.this.mLastTouchX;
                        int offsetMax2 = thisView.getWidth();
                        float percentX2 = SmartRefreshLayout.this.mLastTouchX / (offsetMax2 == 0 ? 1 : offsetMax2);
                        SmartRefreshLayout.this.mRefreshFooter.onHorizontalDrag(percentX2, offsetX2, offsetMax2);
                    }
                }
                if (oldSpinner != SmartRefreshLayout.this.mSpinner && SmartRefreshLayout.this.mOnMultiPurposeListener != null && (SmartRefreshLayout.this.mRefreshFooter instanceof RefreshFooter)) {
                    SmartRefreshLayout.this.mOnMultiPurposeListener.onFooterMoving((RefreshFooter) SmartRefreshLayout.this.mRefreshFooter, isDragging, percent2, offset2, footerHeight, maxDragHeight3);
                }
            }
            return this;
        }

        @Override // com.scwang.smartrefresh.layout.api.RefreshKernel
        public ValueAnimator animSpinner(int endSpinner) {
            SmartRefreshLayout smartRefreshLayout = SmartRefreshLayout.this;
            return smartRefreshLayout.animSpinner(endSpinner, 0, smartRefreshLayout.mReboundInterpolator, SmartRefreshLayout.this.mReboundDuration);
        }

        @Override // com.scwang.smartrefresh.layout.api.RefreshKernel
        public RefreshKernel requestDrawBackgroundFor(RefreshInternal internal, int backgroundColor) {
            if (SmartRefreshLayout.this.mPaint == null && backgroundColor != 0) {
                SmartRefreshLayout.this.mPaint = new Paint();
            }
            if (internal.equals(SmartRefreshLayout.this.mRefreshHeader)) {
                SmartRefreshLayout.this.mHeaderBackgroundColor = backgroundColor;
            } else if (internal.equals(SmartRefreshLayout.this.mRefreshFooter)) {
                SmartRefreshLayout.this.mFooterBackgroundColor = backgroundColor;
            }
            return this;
        }

        @Override // com.scwang.smartrefresh.layout.api.RefreshKernel
        public RefreshKernel requestNeedTouchEventFor(RefreshInternal internal, boolean request) {
            if (internal.equals(SmartRefreshLayout.this.mRefreshHeader)) {
                SmartRefreshLayout.this.mHeaderNeedTouchEventWhenRefreshing = request;
            } else if (internal.equals(SmartRefreshLayout.this.mRefreshFooter)) {
                SmartRefreshLayout.this.mFooterNeedTouchEventWhenLoading = request;
            }
            return this;
        }

        @Override // com.scwang.smartrefresh.layout.api.RefreshKernel
        public RefreshKernel requestDefaultTranslationContentFor(RefreshInternal internal, boolean translation) {
            if (internal.equals(SmartRefreshLayout.this.mRefreshHeader)) {
                if (!SmartRefreshLayout.this.mManualHeaderTranslationContent) {
                    SmartRefreshLayout.this.mManualHeaderTranslationContent = true;
                    SmartRefreshLayout.this.mEnableHeaderTranslationContent = translation;
                }
            } else if (internal.equals(SmartRefreshLayout.this.mRefreshFooter) && !SmartRefreshLayout.this.mManualFooterTranslationContent) {
                SmartRefreshLayout.this.mManualFooterTranslationContent = true;
                SmartRefreshLayout.this.mEnableFooterTranslationContent = translation;
            }
            return this;
        }

        @Override // com.scwang.smartrefresh.layout.api.RefreshKernel
        public RefreshKernel requestRemeasureHeightFor(RefreshInternal internal) {
            if (internal.equals(SmartRefreshLayout.this.mRefreshHeader)) {
                if (SmartRefreshLayout.this.mHeaderHeightStatus.notified) {
                    SmartRefreshLayout smartRefreshLayout = SmartRefreshLayout.this;
                    smartRefreshLayout.mHeaderHeightStatus = smartRefreshLayout.mHeaderHeightStatus.unNotify();
                }
            } else if (internal.equals(SmartRefreshLayout.this.mRefreshFooter) && SmartRefreshLayout.this.mFooterHeightStatus.notified) {
                SmartRefreshLayout smartRefreshLayout2 = SmartRefreshLayout.this;
                smartRefreshLayout2.mFooterHeightStatus = smartRefreshLayout2.mFooterHeightStatus.unNotify();
            }
            return this;
        }

        @Override // com.scwang.smartrefresh.layout.api.RefreshKernel
        public RefreshKernel requestFloorDuration(int duration) {
            SmartRefreshLayout.this.mFloorDuration = duration;
            return this;
        }
    }

    /* JADX INFO: renamed from: com.scwang.smartrefresh.layout.SmartRefreshLayout$10, reason: invalid class name */
    static /* synthetic */ class AnonymousClass10 {
        static final /* synthetic */ int[] $SwitchMap$com$scwang$smartrefresh$layout$constant$RefreshState;

        static {
            int[] iArr = new int[RefreshState.values().length];
            $SwitchMap$com$scwang$smartrefresh$layout$constant$RefreshState = iArr;
            try {
                iArr[RefreshState.None.ordinal()] = 1;
            } catch (NoSuchFieldError e) {
            }
            try {
                $SwitchMap$com$scwang$smartrefresh$layout$constant$RefreshState[RefreshState.PullDownToRefresh.ordinal()] = 2;
            } catch (NoSuchFieldError e2) {
            }
            try {
                $SwitchMap$com$scwang$smartrefresh$layout$constant$RefreshState[RefreshState.PullUpToLoad.ordinal()] = 3;
            } catch (NoSuchFieldError e3) {
            }
            try {
                $SwitchMap$com$scwang$smartrefresh$layout$constant$RefreshState[RefreshState.PullDownCanceled.ordinal()] = 4;
            } catch (NoSuchFieldError e4) {
            }
            try {
                $SwitchMap$com$scwang$smartrefresh$layout$constant$RefreshState[RefreshState.PullUpCanceled.ordinal()] = 5;
            } catch (NoSuchFieldError e5) {
            }
            try {
                $SwitchMap$com$scwang$smartrefresh$layout$constant$RefreshState[RefreshState.ReleaseToRefresh.ordinal()] = 6;
            } catch (NoSuchFieldError e6) {
            }
            try {
                $SwitchMap$com$scwang$smartrefresh$layout$constant$RefreshState[RefreshState.ReleaseToLoad.ordinal()] = 7;
            } catch (NoSuchFieldError e7) {
            }
            try {
                $SwitchMap$com$scwang$smartrefresh$layout$constant$RefreshState[RefreshState.ReleaseToTwoLevel.ordinal()] = 8;
            } catch (NoSuchFieldError e8) {
            }
            try {
                $SwitchMap$com$scwang$smartrefresh$layout$constant$RefreshState[RefreshState.RefreshReleased.ordinal()] = 9;
            } catch (NoSuchFieldError e9) {
            }
            try {
                $SwitchMap$com$scwang$smartrefresh$layout$constant$RefreshState[RefreshState.LoadReleased.ordinal()] = 10;
            } catch (NoSuchFieldError e10) {
            }
            try {
                $SwitchMap$com$scwang$smartrefresh$layout$constant$RefreshState[RefreshState.Refreshing.ordinal()] = 11;
            } catch (NoSuchFieldError e11) {
            }
            try {
                $SwitchMap$com$scwang$smartrefresh$layout$constant$RefreshState[RefreshState.Loading.ordinal()] = 12;
            } catch (NoSuchFieldError e12) {
            }
            try {
                $SwitchMap$com$scwang$smartrefresh$layout$constant$RefreshState[RefreshState.RefreshFinish.ordinal()] = 13;
            } catch (NoSuchFieldError e13) {
            }
            try {
                $SwitchMap$com$scwang$smartrefresh$layout$constant$RefreshState[RefreshState.LoadFinish.ordinal()] = 14;
            } catch (NoSuchFieldError e14) {
            }
            try {
                $SwitchMap$com$scwang$smartrefresh$layout$constant$RefreshState[RefreshState.TwoLevelReleased.ordinal()] = 15;
            } catch (NoSuchFieldError e15) {
            }
            try {
                $SwitchMap$com$scwang$smartrefresh$layout$constant$RefreshState[RefreshState.TwoLevelFinish.ordinal()] = 16;
            } catch (NoSuchFieldError e16) {
            }
            try {
                $SwitchMap$com$scwang$smartrefresh$layout$constant$RefreshState[RefreshState.TwoLevel.ordinal()] = 17;
            } catch (NoSuchFieldError e17) {
            }
        }
    }
}
