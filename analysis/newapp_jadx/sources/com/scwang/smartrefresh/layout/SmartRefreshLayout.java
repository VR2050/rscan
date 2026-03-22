package com.scwang.smartrefresh.layout;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.ValueAnimator;
import android.annotation.SuppressLint;
import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.os.Handler;
import android.util.AttributeSet;
import android.view.MotionEvent;
import android.view.VelocityTracker;
import android.view.View;
import android.view.ViewConfiguration;
import android.view.ViewGroup;
import android.view.animation.AnimationUtils;
import android.view.animation.Interpolator;
import android.webkit.WebView;
import android.widget.AbsListView;
import android.widget.ScrollView;
import android.widget.Scroller;
import android.widget.TextView;
import android.widget.Toast;
import androidx.annotation.ColorInt;
import androidx.annotation.ColorRes;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.content.ContextCompat;
import androidx.core.view.NestedScrollingChildHelper;
import androidx.core.view.NestedScrollingParent;
import androidx.core.view.NestedScrollingParentHelper;
import androidx.core.widget.NestedScrollView;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.material.shadow.ShadowDrawableWrapper;
import com.scwang.smartrefresh.layout.footer.BallPulseFooter;
import com.scwang.smartrefresh.layout.header.BezierRadarHeader;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p340x.p354b.p355a.p356b.InterfaceC2892a;
import p005b.p340x.p354b.p355a.p356b.InterfaceC2893b;
import p005b.p340x.p354b.p355a.p356b.InterfaceC2894c;
import p005b.p340x.p354b.p355a.p356b.InterfaceC2895d;
import p005b.p340x.p354b.p355a.p356b.InterfaceC2896e;
import p005b.p340x.p354b.p355a.p356b.InterfaceC2897f;
import p005b.p340x.p354b.p355a.p356b.InterfaceC2898g;
import p005b.p340x.p354b.p355a.p356b.InterfaceC2899h;
import p005b.p340x.p354b.p355a.p356b.InterfaceC2900i;
import p005b.p340x.p354b.p355a.p356b.InterfaceC2901j;
import p005b.p340x.p354b.p355a.p357c.C2902a;
import p005b.p340x.p354b.p355a.p357c.C2904c;
import p005b.p340x.p354b.p355a.p357c.EnumC2903b;
import p005b.p340x.p354b.p355a.p358d.C2905a;
import p005b.p340x.p354b.p355a.p360f.InterfaceC2911b;
import p005b.p340x.p354b.p355a.p360f.InterfaceC2912c;
import p005b.p340x.p354b.p355a.p360f.InterfaceC2913d;
import p005b.p340x.p354b.p355a.p360f.InterfaceC2914e;
import p005b.p340x.p354b.p355a.p361g.InterpolatorC2917b;
import tv.danmaku.ijk.media.player.IjkMediaCodecInfo;

@SuppressLint({"RestrictedApi"})
/* loaded from: classes2.dex */
public class SmartRefreshLayout extends ViewGroup implements InterfaceC2900i, NestedScrollingParent {
    public static ViewGroup.MarginLayoutParams sDefaultMarginLP = new ViewGroup.MarginLayoutParams(-1, -1);
    public static InterfaceC2892a sFooterCreator;
    public static InterfaceC2893b sHeaderCreator;
    public static InterfaceC2894c sRefreshInitializer;
    public Runnable animationRunnable;
    public boolean mAttachedToWindow;
    public int mCurrentVelocity;
    public boolean mDisableContentWhenLoading;
    public boolean mDisableContentWhenRefresh;
    public char mDragDirection;
    public float mDragRate;
    public boolean mEnableAutoLoadMore;
    public boolean mEnableClipFooterWhenFixedBehind;
    public boolean mEnableClipHeaderWhenFixedBehind;
    public boolean mEnableFooterFollowWhenNoMoreData;
    public boolean mEnableFooterTranslationContent;
    public boolean mEnableHeaderTranslationContent;
    public boolean mEnableLoadMore;
    public boolean mEnableLoadMoreWhenContentNotFull;
    public boolean mEnableNestedScrolling;
    public boolean mEnableOverScrollBounce;
    public boolean mEnableOverScrollDrag;
    public boolean mEnablePreviewInEditMode;
    public boolean mEnablePureScrollMode;
    public boolean mEnableRefresh;
    public boolean mEnableScrollContentWhenLoaded;
    public boolean mEnableScrollContentWhenRefreshed;
    public MotionEvent mFalsifyEvent;
    public int mFixedFooterViewId;
    public int mFixedHeaderViewId;
    public int mFloorDuration;
    public int mFooterBackgroundColor;
    public int mFooterHeight;
    public C2902a mFooterHeightStatus;
    public int mFooterInsetStart;
    public boolean mFooterLocked;
    public float mFooterMaxDragRate;
    public boolean mFooterNeedTouchEventWhenLoading;
    public boolean mFooterNoMoreData;
    public boolean mFooterNoMoreDataEffective;
    public int mFooterTranslationViewId;
    public float mFooterTriggerRate;
    public Handler mHandler;
    public int mHeaderBackgroundColor;
    public int mHeaderHeight;
    public C2902a mHeaderHeightStatus;
    public int mHeaderInsetStart;
    public float mHeaderMaxDragRate;
    public boolean mHeaderNeedTouchEventWhenRefreshing;
    public int mHeaderTranslationViewId;
    public float mHeaderTriggerRate;
    public boolean mIsBeingDragged;
    public InterfaceC2899h mKernel;
    public long mLastOpenTime;
    public int mLastSpinner;
    public float mLastTouchX;
    public float mLastTouchY;
    public InterfaceC2911b mLoadMoreListener;
    public boolean mManualFooterTranslationContent;
    public boolean mManualHeaderTranslationContent;
    public boolean mManualLoadMore;
    public int mMaximumVelocity;
    public int mMinimumVelocity;
    public NestedScrollingChildHelper mNestedChild;
    public boolean mNestedInProgress;
    public NestedScrollingParentHelper mNestedParent;
    public InterfaceC2912c mOnMultiPurposeListener;
    public Paint mPaint;
    public int[] mParentOffsetInWindow;
    public int[] mPrimaryColors;
    public int mReboundDuration;
    public Interpolator mReboundInterpolator;
    public InterfaceC2895d mRefreshContent;
    public InterfaceC2898g mRefreshFooter;
    public InterfaceC2898g mRefreshHeader;
    public InterfaceC2913d mRefreshListener;
    public int mScreenHeightPixels;
    public InterfaceC2901j mScrollBoundaryDecider;
    public Scroller mScroller;
    public int mSpinner;
    public EnumC2903b mState;
    public boolean mSuperDispatchTouchEvent;
    public int mTotalUnconsumed;
    public int mTouchSlop;
    public int mTouchSpinner;
    public float mTouchX;
    public float mTouchY;
    public VelocityTracker mVelocityTracker;
    public boolean mVerticalPermit;
    public EnumC2903b mViceState;
    public ValueAnimator reboundAnimator;

    /* renamed from: com.scwang.smartrefresh.layout.SmartRefreshLayout$a */
    public class C4075a extends AnimatorListenerAdapter {

        /* renamed from: c */
        public final /* synthetic */ boolean f10629c;

        public C4075a(boolean z) {
            this.f10629c = z;
        }

        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
        public void onAnimationEnd(Animator animator) {
            SmartRefreshLayout.this.setStateDirectLoading(this.f10629c);
        }
    }

    /* renamed from: com.scwang.smartrefresh.layout.SmartRefreshLayout$b */
    public class C4076b extends AnimatorListenerAdapter {

        /* renamed from: c */
        public final /* synthetic */ boolean f10631c;

        public C4076b(boolean z) {
            this.f10631c = z;
        }

        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
        public void onAnimationEnd(Animator animator) {
            SmartRefreshLayout.this.mLastOpenTime = System.currentTimeMillis();
            SmartRefreshLayout.this.notifyStateChanged(EnumC2903b.Refreshing);
            SmartRefreshLayout smartRefreshLayout = SmartRefreshLayout.this;
            InterfaceC2913d interfaceC2913d = smartRefreshLayout.mRefreshListener;
            if (interfaceC2913d != null) {
                if (this.f10631c) {
                    interfaceC2913d.mo302b(smartRefreshLayout);
                }
            } else if (smartRefreshLayout.mOnMultiPurposeListener == null) {
                smartRefreshLayout.finishRefresh(3000);
            }
            SmartRefreshLayout smartRefreshLayout2 = SmartRefreshLayout.this;
            InterfaceC2898g interfaceC2898g = smartRefreshLayout2.mRefreshHeader;
            if (interfaceC2898g != null) {
                int i2 = smartRefreshLayout2.mHeaderHeight;
                interfaceC2898g.mo3353f(smartRefreshLayout2, i2, (int) (smartRefreshLayout2.mHeaderMaxDragRate * i2));
            }
            SmartRefreshLayout smartRefreshLayout3 = SmartRefreshLayout.this;
            InterfaceC2912c interfaceC2912c = smartRefreshLayout3.mOnMultiPurposeListener;
            if (interfaceC2912c == null || !(smartRefreshLayout3.mRefreshHeader instanceof InterfaceC2897f)) {
                return;
            }
            if (this.f10631c) {
                interfaceC2912c.mo302b(smartRefreshLayout3);
            }
            SmartRefreshLayout smartRefreshLayout4 = SmartRefreshLayout.this;
            InterfaceC2912c interfaceC2912c2 = smartRefreshLayout4.mOnMultiPurposeListener;
            InterfaceC2897f interfaceC2897f = (InterfaceC2897f) smartRefreshLayout4.mRefreshHeader;
            int i3 = smartRefreshLayout4.mHeaderHeight;
            interfaceC2912c2.m3377p(interfaceC2897f, i3, (int) (smartRefreshLayout4.mHeaderMaxDragRate * i3));
        }
    }

    /* renamed from: com.scwang.smartrefresh.layout.SmartRefreshLayout$c */
    public class C4077c extends AnimatorListenerAdapter {
        public C4077c() {
        }

        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
        public void onAnimationEnd(Animator animator) {
            EnumC2903b enumC2903b;
            EnumC2903b enumC2903b2;
            SmartRefreshLayout smartRefreshLayout = SmartRefreshLayout.this;
            smartRefreshLayout.reboundAnimator = null;
            if (smartRefreshLayout.mSpinner == 0 && (enumC2903b = smartRefreshLayout.mState) != (enumC2903b2 = EnumC2903b.None) && !enumC2903b.f7952z && !enumC2903b.f7951y) {
                smartRefreshLayout.notifyStateChanged(enumC2903b2);
                return;
            }
            EnumC2903b enumC2903b3 = smartRefreshLayout.mState;
            if (enumC2903b3 != smartRefreshLayout.mViceState) {
                smartRefreshLayout.setViceState(enumC2903b3);
            }
        }
    }

    /* renamed from: com.scwang.smartrefresh.layout.SmartRefreshLayout$d */
    public class C4078d implements ValueAnimator.AnimatorUpdateListener {
        public C4078d() {
        }

        @Override // android.animation.ValueAnimator.AnimatorUpdateListener
        public void onAnimationUpdate(ValueAnimator valueAnimator) {
            ((C4087m) SmartRefreshLayout.this.mKernel).m4625b(((Integer) valueAnimator.getAnimatedValue()).intValue(), false);
        }
    }

    /* renamed from: com.scwang.smartrefresh.layout.SmartRefreshLayout$e */
    public class RunnableC4079e implements Runnable {
        public RunnableC4079e() {
        }

        @Override // java.lang.Runnable
        public void run() {
            SmartRefreshLayout smartRefreshLayout = SmartRefreshLayout.this;
            InterfaceC2911b interfaceC2911b = smartRefreshLayout.mLoadMoreListener;
            if (interfaceC2911b != null) {
                interfaceC2911b.m3370a(smartRefreshLayout);
            } else if (smartRefreshLayout.mOnMultiPurposeListener == null) {
                smartRefreshLayout.finishLoadMore(2000);
            }
            SmartRefreshLayout smartRefreshLayout2 = SmartRefreshLayout.this;
            InterfaceC2912c interfaceC2912c = smartRefreshLayout2.mOnMultiPurposeListener;
            if (interfaceC2912c != null) {
                interfaceC2912c.m3370a(smartRefreshLayout2);
            }
        }
    }

    /* renamed from: com.scwang.smartrefresh.layout.SmartRefreshLayout$f */
    public class RunnableC4080f implements Runnable {

        /* renamed from: c */
        public int f10636c = 0;

        /* renamed from: e */
        public final /* synthetic */ int f10637e;

        /* renamed from: f */
        public final /* synthetic */ Boolean f10638f;

        /* renamed from: g */
        public final /* synthetic */ boolean f10639g;

        public RunnableC4080f(int i2, Boolean bool, boolean z) {
            this.f10637e = i2;
            this.f10638f = bool;
            this.f10639g = z;
        }

        @Override // java.lang.Runnable
        public void run() {
            int i2 = this.f10636c;
            if (i2 == 0) {
                SmartRefreshLayout smartRefreshLayout = SmartRefreshLayout.this;
                EnumC2903b enumC2903b = smartRefreshLayout.mState;
                EnumC2903b enumC2903b2 = EnumC2903b.None;
                if (enumC2903b == enumC2903b2 && smartRefreshLayout.mViceState == EnumC2903b.Refreshing) {
                    smartRefreshLayout.mViceState = enumC2903b2;
                    return;
                }
                ValueAnimator valueAnimator = smartRefreshLayout.reboundAnimator;
                if (valueAnimator != null && enumC2903b.f7948v && (enumC2903b.f7951y || enumC2903b == EnumC2903b.RefreshReleased)) {
                    smartRefreshLayout.reboundAnimator = null;
                    valueAnimator.cancel();
                    ((C4087m) SmartRefreshLayout.this.mKernel).m4627d(enumC2903b2);
                    return;
                } else {
                    if (enumC2903b != EnumC2903b.Refreshing || smartRefreshLayout.mRefreshHeader == null || smartRefreshLayout.mRefreshContent == null) {
                        return;
                    }
                    this.f10636c = i2 + 1;
                    smartRefreshLayout.mHandler.postDelayed(this, this.f10637e);
                    SmartRefreshLayout.this.notifyStateChanged(EnumC2903b.RefreshFinish);
                    Boolean bool = this.f10638f;
                    if (bool != null) {
                        SmartRefreshLayout.this.setNoMoreData(bool == Boolean.TRUE);
                        return;
                    }
                    return;
                }
            }
            SmartRefreshLayout smartRefreshLayout2 = SmartRefreshLayout.this;
            int mo3354j = smartRefreshLayout2.mRefreshHeader.mo3354j(smartRefreshLayout2, this.f10639g);
            SmartRefreshLayout smartRefreshLayout3 = SmartRefreshLayout.this;
            InterfaceC2912c interfaceC2912c = smartRefreshLayout3.mOnMultiPurposeListener;
            if (interfaceC2912c != null) {
                InterfaceC2898g interfaceC2898g = smartRefreshLayout3.mRefreshHeader;
                if (interfaceC2898g instanceof InterfaceC2897f) {
                    interfaceC2912c.m3376n((InterfaceC2897f) interfaceC2898g, this.f10639g);
                }
            }
            if (mo3354j < Integer.MAX_VALUE) {
                SmartRefreshLayout smartRefreshLayout4 = SmartRefreshLayout.this;
                if (smartRefreshLayout4.mIsBeingDragged || smartRefreshLayout4.mNestedInProgress) {
                    long currentTimeMillis = System.currentTimeMillis();
                    SmartRefreshLayout smartRefreshLayout5 = SmartRefreshLayout.this;
                    if (smartRefreshLayout5.mIsBeingDragged) {
                        float f2 = smartRefreshLayout5.mLastTouchY;
                        smartRefreshLayout5.mTouchY = f2;
                        smartRefreshLayout5.mTouchSpinner = 0;
                        smartRefreshLayout5.mIsBeingDragged = false;
                        SmartRefreshLayout.super.dispatchTouchEvent(MotionEvent.obtain(currentTimeMillis, currentTimeMillis, 0, smartRefreshLayout5.mLastTouchX, (f2 + smartRefreshLayout5.mSpinner) - (smartRefreshLayout5.mTouchSlop * 2), 0));
                        SmartRefreshLayout smartRefreshLayout6 = SmartRefreshLayout.this;
                        SmartRefreshLayout.super.dispatchTouchEvent(MotionEvent.obtain(currentTimeMillis, currentTimeMillis, 2, smartRefreshLayout6.mLastTouchX, smartRefreshLayout6.mLastTouchY + smartRefreshLayout6.mSpinner, 0));
                    }
                    SmartRefreshLayout smartRefreshLayout7 = SmartRefreshLayout.this;
                    if (smartRefreshLayout7.mNestedInProgress) {
                        smartRefreshLayout7.mTotalUnconsumed = 0;
                        SmartRefreshLayout.super.dispatchTouchEvent(MotionEvent.obtain(currentTimeMillis, currentTimeMillis, 1, smartRefreshLayout7.mLastTouchX, smartRefreshLayout7.mLastTouchY, 0));
                        SmartRefreshLayout smartRefreshLayout8 = SmartRefreshLayout.this;
                        smartRefreshLayout8.mNestedInProgress = false;
                        smartRefreshLayout8.mTouchSpinner = 0;
                    }
                }
                SmartRefreshLayout smartRefreshLayout9 = SmartRefreshLayout.this;
                int i3 = smartRefreshLayout9.mSpinner;
                if (i3 <= 0) {
                    if (i3 < 0) {
                        smartRefreshLayout9.animSpinner(0, mo3354j, smartRefreshLayout9.mReboundInterpolator, smartRefreshLayout9.mReboundDuration);
                        return;
                    } else {
                        ((C4087m) smartRefreshLayout9.mKernel).m4625b(0, false);
                        ((C4087m) SmartRefreshLayout.this.mKernel).m4627d(EnumC2903b.None);
                        return;
                    }
                }
                ValueAnimator animSpinner = smartRefreshLayout9.animSpinner(0, mo3354j, smartRefreshLayout9.mReboundInterpolator, smartRefreshLayout9.mReboundDuration);
                SmartRefreshLayout smartRefreshLayout10 = SmartRefreshLayout.this;
                ValueAnimator.AnimatorUpdateListener m3365e = smartRefreshLayout10.mEnableScrollContentWhenRefreshed ? ((C2905a) smartRefreshLayout10.mRefreshContent).m3365e(smartRefreshLayout10.mSpinner) : null;
                if (animSpinner == null || m3365e == null) {
                    return;
                }
                animSpinner.addUpdateListener(m3365e);
            }
        }
    }

    /* renamed from: com.scwang.smartrefresh.layout.SmartRefreshLayout$g */
    public class RunnableC4081g implements Runnable {

        /* renamed from: c */
        public int f10641c = 0;

        /* renamed from: e */
        public final /* synthetic */ int f10642e;

        /* renamed from: f */
        public final /* synthetic */ boolean f10643f;

        /* renamed from: g */
        public final /* synthetic */ boolean f10644g;

        /* renamed from: com.scwang.smartrefresh.layout.SmartRefreshLayout$g$a */
        public class a implements Runnable {

            /* renamed from: c */
            public final /* synthetic */ int f10646c;

            /* renamed from: com.scwang.smartrefresh.layout.SmartRefreshLayout$g$a$a, reason: collision with other inner class name */
            public class C5126a extends AnimatorListenerAdapter {
                public C5126a() {
                }

                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animator) {
                    RunnableC4081g runnableC4081g = RunnableC4081g.this;
                    SmartRefreshLayout smartRefreshLayout = SmartRefreshLayout.this;
                    smartRefreshLayout.mFooterLocked = false;
                    if (runnableC4081g.f10643f) {
                        smartRefreshLayout.setNoMoreData(true);
                    }
                    SmartRefreshLayout smartRefreshLayout2 = SmartRefreshLayout.this;
                    if (smartRefreshLayout2.mState == EnumC2903b.LoadFinish) {
                        smartRefreshLayout2.notifyStateChanged(EnumC2903b.None);
                    }
                }
            }

            public a(int i2) {
                this.f10646c = i2;
            }

            @Override // java.lang.Runnable
            public void run() {
                ValueAnimator.AnimatorUpdateListener animatorUpdateListener;
                ValueAnimator valueAnimator;
                SmartRefreshLayout smartRefreshLayout = SmartRefreshLayout.this;
                if (!smartRefreshLayout.mEnableScrollContentWhenLoaded || this.f10646c >= 0) {
                    animatorUpdateListener = null;
                } else {
                    animatorUpdateListener = ((C2905a) smartRefreshLayout.mRefreshContent).m3365e(smartRefreshLayout.mSpinner);
                }
                if (animatorUpdateListener != null) {
                    ((C2905a) animatorUpdateListener).onAnimationUpdate(ValueAnimator.ofInt(0, 0));
                }
                C5126a c5126a = new C5126a();
                RunnableC4081g runnableC4081g = RunnableC4081g.this;
                SmartRefreshLayout smartRefreshLayout2 = SmartRefreshLayout.this;
                int i2 = smartRefreshLayout2.mSpinner;
                if (i2 > 0) {
                    valueAnimator = ((C4087m) smartRefreshLayout2.mKernel).m4624a(0);
                } else {
                    if (animatorUpdateListener != null || i2 == 0) {
                        ValueAnimator valueAnimator2 = smartRefreshLayout2.reboundAnimator;
                        if (valueAnimator2 != null) {
                            valueAnimator2.cancel();
                            SmartRefreshLayout.this.reboundAnimator = null;
                        }
                        ((C4087m) SmartRefreshLayout.this.mKernel).m4625b(0, false);
                        ((C4087m) SmartRefreshLayout.this.mKernel).m4627d(EnumC2903b.None);
                    } else if (runnableC4081g.f10643f && smartRefreshLayout2.mEnableFooterFollowWhenNoMoreData) {
                        int i3 = smartRefreshLayout2.mFooterHeight;
                        if (i2 >= (-i3)) {
                            smartRefreshLayout2.notifyStateChanged(EnumC2903b.None);
                        } else {
                            valueAnimator = ((C4087m) smartRefreshLayout2.mKernel).m4624a(-i3);
                        }
                    } else {
                        valueAnimator = ((C4087m) smartRefreshLayout2.mKernel).m4624a(0);
                    }
                    valueAnimator = null;
                }
                if (valueAnimator != null) {
                    valueAnimator.addListener(c5126a);
                } else {
                    c5126a.onAnimationEnd(null);
                }
            }
        }

        public RunnableC4081g(int i2, boolean z, boolean z2) {
            this.f10642e = i2;
            this.f10643f = z;
            this.f10644g = z2;
        }

        /* JADX WARN: Code restructure failed: missing block: B:45:0x0099, code lost:
        
            if (((p005b.p340x.p354b.p355a.p358d.C2905a) r2.mRefreshContent).m3361a() != false) goto L46;
         */
        @Override // java.lang.Runnable
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public void run() {
            /*
                Method dump skipped, instructions count: 300
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: com.scwang.smartrefresh.layout.SmartRefreshLayout.RunnableC4081g.run():void");
        }
    }

    /* renamed from: com.scwang.smartrefresh.layout.SmartRefreshLayout$h */
    public class RunnableC4082h implements Runnable {

        /* renamed from: c */
        public final /* synthetic */ float f10649c;

        /* renamed from: e */
        public final /* synthetic */ int f10650e;

        /* renamed from: f */
        public final /* synthetic */ boolean f10651f;

        /* renamed from: com.scwang.smartrefresh.layout.SmartRefreshLayout$h$a */
        public class a implements ValueAnimator.AnimatorUpdateListener {
            public a() {
            }

            @Override // android.animation.ValueAnimator.AnimatorUpdateListener
            public void onAnimationUpdate(ValueAnimator valueAnimator) {
                SmartRefreshLayout smartRefreshLayout = SmartRefreshLayout.this;
                if (smartRefreshLayout.reboundAnimator != null) {
                    ((C4087m) smartRefreshLayout.mKernel).m4625b(((Integer) valueAnimator.getAnimatedValue()).intValue(), true);
                }
            }
        }

        /* renamed from: com.scwang.smartrefresh.layout.SmartRefreshLayout$h$b */
        public class b extends AnimatorListenerAdapter {
            public b() {
            }

            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animator) {
                SmartRefreshLayout smartRefreshLayout = SmartRefreshLayout.this;
                if (smartRefreshLayout.reboundAnimator != null) {
                    smartRefreshLayout.reboundAnimator = null;
                    EnumC2903b enumC2903b = smartRefreshLayout.mState;
                    EnumC2903b enumC2903b2 = EnumC2903b.ReleaseToRefresh;
                    if (enumC2903b != enumC2903b2) {
                        ((C4087m) smartRefreshLayout.mKernel).m4627d(enumC2903b2);
                    }
                    SmartRefreshLayout.this.setStateRefreshing(!r3.f10651f);
                }
            }
        }

        public RunnableC4082h(float f2, int i2, boolean z) {
            this.f10649c = f2;
            this.f10650e = i2;
            this.f10651f = z;
        }

        @Override // java.lang.Runnable
        public void run() {
            SmartRefreshLayout smartRefreshLayout = SmartRefreshLayout.this;
            if (smartRefreshLayout.mViceState != EnumC2903b.Refreshing) {
                return;
            }
            ValueAnimator valueAnimator = smartRefreshLayout.reboundAnimator;
            if (valueAnimator != null) {
                valueAnimator.cancel();
            }
            SmartRefreshLayout.this.mLastTouchX = r0.getMeasuredWidth() / 2.0f;
            ((C4087m) SmartRefreshLayout.this.mKernel).m4627d(EnumC2903b.PullDownToRefresh);
            SmartRefreshLayout smartRefreshLayout2 = SmartRefreshLayout.this;
            smartRefreshLayout2.reboundAnimator = ValueAnimator.ofInt(smartRefreshLayout2.mSpinner, (int) (smartRefreshLayout2.mHeaderHeight * this.f10649c));
            SmartRefreshLayout.this.reboundAnimator.setDuration(this.f10650e);
            ValueAnimator valueAnimator2 = SmartRefreshLayout.this.reboundAnimator;
            float f2 = InterpolatorC2917b.f7984a;
            valueAnimator2.setInterpolator(new InterpolatorC2917b(0));
            SmartRefreshLayout.this.reboundAnimator.addUpdateListener(new a());
            SmartRefreshLayout.this.reboundAnimator.addListener(new b());
            SmartRefreshLayout.this.reboundAnimator.start();
        }
    }

    /* renamed from: com.scwang.smartrefresh.layout.SmartRefreshLayout$i */
    public class RunnableC4083i implements Runnable {

        /* renamed from: c */
        public final /* synthetic */ float f10655c;

        /* renamed from: e */
        public final /* synthetic */ int f10656e;

        /* renamed from: f */
        public final /* synthetic */ boolean f10657f;

        /* renamed from: com.scwang.smartrefresh.layout.SmartRefreshLayout$i$a */
        public class a implements ValueAnimator.AnimatorUpdateListener {
            public a() {
            }

            @Override // android.animation.ValueAnimator.AnimatorUpdateListener
            public void onAnimationUpdate(ValueAnimator valueAnimator) {
                SmartRefreshLayout smartRefreshLayout = SmartRefreshLayout.this;
                if (smartRefreshLayout.reboundAnimator != null) {
                    ((C4087m) smartRefreshLayout.mKernel).m4625b(((Integer) valueAnimator.getAnimatedValue()).intValue(), true);
                }
            }
        }

        /* renamed from: com.scwang.smartrefresh.layout.SmartRefreshLayout$i$b */
        public class b extends AnimatorListenerAdapter {
            public b() {
            }

            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animator) {
                SmartRefreshLayout smartRefreshLayout = SmartRefreshLayout.this;
                if (smartRefreshLayout.reboundAnimator != null) {
                    smartRefreshLayout.reboundAnimator = null;
                    EnumC2903b enumC2903b = smartRefreshLayout.mState;
                    EnumC2903b enumC2903b2 = EnumC2903b.ReleaseToLoad;
                    if (enumC2903b != enumC2903b2) {
                        ((C4087m) smartRefreshLayout.mKernel).m4627d(enumC2903b2);
                    }
                    SmartRefreshLayout.this.setStateLoading(!r3.f10657f);
                }
            }
        }

        public RunnableC4083i(float f2, int i2, boolean z) {
            this.f10655c = f2;
            this.f10656e = i2;
            this.f10657f = z;
        }

        @Override // java.lang.Runnable
        public void run() {
            SmartRefreshLayout smartRefreshLayout = SmartRefreshLayout.this;
            if (smartRefreshLayout.mViceState != EnumC2903b.Loading) {
                return;
            }
            ValueAnimator valueAnimator = smartRefreshLayout.reboundAnimator;
            if (valueAnimator != null) {
                valueAnimator.cancel();
            }
            SmartRefreshLayout.this.mLastTouchX = r0.getMeasuredWidth() / 2.0f;
            ((C4087m) SmartRefreshLayout.this.mKernel).m4627d(EnumC2903b.PullUpToLoad);
            SmartRefreshLayout smartRefreshLayout2 = SmartRefreshLayout.this;
            smartRefreshLayout2.reboundAnimator = ValueAnimator.ofInt(smartRefreshLayout2.mSpinner, -((int) (smartRefreshLayout2.mFooterHeight * this.f10655c)));
            SmartRefreshLayout.this.reboundAnimator.setDuration(this.f10656e);
            ValueAnimator valueAnimator2 = SmartRefreshLayout.this.reboundAnimator;
            float f2 = InterpolatorC2917b.f7984a;
            valueAnimator2.setInterpolator(new InterpolatorC2917b(0));
            SmartRefreshLayout.this.reboundAnimator.addUpdateListener(new a());
            SmartRefreshLayout.this.reboundAnimator.addListener(new b());
            SmartRefreshLayout.this.reboundAnimator.start();
        }
    }

    /* renamed from: com.scwang.smartrefresh.layout.SmartRefreshLayout$j */
    public class RunnableC4084j implements Runnable {

        /* renamed from: e */
        public int f10662e;

        /* renamed from: h */
        public float f10665h;

        /* renamed from: c */
        public int f10661c = 0;

        /* renamed from: g */
        public float f10664g = 0.0f;

        /* renamed from: f */
        public long f10663f = AnimationUtils.currentAnimationTimeMillis();

        public RunnableC4084j(float f2, int i2) {
            this.f10665h = f2;
            this.f10662e = i2;
            SmartRefreshLayout.this.mHandler.postDelayed(this, 10);
            if (f2 > 0.0f) {
                ((C4087m) SmartRefreshLayout.this.mKernel).m4627d(EnumC2903b.PullDownToRefresh);
            } else {
                ((C4087m) SmartRefreshLayout.this.mKernel).m4627d(EnumC2903b.PullUpToLoad);
            }
        }

        @Override // java.lang.Runnable
        public void run() {
            SmartRefreshLayout smartRefreshLayout = SmartRefreshLayout.this;
            if (smartRefreshLayout.animationRunnable != this || smartRefreshLayout.mState.f7946A) {
                return;
            }
            if (Math.abs(smartRefreshLayout.mSpinner) < Math.abs(this.f10662e)) {
                double d2 = this.f10665h;
                this.f10661c = this.f10661c + 1;
                this.f10665h = (float) (Math.pow(0.949999988079071d, r4 * 2) * d2);
            } else if (this.f10662e != 0) {
                double d3 = this.f10665h;
                this.f10661c = this.f10661c + 1;
                this.f10665h = (float) (Math.pow(0.44999998807907104d, r4 * 2) * d3);
            } else {
                double d4 = this.f10665h;
                this.f10661c = this.f10661c + 1;
                this.f10665h = (float) (Math.pow(0.8500000238418579d, r4 * 2) * d4);
            }
            long currentAnimationTimeMillis = AnimationUtils.currentAnimationTimeMillis();
            float f2 = this.f10665h * (((currentAnimationTimeMillis - this.f10663f) * 1.0f) / 1000.0f);
            if (Math.abs(f2) >= 1.0f) {
                this.f10663f = currentAnimationTimeMillis;
                float f3 = this.f10664g + f2;
                this.f10664g = f3;
                SmartRefreshLayout.this.moveSpinnerInfinitely(f3);
                SmartRefreshLayout.this.mHandler.postDelayed(this, 10);
                return;
            }
            SmartRefreshLayout smartRefreshLayout2 = SmartRefreshLayout.this;
            EnumC2903b enumC2903b = smartRefreshLayout2.mViceState;
            boolean z = enumC2903b.f7951y;
            if (z && enumC2903b.f7948v) {
                ((C4087m) smartRefreshLayout2.mKernel).m4627d(EnumC2903b.PullDownCanceled);
            } else if (z && enumC2903b.f7949w) {
                ((C4087m) smartRefreshLayout2.mKernel).m4627d(EnumC2903b.PullUpCanceled);
            }
            SmartRefreshLayout smartRefreshLayout3 = SmartRefreshLayout.this;
            smartRefreshLayout3.animationRunnable = null;
            if (Math.abs(smartRefreshLayout3.mSpinner) >= Math.abs(this.f10662e)) {
                int min = Math.min(Math.max((int) InterpolatorC2917b.m3387h(Math.abs(SmartRefreshLayout.this.mSpinner - this.f10662e)), 30), 100) * 10;
                SmartRefreshLayout smartRefreshLayout4 = SmartRefreshLayout.this;
                smartRefreshLayout4.animSpinner(this.f10662e, 0, smartRefreshLayout4.mReboundInterpolator, min);
            }
        }
    }

    /* renamed from: com.scwang.smartrefresh.layout.SmartRefreshLayout$k */
    public class RunnableC4085k implements Runnable {

        /* renamed from: c */
        public int f10667c;

        /* renamed from: e */
        public float f10668e;

        /* renamed from: f */
        public long f10669f = 0;

        /* renamed from: g */
        public long f10670g = AnimationUtils.currentAnimationTimeMillis();

        public RunnableC4085k(float f2) {
            this.f10668e = f2;
            this.f10667c = SmartRefreshLayout.this.mSpinner;
        }

        @Override // java.lang.Runnable
        public void run() {
            SmartRefreshLayout smartRefreshLayout = SmartRefreshLayout.this;
            if (smartRefreshLayout.animationRunnable != this || smartRefreshLayout.mState.f7946A) {
                return;
            }
            long currentAnimationTimeMillis = AnimationUtils.currentAnimationTimeMillis();
            long j2 = currentAnimationTimeMillis - this.f10670g;
            float pow = (float) (Math.pow(0.98f, (currentAnimationTimeMillis - this.f10669f) / (1000.0f / 10)) * this.f10668e);
            this.f10668e = pow;
            float f2 = ((j2 * 1.0f) / 1000.0f) * pow;
            if (Math.abs(f2) <= 1.0f) {
                SmartRefreshLayout.this.animationRunnable = null;
                return;
            }
            this.f10670g = currentAnimationTimeMillis;
            int i2 = (int) (this.f10667c + f2);
            this.f10667c = i2;
            SmartRefreshLayout smartRefreshLayout2 = SmartRefreshLayout.this;
            if (smartRefreshLayout2.mSpinner * i2 > 0) {
                ((C4087m) smartRefreshLayout2.mKernel).m4625b(i2, true);
                SmartRefreshLayout.this.mHandler.postDelayed(this, 10);
                return;
            }
            smartRefreshLayout2.animationRunnable = null;
            ((C4087m) smartRefreshLayout2.mKernel).m4625b(0, true);
            View view = ((C2905a) SmartRefreshLayout.this.mRefreshContent).f7964f;
            int i3 = (int) (-this.f10668e);
            float f3 = InterpolatorC2917b.f7984a;
            if (view instanceof ScrollView) {
                ((ScrollView) view).fling(i3);
            } else if (view instanceof AbsListView) {
                ((AbsListView) view).fling(i3);
            } else if (view instanceof WebView) {
                ((WebView) view).flingScroll(0, i3);
            } else if (view instanceof NestedScrollView) {
                ((NestedScrollView) view).fling(i3);
            } else if (view instanceof RecyclerView) {
                ((RecyclerView) view).fling(0, i3);
            }
            SmartRefreshLayout smartRefreshLayout3 = SmartRefreshLayout.this;
            if (!smartRefreshLayout3.mFooterLocked || f2 <= 0.0f) {
                return;
            }
            smartRefreshLayout3.mFooterLocked = false;
        }
    }

    /* renamed from: com.scwang.smartrefresh.layout.SmartRefreshLayout$m */
    public class C4087m implements InterfaceC2899h {
        public C4087m() {
        }

        /* renamed from: a */
        public ValueAnimator m4624a(int i2) {
            SmartRefreshLayout smartRefreshLayout = SmartRefreshLayout.this;
            return smartRefreshLayout.animSpinner(i2, 0, smartRefreshLayout.mReboundInterpolator, smartRefreshLayout.mReboundDuration);
        }

        /* JADX WARN: Removed duplicated region for block: B:49:0x00b4  */
        /* JADX WARN: Removed duplicated region for block: B:51:0x00b7  */
        /* JADX WARN: Removed duplicated region for block: B:54:0x00bd  */
        /* renamed from: b */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public p005b.p340x.p354b.p355a.p356b.InterfaceC2899h m4625b(int r19, boolean r20) {
            /*
                Method dump skipped, instructions count: 907
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: com.scwang.smartrefresh.layout.SmartRefreshLayout.C4087m.m4625b(int, boolean):b.x.b.a.b.h");
        }

        /* renamed from: c */
        public InterfaceC2899h m4626c(@NonNull InterfaceC2898g interfaceC2898g, int i2) {
            SmartRefreshLayout smartRefreshLayout = SmartRefreshLayout.this;
            if (smartRefreshLayout.mPaint == null && i2 != 0) {
                smartRefreshLayout.mPaint = new Paint();
            }
            if (interfaceC2898g.equals(SmartRefreshLayout.this.mRefreshHeader)) {
                SmartRefreshLayout.this.mHeaderBackgroundColor = i2;
            } else if (interfaceC2898g.equals(SmartRefreshLayout.this.mRefreshFooter)) {
                SmartRefreshLayout.this.mFooterBackgroundColor = i2;
            }
            return this;
        }

        /* renamed from: d */
        public InterfaceC2899h m4627d(@NonNull EnumC2903b enumC2903b) {
            switch (enumC2903b) {
                case None:
                    SmartRefreshLayout smartRefreshLayout = SmartRefreshLayout.this;
                    EnumC2903b enumC2903b2 = smartRefreshLayout.mState;
                    EnumC2903b enumC2903b3 = EnumC2903b.None;
                    if (enumC2903b2 != enumC2903b3 && smartRefreshLayout.mSpinner == 0) {
                        smartRefreshLayout.notifyStateChanged(enumC2903b3);
                        break;
                    } else if (smartRefreshLayout.mSpinner != 0) {
                        m4624a(0);
                        break;
                    }
                    break;
                case PullDownToRefresh:
                    SmartRefreshLayout smartRefreshLayout2 = SmartRefreshLayout.this;
                    if (!smartRefreshLayout2.mState.f7952z && smartRefreshLayout2.isEnableRefreshOrLoadMore(smartRefreshLayout2.mEnableRefresh)) {
                        SmartRefreshLayout.this.notifyStateChanged(EnumC2903b.PullDownToRefresh);
                        break;
                    } else {
                        SmartRefreshLayout.this.setViceState(EnumC2903b.PullDownToRefresh);
                        break;
                    }
                    break;
                case PullUpToLoad:
                    SmartRefreshLayout smartRefreshLayout3 = SmartRefreshLayout.this;
                    if (smartRefreshLayout3.isEnableRefreshOrLoadMore(smartRefreshLayout3.mEnableLoadMore)) {
                        SmartRefreshLayout smartRefreshLayout4 = SmartRefreshLayout.this;
                        EnumC2903b enumC2903b4 = smartRefreshLayout4.mState;
                        if (!enumC2903b4.f7952z && !enumC2903b4.f7946A && (!smartRefreshLayout4.mFooterNoMoreData || !smartRefreshLayout4.mEnableFooterFollowWhenNoMoreData || !smartRefreshLayout4.mFooterNoMoreDataEffective)) {
                            smartRefreshLayout4.notifyStateChanged(EnumC2903b.PullUpToLoad);
                            break;
                        }
                    }
                    SmartRefreshLayout.this.setViceState(EnumC2903b.PullUpToLoad);
                    break;
                case PullDownCanceled:
                    SmartRefreshLayout smartRefreshLayout5 = SmartRefreshLayout.this;
                    if (!smartRefreshLayout5.mState.f7952z && smartRefreshLayout5.isEnableRefreshOrLoadMore(smartRefreshLayout5.mEnableRefresh)) {
                        SmartRefreshLayout.this.notifyStateChanged(EnumC2903b.PullDownCanceled);
                        m4627d(EnumC2903b.None);
                        break;
                    } else {
                        SmartRefreshLayout.this.setViceState(EnumC2903b.PullDownCanceled);
                        break;
                    }
                    break;
                case PullUpCanceled:
                    SmartRefreshLayout smartRefreshLayout6 = SmartRefreshLayout.this;
                    if (smartRefreshLayout6.isEnableRefreshOrLoadMore(smartRefreshLayout6.mEnableLoadMore)) {
                        SmartRefreshLayout smartRefreshLayout7 = SmartRefreshLayout.this;
                        if (!smartRefreshLayout7.mState.f7952z && (!smartRefreshLayout7.mFooterNoMoreData || !smartRefreshLayout7.mEnableFooterFollowWhenNoMoreData || !smartRefreshLayout7.mFooterNoMoreDataEffective)) {
                            smartRefreshLayout7.notifyStateChanged(EnumC2903b.PullUpCanceled);
                            m4627d(EnumC2903b.None);
                            break;
                        }
                    }
                    SmartRefreshLayout.this.setViceState(EnumC2903b.PullUpCanceled);
                    break;
                case ReleaseToRefresh:
                    SmartRefreshLayout smartRefreshLayout8 = SmartRefreshLayout.this;
                    if (!smartRefreshLayout8.mState.f7952z && smartRefreshLayout8.isEnableRefreshOrLoadMore(smartRefreshLayout8.mEnableRefresh)) {
                        SmartRefreshLayout.this.notifyStateChanged(EnumC2903b.ReleaseToRefresh);
                        break;
                    } else {
                        SmartRefreshLayout.this.setViceState(EnumC2903b.ReleaseToRefresh);
                        break;
                    }
                case ReleaseToLoad:
                    SmartRefreshLayout smartRefreshLayout9 = SmartRefreshLayout.this;
                    if (smartRefreshLayout9.isEnableRefreshOrLoadMore(smartRefreshLayout9.mEnableLoadMore)) {
                        SmartRefreshLayout smartRefreshLayout10 = SmartRefreshLayout.this;
                        EnumC2903b enumC2903b5 = smartRefreshLayout10.mState;
                        if (!enumC2903b5.f7952z && !enumC2903b5.f7946A && (!smartRefreshLayout10.mFooterNoMoreData || !smartRefreshLayout10.mEnableFooterFollowWhenNoMoreData || !smartRefreshLayout10.mFooterNoMoreDataEffective)) {
                            smartRefreshLayout10.notifyStateChanged(EnumC2903b.ReleaseToLoad);
                            break;
                        }
                    }
                    SmartRefreshLayout.this.setViceState(EnumC2903b.ReleaseToLoad);
                    break;
                case ReleaseToTwoLevel:
                    SmartRefreshLayout smartRefreshLayout11 = SmartRefreshLayout.this;
                    if (!smartRefreshLayout11.mState.f7952z && smartRefreshLayout11.isEnableRefreshOrLoadMore(smartRefreshLayout11.mEnableRefresh)) {
                        SmartRefreshLayout.this.notifyStateChanged(EnumC2903b.ReleaseToTwoLevel);
                        break;
                    } else {
                        SmartRefreshLayout.this.setViceState(EnumC2903b.ReleaseToTwoLevel);
                        break;
                    }
                    break;
                case TwoLevelReleased:
                    SmartRefreshLayout.this.notifyStateChanged(EnumC2903b.TwoLevelReleased);
                    break;
                case RefreshReleased:
                    SmartRefreshLayout smartRefreshLayout12 = SmartRefreshLayout.this;
                    if (!smartRefreshLayout12.mState.f7952z && smartRefreshLayout12.isEnableRefreshOrLoadMore(smartRefreshLayout12.mEnableRefresh)) {
                        SmartRefreshLayout.this.notifyStateChanged(EnumC2903b.RefreshReleased);
                        break;
                    } else {
                        SmartRefreshLayout.this.setViceState(EnumC2903b.RefreshReleased);
                        break;
                    }
                    break;
                case LoadReleased:
                    SmartRefreshLayout smartRefreshLayout13 = SmartRefreshLayout.this;
                    if (!smartRefreshLayout13.mState.f7952z && smartRefreshLayout13.isEnableRefreshOrLoadMore(smartRefreshLayout13.mEnableLoadMore)) {
                        SmartRefreshLayout.this.notifyStateChanged(EnumC2903b.LoadReleased);
                        break;
                    } else {
                        SmartRefreshLayout.this.setViceState(EnumC2903b.LoadReleased);
                        break;
                    }
                case Refreshing:
                    SmartRefreshLayout.this.setStateRefreshing(true);
                    break;
                case Loading:
                    SmartRefreshLayout.this.setStateLoading(true);
                    break;
                case TwoLevel:
                    SmartRefreshLayout.this.notifyStateChanged(EnumC2903b.TwoLevel);
                    break;
                case RefreshFinish:
                    SmartRefreshLayout smartRefreshLayout14 = SmartRefreshLayout.this;
                    if (smartRefreshLayout14.mState == EnumC2903b.Refreshing) {
                        smartRefreshLayout14.notifyStateChanged(EnumC2903b.RefreshFinish);
                        break;
                    }
                    break;
                case LoadFinish:
                    SmartRefreshLayout smartRefreshLayout15 = SmartRefreshLayout.this;
                    if (smartRefreshLayout15.mState == EnumC2903b.Loading) {
                        smartRefreshLayout15.notifyStateChanged(EnumC2903b.LoadFinish);
                        break;
                    }
                    break;
                case TwoLevelFinish:
                    SmartRefreshLayout.this.notifyStateChanged(EnumC2903b.TwoLevelFinish);
                    break;
            }
            return null;
        }
    }

    public SmartRefreshLayout(Context context) {
        this(context, null);
    }

    public static void setDefaultRefreshFooterCreator(@NonNull InterfaceC2892a interfaceC2892a) {
        sFooterCreator = interfaceC2892a;
    }

    public static void setDefaultRefreshHeaderCreator(@NonNull InterfaceC2893b interfaceC2893b) {
        sHeaderCreator = interfaceC2893b;
    }

    public static void setDefaultRefreshInitializer(@NonNull InterfaceC2894c interfaceC2894c) {
        sRefreshInitializer = interfaceC2894c;
    }

    public ValueAnimator animSpinner(int i2, int i3, Interpolator interpolator, int i4) {
        if (this.mSpinner == i2) {
            return null;
        }
        ValueAnimator valueAnimator = this.reboundAnimator;
        if (valueAnimator != null) {
            valueAnimator.cancel();
        }
        this.animationRunnable = null;
        ValueAnimator ofInt = ValueAnimator.ofInt(this.mSpinner, i2);
        this.reboundAnimator = ofInt;
        ofInt.setDuration(i4);
        this.reboundAnimator.setInterpolator(interpolator);
        this.reboundAnimator.addListener(new C4077c());
        this.reboundAnimator.addUpdateListener(new C4078d());
        this.reboundAnimator.setStartDelay(i3);
        this.reboundAnimator.start();
        return this.reboundAnimator;
    }

    public void animSpinnerBounce(float f2) {
        EnumC2903b enumC2903b;
        if (this.reboundAnimator == null) {
            if (f2 > 0.0f && ((enumC2903b = this.mState) == EnumC2903b.Refreshing || enumC2903b == EnumC2903b.TwoLevel)) {
                this.animationRunnable = new RunnableC4084j(f2, this.mHeaderHeight);
                return;
            }
            if (f2 < 0.0f && (this.mState == EnumC2903b.Loading || ((this.mEnableFooterFollowWhenNoMoreData && this.mFooterNoMoreData && this.mFooterNoMoreDataEffective && isEnableRefreshOrLoadMore(this.mEnableLoadMore)) || (this.mEnableAutoLoadMore && !this.mFooterNoMoreData && isEnableRefreshOrLoadMore(this.mEnableLoadMore) && this.mState != EnumC2903b.Refreshing)))) {
                this.animationRunnable = new RunnableC4084j(f2, -this.mFooterHeight);
            } else if (this.mSpinner == 0 && this.mEnableOverScrollBounce) {
                this.animationRunnable = new RunnableC4084j(f2, 0);
            }
        }
    }

    public boolean autoLoadMore() {
        int i2 = this.mReboundDuration;
        int i3 = this.mFooterHeight;
        float f2 = ((this.mFooterMaxDragRate / 2.0f) + 0.5f) * i3 * 1.0f;
        if (i3 == 0) {
            i3 = 1;
        }
        return autoLoadMore(0, i2, f2 / i3, false);
    }

    public boolean autoLoadMoreAnimationOnly() {
        int i2 = this.mReboundDuration;
        int i3 = this.mFooterHeight;
        float f2 = ((this.mFooterMaxDragRate / 2.0f) + 0.5f) * i3 * 1.0f;
        if (i3 == 0) {
            i3 = 1;
        }
        return autoLoadMore(0, i2, f2 / i3, true);
    }

    public boolean autoRefresh() {
        int i2 = this.mAttachedToWindow ? 0 : 400;
        int i3 = this.mReboundDuration;
        float f2 = (this.mHeaderMaxDragRate / 2.0f) + 0.5f;
        int i4 = this.mHeaderHeight;
        float f3 = f2 * i4 * 1.0f;
        if (i4 == 0) {
            i4 = 1;
        }
        return autoRefresh(i2, i3, f3 / i4, false);
    }

    public boolean autoRefreshAnimationOnly() {
        int i2 = this.mAttachedToWindow ? 0 : 400;
        int i3 = this.mReboundDuration;
        float f2 = (this.mHeaderMaxDragRate / 2.0f) + 0.5f;
        int i4 = this.mHeaderHeight;
        float f3 = f2 * i4 * 1.0f;
        if (i4 == 0) {
            i4 = 1;
        }
        return autoRefresh(i2, i3, f3 / i4, true);
    }

    public InterfaceC2900i closeHeaderOrFooter() {
        EnumC2903b enumC2903b = this.mState;
        if (enumC2903b == EnumC2903b.Refreshing) {
            finishRefresh();
        } else if (enumC2903b == EnumC2903b.Loading) {
            finishLoadMore();
        } else if (this.mSpinner != 0) {
            animSpinner(0, 0, this.mReboundInterpolator, this.mReboundDuration);
        }
        return this;
    }

    @Override // android.view.View
    public void computeScroll() {
        this.mScroller.getCurrY();
        if (this.mScroller.computeScrollOffset()) {
            int finalY = this.mScroller.getFinalY();
            if ((finalY >= 0 || !((this.mEnableRefresh || this.mEnableOverScrollDrag) && ((C2905a) this.mRefreshContent).m3362b())) && (finalY <= 0 || !((this.mEnableLoadMore || this.mEnableOverScrollDrag) && ((C2905a) this.mRefreshContent).m3361a()))) {
                this.mVerticalPermit = true;
                invalidate();
            } else {
                if (this.mVerticalPermit) {
                    animSpinnerBounce(finalY > 0 ? -this.mScroller.getCurrVelocity() : this.mScroller.getCurrVelocity());
                }
                this.mScroller.forceFinished(true);
            }
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:61:0x00c6, code lost:
    
        if (r4.f7946A == false) goto L68;
     */
    /* JADX WARN: Code restructure failed: missing block: B:63:0x00ca, code lost:
    
        if (r4.f7948v == false) goto L68;
     */
    /* JADX WARN: Code restructure failed: missing block: B:69:0x00d8, code lost:
    
        if (r4.f7946A == false) goto L77;
     */
    /* JADX WARN: Code restructure failed: missing block: B:71:0x00dc, code lost:
    
        if (r4.f7949w == false) goto L77;
     */
    /* JADX WARN: Code restructure failed: missing block: B:89:0x0108, code lost:
    
        if (r6 != 3) goto L229;
     */
    @Override // android.view.ViewGroup, android.view.View
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean dispatchTouchEvent(android.view.MotionEvent r23) {
        /*
            Method dump skipped, instructions count: 931
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.scwang.smartrefresh.layout.SmartRefreshLayout.dispatchTouchEvent(android.view.MotionEvent):boolean");
    }

    @Override // android.view.ViewGroup
    public boolean drawChild(Canvas canvas, View view, long j2) {
        Paint paint;
        Paint paint2;
        InterfaceC2895d interfaceC2895d = this.mRefreshContent;
        View view2 = interfaceC2895d != null ? ((C2905a) interfaceC2895d).f7962c : null;
        InterfaceC2898g interfaceC2898g = this.mRefreshHeader;
        if (interfaceC2898g != null && interfaceC2898g.getView() == view) {
            if (!isEnableRefreshOrLoadMore(this.mEnableRefresh) || (!this.mEnablePreviewInEditMode && isInEditMode())) {
                return true;
            }
            if (view2 != null) {
                int max = Math.max(view2.getPaddingTop() + view2.getTop() + this.mSpinner, view.getTop());
                int i2 = this.mHeaderBackgroundColor;
                if (i2 != 0 && (paint2 = this.mPaint) != null) {
                    paint2.setColor(i2);
                    if (this.mRefreshHeader.getSpinnerStyle().f7961i) {
                        max = view.getBottom();
                    } else if (this.mRefreshHeader.getSpinnerStyle() == C2904c.f7953a) {
                        max = view.getBottom() + this.mSpinner;
                    }
                    canvas.drawRect(0.0f, view.getTop(), getWidth(), max, this.mPaint);
                }
                if (this.mEnableClipHeaderWhenFixedBehind && this.mRefreshHeader.getSpinnerStyle() == C2904c.f7955c) {
                    canvas.save();
                    canvas.clipRect(view.getLeft(), view.getTop(), view.getRight(), max);
                    boolean drawChild = super.drawChild(canvas, view, j2);
                    canvas.restore();
                    return drawChild;
                }
            }
        }
        InterfaceC2898g interfaceC2898g2 = this.mRefreshFooter;
        if (interfaceC2898g2 != null && interfaceC2898g2.getView() == view) {
            if (!isEnableRefreshOrLoadMore(this.mEnableLoadMore) || (!this.mEnablePreviewInEditMode && isInEditMode())) {
                return true;
            }
            if (view2 != null) {
                int min = Math.min((view2.getBottom() - view2.getPaddingBottom()) + this.mSpinner, view.getBottom());
                int i3 = this.mFooterBackgroundColor;
                if (i3 != 0 && (paint = this.mPaint) != null) {
                    paint.setColor(i3);
                    if (this.mRefreshFooter.getSpinnerStyle().f7961i) {
                        min = view.getTop();
                    } else if (this.mRefreshFooter.getSpinnerStyle() == C2904c.f7953a) {
                        min = view.getTop() + this.mSpinner;
                    }
                    canvas.drawRect(0.0f, min, getWidth(), view.getBottom(), this.mPaint);
                }
                if (this.mEnableClipFooterWhenFixedBehind && this.mRefreshFooter.getSpinnerStyle() == C2904c.f7955c) {
                    canvas.save();
                    canvas.clipRect(view.getLeft(), min, view.getRight(), view.getBottom());
                    boolean drawChild2 = super.drawChild(canvas, view, j2);
                    canvas.restore();
                    return drawChild2;
                }
            }
        }
        return super.drawChild(canvas, view, j2);
    }

    public InterfaceC2900i finishLoadMore() {
        return finishLoadMore(true);
    }

    public InterfaceC2900i finishLoadMoreWithNoMoreData() {
        return finishLoadMore(Math.min(Math.max(0, 300 - ((int) (System.currentTimeMillis() - this.mLastOpenTime))), IjkMediaCodecInfo.RANK_SECURE) << 16, true, true);
    }

    public InterfaceC2900i finishRefresh() {
        return finishRefresh(true);
    }

    public InterfaceC2900i finishRefreshWithNoMoreData() {
        return finishRefresh(Math.min(Math.max(0, 300 - ((int) (System.currentTimeMillis() - this.mLastOpenTime))), IjkMediaCodecInfo.RANK_SECURE) << 16, true, Boolean.TRUE);
    }

    @Override // android.view.ViewGroup
    public ViewGroup.LayoutParams generateLayoutParams(AttributeSet attributeSet) {
        return new C4086l(getContext(), attributeSet);
    }

    @Override // p005b.p340x.p354b.p355a.p356b.InterfaceC2900i
    @NonNull
    public ViewGroup getLayout() {
        return this;
    }

    @Override // android.view.ViewGroup, androidx.core.view.NestedScrollingParent
    public int getNestedScrollAxes() {
        return this.mNestedParent.getNestedScrollAxes();
    }

    @Nullable
    public InterfaceC2896e getRefreshFooter() {
        InterfaceC2898g interfaceC2898g = this.mRefreshFooter;
        if (interfaceC2898g instanceof InterfaceC2896e) {
            return (InterfaceC2896e) interfaceC2898g;
        }
        return null;
    }

    @Nullable
    public InterfaceC2897f getRefreshHeader() {
        InterfaceC2898g interfaceC2898g = this.mRefreshHeader;
        if (interfaceC2898g instanceof InterfaceC2897f) {
            return (InterfaceC2897f) interfaceC2898g;
        }
        return null;
    }

    @NonNull
    public EnumC2903b getState() {
        return this.mState;
    }

    public boolean interceptAnimatorByAction(int i2) {
        if (i2 == 0) {
            if (this.reboundAnimator != null) {
                EnumC2903b enumC2903b = this.mState;
                if (enumC2903b.f7946A || enumC2903b == EnumC2903b.TwoLevelReleased) {
                    return true;
                }
                if (enumC2903b == EnumC2903b.PullDownCanceled) {
                    ((C4087m) this.mKernel).m4627d(EnumC2903b.PullDownToRefresh);
                } else if (enumC2903b == EnumC2903b.PullUpCanceled) {
                    ((C4087m) this.mKernel).m4627d(EnumC2903b.PullUpToLoad);
                }
                this.reboundAnimator.cancel();
                this.reboundAnimator = null;
            }
            this.animationRunnable = null;
        }
        return this.reboundAnimator != null;
    }

    public boolean isEnableRefreshOrLoadMore(boolean z) {
        return z && !this.mEnablePureScrollMode;
    }

    public boolean isEnableTranslationContent(boolean z, InterfaceC2898g interfaceC2898g) {
        return z || this.mEnablePureScrollMode || interfaceC2898g == null || interfaceC2898g.getSpinnerStyle() == C2904c.f7955c;
    }

    @Override // android.view.View
    public boolean isNestedScrollingEnabled() {
        return this.mEnableNestedScrolling && (this.mEnableOverScrollDrag || this.mEnableRefresh || this.mEnableLoadMore);
    }

    public void moveSpinnerInfinitely(float f2) {
        EnumC2903b enumC2903b;
        float f3 = (!this.mNestedInProgress || this.mEnableLoadMoreWhenContentNotFull || f2 >= 0.0f || ((C2905a) this.mRefreshContent).m3361a()) ? f2 : 0.0f;
        if (f3 > this.mScreenHeightPixels * 5 && getTag() == null) {
            Toast.makeText(getContext(), "你这么死拉，臣妾做不到啊！", 0).show();
            setTag("你这么死拉，臣妾做不到啊！");
        }
        EnumC2903b enumC2903b2 = this.mState;
        if (enumC2903b2 == EnumC2903b.TwoLevel && f3 > 0.0f) {
            ((C4087m) this.mKernel).m4625b(Math.min((int) f3, getMeasuredHeight()), true);
        } else if (enumC2903b2 == EnumC2903b.Refreshing && f3 >= 0.0f) {
            int i2 = this.mHeaderHeight;
            if (f3 < i2) {
                ((C4087m) this.mKernel).m4625b((int) f3, true);
            } else {
                double d2 = (this.mHeaderMaxDragRate - 1.0f) * i2;
                int max = Math.max((this.mScreenHeightPixels * 4) / 3, getHeight());
                int i3 = this.mHeaderHeight;
                double d3 = max - i3;
                double max2 = Math.max(0.0f, (f3 - i3) * this.mDragRate);
                double d4 = -max2;
                if (d3 == ShadowDrawableWrapper.COS_45) {
                    d3 = 1.0d;
                }
                ((C4087m) this.mKernel).m4625b(((int) Math.min((1.0d - Math.pow(100.0d, d4 / d3)) * d2, max2)) + this.mHeaderHeight, true);
            }
        } else if (f3 < 0.0f && (enumC2903b2 == EnumC2903b.Loading || ((this.mEnableFooterFollowWhenNoMoreData && this.mFooterNoMoreData && this.mFooterNoMoreDataEffective && isEnableRefreshOrLoadMore(this.mEnableLoadMore)) || (this.mEnableAutoLoadMore && !this.mFooterNoMoreData && isEnableRefreshOrLoadMore(this.mEnableLoadMore))))) {
            int i4 = this.mFooterHeight;
            if (f3 > (-i4)) {
                ((C4087m) this.mKernel).m4625b((int) f3, true);
            } else {
                double d5 = (this.mFooterMaxDragRate - 1.0f) * i4;
                int max3 = Math.max((this.mScreenHeightPixels * 4) / 3, getHeight());
                int i5 = this.mFooterHeight;
                double d6 = max3 - i5;
                double d7 = -Math.min(0.0f, (i5 + f3) * this.mDragRate);
                double d8 = -d7;
                if (d6 == ShadowDrawableWrapper.COS_45) {
                    d6 = 1.0d;
                }
                ((C4087m) this.mKernel).m4625b(((int) (-Math.min((1.0d - Math.pow(100.0d, d8 / d6)) * d5, d7))) - this.mFooterHeight, true);
            }
        } else if (f3 >= 0.0f) {
            double d9 = this.mHeaderMaxDragRate * this.mHeaderHeight;
            double max4 = Math.max(this.mScreenHeightPixels / 2, getHeight());
            double max5 = Math.max(0.0f, this.mDragRate * f3);
            double d10 = -max5;
            if (max4 == ShadowDrawableWrapper.COS_45) {
                max4 = 1.0d;
            }
            ((C4087m) this.mKernel).m4625b((int) Math.min((1.0d - Math.pow(100.0d, d10 / max4)) * d9, max5), true);
        } else {
            double d11 = this.mFooterMaxDragRate * this.mFooterHeight;
            double max6 = Math.max(this.mScreenHeightPixels / 2, getHeight());
            double d12 = -Math.min(0.0f, this.mDragRate * f3);
            double d13 = -d12;
            if (max6 == ShadowDrawableWrapper.COS_45) {
                max6 = 1.0d;
            }
            ((C4087m) this.mKernel).m4625b((int) (-Math.min((1.0d - Math.pow(100.0d, d13 / max6)) * d11, d12)), true);
        }
        if (!this.mEnableAutoLoadMore || this.mFooterNoMoreData || !isEnableRefreshOrLoadMore(this.mEnableLoadMore) || f3 >= 0.0f || (enumC2903b = this.mState) == EnumC2903b.Refreshing || enumC2903b == EnumC2903b.Loading || enumC2903b == EnumC2903b.LoadFinish) {
            return;
        }
        if (this.mDisableContentWhenLoading) {
            this.animationRunnable = null;
            ((C4087m) this.mKernel).m4624a(-this.mFooterHeight);
        }
        setStateDirectLoading(false);
        this.mHandler.postDelayed(new RunnableC4079e(), this.mReboundDuration);
    }

    public void notifyStateChanged(EnumC2903b enumC2903b) {
        EnumC2903b enumC2903b2 = this.mState;
        if (enumC2903b2 == enumC2903b) {
            if (this.mViceState != enumC2903b2) {
                this.mViceState = enumC2903b2;
                return;
            }
            return;
        }
        this.mState = enumC2903b;
        this.mViceState = enumC2903b;
        InterfaceC2898g interfaceC2898g = this.mRefreshHeader;
        InterfaceC2898g interfaceC2898g2 = this.mRefreshFooter;
        InterfaceC2912c interfaceC2912c = this.mOnMultiPurposeListener;
        if (interfaceC2898g != null) {
            interfaceC2898g.mo3379e(this, enumC2903b2, enumC2903b);
        }
        if (interfaceC2898g2 != null) {
            interfaceC2898g2.mo3379e(this, enumC2903b2, enumC2903b);
        }
        if (interfaceC2912c != null) {
            interfaceC2912c.mo3379e(this, enumC2903b2, enumC2903b);
        }
        if (enumC2903b == EnumC2903b.LoadFinish) {
            this.mFooterLocked = false;
        }
    }

    @Override // android.view.ViewGroup, android.view.View
    public void onAttachedToWindow() {
        InterfaceC2898g interfaceC2898g;
        super.onAttachedToWindow();
        boolean z = true;
        this.mAttachedToWindow = true;
        if (!isInEditMode()) {
            if (this.mRefreshHeader == null) {
                InterfaceC2893b interfaceC2893b = sHeaderCreator;
                if (interfaceC2893b != null) {
                    setRefreshHeader(interfaceC2893b.m3347a(getContext(), this));
                } else {
                    setRefreshHeader(new BezierRadarHeader(getContext()));
                }
            }
            if (this.mRefreshFooter == null) {
                InterfaceC2892a interfaceC2892a = sFooterCreator;
                if (interfaceC2892a != null) {
                    setRefreshFooter(interfaceC2892a.m3346a(getContext(), this));
                } else {
                    boolean z2 = this.mEnableLoadMore;
                    setRefreshFooter(new BallPulseFooter(getContext()));
                    this.mEnableLoadMore = z2;
                }
            } else {
                if (!this.mEnableLoadMore && this.mManualLoadMore) {
                    z = false;
                }
                this.mEnableLoadMore = z;
            }
            if (this.mRefreshContent == null) {
                int childCount = getChildCount();
                for (int i2 = 0; i2 < childCount; i2++) {
                    View childAt = getChildAt(i2);
                    InterfaceC2898g interfaceC2898g2 = this.mRefreshHeader;
                    if ((interfaceC2898g2 == null || childAt != interfaceC2898g2.getView()) && ((interfaceC2898g = this.mRefreshFooter) == null || childAt != interfaceC2898g.getView())) {
                        this.mRefreshContent = new C2905a(childAt);
                    }
                }
            }
            if (this.mRefreshContent == null) {
                int m3382c = InterpolatorC2917b.m3382c(20.0f);
                TextView textView = new TextView(getContext());
                textView.setTextColor(-39424);
                textView.setGravity(17);
                textView.setTextSize(20.0f);
                textView.setText(R$string.srl_content_empty);
                super.addView(textView, 0, new C4086l(-1, -1));
                C2905a c2905a = new C2905a(textView);
                this.mRefreshContent = c2905a;
                c2905a.f7962c.setPadding(m3382c, m3382c, m3382c, m3382c);
            }
            View findViewById = findViewById(this.mFixedHeaderViewId);
            View findViewById2 = findViewById(this.mFixedFooterViewId);
            ((C2905a) this.mRefreshContent).m3366f(this.mScrollBoundaryDecider);
            InterfaceC2895d interfaceC2895d = this.mRefreshContent;
            ((C2905a) interfaceC2895d).f7970l.f7973c = this.mEnableLoadMoreWhenContentNotFull;
            ((C2905a) interfaceC2895d).m3367g(this.mKernel, findViewById, findViewById2);
            if (this.mSpinner != 0) {
                notifyStateChanged(EnumC2903b.None);
                InterfaceC2895d interfaceC2895d2 = this.mRefreshContent;
                this.mSpinner = 0;
                ((C2905a) interfaceC2895d2).m3364d(0, this.mHeaderTranslationViewId, this.mFooterTranslationViewId);
            }
        }
        int[] iArr = this.mPrimaryColors;
        if (iArr != null) {
            InterfaceC2898g interfaceC2898g3 = this.mRefreshHeader;
            if (interfaceC2898g3 != null) {
                interfaceC2898g3.setPrimaryColors(iArr);
            }
            InterfaceC2898g interfaceC2898g4 = this.mRefreshFooter;
            if (interfaceC2898g4 != null) {
                interfaceC2898g4.setPrimaryColors(this.mPrimaryColors);
            }
        }
        InterfaceC2895d interfaceC2895d3 = this.mRefreshContent;
        if (interfaceC2895d3 != null) {
            super.bringChildToFront(((C2905a) interfaceC2895d3).f7962c);
        }
        InterfaceC2898g interfaceC2898g5 = this.mRefreshHeader;
        if (interfaceC2898g5 != null && interfaceC2898g5.getSpinnerStyle().f7960h) {
            super.bringChildToFront(this.mRefreshHeader.getView());
        }
        InterfaceC2898g interfaceC2898g6 = this.mRefreshFooter;
        if (interfaceC2898g6 == null || !interfaceC2898g6.getSpinnerStyle().f7960h) {
            return;
        }
        super.bringChildToFront(this.mRefreshFooter.getView());
    }

    @Override // android.view.ViewGroup, android.view.View
    public void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        this.mAttachedToWindow = false;
        ((C4087m) this.mKernel).m4625b(0, true);
        notifyStateChanged(EnumC2903b.None);
        Handler handler = this.mHandler;
        if (handler != null) {
            handler.removeCallbacksAndMessages(null);
        }
        this.mManualLoadMore = true;
        this.animationRunnable = null;
        ValueAnimator valueAnimator = this.reboundAnimator;
        if (valueAnimator != null) {
            valueAnimator.removeAllListeners();
            this.reboundAnimator.removeAllUpdateListeners();
            this.reboundAnimator.cancel();
            this.reboundAnimator = null;
        }
        this.mFooterLocked = false;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:31:0x0052  */
    @Override // android.view.View
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void onFinishInflate() {
        /*
            r11 = this;
            super.onFinishInflate()
            int r0 = super.getChildCount()
            r1 = 3
            if (r0 > r1) goto L9e
            r2 = -1
            r3 = 0
            r4 = 0
            r5 = -1
            r6 = 0
        Lf:
            r7 = 2
            r8 = 1
            if (r4 >= r0) goto L33
            android.view.View r9 = super.getChildAt(r4)
            boolean r10 = p005b.p340x.p354b.p355a.p361g.InterpolatorC2917b.m3383d(r9)
            if (r10 == 0) goto L24
            if (r6 < r7) goto L21
            if (r4 != r8) goto L24
        L21:
            r5 = r4
            r6 = 2
            goto L30
        L24:
            boolean r7 = r9 instanceof p005b.p340x.p354b.p355a.p356b.InterfaceC2898g
            if (r7 != 0) goto L30
            if (r6 >= r8) goto L30
            if (r4 <= 0) goto L2e
            r6 = 1
            goto L2f
        L2e:
            r6 = 0
        L2f:
            r5 = r4
        L30:
            int r4 = r4 + 1
            goto Lf
        L33:
            if (r5 < 0) goto L4d
            b.x.b.a.d.a r4 = new b.x.b.a.d.a
            android.view.View r6 = super.getChildAt(r5)
            r4.<init>(r6)
            r11.mRefreshContent = r4
            if (r5 != r8) goto L48
            if (r0 != r1) goto L46
            r1 = 0
            goto L4f
        L46:
            r1 = 0
            goto L4e
        L48:
            if (r0 != r7) goto L4d
            r1 = -1
            r7 = 1
            goto L4f
        L4d:
            r1 = -1
        L4e:
            r7 = -1
        L4f:
            r4 = 0
        L50:
            if (r4 >= r0) goto L9d
            android.view.View r5 = super.getChildAt(r4)
            if (r4 == r1) goto L8b
            if (r4 == r7) goto L65
            if (r1 != r2) goto L65
            b.x.b.a.b.g r6 = r11.mRefreshHeader
            if (r6 != 0) goto L65
            boolean r6 = r5 instanceof p005b.p340x.p354b.p355a.p356b.InterfaceC2897f
            if (r6 == 0) goto L65
            goto L8b
        L65:
            if (r4 == r7) goto L6d
            if (r7 != r2) goto L9a
            boolean r6 = r5 instanceof p005b.p340x.p354b.p355a.p356b.InterfaceC2896e
            if (r6 == 0) goto L9a
        L6d:
            boolean r6 = r11.mEnableLoadMore
            if (r6 != 0) goto L78
            boolean r6 = r11.mManualLoadMore
            if (r6 != 0) goto L76
            goto L78
        L76:
            r6 = 0
            goto L79
        L78:
            r6 = 1
        L79:
            r11.mEnableLoadMore = r6
            boolean r6 = r5 instanceof p005b.p340x.p354b.p355a.p356b.InterfaceC2896e
            if (r6 == 0) goto L82
            b.x.b.a.b.e r5 = (p005b.p340x.p354b.p355a.p356b.InterfaceC2896e) r5
            goto L88
        L82:
            com.scwang.smartrefresh.layout.impl.RefreshFooterWrapper r6 = new com.scwang.smartrefresh.layout.impl.RefreshFooterWrapper
            r6.<init>(r5)
            r5 = r6
        L88:
            r11.mRefreshFooter = r5
            goto L9a
        L8b:
            boolean r6 = r5 instanceof p005b.p340x.p354b.p355a.p356b.InterfaceC2897f
            if (r6 == 0) goto L92
            b.x.b.a.b.f r5 = (p005b.p340x.p354b.p355a.p356b.InterfaceC2897f) r5
            goto L98
        L92:
            com.scwang.smartrefresh.layout.impl.RefreshHeaderWrapper r6 = new com.scwang.smartrefresh.layout.impl.RefreshHeaderWrapper
            r6.<init>(r5)
            r5 = r6
        L98:
            r11.mRefreshHeader = r5
        L9a:
            int r4 = r4 + 1
            goto L50
        L9d:
            return
        L9e:
            java.lang.RuntimeException r0 = new java.lang.RuntimeException
            java.lang.String r1 = "最多只支持3个子View，Most only support three sub view"
            r0.<init>(r1)
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.scwang.smartrefresh.layout.SmartRefreshLayout.onFinishInflate():void");
    }

    @Override // android.view.ViewGroup, android.view.View
    public void onLayout(boolean z, int i2, int i3, int i4, int i5) {
        int i6;
        int paddingLeft = getPaddingLeft();
        int paddingTop = getPaddingTop();
        getPaddingBottom();
        int childCount = super.getChildCount();
        for (int i7 = 0; i7 < childCount; i7++) {
            View childAt = super.getChildAt(i7);
            if (childAt.getVisibility() != 8 && childAt.getTag(R$string.srl_component_falsify) != childAt) {
                InterfaceC2895d interfaceC2895d = this.mRefreshContent;
                if (interfaceC2895d != null && ((C2905a) interfaceC2895d).f7962c == childAt) {
                    boolean z2 = isInEditMode() && this.mEnablePreviewInEditMode && isEnableRefreshOrLoadMore(this.mEnableRefresh) && this.mRefreshHeader != null;
                    View view = ((C2905a) this.mRefreshContent).f7962c;
                    ViewGroup.LayoutParams layoutParams = view.getLayoutParams();
                    ViewGroup.MarginLayoutParams marginLayoutParams = layoutParams instanceof ViewGroup.MarginLayoutParams ? (ViewGroup.MarginLayoutParams) layoutParams : sDefaultMarginLP;
                    int i8 = marginLayoutParams.leftMargin + paddingLeft;
                    int i9 = marginLayoutParams.topMargin + paddingTop;
                    int measuredWidth = view.getMeasuredWidth() + i8;
                    int measuredHeight = view.getMeasuredHeight() + i9;
                    if (z2 && isEnableTranslationContent(this.mEnableHeaderTranslationContent, this.mRefreshHeader)) {
                        int i10 = this.mHeaderHeight;
                        i9 += i10;
                        measuredHeight += i10;
                    }
                    view.layout(i8, i9, measuredWidth, measuredHeight);
                }
                InterfaceC2898g interfaceC2898g = this.mRefreshHeader;
                if (interfaceC2898g != null && interfaceC2898g.getView() == childAt) {
                    boolean z3 = isInEditMode() && this.mEnablePreviewInEditMode && isEnableRefreshOrLoadMore(this.mEnableRefresh);
                    View view2 = this.mRefreshHeader.getView();
                    ViewGroup.LayoutParams layoutParams2 = view2.getLayoutParams();
                    ViewGroup.MarginLayoutParams marginLayoutParams2 = layoutParams2 instanceof ViewGroup.MarginLayoutParams ? (ViewGroup.MarginLayoutParams) layoutParams2 : sDefaultMarginLP;
                    int i11 = marginLayoutParams2.leftMargin;
                    int i12 = marginLayoutParams2.topMargin + this.mHeaderInsetStart;
                    int measuredWidth2 = view2.getMeasuredWidth() + i11;
                    int measuredHeight2 = view2.getMeasuredHeight() + i12;
                    if (!z3 && this.mRefreshHeader.getSpinnerStyle() == C2904c.f7953a) {
                        int i13 = this.mHeaderHeight;
                        i12 -= i13;
                        measuredHeight2 -= i13;
                    }
                    view2.layout(i11, i12, measuredWidth2, measuredHeight2);
                }
                InterfaceC2898g interfaceC2898g2 = this.mRefreshFooter;
                if (interfaceC2898g2 != null && interfaceC2898g2.getView() == childAt) {
                    boolean z4 = isInEditMode() && this.mEnablePreviewInEditMode && isEnableRefreshOrLoadMore(this.mEnableLoadMore);
                    View view3 = this.mRefreshFooter.getView();
                    ViewGroup.LayoutParams layoutParams3 = view3.getLayoutParams();
                    ViewGroup.MarginLayoutParams marginLayoutParams3 = layoutParams3 instanceof ViewGroup.MarginLayoutParams ? (ViewGroup.MarginLayoutParams) layoutParams3 : sDefaultMarginLP;
                    C2904c spinnerStyle = this.mRefreshFooter.getSpinnerStyle();
                    int i14 = marginLayoutParams3.leftMargin;
                    int measuredHeight3 = (getMeasuredHeight() + marginLayoutParams3.topMargin) - this.mFooterInsetStart;
                    if (this.mFooterNoMoreData && this.mFooterNoMoreDataEffective && this.mEnableFooterFollowWhenNoMoreData && this.mRefreshContent != null && this.mRefreshFooter.getSpinnerStyle() == C2904c.f7953a && isEnableRefreshOrLoadMore(this.mEnableLoadMore)) {
                        View view4 = ((C2905a) this.mRefreshContent).f7962c;
                        ViewGroup.LayoutParams layoutParams4 = view4.getLayoutParams();
                        measuredHeight3 = view4.getMeasuredHeight() + paddingTop + paddingTop + (layoutParams4 instanceof ViewGroup.MarginLayoutParams ? ((ViewGroup.MarginLayoutParams) layoutParams4).topMargin : 0);
                    }
                    if (spinnerStyle == C2904c.f7957e) {
                        measuredHeight3 = marginLayoutParams3.topMargin - this.mFooterInsetStart;
                    } else {
                        if (z4 || spinnerStyle == C2904c.f7956d || spinnerStyle == C2904c.f7955c) {
                            i6 = this.mFooterHeight;
                        } else if (spinnerStyle.f7961i && this.mSpinner < 0) {
                            i6 = Math.max(isEnableRefreshOrLoadMore(this.mEnableLoadMore) ? -this.mSpinner : 0, 0);
                        }
                        measuredHeight3 -= i6;
                    }
                    view3.layout(i14, measuredHeight3, view3.getMeasuredWidth() + i14, view3.getMeasuredHeight() + measuredHeight3);
                }
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:28:0x00d6  */
    /* JADX WARN: Removed duplicated region for block: B:31:0x0100  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x0119  */
    /* JADX WARN: Removed duplicated region for block: B:41:0x00dd  */
    @Override // android.view.View
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void onMeasure(int r18, int r19) {
        /*
            Method dump skipped, instructions count: 783
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.scwang.smartrefresh.layout.SmartRefreshLayout.onMeasure(int, int):void");
    }

    @Override // android.view.ViewGroup, android.view.ViewParent, androidx.core.view.NestedScrollingParent
    public boolean onNestedFling(@NonNull View view, float f2, float f3, boolean z) {
        return this.mNestedChild.dispatchNestedFling(f2, f3, z);
    }

    @Override // android.view.ViewGroup, android.view.ViewParent, androidx.core.view.NestedScrollingParent
    public boolean onNestedPreFling(@NonNull View view, float f2, float f3) {
        return (this.mFooterLocked && f3 > 0.0f) || startFlingIfNeed(-f3) || this.mNestedChild.dispatchNestedPreFling(f2, f3);
    }

    @Override // android.view.ViewGroup, android.view.ViewParent, androidx.core.view.NestedScrollingParent
    public void onNestedPreScroll(@NonNull View view, int i2, int i3, @NonNull int[] iArr) {
        int i4 = this.mTotalUnconsumed;
        int i5 = 0;
        if (i3 * i4 > 0) {
            if (Math.abs(i3) > Math.abs(this.mTotalUnconsumed)) {
                int i6 = this.mTotalUnconsumed;
                this.mTotalUnconsumed = 0;
                i5 = i6;
            } else {
                this.mTotalUnconsumed -= i3;
                i5 = i3;
            }
            moveSpinnerInfinitely(this.mTotalUnconsumed);
        } else if (i3 > 0 && this.mFooterLocked) {
            int i7 = i4 - i3;
            this.mTotalUnconsumed = i7;
            moveSpinnerInfinitely(i7);
            i5 = i3;
        }
        this.mNestedChild.dispatchNestedPreScroll(i2, i3 - i5, iArr, null);
        iArr[1] = iArr[1] + i5;
    }

    /* JADX WARN: Code restructure failed: missing block: B:12:0x0030, code lost:
    
        if (((p005b.p340x.p354b.p355a.p358d.C2906b) r8).m3369b(((p005b.p340x.p354b.p355a.p358d.C2905a) r6.mRefreshContent).f7962c) == false) goto L14;
     */
    /* JADX WARN: Code restructure failed: missing block: B:45:0x0050, code lost:
    
        if (((p005b.p340x.p354b.p355a.p358d.C2906b) r8).m3368a(((p005b.p340x.p354b.p355a.p358d.C2905a) r6.mRefreshContent).f7962c) != false) goto L25;
     */
    /* JADX WARN: Removed duplicated region for block: B:28:0x0060  */
    /* JADX WARN: Removed duplicated region for block: B:31:0x006c  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x0063  */
    @Override // android.view.ViewGroup, android.view.ViewParent, androidx.core.view.NestedScrollingParent
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void onNestedScroll(@androidx.annotation.NonNull android.view.View r7, int r8, int r9, int r10, int r11) {
        /*
            r6 = this;
            androidx.core.view.NestedScrollingChildHelper r0 = r6.mNestedChild
            int[] r5 = r6.mParentOffsetInWindow
            r1 = r8
            r2 = r9
            r3 = r10
            r4 = r11
            boolean r7 = r0.dispatchNestedScroll(r1, r2, r3, r4, r5)
            int[] r8 = r6.mParentOffsetInWindow
            r10 = 1
            r8 = r8[r10]
            int r11 = r11 + r8
            if (r11 >= 0) goto L32
            boolean r8 = r6.mEnableRefresh
            if (r8 != 0) goto L1c
            boolean r8 = r6.mEnableOverScrollDrag
            if (r8 == 0) goto L32
        L1c:
            int r8 = r6.mTotalUnconsumed
            if (r8 != 0) goto L52
            b.x.b.a.b.j r8 = r6.mScrollBoundaryDecider
            if (r8 == 0) goto L52
            b.x.b.a.b.d r0 = r6.mRefreshContent
            b.x.b.a.d.a r0 = (p005b.p340x.p354b.p355a.p358d.C2905a) r0
            android.view.View r0 = r0.f7962c
            b.x.b.a.d.b r8 = (p005b.p340x.p354b.p355a.p358d.C2906b) r8
            boolean r8 = r8.m3369b(r0)
            if (r8 != 0) goto L52
        L32:
            if (r11 <= 0) goto L82
            boolean r8 = r6.mEnableLoadMore
            if (r8 != 0) goto L3c
            boolean r8 = r6.mEnableOverScrollDrag
            if (r8 == 0) goto L82
        L3c:
            int r8 = r6.mTotalUnconsumed
            if (r8 != 0) goto L52
            b.x.b.a.b.j r8 = r6.mScrollBoundaryDecider
            if (r8 == 0) goto L52
            b.x.b.a.b.d r0 = r6.mRefreshContent
            b.x.b.a.d.a r0 = (p005b.p340x.p354b.p355a.p358d.C2905a) r0
            android.view.View r0 = r0.f7962c
            b.x.b.a.d.b r8 = (p005b.p340x.p354b.p355a.p358d.C2906b) r8
            boolean r8 = r8.m3368a(r0)
            if (r8 == 0) goto L82
        L52:
            b.x.b.a.c.b r8 = r6.mViceState
            b.x.b.a.c.b r0 = p005b.p340x.p354b.p355a.p357c.EnumC2903b.None
            if (r8 == r0) goto L5c
            boolean r8 = r8.f7952z
            if (r8 == 0) goto L79
        L5c:
            b.x.b.a.b.h r8 = r6.mKernel
            if (r11 <= 0) goto L63
            b.x.b.a.c.b r0 = p005b.p340x.p354b.p355a.p357c.EnumC2903b.PullUpToLoad
            goto L65
        L63:
            b.x.b.a.c.b r0 = p005b.p340x.p354b.p355a.p357c.EnumC2903b.PullDownToRefresh
        L65:
            com.scwang.smartrefresh.layout.SmartRefreshLayout$m r8 = (com.scwang.smartrefresh.layout.SmartRefreshLayout.C4087m) r8
            r8.m4627d(r0)
            if (r7 != 0) goto L79
            android.view.ViewParent r7 = r6.getParent()
            boolean r8 = r7 instanceof android.view.ViewGroup
            if (r8 == 0) goto L79
            android.view.ViewGroup r7 = (android.view.ViewGroup) r7
            r7.requestDisallowInterceptTouchEvent(r10)
        L79:
            int r7 = r6.mTotalUnconsumed
            int r7 = r7 - r11
            r6.mTotalUnconsumed = r7
            float r7 = (float) r7
            r6.moveSpinnerInfinitely(r7)
        L82:
            boolean r7 = r6.mFooterLocked
            if (r7 == 0) goto L8b
            if (r9 >= 0) goto L8b
            r7 = 0
            r6.mFooterLocked = r7
        L8b:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.scwang.smartrefresh.layout.SmartRefreshLayout.onNestedScroll(android.view.View, int, int, int, int):void");
    }

    @Override // android.view.ViewGroup, android.view.ViewParent, androidx.core.view.NestedScrollingParent
    public void onNestedScrollAccepted(@NonNull View view, @NonNull View view2, int i2) {
        this.mNestedParent.onNestedScrollAccepted(view, view2, i2);
        this.mNestedChild.startNestedScroll(i2 & 2);
        this.mTotalUnconsumed = this.mSpinner;
        this.mNestedInProgress = true;
        interceptAnimatorByAction(0);
    }

    @Override // android.view.ViewGroup, android.view.ViewParent, androidx.core.view.NestedScrollingParent
    public boolean onStartNestedScroll(@NonNull View view, @NonNull View view2, int i2) {
        return (isEnabled() && isNestedScrollingEnabled() && (i2 & 2) != 0) && (this.mEnableOverScrollDrag || this.mEnableRefresh || this.mEnableLoadMore);
    }

    @Override // android.view.ViewGroup, android.view.ViewParent, androidx.core.view.NestedScrollingParent
    public void onStopNestedScroll(@NonNull View view) {
        this.mNestedParent.onStopNestedScroll(view);
        this.mNestedInProgress = false;
        this.mTotalUnconsumed = 0;
        overSpinner();
        this.mNestedChild.stopNestedScroll();
    }

    public void overSpinner() {
        EnumC2903b enumC2903b = this.mState;
        EnumC2903b enumC2903b2 = EnumC2903b.TwoLevel;
        if (enumC2903b == enumC2903b2) {
            if (this.mCurrentVelocity > -1000 && this.mSpinner > getMeasuredHeight() / 2) {
                ValueAnimator m4624a = ((C4087m) this.mKernel).m4624a(getMeasuredHeight());
                if (m4624a != null) {
                    m4624a.setDuration(this.mFloorDuration);
                    return;
                }
                return;
            }
            if (this.mIsBeingDragged) {
                C4087m c4087m = (C4087m) this.mKernel;
                SmartRefreshLayout smartRefreshLayout = SmartRefreshLayout.this;
                if (smartRefreshLayout.mState == enumC2903b2) {
                    ((C4087m) smartRefreshLayout.mKernel).m4627d(EnumC2903b.TwoLevelFinish);
                    if (SmartRefreshLayout.this.mSpinner != 0) {
                        c4087m.m4624a(0).setDuration(SmartRefreshLayout.this.mFloorDuration);
                        return;
                    } else {
                        c4087m.m4625b(0, false);
                        SmartRefreshLayout.this.notifyStateChanged(EnumC2903b.None);
                        return;
                    }
                }
                return;
            }
            return;
        }
        EnumC2903b enumC2903b3 = EnumC2903b.Loading;
        if (enumC2903b == enumC2903b3 || (this.mEnableFooterFollowWhenNoMoreData && this.mFooterNoMoreData && this.mFooterNoMoreDataEffective && this.mSpinner < 0 && isEnableRefreshOrLoadMore(this.mEnableLoadMore))) {
            int i2 = this.mSpinner;
            int i3 = this.mFooterHeight;
            if (i2 < (-i3)) {
                ((C4087m) this.mKernel).m4624a(-i3);
                return;
            } else {
                if (i2 > 0) {
                    ((C4087m) this.mKernel).m4624a(0);
                    return;
                }
                return;
            }
        }
        EnumC2903b enumC2903b4 = this.mState;
        EnumC2903b enumC2903b5 = EnumC2903b.Refreshing;
        if (enumC2903b4 == enumC2903b5) {
            int i4 = this.mSpinner;
            int i5 = this.mHeaderHeight;
            if (i4 > i5) {
                ((C4087m) this.mKernel).m4624a(i5);
                return;
            } else {
                if (i4 < 0) {
                    ((C4087m) this.mKernel).m4624a(0);
                    return;
                }
                return;
            }
        }
        if (enumC2903b4 == EnumC2903b.PullDownToRefresh) {
            ((C4087m) this.mKernel).m4627d(EnumC2903b.PullDownCanceled);
            return;
        }
        if (enumC2903b4 == EnumC2903b.PullUpToLoad) {
            ((C4087m) this.mKernel).m4627d(EnumC2903b.PullUpCanceled);
            return;
        }
        if (enumC2903b4 == EnumC2903b.ReleaseToRefresh) {
            ((C4087m) this.mKernel).m4627d(enumC2903b5);
            return;
        }
        if (enumC2903b4 == EnumC2903b.ReleaseToLoad) {
            ((C4087m) this.mKernel).m4627d(enumC2903b3);
            return;
        }
        if (enumC2903b4 == EnumC2903b.ReleaseToTwoLevel) {
            ((C4087m) this.mKernel).m4627d(EnumC2903b.TwoLevelReleased);
            return;
        }
        if (enumC2903b4 == EnumC2903b.RefreshReleased) {
            if (this.reboundAnimator == null) {
                ((C4087m) this.mKernel).m4624a(this.mHeaderHeight);
                return;
            }
            return;
        }
        if (enumC2903b4 != EnumC2903b.LoadReleased) {
            if (this.mSpinner != 0) {
                ((C4087m) this.mKernel).m4624a(0);
            }
        } else if (this.reboundAnimator == null) {
            ((C4087m) this.mKernel).m4624a(-this.mFooterHeight);
        }
    }

    public InterfaceC2900i resetNoMoreData() {
        return setNoMoreData(false);
    }

    public InterfaceC2900i setDisableContentWhenLoading(boolean z) {
        this.mDisableContentWhenLoading = z;
        return this;
    }

    public InterfaceC2900i setDisableContentWhenRefresh(boolean z) {
        this.mDisableContentWhenRefresh = z;
        return this;
    }

    public InterfaceC2900i setDragRate(float f2) {
        this.mDragRate = f2;
        return this;
    }

    @Override // p005b.p340x.p354b.p355a.p356b.InterfaceC2900i
    public InterfaceC2900i setEnableAutoLoadMore(boolean z) {
        this.mEnableAutoLoadMore = z;
        return this;
    }

    public InterfaceC2900i setEnableClipFooterWhenFixedBehind(boolean z) {
        this.mEnableClipFooterWhenFixedBehind = z;
        return this;
    }

    public InterfaceC2900i setEnableClipHeaderWhenFixedBehind(boolean z) {
        this.mEnableClipHeaderWhenFixedBehind = z;
        return this;
    }

    @Deprecated
    public InterfaceC2900i setEnableFooterFollowWhenLoadFinished(boolean z) {
        this.mEnableFooterFollowWhenNoMoreData = z;
        return this;
    }

    public InterfaceC2900i setEnableFooterFollowWhenNoMoreData(boolean z) {
        this.mEnableFooterFollowWhenNoMoreData = z;
        return this;
    }

    public InterfaceC2900i setEnableFooterTranslationContent(boolean z) {
        this.mEnableFooterTranslationContent = z;
        this.mManualFooterTranslationContent = true;
        return this;
    }

    public InterfaceC2900i setEnableHeaderTranslationContent(boolean z) {
        this.mEnableHeaderTranslationContent = z;
        this.mManualHeaderTranslationContent = true;
        return this;
    }

    public InterfaceC2900i setEnableLoadMore(boolean z) {
        this.mManualLoadMore = true;
        this.mEnableLoadMore = z;
        return this;
    }

    public InterfaceC2900i setEnableLoadMoreWhenContentNotFull(boolean z) {
        this.mEnableLoadMoreWhenContentNotFull = z;
        InterfaceC2895d interfaceC2895d = this.mRefreshContent;
        if (interfaceC2895d != null) {
            ((C2905a) interfaceC2895d).f7970l.f7973c = z;
        }
        return this;
    }

    @Override // p005b.p340x.p354b.p355a.p356b.InterfaceC2900i
    public InterfaceC2900i setEnableNestedScroll(boolean z) {
        setNestedScrollingEnabled(z);
        return this;
    }

    public InterfaceC2900i setEnableOverScrollBounce(boolean z) {
        this.mEnableOverScrollBounce = z;
        return this;
    }

    public InterfaceC2900i setEnableOverScrollDrag(boolean z) {
        this.mEnableOverScrollDrag = z;
        return this;
    }

    public InterfaceC2900i setEnablePureScrollMode(boolean z) {
        this.mEnablePureScrollMode = z;
        return this;
    }

    public InterfaceC2900i setEnableRefresh(boolean z) {
        this.mEnableRefresh = z;
        return this;
    }

    public InterfaceC2900i setEnableScrollContentWhenLoaded(boolean z) {
        this.mEnableScrollContentWhenLoaded = z;
        return this;
    }

    public InterfaceC2900i setEnableScrollContentWhenRefreshed(boolean z) {
        this.mEnableScrollContentWhenRefreshed = z;
        return this;
    }

    public InterfaceC2900i setFooterHeight(float f2) {
        int m3382c = InterpolatorC2917b.m3382c(f2);
        if (m3382c == this.mFooterHeight) {
            return this;
        }
        C2902a c2902a = this.mFooterHeightStatus;
        C2902a c2902a2 = C2902a.f7922j;
        if (c2902a.m3357a(c2902a2)) {
            this.mFooterHeight = m3382c;
            InterfaceC2898g interfaceC2898g = this.mRefreshFooter;
            if (interfaceC2898g != null && this.mAttachedToWindow && this.mFooterHeightStatus.f7927o) {
                C2904c spinnerStyle = interfaceC2898g.getSpinnerStyle();
                if (spinnerStyle != C2904c.f7957e && !spinnerStyle.f7961i) {
                    View view = this.mRefreshFooter.getView();
                    ViewGroup.LayoutParams layoutParams = view.getLayoutParams();
                    ViewGroup.MarginLayoutParams marginLayoutParams = layoutParams instanceof ViewGroup.MarginLayoutParams ? (ViewGroup.MarginLayoutParams) layoutParams : sDefaultMarginLP;
                    view.measure(View.MeasureSpec.makeMeasureSpec(view.getMeasuredWidth(), 1073741824), View.MeasureSpec.makeMeasureSpec(Math.max((this.mFooterHeight - marginLayoutParams.bottomMargin) - marginLayoutParams.topMargin, 0), 1073741824));
                    int i2 = marginLayoutParams.leftMargin;
                    int measuredHeight = ((getMeasuredHeight() + marginLayoutParams.topMargin) - this.mFooterInsetStart) - (spinnerStyle != C2904c.f7953a ? this.mFooterHeight : 0);
                    view.layout(i2, measuredHeight, view.getMeasuredWidth() + i2, view.getMeasuredHeight() + measuredHeight);
                }
                this.mFooterHeightStatus = c2902a2;
                InterfaceC2898g interfaceC2898g2 = this.mRefreshFooter;
                InterfaceC2899h interfaceC2899h = this.mKernel;
                int i3 = this.mFooterHeight;
                interfaceC2898g2.mo3356o(interfaceC2899h, i3, (int) (this.mFooterMaxDragRate * i3));
            } else {
                this.mFooterHeightStatus = C2902a.f7921i;
            }
        }
        return this;
    }

    public InterfaceC2900i setFooterInsetStart(float f2) {
        this.mFooterInsetStart = InterpolatorC2917b.m3382c(f2);
        return this;
    }

    public InterfaceC2900i setFooterMaxDragRate(float f2) {
        this.mFooterMaxDragRate = f2;
        InterfaceC2898g interfaceC2898g = this.mRefreshFooter;
        if (interfaceC2898g == null || !this.mAttachedToWindow) {
            this.mFooterHeightStatus = this.mFooterHeightStatus.m3358b();
        } else {
            InterfaceC2899h interfaceC2899h = this.mKernel;
            int i2 = this.mFooterHeight;
            interfaceC2898g.mo3356o(interfaceC2899h, i2, (int) (i2 * f2));
        }
        return this;
    }

    public InterfaceC2900i setFooterTriggerRate(float f2) {
        this.mFooterTriggerRate = f2;
        return this;
    }

    public InterfaceC2900i setHeaderHeight(float f2) {
        int m3382c = InterpolatorC2917b.m3382c(f2);
        if (m3382c == this.mHeaderHeight) {
            return this;
        }
        C2902a c2902a = this.mHeaderHeightStatus;
        C2902a c2902a2 = C2902a.f7922j;
        if (c2902a.m3357a(c2902a2)) {
            this.mHeaderHeight = m3382c;
            InterfaceC2898g interfaceC2898g = this.mRefreshHeader;
            if (interfaceC2898g != null && this.mAttachedToWindow && this.mHeaderHeightStatus.f7927o) {
                C2904c spinnerStyle = interfaceC2898g.getSpinnerStyle();
                if (spinnerStyle != C2904c.f7957e && !spinnerStyle.f7961i) {
                    View view = this.mRefreshHeader.getView();
                    ViewGroup.LayoutParams layoutParams = view.getLayoutParams();
                    ViewGroup.MarginLayoutParams marginLayoutParams = layoutParams instanceof ViewGroup.MarginLayoutParams ? (ViewGroup.MarginLayoutParams) layoutParams : sDefaultMarginLP;
                    view.measure(View.MeasureSpec.makeMeasureSpec(view.getMeasuredWidth(), 1073741824), View.MeasureSpec.makeMeasureSpec(Math.max((this.mHeaderHeight - marginLayoutParams.bottomMargin) - marginLayoutParams.topMargin, 0), 1073741824));
                    int i2 = marginLayoutParams.leftMargin;
                    int i3 = (marginLayoutParams.topMargin + this.mHeaderInsetStart) - (spinnerStyle == C2904c.f7953a ? this.mHeaderHeight : 0);
                    view.layout(i2, i3, view.getMeasuredWidth() + i2, view.getMeasuredHeight() + i3);
                }
                this.mHeaderHeightStatus = c2902a2;
                InterfaceC2898g interfaceC2898g2 = this.mRefreshHeader;
                InterfaceC2899h interfaceC2899h = this.mKernel;
                int i4 = this.mHeaderHeight;
                interfaceC2898g2.mo3356o(interfaceC2899h, i4, (int) (this.mHeaderMaxDragRate * i4));
            } else {
                this.mHeaderHeightStatus = C2902a.f7921i;
            }
        }
        return this;
    }

    public InterfaceC2900i setHeaderInsetStart(float f2) {
        this.mHeaderInsetStart = InterpolatorC2917b.m3382c(f2);
        return this;
    }

    @Override // p005b.p340x.p354b.p355a.p356b.InterfaceC2900i
    public InterfaceC2900i setHeaderMaxDragRate(float f2) {
        this.mHeaderMaxDragRate = f2;
        InterfaceC2898g interfaceC2898g = this.mRefreshHeader;
        if (interfaceC2898g == null || !this.mAttachedToWindow) {
            this.mHeaderHeightStatus = this.mHeaderHeightStatus.m3358b();
        } else {
            InterfaceC2899h interfaceC2899h = this.mKernel;
            int i2 = this.mHeaderHeight;
            interfaceC2898g.mo3356o(interfaceC2899h, i2, (int) (f2 * i2));
        }
        return this;
    }

    public InterfaceC2900i setHeaderTriggerRate(float f2) {
        this.mHeaderTriggerRate = f2;
        return this;
    }

    @Override // android.view.View
    public void setNestedScrollingEnabled(boolean z) {
        this.mEnableNestedScrolling = z;
        this.mNestedChild.setNestedScrollingEnabled(z);
    }

    public InterfaceC2900i setNoMoreData(boolean z) {
        if (this.mState == EnumC2903b.Loading && z) {
            finishLoadMoreWithNoMoreData();
            return this;
        }
        if (this.mFooterNoMoreData != z) {
            this.mFooterNoMoreData = z;
            InterfaceC2898g interfaceC2898g = this.mRefreshFooter;
            if (interfaceC2898g instanceof InterfaceC2896e) {
                if (((InterfaceC2896e) interfaceC2898g).mo3349a(z)) {
                    this.mFooterNoMoreDataEffective = true;
                    if (this.mFooterNoMoreData && this.mEnableFooterFollowWhenNoMoreData && this.mSpinner > 0 && this.mRefreshFooter.getSpinnerStyle() == C2904c.f7953a && isEnableRefreshOrLoadMore(this.mEnableLoadMore) && isEnableTranslationContent(this.mEnableRefresh, this.mRefreshHeader)) {
                        this.mRefreshFooter.getView().setTranslationY(this.mSpinner);
                    }
                } else {
                    this.mFooterNoMoreDataEffective = false;
                    StringBuilder m586H = C1499a.m586H("Footer:");
                    m586H.append(this.mRefreshFooter);
                    m586H.append(" NoMoreData is not supported.(不支持NoMoreData，请使用[ClassicsFooter]或者[自定义Footer并实现setNoMoreData方法且返回true])");
                    new RuntimeException(m586H.toString()).printStackTrace();
                }
            }
        }
        return this;
    }

    public InterfaceC2900i setOnLoadMoreListener(InterfaceC2911b interfaceC2911b) {
        this.mLoadMoreListener = interfaceC2911b;
        this.mEnableLoadMore = this.mEnableLoadMore || !(this.mManualLoadMore || interfaceC2911b == null);
        return this;
    }

    public InterfaceC2900i setOnMultiPurposeListener(InterfaceC2912c interfaceC2912c) {
        this.mOnMultiPurposeListener = interfaceC2912c;
        return this;
    }

    public InterfaceC2900i setOnRefreshListener(InterfaceC2913d interfaceC2913d) {
        this.mRefreshListener = interfaceC2913d;
        return this;
    }

    public InterfaceC2900i setOnRefreshLoadMoreListener(InterfaceC2914e interfaceC2914e) {
        this.mRefreshListener = interfaceC2914e;
        this.mLoadMoreListener = interfaceC2914e;
        this.mEnableLoadMore = this.mEnableLoadMore || !(this.mManualLoadMore || interfaceC2914e == null);
        return this;
    }

    public InterfaceC2900i setPrimaryColors(@ColorInt int... iArr) {
        InterfaceC2898g interfaceC2898g = this.mRefreshHeader;
        if (interfaceC2898g != null) {
            interfaceC2898g.setPrimaryColors(iArr);
        }
        InterfaceC2898g interfaceC2898g2 = this.mRefreshFooter;
        if (interfaceC2898g2 != null) {
            interfaceC2898g2.setPrimaryColors(iArr);
        }
        this.mPrimaryColors = iArr;
        return this;
    }

    public InterfaceC2900i setPrimaryColorsId(@ColorRes int... iArr) {
        int[] iArr2 = new int[iArr.length];
        for (int i2 = 0; i2 < iArr.length; i2++) {
            iArr2[i2] = ContextCompat.getColor(getContext(), iArr[i2]);
        }
        setPrimaryColors(iArr2);
        return this;
    }

    public InterfaceC2900i setReboundDuration(int i2) {
        this.mReboundDuration = i2;
        return this;
    }

    public InterfaceC2900i setReboundInterpolator(@NonNull Interpolator interpolator) {
        this.mReboundInterpolator = interpolator;
        return this;
    }

    public InterfaceC2900i setRefreshContent(@NonNull View view) {
        return setRefreshContent(view, -1, -1);
    }

    public InterfaceC2900i setRefreshFooter(@NonNull InterfaceC2896e interfaceC2896e) {
        return setRefreshFooter(interfaceC2896e, -1, -2);
    }

    public InterfaceC2900i setRefreshHeader(@NonNull InterfaceC2897f interfaceC2897f) {
        return setRefreshHeader(interfaceC2897f, -1, -2);
    }

    public InterfaceC2900i setScrollBoundaryDecider(InterfaceC2901j interfaceC2901j) {
        this.mScrollBoundaryDecider = interfaceC2901j;
        InterfaceC2895d interfaceC2895d = this.mRefreshContent;
        if (interfaceC2895d != null) {
            ((C2905a) interfaceC2895d).m3366f(interfaceC2901j);
        }
        return this;
    }

    public void setStateDirectLoading(boolean z) {
        EnumC2903b enumC2903b = this.mState;
        EnumC2903b enumC2903b2 = EnumC2903b.Loading;
        if (enumC2903b != enumC2903b2) {
            this.mLastOpenTime = System.currentTimeMillis();
            this.mFooterLocked = true;
            notifyStateChanged(enumC2903b2);
            InterfaceC2911b interfaceC2911b = this.mLoadMoreListener;
            if (interfaceC2911b != null) {
                if (z) {
                    interfaceC2911b.m3370a(this);
                }
            } else if (this.mOnMultiPurposeListener == null) {
                finishLoadMore(2000);
            }
            InterfaceC2898g interfaceC2898g = this.mRefreshFooter;
            if (interfaceC2898g != null) {
                int i2 = this.mFooterHeight;
                interfaceC2898g.mo3353f(this, i2, (int) (this.mFooterMaxDragRate * i2));
            }
            InterfaceC2912c interfaceC2912c = this.mOnMultiPurposeListener;
            if (interfaceC2912c == null || !(this.mRefreshFooter instanceof InterfaceC2896e)) {
                return;
            }
            if (z) {
                interfaceC2912c.m3370a(this);
            }
            InterfaceC2912c interfaceC2912c2 = this.mOnMultiPurposeListener;
            InterfaceC2896e interfaceC2896e = (InterfaceC2896e) this.mRefreshFooter;
            int i3 = this.mFooterHeight;
            interfaceC2912c2.m3373i(interfaceC2896e, i3, (int) (this.mFooterMaxDragRate * i3));
        }
    }

    public void setStateLoading(boolean z) {
        C4075a c4075a = new C4075a(z);
        notifyStateChanged(EnumC2903b.LoadReleased);
        ValueAnimator m4624a = ((C4087m) this.mKernel).m4624a(-this.mFooterHeight);
        if (m4624a != null) {
            m4624a.addListener(c4075a);
        }
        InterfaceC2898g interfaceC2898g = this.mRefreshFooter;
        if (interfaceC2898g != null) {
            int i2 = this.mFooterHeight;
            interfaceC2898g.mo3355k(this, i2, (int) (this.mFooterMaxDragRate * i2));
        }
        InterfaceC2912c interfaceC2912c = this.mOnMultiPurposeListener;
        if (interfaceC2912c != null) {
            InterfaceC2898g interfaceC2898g2 = this.mRefreshFooter;
            if (interfaceC2898g2 instanceof InterfaceC2896e) {
                int i3 = this.mFooterHeight;
                interfaceC2912c.m3375m((InterfaceC2896e) interfaceC2898g2, i3, (int) (this.mFooterMaxDragRate * i3));
            }
        }
        if (m4624a == null) {
            c4075a.onAnimationEnd(null);
        }
    }

    public void setStateRefreshing(boolean z) {
        C4076b c4076b = new C4076b(z);
        notifyStateChanged(EnumC2903b.RefreshReleased);
        ValueAnimator m4624a = ((C4087m) this.mKernel).m4624a(this.mHeaderHeight);
        if (m4624a != null) {
            m4624a.addListener(c4076b);
        }
        InterfaceC2898g interfaceC2898g = this.mRefreshHeader;
        if (interfaceC2898g != null) {
            int i2 = this.mHeaderHeight;
            interfaceC2898g.mo3355k(this, i2, (int) (this.mHeaderMaxDragRate * i2));
        }
        InterfaceC2912c interfaceC2912c = this.mOnMultiPurposeListener;
        if (interfaceC2912c != null) {
            InterfaceC2898g interfaceC2898g2 = this.mRefreshHeader;
            if (interfaceC2898g2 instanceof InterfaceC2897f) {
                int i3 = this.mHeaderHeight;
                interfaceC2912c.m3371g((InterfaceC2897f) interfaceC2898g2, i3, (int) (this.mHeaderMaxDragRate * i3));
            }
        }
        if (m4624a == null) {
            c4076b.onAnimationEnd(null);
        }
    }

    public void setViceState(EnumC2903b enumC2903b) {
        EnumC2903b enumC2903b2 = this.mState;
        if (enumC2903b2.f7951y && enumC2903b2.f7948v != enumC2903b.f7948v) {
            notifyStateChanged(EnumC2903b.None);
        }
        if (this.mViceState != enumC2903b) {
            this.mViceState = enumC2903b;
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:57:0x00ef, code lost:
    
        if (r4 <= r14.mHeaderHeight) goto L71;
     */
    /* JADX WARN: Code restructure failed: missing block: B:60:0x00f6, code lost:
    
        if (r4 >= (-r14.mFooterHeight)) goto L76;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean startFlingIfNeed(float r14) {
        /*
            Method dump skipped, instructions count: 362
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.scwang.smartrefresh.layout.SmartRefreshLayout.startFlingIfNeed(float):boolean");
    }

    public SmartRefreshLayout(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        this.mFloorDuration = IjkMediaCodecInfo.RANK_SECURE;
        this.mReboundDuration = IjkMediaCodecInfo.RANK_SECURE;
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
        C2902a c2902a = C2902a.f7913a;
        this.mHeaderHeightStatus = c2902a;
        this.mFooterHeightStatus = c2902a;
        this.mHeaderMaxDragRate = 2.5f;
        this.mFooterMaxDragRate = 2.5f;
        this.mHeaderTriggerRate = 1.0f;
        this.mFooterTriggerRate = 1.0f;
        this.mKernel = new C4087m();
        EnumC2903b enumC2903b = EnumC2903b.None;
        this.mState = enumC2903b;
        this.mViceState = enumC2903b;
        this.mLastOpenTime = 0L;
        this.mHeaderBackgroundColor = 0;
        this.mFooterBackgroundColor = 0;
        this.mFooterLocked = false;
        this.mVerticalPermit = false;
        this.mFalsifyEvent = null;
        ViewConfiguration viewConfiguration = ViewConfiguration.get(context);
        this.mHandler = new Handler();
        this.mScroller = new Scroller(context);
        this.mVelocityTracker = VelocityTracker.obtain();
        this.mScreenHeightPixels = context.getResources().getDisplayMetrics().heightPixels;
        float f2 = InterpolatorC2917b.f7984a;
        this.mReboundInterpolator = new InterpolatorC2917b(0);
        this.mTouchSlop = viewConfiguration.getScaledTouchSlop();
        this.mMinimumVelocity = viewConfiguration.getScaledMinimumFlingVelocity();
        this.mMaximumVelocity = viewConfiguration.getScaledMaximumFlingVelocity();
        this.mFooterHeight = InterpolatorC2917b.m3382c(60.0f);
        this.mHeaderHeight = InterpolatorC2917b.m3382c(100.0f);
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, R$styleable.SmartRefreshLayout);
        if (!obtainStyledAttributes.hasValue(R$styleable.SmartRefreshLayout_android_clipToPadding)) {
            super.setClipToPadding(false);
        }
        if (!obtainStyledAttributes.hasValue(R$styleable.SmartRefreshLayout_android_clipChildren)) {
            super.setClipChildren(false);
        }
        InterfaceC2894c interfaceC2894c = sRefreshInitializer;
        if (interfaceC2894c != null) {
            interfaceC2894c.m3348a(context, this);
        }
        this.mDragRate = obtainStyledAttributes.getFloat(R$styleable.SmartRefreshLayout_srlDragRate, this.mDragRate);
        this.mHeaderMaxDragRate = obtainStyledAttributes.getFloat(R$styleable.SmartRefreshLayout_srlHeaderMaxDragRate, this.mHeaderMaxDragRate);
        this.mFooterMaxDragRate = obtainStyledAttributes.getFloat(R$styleable.SmartRefreshLayout_srlFooterMaxDragRate, this.mFooterMaxDragRate);
        this.mHeaderTriggerRate = obtainStyledAttributes.getFloat(R$styleable.SmartRefreshLayout_srlHeaderTriggerRate, this.mHeaderTriggerRate);
        this.mFooterTriggerRate = obtainStyledAttributes.getFloat(R$styleable.SmartRefreshLayout_srlFooterTriggerRate, this.mFooterTriggerRate);
        this.mEnableRefresh = obtainStyledAttributes.getBoolean(R$styleable.SmartRefreshLayout_srlEnableRefresh, this.mEnableRefresh);
        this.mReboundDuration = obtainStyledAttributes.getInt(R$styleable.SmartRefreshLayout_srlReboundDuration, this.mReboundDuration);
        int i2 = R$styleable.SmartRefreshLayout_srlEnableLoadMore;
        this.mEnableLoadMore = obtainStyledAttributes.getBoolean(i2, this.mEnableLoadMore);
        int i3 = R$styleable.SmartRefreshLayout_srlHeaderHeight;
        this.mHeaderHeight = obtainStyledAttributes.getDimensionPixelOffset(i3, this.mHeaderHeight);
        int i4 = R$styleable.SmartRefreshLayout_srlFooterHeight;
        this.mFooterHeight = obtainStyledAttributes.getDimensionPixelOffset(i4, this.mFooterHeight);
        this.mHeaderInsetStart = obtainStyledAttributes.getDimensionPixelOffset(R$styleable.SmartRefreshLayout_srlHeaderInsetStart, this.mHeaderInsetStart);
        this.mFooterInsetStart = obtainStyledAttributes.getDimensionPixelOffset(R$styleable.SmartRefreshLayout_srlFooterInsetStart, this.mFooterInsetStart);
        this.mDisableContentWhenRefresh = obtainStyledAttributes.getBoolean(R$styleable.SmartRefreshLayout_srlDisableContentWhenRefresh, this.mDisableContentWhenRefresh);
        this.mDisableContentWhenLoading = obtainStyledAttributes.getBoolean(R$styleable.SmartRefreshLayout_srlDisableContentWhenLoading, this.mDisableContentWhenLoading);
        int i5 = R$styleable.SmartRefreshLayout_srlEnableHeaderTranslationContent;
        this.mEnableHeaderTranslationContent = obtainStyledAttributes.getBoolean(i5, this.mEnableHeaderTranslationContent);
        int i6 = R$styleable.SmartRefreshLayout_srlEnableFooterTranslationContent;
        this.mEnableFooterTranslationContent = obtainStyledAttributes.getBoolean(i6, this.mEnableFooterTranslationContent);
        this.mEnablePreviewInEditMode = obtainStyledAttributes.getBoolean(R$styleable.SmartRefreshLayout_srlEnablePreviewInEditMode, this.mEnablePreviewInEditMode);
        this.mEnableAutoLoadMore = obtainStyledAttributes.getBoolean(R$styleable.SmartRefreshLayout_srlEnableAutoLoadMore, this.mEnableAutoLoadMore);
        this.mEnableOverScrollBounce = obtainStyledAttributes.getBoolean(R$styleable.SmartRefreshLayout_srlEnableOverScrollBounce, this.mEnableOverScrollBounce);
        this.mEnablePureScrollMode = obtainStyledAttributes.getBoolean(R$styleable.SmartRefreshLayout_srlEnablePureScrollMode, this.mEnablePureScrollMode);
        this.mEnableScrollContentWhenLoaded = obtainStyledAttributes.getBoolean(R$styleable.SmartRefreshLayout_srlEnableScrollContentWhenLoaded, this.mEnableScrollContentWhenLoaded);
        this.mEnableScrollContentWhenRefreshed = obtainStyledAttributes.getBoolean(R$styleable.SmartRefreshLayout_srlEnableScrollContentWhenRefreshed, this.mEnableScrollContentWhenRefreshed);
        this.mEnableLoadMoreWhenContentNotFull = obtainStyledAttributes.getBoolean(R$styleable.SmartRefreshLayout_srlEnableLoadMoreWhenContentNotFull, this.mEnableLoadMoreWhenContentNotFull);
        boolean z = obtainStyledAttributes.getBoolean(R$styleable.SmartRefreshLayout_srlEnableFooterFollowWhenLoadFinished, this.mEnableFooterFollowWhenNoMoreData);
        this.mEnableFooterFollowWhenNoMoreData = z;
        this.mEnableFooterFollowWhenNoMoreData = obtainStyledAttributes.getBoolean(R$styleable.SmartRefreshLayout_srlEnableFooterFollowWhenNoMoreData, z);
        this.mEnableClipHeaderWhenFixedBehind = obtainStyledAttributes.getBoolean(R$styleable.SmartRefreshLayout_srlEnableClipHeaderWhenFixedBehind, this.mEnableClipHeaderWhenFixedBehind);
        this.mEnableClipFooterWhenFixedBehind = obtainStyledAttributes.getBoolean(R$styleable.SmartRefreshLayout_srlEnableClipFooterWhenFixedBehind, this.mEnableClipFooterWhenFixedBehind);
        this.mEnableOverScrollDrag = obtainStyledAttributes.getBoolean(R$styleable.SmartRefreshLayout_srlEnableOverScrollDrag, this.mEnableOverScrollDrag);
        this.mFixedHeaderViewId = obtainStyledAttributes.getResourceId(R$styleable.SmartRefreshLayout_srlFixedHeaderViewId, this.mFixedHeaderViewId);
        this.mFixedFooterViewId = obtainStyledAttributes.getResourceId(R$styleable.SmartRefreshLayout_srlFixedFooterViewId, this.mFixedFooterViewId);
        this.mHeaderTranslationViewId = obtainStyledAttributes.getResourceId(R$styleable.SmartRefreshLayout_srlHeaderTranslationViewId, this.mHeaderTranslationViewId);
        this.mFooterTranslationViewId = obtainStyledAttributes.getResourceId(R$styleable.SmartRefreshLayout_srlFooterTranslationViewId, this.mFooterTranslationViewId);
        boolean z2 = obtainStyledAttributes.getBoolean(R$styleable.SmartRefreshLayout_srlEnableNestedScrolling, this.mEnableNestedScrolling);
        this.mEnableNestedScrolling = z2;
        this.mNestedChild.setNestedScrollingEnabled(z2);
        this.mManualLoadMore = this.mManualLoadMore || obtainStyledAttributes.hasValue(i2);
        this.mManualHeaderTranslationContent = this.mManualHeaderTranslationContent || obtainStyledAttributes.hasValue(i5);
        this.mManualFooterTranslationContent = this.mManualFooterTranslationContent || obtainStyledAttributes.hasValue(i6);
        this.mHeaderHeightStatus = obtainStyledAttributes.hasValue(i3) ? C2902a.f7919g : this.mHeaderHeightStatus;
        this.mFooterHeightStatus = obtainStyledAttributes.hasValue(i4) ? C2902a.f7919g : this.mFooterHeightStatus;
        int color = obtainStyledAttributes.getColor(R$styleable.SmartRefreshLayout_srlAccentColor, 0);
        int color2 = obtainStyledAttributes.getColor(R$styleable.SmartRefreshLayout_srlPrimaryColor, 0);
        if (color2 != 0) {
            if (color != 0) {
                this.mPrimaryColors = new int[]{color2, color};
            } else {
                this.mPrimaryColors = new int[]{color2};
            }
        } else if (color != 0) {
            this.mPrimaryColors = new int[]{0, color};
        }
        if (this.mEnablePureScrollMode && !this.mManualLoadMore && !this.mEnableLoadMore) {
            this.mEnableLoadMore = true;
        }
        obtainStyledAttributes.recycle();
    }

    public boolean autoLoadMore(int i2, int i3, float f2, boolean z) {
        if (this.mState != EnumC2903b.None || !isEnableRefreshOrLoadMore(this.mEnableLoadMore) || this.mFooterNoMoreData) {
            return false;
        }
        RunnableC4083i runnableC4083i = new RunnableC4083i(f2, i3, z);
        setViceState(EnumC2903b.Loading);
        if (i2 > 0) {
            this.mHandler.postDelayed(runnableC4083i, i2);
            return true;
        }
        runnableC4083i.run();
        return true;
    }

    @Deprecated
    public boolean autoRefresh(int i2) {
        int i3 = this.mReboundDuration;
        float f2 = (this.mHeaderMaxDragRate / 2.0f) + 0.5f;
        int i4 = this.mHeaderHeight;
        float f3 = f2 * i4 * 1.0f;
        if (i4 == 0) {
            i4 = 1;
        }
        return autoRefresh(i2, i3, f3 / i4, false);
    }

    public InterfaceC2900i finishLoadMore(int i2) {
        return finishLoadMore(i2, true, false);
    }

    public InterfaceC2900i finishRefresh(int i2) {
        return finishRefresh(i2, true, Boolean.FALSE);
    }

    public InterfaceC2900i setRefreshContent(@NonNull View view, int i2, int i3) {
        InterfaceC2895d interfaceC2895d = this.mRefreshContent;
        if (interfaceC2895d != null) {
            super.removeView(((C2905a) interfaceC2895d).f7962c);
        }
        super.addView(view, getChildCount(), new C4086l(i2, i3));
        this.mRefreshContent = new C2905a(view);
        if (this.mAttachedToWindow) {
            View findViewById = findViewById(this.mFixedHeaderViewId);
            View findViewById2 = findViewById(this.mFixedFooterViewId);
            ((C2905a) this.mRefreshContent).m3366f(this.mScrollBoundaryDecider);
            InterfaceC2895d interfaceC2895d2 = this.mRefreshContent;
            ((C2905a) interfaceC2895d2).f7970l.f7973c = this.mEnableLoadMoreWhenContentNotFull;
            ((C2905a) interfaceC2895d2).m3367g(this.mKernel, findViewById, findViewById2);
        }
        InterfaceC2898g interfaceC2898g = this.mRefreshHeader;
        if (interfaceC2898g != null && interfaceC2898g.getSpinnerStyle().f7960h) {
            super.bringChildToFront(this.mRefreshHeader.getView());
        }
        InterfaceC2898g interfaceC2898g2 = this.mRefreshFooter;
        if (interfaceC2898g2 != null && interfaceC2898g2.getSpinnerStyle().f7960h) {
            super.bringChildToFront(this.mRefreshFooter.getView());
        }
        return this;
    }

    public InterfaceC2900i setRefreshFooter(@NonNull InterfaceC2896e interfaceC2896e, int i2, int i3) {
        InterfaceC2898g interfaceC2898g;
        InterfaceC2898g interfaceC2898g2 = this.mRefreshFooter;
        if (interfaceC2898g2 != null) {
            super.removeView(interfaceC2898g2.getView());
        }
        this.mRefreshFooter = interfaceC2896e;
        this.mFooterLocked = false;
        this.mFooterBackgroundColor = 0;
        this.mFooterNoMoreDataEffective = false;
        this.mFooterNeedTouchEventWhenLoading = false;
        this.mFooterHeightStatus = this.mFooterHeightStatus.m3358b();
        this.mEnableLoadMore = !this.mManualLoadMore || this.mEnableLoadMore;
        if (this.mRefreshFooter.getSpinnerStyle().f7960h) {
            super.addView(this.mRefreshFooter.getView(), getChildCount(), new C4086l(i2, i3));
        } else {
            super.addView(this.mRefreshFooter.getView(), 0, new C4086l(i2, i3));
        }
        int[] iArr = this.mPrimaryColors;
        if (iArr != null && (interfaceC2898g = this.mRefreshFooter) != null) {
            interfaceC2898g.setPrimaryColors(iArr);
        }
        return this;
    }

    public InterfaceC2900i setRefreshHeader(@NonNull InterfaceC2897f interfaceC2897f, int i2, int i3) {
        InterfaceC2898g interfaceC2898g;
        InterfaceC2898g interfaceC2898g2 = this.mRefreshHeader;
        if (interfaceC2898g2 != null) {
            super.removeView(interfaceC2898g2.getView());
        }
        this.mRefreshHeader = interfaceC2897f;
        this.mHeaderBackgroundColor = 0;
        this.mHeaderNeedTouchEventWhenRefreshing = false;
        this.mHeaderHeightStatus = this.mHeaderHeightStatus.m3358b();
        if (this.mRefreshHeader.getSpinnerStyle().f7960h) {
            super.addView(this.mRefreshHeader.getView(), getChildCount(), new C4086l(i2, i3));
        } else {
            super.addView(this.mRefreshHeader.getView(), 0, new C4086l(i2, i3));
        }
        int[] iArr = this.mPrimaryColors;
        if (iArr != null && (interfaceC2898g = this.mRefreshHeader) != null) {
            interfaceC2898g.setPrimaryColors(iArr);
        }
        return this;
    }

    public boolean autoRefresh(int i2, int i3, float f2, boolean z) {
        if (this.mState != EnumC2903b.None || !isEnableRefreshOrLoadMore(this.mEnableRefresh)) {
            return false;
        }
        RunnableC4082h runnableC4082h = new RunnableC4082h(f2, i3, z);
        setViceState(EnumC2903b.Refreshing);
        if (i2 > 0) {
            this.mHandler.postDelayed(runnableC4082h, i2);
            return true;
        }
        runnableC4082h.run();
        return true;
    }

    public InterfaceC2900i finishLoadMore(boolean z) {
        return finishLoadMore(z ? Math.min(Math.max(0, 300 - ((int) (System.currentTimeMillis() - this.mLastOpenTime))), IjkMediaCodecInfo.RANK_SECURE) << 16 : 0, z, false);
    }

    public InterfaceC2900i finishRefresh(boolean z) {
        if (z) {
            return finishRefresh(Math.min(Math.max(0, 300 - ((int) (System.currentTimeMillis() - this.mLastOpenTime))), IjkMediaCodecInfo.RANK_SECURE) << 16, true, Boolean.FALSE);
        }
        return finishRefresh(0, false, null);
    }

    public InterfaceC2900i finishLoadMore(int i2, boolean z, boolean z2) {
        int i3 = i2 >> 16;
        int i4 = (i2 << 16) >> 16;
        RunnableC4081g runnableC4081g = new RunnableC4081g(i3, z2, z);
        if (i4 > 0) {
            this.mHandler.postDelayed(runnableC4081g, i4);
        } else {
            runnableC4081g.run();
        }
        return this;
    }

    public InterfaceC2900i finishRefresh(int i2, boolean z, Boolean bool) {
        int i3 = i2 >> 16;
        int i4 = (i2 << 16) >> 16;
        RunnableC4080f runnableC4080f = new RunnableC4080f(i3, bool, z);
        if (i4 > 0) {
            this.mHandler.postDelayed(runnableC4080f, i4);
        } else {
            runnableC4080f.run();
        }
        return this;
    }

    /* renamed from: com.scwang.smartrefresh.layout.SmartRefreshLayout$l */
    public static class C4086l extends ViewGroup.MarginLayoutParams {

        /* renamed from: a */
        public int f10672a;

        /* renamed from: b */
        public C2904c f10673b;

        public C4086l(Context context, AttributeSet attributeSet) {
            super(context, attributeSet);
            this.f10672a = 0;
            this.f10673b = null;
            TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, R$styleable.SmartRefreshLayout_Layout);
            this.f10672a = obtainStyledAttributes.getColor(R$styleable.SmartRefreshLayout_Layout_layout_srlBackgroundColor, this.f10672a);
            int i2 = R$styleable.SmartRefreshLayout_Layout_layout_srlSpinnerStyle;
            if (obtainStyledAttributes.hasValue(i2)) {
                this.f10673b = C2904c.f7958f[obtainStyledAttributes.getInt(i2, 0)];
            }
            obtainStyledAttributes.recycle();
        }

        public C4086l(int i2, int i3) {
            super(i2, i3);
            this.f10672a = 0;
            this.f10673b = null;
        }
    }
}
