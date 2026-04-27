package im.uwrkaxlmjj.ui.hviews.swipelist;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.ValueAnimator;
import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Rect;
import android.os.Build;
import android.util.AttributeSet;
import android.view.MotionEvent;
import android.view.VelocityTracker;
import android.view.View;
import android.view.ViewConfiguration;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.view.animation.Interpolator;
import android.view.animation.OvershootInterpolator;
import android.widget.FrameLayout;
import androidx.collection.SimpleArrayMap;
import androidx.core.view.ViewCompat;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.R;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import java.util.LinkedList;
import java.util.List;

/* JADX INFO: loaded from: classes5.dex */
public class SlidingItemMenuRecyclerView extends RecyclerListView {
    public static final int DEFAULT_ITEM_SCROLL_DURATION = 500;
    private static final String TAG = "SlidingItemMenuRecyclerView";
    private static final int TAG_ITEM_ANIMATOR = 2131297360;
    private static final int TAG_ITEM_MENU_WIDTH = 2131297361;
    private static final int TAG_MENU_ITEM_WIDTHS = 2131297362;
    private ViewGroup mActiveItem;
    private final Rect mActiveItemBounds;
    private final Rect mActiveItemMenuBounds;
    private int mDownX;
    private int mDownY;
    private ViewGroup mFullyOpenedItem;
    private boolean mHasItemFullyOpenOnActionDown;
    private boolean mIsItemBeingDragged;
    private boolean mIsItemDraggable;
    private boolean mIsVerticalScrollBarEnabled;
    private final float mItemMinimumFlingVelocity;
    private int mItemScrollDuration;
    private final List<ViewGroup> mOpenedItems;
    protected final float mTouchSlop;
    private final float[] mTouchX;
    private final float[] mTouchY;
    private VelocityTracker mVelocityTracker;
    private static final Interpolator sViscousFluidInterpolator = new ViscousFluidInterpolator(6.66f);
    private static final Interpolator sOvershootInterpolator = new OvershootInterpolator(1.0f);

    public boolean isItemScrollingEnabled() {
        return isItemDraggable();
    }

    public boolean isItemDraggable() {
        return this.mIsItemDraggable;
    }

    public void setItemScrollingEnabled(boolean enabled) {
        setItemDraggable(enabled);
    }

    public void setItemDraggable(boolean draggable) {
        this.mIsItemDraggable = draggable;
    }

    public int getItemScrollDuration() {
        return this.mItemScrollDuration;
    }

    public void setItemScrollDuration(int duration) {
        if (duration < 0) {
            throw new IllegalArgumentException("The animators for opening/closing the item views cannot have negative duration: " + duration);
        }
        this.mItemScrollDuration = duration;
    }

    public SlidingItemMenuRecyclerView(Context context) {
        this(context, null);
    }

    public SlidingItemMenuRecyclerView(Context context, AttributeSet attrs) {
        this(context, attrs, 0);
    }

    public SlidingItemMenuRecyclerView(Context context, AttributeSet attrs, int defStyle) {
        super(context, attrs, defStyle);
        this.mTouchX = new float[2];
        this.mTouchY = new float[2];
        this.mActiveItemBounds = new Rect();
        this.mActiveItemMenuBounds = new Rect();
        this.mOpenedItems = new LinkedList();
        float dp = context.getResources().getDisplayMetrics().density;
        this.mTouchSlop = ViewConfiguration.getTouchSlop() * dp;
        this.mItemMinimumFlingVelocity = 200.0f * dp;
        TypedArray ta = context.obtainStyledAttributes(attrs, R.styleable.SlidingItemMenuRecyclerView, defStyle, 0);
        setItemDraggable(ta.getBoolean(1, true));
        setItemScrollDuration(ta.getInteger(0, DEFAULT_ITEM_SCROLL_DURATION));
        ta.recycle();
    }

    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView, android.view.View
    public void setVerticalScrollBarEnabled(boolean verticalScrollBarEnabled) {
        this.mIsVerticalScrollBarEnabled = verticalScrollBarEnabled;
        super.setVerticalScrollBarEnabled(verticalScrollBarEnabled);
    }

    private boolean childHasMenu(ViewGroup itemView) {
        if (itemView.getVisibility() != 0) {
            return false;
        }
        int itemChildCount = itemView.getChildCount();
        View itemLastChild = itemView.getChildAt(itemChildCount >= 2 ? itemChildCount - 1 : 1);
        if (!(itemLastChild instanceof FrameLayout)) {
            return false;
        }
        FrameLayout itemMenu = (FrameLayout) itemLastChild;
        int menuItemCount = itemMenu.getChildCount();
        int[] menuItemWidths = new int[menuItemCount];
        int itemMenuWidth = 0;
        for (int i = 0; i < menuItemCount; i++) {
            menuItemWidths[i] = ((FrameLayout) itemMenu.getChildAt(i)).getChildAt(0).getWidth();
            itemMenuWidth += menuItemWidths[i];
        }
        if (itemMenuWidth <= 0) {
            return false;
        }
        itemView.setTag(mpEIGo.juqQQs.esbSDO.R.attr.tag_itemMenuWidth, Integer.valueOf(itemMenuWidth));
        itemView.setTag(mpEIGo.juqQQs.esbSDO.R.attr.tag_menuItemWidths, menuItemWidths);
        return true;
    }

    private void resolveActiveItemMenuBounds() {
        int itemMenuWidth = ((Integer) this.mActiveItem.getTag(mpEIGo.juqQQs.esbSDO.R.attr.tag_itemMenuWidth)).intValue();
        int left = Utils.isLayoutRtl(this.mActiveItem) ? 0 : this.mActiveItem.getRight() - itemMenuWidth;
        int right = left + itemMenuWidth;
        this.mActiveItemMenuBounds.set(left, this.mActiveItemBounds.top, right, this.mActiveItemBounds.bottom);
    }

    @Override // android.view.ViewGroup, android.view.View
    public boolean dispatchTouchEvent(MotionEvent ev) {
        return super.dispatchTouchEvent(ev);
    }

    /* JADX WARN: Code restructure failed: missing block: B:14:0x0027, code lost:
    
        if (r2 != 3) goto L41;
     */
    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView, androidx.recyclerview.widget.RecyclerView, android.view.ViewGroup
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean onInterceptTouchEvent(android.view.MotionEvent r11) {
        /*
            Method dump skipped, instruction units count: 234
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.hviews.swipelist.SlidingItemMenuRecyclerView.onInterceptTouchEvent(android.view.MotionEvent):boolean");
    }

    @Override // androidx.recyclerview.widget.RecyclerView, android.view.View
    public boolean onTouchEvent(MotionEvent e) {
        int finalXFromEndToStart;
        if (this.mIsVerticalScrollBarEnabled) {
            super.setVerticalScrollBarEnabled(!this.mIsItemBeingDragged);
        }
        if (this.mVelocityTracker == null) {
            this.mVelocityTracker = VelocityTracker.obtain();
        }
        this.mVelocityTracker.addMovement(e);
        int action = e.getAction() & 255;
        if (action == 1) {
            if (this.mIsItemDraggable && this.mIsItemBeingDragged) {
                boolean rtl = Utils.isLayoutRtl(this.mActiveItem);
                float translationX = this.mActiveItem.getChildAt(0).getTranslationX();
                int itemMenuWidth = ((Integer) this.mActiveItem.getTag(mpEIGo.juqQQs.esbSDO.R.attr.tag_itemMenuWidth)).intValue();
                if (translationX != 0.0f) {
                    if ((!rtl && translationX == (-itemMenuWidth)) || (rtl && translationX == itemMenuWidth)) {
                        this.mFullyOpenedItem = this.mActiveItem;
                    } else {
                        float[] fArr = this.mTouchX;
                        float dx = rtl ? fArr[fArr.length - 2] - fArr[fArr.length - 1] : fArr[fArr.length - 1] - fArr[fArr.length - 2];
                        this.mVelocityTracker.computeCurrentVelocity(1000);
                        float velocityX = Math.abs(this.mVelocityTracker.getXVelocity());
                        if (dx < 0.0f && velocityX >= this.mItemMinimumFlingVelocity) {
                            smoothTranslateItemViewXTo(this.mActiveItem, rtl ? itemMenuWidth : -itemMenuWidth, this.mItemScrollDuration);
                            this.mFullyOpenedItem = this.mActiveItem;
                            clearTouch();
                            cancelParentTouch(e);
                            return true;
                        }
                        if (dx > 0.0f && velocityX >= this.mItemMinimumFlingVelocity) {
                            releaseItemView(true);
                            clearTouch();
                            cancelParentTouch(e);
                            return true;
                        }
                        float middle = itemMenuWidth / 2.0f;
                        if (Math.abs(translationX) < middle) {
                            releaseItemView(true);
                        } else {
                            smoothTranslateItemViewXTo(this.mActiveItem, rtl ? itemMenuWidth : -itemMenuWidth, this.mItemScrollDuration);
                            this.mFullyOpenedItem = this.mActiveItem;
                        }
                    }
                }
                clearTouch();
                cancelParentTouch(e);
                return true;
            }
        } else {
            if (action == 2) {
                markCurrTouchPoint(e.getX(), e.getY());
                if (!this.mIsItemDraggable && cancelTouch()) {
                    return true;
                }
                if (this.mIsItemBeingDragged) {
                    float[] fArr2 = this.mTouchX;
                    float dx2 = fArr2[fArr2.length - 1] - fArr2[fArr2.length - 2];
                    float translationX2 = this.mActiveItem.getChildAt(0).getTranslationX();
                    boolean rtl2 = Utils.isLayoutRtl(this.mActiveItem);
                    if (rtl2) {
                        finalXFromEndToStart = ((Integer) this.mActiveItem.getTag(mpEIGo.juqQQs.esbSDO.R.attr.tag_itemMenuWidth)).intValue();
                    } else {
                        finalXFromEndToStart = -((Integer) this.mActiveItem.getTag(mpEIGo.juqQQs.esbSDO.R.attr.tag_itemMenuWidth)).intValue();
                    }
                    if ((!rtl2 && dx2 + translationX2 < finalXFromEndToStart) || (rtl2 && dx2 + translationX2 > finalXFromEndToStart)) {
                        dx2 /= 3.0f;
                    } else if ((!rtl2 && dx2 + translationX2 > 0.0f) || (rtl2 && dx2 + translationX2 < 0.0f)) {
                        dx2 = 0.0f - translationX2;
                    }
                    translateItemViewXBy(this.mActiveItem, dx2);
                    return true;
                }
                if ((this.mHasItemFullyOpenOnActionDown | tryHandleItemScrollingEvent()) || this.mOpenedItems.size() > 0) {
                    return true;
                }
            } else if (action != 3) {
                if ((action == 5 || action == 6) && (this.mIsItemBeingDragged || this.mHasItemFullyOpenOnActionDown || this.mOpenedItems.size() > 0)) {
                    return true;
                }
            }
            return super.onTouchEvent(e);
        }
        cancelTouch();
        return super.onTouchEvent(e);
    }

    private void markCurrTouchPoint(float x, float y) {
        float[] fArr = this.mTouchX;
        System.arraycopy(fArr, 1, fArr, 0, fArr.length - 1);
        float[] fArr2 = this.mTouchX;
        fArr2[fArr2.length - 1] = x;
        float[] fArr3 = this.mTouchY;
        System.arraycopy(fArr3, 1, fArr3, 0, fArr3.length - 1);
        float[] fArr4 = this.mTouchY;
        fArr4[fArr4.length - 1] = y;
    }

    private boolean tryHandleItemScrollingEvent() {
        if (this.mActiveItem == null || !this.mIsItemDraggable || getScrollState() != 0 || getLayoutManager().canScrollHorizontally()) {
            return false;
        }
        float[] fArr = this.mTouchY;
        float absDy = Math.abs(fArr[fArr.length - 1] - this.mDownY);
        if (absDy <= this.mTouchSlop) {
            float[] fArr2 = this.mTouchX;
            float dx = fArr2[fArr2.length - 1] - this.mDownX;
            if (this.mOpenedItems.size() == 0) {
                boolean rtl = Utils.isLayoutRtl(this.mActiveItem);
                this.mIsItemBeingDragged = (rtl && dx > this.mTouchSlop) || (!rtl && dx < (-this.mTouchSlop));
            } else {
                this.mIsItemBeingDragged = Math.abs(dx) > this.mTouchSlop;
            }
            if (this.mIsItemBeingDragged) {
                requestParentDisallowInterceptTouchEvent();
                return true;
            }
        }
        return false;
    }

    private void requestParentDisallowInterceptTouchEvent() {
        ViewParent parent = getParent();
        if (parent != null) {
            parent.requestDisallowInterceptTouchEvent(true);
        }
    }

    private boolean cancelTouch() {
        if (this.mIsItemBeingDragged) {
            releaseItemView(true);
            clearTouch();
            return true;
        }
        if (this.mHasItemFullyOpenOnActionDown) {
            if (this.mActiveItem == this.mFullyOpenedItem) {
                releaseItemView(true);
            }
            clearTouch();
            return true;
        }
        return false;
    }

    private void clearTouch() {
        VelocityTracker velocityTracker = this.mVelocityTracker;
        if (velocityTracker != null) {
            velocityTracker.recycle();
            this.mVelocityTracker = null;
        }
        resetTouch();
    }

    private void resetTouch() {
        this.mActiveItem = null;
        this.mHasItemFullyOpenOnActionDown = false;
        this.mActiveItemBounds.setEmpty();
        this.mActiveItemMenuBounds.setEmpty();
        this.mIsItemBeingDragged = false;
        VelocityTracker velocityTracker = this.mVelocityTracker;
        if (velocityTracker != null) {
            velocityTracker.clear();
        }
    }

    private void cancelParentTouch(MotionEvent e) {
        int action = e.getAction();
        e.setAction(3);
        super.onTouchEvent(e);
        e.setAction(action);
    }

    public void releaseItemView() {
        releaseItemView(true);
    }

    public void releaseItemView(boolean animate) {
        releaseItemViewInternal(this.mIsItemBeingDragged ? this.mActiveItem : this.mFullyOpenedItem, animate ? this.mItemScrollDuration : 0);
    }

    private void releaseItemViewInternal(ViewGroup itemView, int duration) {
        if (itemView != null) {
            if (duration > 0) {
                smoothTranslateItemViewXTo(itemView, 0.0f, duration);
            } else {
                translateItemViewXTo(itemView, 0.0f);
            }
            if (this.mFullyOpenedItem == itemView) {
                this.mFullyOpenedItem = null;
            }
        }
    }

    public boolean openItemAtPosition(int position) {
        return openItemAtPosition(position, true);
    }

    public boolean openItemAtPosition(int position, boolean animate) {
        ViewGroup itemView;
        float fIntValue;
        RecyclerView.LayoutManager lm = getLayoutManager();
        if (lm == null) {
            return false;
        }
        View view = lm.findViewByPosition(position);
        if (!(view instanceof ViewGroup) || this.mFullyOpenedItem == (itemView = (ViewGroup) view) || !childHasMenu(itemView)) {
            return false;
        }
        if (!cancelTouch()) {
            releaseItemView(animate);
        }
        if (Utils.isLayoutRtl(itemView)) {
            fIntValue = ((Integer) itemView.getTag(mpEIGo.juqQQs.esbSDO.R.attr.tag_itemMenuWidth)).intValue();
        } else {
            fIntValue = -((Integer) itemView.getTag(mpEIGo.juqQQs.esbSDO.R.attr.tag_itemMenuWidth)).intValue();
        }
        smoothTranslateItemViewXTo(itemView, fIntValue, animate ? this.mItemScrollDuration : 0);
        this.mFullyOpenedItem = itemView;
        return true;
    }

    private void smoothTranslateItemViewXTo(ViewGroup itemView, float x, int duration) {
        smoothTranslateItemViewXBy(itemView, x - itemView.getChildAt(0).getTranslationX(), duration);
    }

    private void smoothTranslateItemViewXBy(ViewGroup itemView, float dx, int duration) {
        TranslateItemViewXAnimator animator = (TranslateItemViewXAnimator) itemView.getTag(mpEIGo.juqQQs.esbSDO.R.attr.tag_itemAnimator);
        if (dx != 0.0f && duration > 0) {
            boolean canceled = false;
            if (animator == null) {
                animator = new TranslateItemViewXAnimator(this, itemView);
                itemView.setTag(mpEIGo.juqQQs.esbSDO.R.attr.tag_itemAnimator, animator);
            } else if (animator.isRunning()) {
                animator.removeListener(animator.listener);
                animator.cancel();
                canceled = true;
            }
            animator.setFloatValues(0.0f, dx);
            boolean rtl = Utils.isLayoutRtl(itemView);
            Interpolator interpolator = ((rtl || dx >= 0.0f) && (!rtl || dx <= 0.0f)) ? sViscousFluidInterpolator : sOvershootInterpolator;
            animator.setInterpolator(interpolator);
            animator.setDuration(duration);
            animator.start();
            if (canceled) {
                animator.addListener(animator.listener);
                return;
            }
            return;
        }
        if (animator != null && animator.isRunning()) {
            animator.cancel();
        }
        baseTranslateItemViewXBy(itemView, dx);
    }

    private void translateItemViewXTo(ViewGroup itemView, float x) {
        translateItemViewXBy(itemView, x - itemView.getChildAt(0).getTranslationX());
    }

    private void translateItemViewXBy(ViewGroup itemView, float dx) {
        TranslateItemViewXAnimator animator = (TranslateItemViewXAnimator) itemView.getTag(mpEIGo.juqQQs.esbSDO.R.attr.tag_itemAnimator);
        if (animator != null && animator.isRunning()) {
            animator.cancel();
        }
        baseTranslateItemViewXBy(itemView, dx);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void baseTranslateItemViewXBy(ViewGroup itemView, float dx) {
        if (dx == 0.0f) {
            return;
        }
        float translationX = itemView.getChildAt(0).getTranslationX() + dx;
        int itemMenuWidth = ((Integer) itemView.getTag(mpEIGo.juqQQs.esbSDO.R.attr.tag_itemMenuWidth)).intValue();
        boolean rtl = Utils.isLayoutRtl(itemView);
        if ((!rtl && translationX > (-itemMenuWidth) * 0.05f) || (rtl && translationX < itemMenuWidth * 0.05f)) {
            this.mOpenedItems.remove(itemView);
        } else if (!this.mOpenedItems.contains(itemView)) {
            this.mOpenedItems.add(itemView);
        }
        int itemChildCount = itemView.getChildCount();
        for (int i = 0; i < itemChildCount; i++) {
            itemView.getChildAt(i).setTranslationX(translationX);
        }
        int i2 = itemChildCount - 1;
        FrameLayout itemMenu = (FrameLayout) itemView.getChildAt(i2);
        int[] menuItemWidths = (int[]) itemView.getTag(mpEIGo.juqQQs.esbSDO.R.attr.tag_menuItemWidths);
        float menuItemFrameDx = 0.0f;
        int menuItemCount = itemMenu.getChildCount();
        for (int i3 = 1; i3 < menuItemCount; i3++) {
            FrameLayout menuItemFrame = (FrameLayout) itemMenu.getChildAt(i3);
            menuItemFrameDx -= (menuItemWidths[i3 - 1] * dx) / itemMenuWidth;
            menuItemFrame.setTranslationX(menuItemFrame.getTranslationX() + menuItemFrameDx);
        }
    }

    private static final class TranslateItemViewXAnimator extends ValueAnimator {
        float cachedDeltaTransX;
        final Animator.AnimatorListener listener;

        TranslateItemViewXAnimator(final SlidingItemMenuRecyclerView parent, final ViewGroup itemView) {
            AnimatorListenerAdapter animatorListenerAdapter = new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.hviews.swipelist.SlidingItemMenuRecyclerView.TranslateItemViewXAnimator.1
                final SimpleArrayMap<View, Integer> childrenLayerTypes = new SimpleArrayMap<>(0);

                void ensureChildrenLayerTypes() {
                    int itemChildCount = itemView.getChildCount();
                    ViewGroup itemMenu = (ViewGroup) itemView.getChildAt(itemChildCount - 1);
                    int menuItemCount = itemMenu.getChildCount();
                    this.childrenLayerTypes.clear();
                    this.childrenLayerTypes.ensureCapacity((itemChildCount - 1) + menuItemCount);
                    for (int i = 0; i < itemChildCount - 1; i++) {
                        View itemChild = itemView.getChildAt(i);
                        this.childrenLayerTypes.put(itemChild, Integer.valueOf(itemChild.getLayerType()));
                    }
                    for (int i2 = 0; i2 < menuItemCount; i2++) {
                        View menuItemFrame = itemMenu.getChildAt(i2);
                        this.childrenLayerTypes.put(menuItemFrame, Integer.valueOf(menuItemFrame.getLayerType()));
                    }
                }

                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationStart(Animator animation) {
                    ensureChildrenLayerTypes();
                    for (int i = this.childrenLayerTypes.size() - 1; i >= 0; i--) {
                        View child = this.childrenLayerTypes.keyAt(i);
                        child.setLayerType(2, null);
                        if (Build.VERSION.SDK_INT >= 12 && ViewCompat.isAttachedToWindow(child)) {
                            child.buildLayer();
                        }
                    }
                }

                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation) {
                    for (int i = this.childrenLayerTypes.size() - 1; i >= 0; i--) {
                        this.childrenLayerTypes.keyAt(i).setLayerType(this.childrenLayerTypes.valueAt(i).intValue(), null);
                    }
                }
            };
            this.listener = animatorListenerAdapter;
            addListener(animatorListenerAdapter);
            addUpdateListener(new ValueAnimator.AnimatorUpdateListener() { // from class: im.uwrkaxlmjj.ui.hviews.swipelist.SlidingItemMenuRecyclerView.TranslateItemViewXAnimator.2
                @Override // android.animation.ValueAnimator.AnimatorUpdateListener
                public void onAnimationUpdate(ValueAnimator animation) {
                    float deltaTransX = ((Float) animation.getAnimatedValue()).floatValue();
                    parent.baseTranslateItemViewXBy(itemView, deltaTransX - TranslateItemViewXAnimator.this.cachedDeltaTransX);
                    TranslateItemViewXAnimator.this.cachedDeltaTransX = deltaTransX;
                }
            });
        }

        @Override // android.animation.ValueAnimator, android.animation.Animator
        public void start() {
            this.cachedDeltaTransX = 0.0f;
            super.start();
        }
    }

    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView, androidx.recyclerview.widget.RecyclerView, android.view.ViewGroup, android.view.View
    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        releaseItemViewInternal(this.mFullyOpenedItem, 0);
        if (this.mOpenedItems.size() > 0) {
            ViewGroup[] openedItems = (ViewGroup[]) this.mOpenedItems.toArray(new ViewGroup[0]);
            for (ViewGroup openedItem : openedItems) {
                Animator animator = (Animator) openedItem.getTag(mpEIGo.juqQQs.esbSDO.R.attr.tag_itemAnimator);
                if (animator != null && animator.isRunning()) {
                    animator.end();
                }
            }
            this.mOpenedItems.clear();
        }
    }
}
