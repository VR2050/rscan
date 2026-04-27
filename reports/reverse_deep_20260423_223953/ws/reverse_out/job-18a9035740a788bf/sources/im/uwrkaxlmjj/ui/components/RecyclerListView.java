package im.uwrkaxlmjj.ui.components;

import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.RectF;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.TransitionDrawable;
import android.os.Build;
import android.os.SystemClock;
import android.text.Layout;
import android.text.StaticLayout;
import android.text.TextPaint;
import android.util.AttributeSet;
import android.util.SparseIntArray;
import android.util.StateSet;
import android.view.GestureDetector;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewConfiguration;
import android.view.ViewGroup;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;

/* JADX INFO: loaded from: classes5.dex */
public class RecyclerListView extends RecyclerView {
    private static int[] attributes;
    private static boolean gotAttributes;
    private Runnable clickRunnable;
    private int currentChildPosition;
    private View currentChildView;
    private int currentFirst;
    private int currentVisible;
    private boolean disableHighlightState;
    private boolean disallowInterceptTouchEvents;
    private View emptyView;
    private FastScroll fastScroll;
    private boolean foreIntercept;
    private GestureDetector gestureDetector;
    private ArrayList<View> headers;
    private ArrayList<View> headersCache;
    private boolean hiddenByEmptyView;
    private boolean ignoreOnScroll;
    private boolean instantClick;
    private boolean interceptedByChild;
    private boolean isChildViewEnabled;
    private long lastAlphaAnimationTime;
    private boolean longPressCalled;
    private RecyclerView.AdapterDataObserver observer;
    private OnInterceptTouchListener onInterceptTouchListener;
    private OnItemClickListener onItemClickListener;
    private OnItemClickListenerExtended onItemClickListenerExtended;
    private OnItemLongClickListener onItemLongClickListener;
    private OnItemLongClickListenerExtended onItemLongClickListenerExtended;
    private RecyclerView.OnScrollListener onScrollListener;
    private IntReturnCallback pendingHighlightPosition;
    private View pinnedHeader;
    private float pinnedHeaderShadowAlpha;
    private Drawable pinnedHeaderShadowDrawable;
    private float pinnedHeaderShadowTargetAlpha;
    private Runnable removeHighlighSelectionRunnable;
    private boolean scrollEnabled;
    private boolean scrollingByUser;
    private int sectionOffset;
    private SectionsAdapter sectionsAdapter;
    private int sectionsCount;
    private int sectionsType;
    private Runnable selectChildRunnable;
    private Drawable selectorDrawable;
    private int selectorPosition;
    private android.graphics.Rect selectorRect;
    private boolean selfOnLayout;
    private int startSection;
    private boolean wasPressed;

    public static abstract class FastScrollAdapter extends SelectionAdapter {
        public abstract String getLetter(int i);

        public abstract int getPositionForScrollProgress(float f);
    }

    public interface IntReturnCallback {
        int run();
    }

    public interface OnInterceptTouchListener {
        boolean onInterceptTouchEvent(MotionEvent motionEvent);
    }

    public interface OnItemClickListener {
        void onItemClick(View view, int i);
    }

    public interface OnItemClickListenerExtended {
        void onItemClick(View view, int i, float f, float f2);
    }

    public interface OnItemLongClickListener {
        boolean onItemClick(View view, int i);
    }

    public interface OnItemLongClickListenerExtended {
        boolean onItemClick(View view, int i, float f, float f2);

        void onLongClickRelease();

        void onMove(float f, float f2);
    }

    public static abstract class SelectionAdapter extends RecyclerView.Adapter {
        public abstract boolean isEnabled(RecyclerView.ViewHolder viewHolder);

        public int getSelectionBottomPadding(View view) {
            return 0;
        }
    }

    public static abstract class SectionsAdapter extends FastScrollAdapter {
        private int count;
        private SparseIntArray sectionCache;
        private int sectionCount;
        private SparseIntArray sectionCountCache;
        private SparseIntArray sectionPositionCache;

        public abstract int getCountForSection(int i);

        public abstract Object getItem(int i, int i2);

        public abstract int getItemViewType(int i, int i2);

        public abstract int getSectionCount();

        public abstract View getSectionHeaderView(int i, View view);

        public abstract boolean isEnabled(int i, int i2);

        public abstract void onBindViewHolder(int i, int i2, RecyclerView.ViewHolder viewHolder);

        private void cleanupCache() {
            SparseIntArray sparseIntArray = this.sectionCache;
            if (sparseIntArray == null) {
                this.sectionCache = new SparseIntArray();
                this.sectionPositionCache = new SparseIntArray();
                this.sectionCountCache = new SparseIntArray();
            } else {
                sparseIntArray.clear();
                this.sectionPositionCache.clear();
                this.sectionCountCache.clear();
            }
            this.count = -1;
            this.sectionCount = -1;
        }

        public void notifySectionsChanged() {
            cleanupCache();
        }

        public SectionsAdapter() {
            cleanupCache();
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void notifyDataSetChanged() {
            cleanupCache();
            super.notifyDataSetChanged();
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            int position = holder.getAdapterPosition();
            return isEnabled(getSectionForPosition(position), getPositionInSectionForPosition(position));
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            int i = this.count;
            if (i >= 0) {
                return i;
            }
            this.count = 0;
            int N = internalGetSectionCount();
            for (int i2 = 0; i2 < N; i2++) {
                this.count += internalGetCountForSection(i2);
            }
            int i3 = this.count;
            return i3;
        }

        public final Object getItem(int position) {
            return getItem(getSectionForPosition(position), getPositionInSectionForPosition(position));
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            return getItemViewType(getSectionForPosition(position), getPositionInSectionForPosition(position));
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            onBindViewHolder(getSectionForPosition(position), getPositionInSectionForPosition(position), holder);
        }

        private int internalGetCountForSection(int section) {
            int cachedSectionCount = this.sectionCountCache.get(section, Integer.MAX_VALUE);
            if (cachedSectionCount != Integer.MAX_VALUE) {
                return cachedSectionCount;
            }
            int sectionCount = getCountForSection(section);
            this.sectionCountCache.put(section, sectionCount);
            return sectionCount;
        }

        private int internalGetSectionCount() {
            int i = this.sectionCount;
            if (i >= 0) {
                return i;
            }
            int sectionCount = getSectionCount();
            this.sectionCount = sectionCount;
            return sectionCount;
        }

        public final int getSectionForPosition(int position) {
            int cachedSection = this.sectionCache.get(position, Integer.MAX_VALUE);
            if (cachedSection != Integer.MAX_VALUE) {
                return cachedSection;
            }
            int sectionStart = 0;
            int N = internalGetSectionCount();
            for (int i = 0; i < N; i++) {
                int sectionCount = internalGetCountForSection(i);
                int sectionEnd = sectionStart + sectionCount;
                if (position >= sectionStart && position < sectionEnd) {
                    this.sectionCache.put(position, i);
                    return i;
                }
                sectionStart = sectionEnd;
            }
            return -1;
        }

        public int getPositionInSectionForPosition(int position) {
            int cachedPosition = this.sectionPositionCache.get(position, Integer.MAX_VALUE);
            if (cachedPosition != Integer.MAX_VALUE) {
                return cachedPosition;
            }
            int sectionStart = 0;
            int N = internalGetSectionCount();
            for (int i = 0; i < N; i++) {
                int sectionCount = internalGetCountForSection(i);
                int sectionEnd = sectionStart + sectionCount;
                if (position >= sectionStart && position < sectionEnd) {
                    int positionInSection = position - sectionStart;
                    this.sectionPositionCache.put(position, positionInSection);
                    return positionInSection;
                }
                sectionStart = sectionEnd;
            }
            return -1;
        }
    }

    public static class Holder extends RecyclerView.ViewHolder {
        public Holder(View itemView) {
            super(itemView);
        }
    }

    private class FastScroll extends View {
        private float bubbleProgress;
        private int[] colors;
        private String currentLetter;
        private long lastUpdateTime;
        private float lastY;
        private StaticLayout letterLayout;
        private TextPaint letterPaint;
        private StaticLayout oldLetterLayout;
        private Paint paint;
        private Path path;
        private boolean pressed;
        private float progress;
        private float[] radii;
        private RectF rect;
        private int scrollX;
        private float startDy;
        private float textX;
        private float textY;

        public FastScroll(Context context) {
            super(context);
            this.rect = new RectF();
            this.paint = new Paint(1);
            this.letterPaint = new TextPaint(1);
            this.path = new Path();
            this.radii = new float[8];
            this.colors = new int[6];
            this.letterPaint.setTextSize(AndroidUtilities.dp(45.0f));
            for (int a = 0; a < 8; a++) {
                this.radii[a] = AndroidUtilities.dp(44.0f);
            }
            this.scrollX = AndroidUtilities.dp(LocaleController.isRTL ? 10.0f : 117.0f);
            updateColors();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void updateColors() {
            int inactive = Theme.getColor(Theme.key_fastScrollInactive);
            int active = Theme.getColor(Theme.key_fastScrollActive);
            this.paint.setColor(inactive);
            this.letterPaint.setColor(Theme.getColor(Theme.key_fastScrollText));
            this.colors[0] = Color.red(inactive);
            this.colors[1] = Color.red(active);
            this.colors[2] = Color.green(inactive);
            this.colors[3] = Color.green(active);
            this.colors[4] = Color.blue(inactive);
            this.colors[5] = Color.blue(active);
            invalidate();
        }

        @Override // android.view.View
        public boolean onTouchEvent(MotionEvent event) {
            int action = event.getAction();
            if (action == 0) {
                float x = event.getX();
                this.lastY = event.getY();
                float currentY = ((float) Math.ceil((getMeasuredHeight() - AndroidUtilities.dp(54.0f)) * this.progress)) + AndroidUtilities.dp(12.0f);
                if ((!LocaleController.isRTL || x <= AndroidUtilities.dp(25.0f)) && (LocaleController.isRTL || x >= AndroidUtilities.dp(107.0f))) {
                    float f = this.lastY;
                    if (f >= currentY && f <= AndroidUtilities.dp(30.0f) + currentY) {
                        this.startDy = this.lastY - currentY;
                        this.pressed = true;
                        this.lastUpdateTime = System.currentTimeMillis();
                        getCurrentLetter();
                        invalidate();
                        return true;
                    }
                }
                return false;
            }
            if (action != 1) {
                if (action == 2) {
                    if (!this.pressed) {
                        return true;
                    }
                    float newY = event.getY();
                    float minY = AndroidUtilities.dp(12.0f) + this.startDy;
                    float maxY = (getMeasuredHeight() - AndroidUtilities.dp(42.0f)) + this.startDy;
                    if (newY < minY) {
                        newY = minY;
                    } else if (newY > maxY) {
                        newY = maxY;
                    }
                    float dy = newY - this.lastY;
                    this.lastY = newY;
                    float measuredHeight = this.progress + (dy / (getMeasuredHeight() - AndroidUtilities.dp(54.0f)));
                    this.progress = measuredHeight;
                    if (measuredHeight < 0.0f) {
                        this.progress = 0.0f;
                    } else if (measuredHeight > 1.0f) {
                        this.progress = 1.0f;
                    }
                    getCurrentLetter();
                    invalidate();
                    return true;
                }
                if (action != 3) {
                    return super.onTouchEvent(event);
                }
            }
            this.pressed = false;
            this.lastUpdateTime = System.currentTimeMillis();
            invalidate();
            return true;
        }

        private void getCurrentLetter() {
            RecyclerView.LayoutManager layoutManager = RecyclerListView.this.getLayoutManager();
            if (layoutManager instanceof LinearLayoutManager) {
                LinearLayoutManager linearLayoutManager = (LinearLayoutManager) layoutManager;
                if (linearLayoutManager.getOrientation() == 1) {
                    RecyclerView.Adapter adapter = RecyclerListView.this.getAdapter();
                    if (adapter instanceof FastScrollAdapter) {
                        FastScrollAdapter fastScrollAdapter = (FastScrollAdapter) adapter;
                        int position = fastScrollAdapter.getPositionForScrollProgress(this.progress);
                        linearLayoutManager.scrollToPositionWithOffset(position, RecyclerListView.this.sectionOffset);
                        String newLetter = fastScrollAdapter.getLetter(position);
                        if (newLetter == null) {
                            StaticLayout staticLayout = this.letterLayout;
                            if (staticLayout != null) {
                                this.oldLetterLayout = staticLayout;
                            }
                            this.letterLayout = null;
                            return;
                        }
                        if (!newLetter.equals(this.currentLetter)) {
                            StaticLayout staticLayout2 = new StaticLayout(newLetter, this.letterPaint, 1000, Layout.Alignment.ALIGN_NORMAL, 1.0f, 0.0f, false);
                            this.letterLayout = staticLayout2;
                            this.oldLetterLayout = null;
                            if (staticLayout2.getLineCount() > 0) {
                                this.letterLayout.getLineWidth(0);
                                this.letterLayout.getLineLeft(0);
                                if (LocaleController.isRTL) {
                                    this.textX = (AndroidUtilities.dp(10.0f) + ((AndroidUtilities.dp(88.0f) - this.letterLayout.getLineWidth(0)) / 2.0f)) - this.letterLayout.getLineLeft(0);
                                } else {
                                    this.textX = ((AndroidUtilities.dp(88.0f) - this.letterLayout.getLineWidth(0)) / 2.0f) - this.letterLayout.getLineLeft(0);
                                }
                                this.textY = (AndroidUtilities.dp(88.0f) - this.letterLayout.getHeight()) / 2;
                            }
                        }
                    }
                }
            }
        }

        @Override // android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            setMeasuredDimension(AndroidUtilities.dp(132.0f), View.MeasureSpec.getSize(heightMeasureSpec));
        }

        /* JADX WARN: Removed duplicated region for block: B:19:0x012b  */
        /* JADX WARN: Removed duplicated region for block: B:25:0x013d  */
        /* JADX WARN: Removed duplicated region for block: B:41:0x0199  */
        /* JADX WARN: Removed duplicated region for block: B:43:0x019d  */
        @Override // android.view.View
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        protected void onDraw(android.graphics.Canvas r20) {
            /*
                Method dump skipped, instruction units count: 542
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.components.RecyclerListView.FastScroll.onDraw(android.graphics.Canvas):void");
        }

        @Override // android.view.View
        public void layout(int l, int t, int r, int b) {
            if (!RecyclerListView.this.selfOnLayout) {
                return;
            }
            super.layout(l, t, r, b);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setProgress(float value) {
            this.progress = value;
            invalidate();
        }
    }

    public boolean getLongPressCalled() {
        return this.longPressCalled;
    }

    /* JADX INFO: Access modifiers changed from: private */
    class RecyclerListViewItemClickListener implements RecyclerView.OnItemTouchListener {
        public RecyclerListViewItemClickListener(Context context) {
            RecyclerListView.this.gestureDetector = new GestureDetector(context, new GestureDetector.OnGestureListener() { // from class: im.uwrkaxlmjj.ui.components.RecyclerListView.RecyclerListViewItemClickListener.1
                @Override // android.view.GestureDetector.OnGestureListener
                public boolean onSingleTapUp(MotionEvent e) {
                    if (RecyclerListView.this.currentChildView != null && (RecyclerListView.this.onItemClickListener != null || RecyclerListView.this.onItemClickListenerExtended != null)) {
                        RecyclerListView.this.onChildPressed(RecyclerListView.this.currentChildView, true);
                        final View view = RecyclerListView.this.currentChildView;
                        final int position = RecyclerListView.this.currentChildPosition;
                        final float x = e.getX();
                        final float y = e.getY();
                        if (RecyclerListView.this.instantClick && position != -1) {
                            view.playSoundEffect(0);
                            view.sendAccessibilityEvent(1);
                            if (RecyclerListView.this.onItemClickListener != null) {
                                RecyclerListView.this.onItemClickListener.onItemClick(view, position);
                            } else if (RecyclerListView.this.onItemClickListenerExtended != null) {
                                RecyclerListView.this.onItemClickListenerExtended.onItemClick(view, position, x - view.getX(), y - view.getY());
                            }
                        }
                        AndroidUtilities.runOnUIThread(RecyclerListView.this.clickRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.components.RecyclerListView.RecyclerListViewItemClickListener.1.1
                            @Override // java.lang.Runnable
                            public void run() {
                                if (this == RecyclerListView.this.clickRunnable) {
                                    RecyclerListView.this.clickRunnable = null;
                                }
                                if (view != null) {
                                    RecyclerListView.this.onChildPressed(view, false);
                                    if (!RecyclerListView.this.instantClick) {
                                        view.playSoundEffect(0);
                                        view.sendAccessibilityEvent(1);
                                        if (position != -1) {
                                            if (RecyclerListView.this.onItemClickListener != null) {
                                                RecyclerListView.this.onItemClickListener.onItemClick(view, position);
                                            } else if (RecyclerListView.this.onItemClickListenerExtended != null) {
                                                OnItemClickListenerExtended onItemClickListenerExtended = RecyclerListView.this.onItemClickListenerExtended;
                                                View view2 = view;
                                                onItemClickListenerExtended.onItemClick(view2, position, x - view2.getX(), y - view.getY());
                                            }
                                        }
                                    }
                                }
                            }
                        }, ViewConfiguration.getPressedStateDuration());
                        if (RecyclerListView.this.selectChildRunnable != null) {
                            View pressedChild = RecyclerListView.this.currentChildView;
                            AndroidUtilities.cancelRunOnUIThread(RecyclerListView.this.selectChildRunnable);
                            RecyclerListView.this.selectChildRunnable = null;
                            RecyclerListView.this.currentChildView = null;
                            RecyclerListView.this.interceptedByChild = false;
                            RecyclerListView.this.removeSelection(pressedChild, e);
                        }
                    }
                    return true;
                }

                @Override // android.view.GestureDetector.OnGestureListener
                public void onLongPress(MotionEvent event) {
                    if (RecyclerListView.this.currentChildView != null && RecyclerListView.this.currentChildPosition != -1) {
                        if (RecyclerListView.this.onItemLongClickListener != null || RecyclerListView.this.onItemLongClickListenerExtended != null) {
                            View child = RecyclerListView.this.currentChildView;
                            if (RecyclerListView.this.onItemLongClickListener != null) {
                                if (RecyclerListView.this.onItemLongClickListener.onItemClick(RecyclerListView.this.currentChildView, RecyclerListView.this.currentChildPosition)) {
                                    child.performHapticFeedback(0);
                                    child.sendAccessibilityEvent(2);
                                    return;
                                }
                                return;
                            }
                            if (RecyclerListView.this.onItemLongClickListenerExtended != null && RecyclerListView.this.onItemLongClickListenerExtended.onItemClick(RecyclerListView.this.currentChildView, RecyclerListView.this.currentChildPosition, event.getX() - RecyclerListView.this.currentChildView.getX(), event.getY() - RecyclerListView.this.currentChildView.getY())) {
                                child.performHapticFeedback(0);
                                child.sendAccessibilityEvent(2);
                                RecyclerListView.this.longPressCalled = true;
                            }
                        }
                    }
                }

                @Override // android.view.GestureDetector.OnGestureListener
                public boolean onDown(MotionEvent e) {
                    return false;
                }

                @Override // android.view.GestureDetector.OnGestureListener
                public void onShowPress(MotionEvent e) {
                }

                @Override // android.view.GestureDetector.OnGestureListener
                public boolean onScroll(MotionEvent e1, MotionEvent e2, float distanceX, float distanceY) {
                    return false;
                }

                @Override // android.view.GestureDetector.OnGestureListener
                public boolean onFling(MotionEvent e1, MotionEvent e2, float velocityX, float velocityY) {
                    return false;
                }
            });
            RecyclerListView.this.gestureDetector.setIsLongpressEnabled(false);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.OnItemTouchListener
        public boolean onInterceptTouchEvent(RecyclerView view, MotionEvent event) {
            int action = event.getActionMasked();
            boolean isScrollIdle = RecyclerListView.this.getScrollState() == 0;
            if ((action == 0 || action == 5) && RecyclerListView.this.currentChildView == null && isScrollIdle) {
                float ex = event.getX();
                float ey = event.getY();
                RecyclerListView.this.longPressCalled = false;
                if (RecyclerListView.this.allowSelectChildAtPosition(ex, ey)) {
                    RecyclerListView recyclerListView = RecyclerListView.this;
                    recyclerListView.currentChildView = recyclerListView.findChildViewUnder(ex, ey);
                }
                if (RecyclerListView.this.currentChildView instanceof ViewGroup) {
                    float x = event.getX() - RecyclerListView.this.currentChildView.getLeft();
                    float y = event.getY() - RecyclerListView.this.currentChildView.getTop();
                    ViewGroup viewGroup = (ViewGroup) RecyclerListView.this.currentChildView;
                    int count = viewGroup.getChildCount();
                    int i = count - 1;
                    while (true) {
                        if (i < 0) {
                            break;
                        }
                        View child = viewGroup.getChildAt(i);
                        if (x >= child.getLeft() && x <= child.getRight() && y >= child.getTop() && y <= child.getBottom() && child.isClickable()) {
                            RecyclerListView.this.currentChildView = null;
                            break;
                        }
                        i--;
                    }
                }
                RecyclerListView.this.currentChildPosition = -1;
                if (RecyclerListView.this.currentChildView != null) {
                    RecyclerListView recyclerListView2 = RecyclerListView.this;
                    recyclerListView2.currentChildPosition = view.getChildPosition(recyclerListView2.currentChildView);
                    MotionEvent childEvent = MotionEvent.obtain(0L, 0L, event.getActionMasked(), event.getX() - RecyclerListView.this.currentChildView.getLeft(), event.getY() - RecyclerListView.this.currentChildView.getTop(), 0);
                    if (RecyclerListView.this.currentChildView.onTouchEvent(childEvent)) {
                        RecyclerListView.this.interceptedByChild = true;
                    }
                    childEvent.recycle();
                }
            }
            if (RecyclerListView.this.currentChildView != null && !RecyclerListView.this.interceptedByChild && event != null) {
                try {
                    RecyclerListView.this.gestureDetector.onTouchEvent(event);
                } catch (Exception e) {
                    FileLog.e(e);
                }
            }
            if (action == 0 || action == 5) {
                if (!RecyclerListView.this.interceptedByChild && RecyclerListView.this.currentChildView != null) {
                    RecyclerListView.this.selectChildRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$RecyclerListView$RecyclerListViewItemClickListener$NBzI6gHcrzo8yH0C3TnYVNK6wew
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$onInterceptTouchEvent$0$RecyclerListView$RecyclerListViewItemClickListener();
                        }
                    };
                    AndroidUtilities.runOnUIThread(RecyclerListView.this.selectChildRunnable, ViewConfiguration.getTapTimeout());
                    if (!RecyclerListView.this.currentChildView.isEnabled()) {
                        RecyclerListView.this.selectorRect.setEmpty();
                        return false;
                    }
                    RecyclerListView recyclerListView3 = RecyclerListView.this;
                    recyclerListView3.positionSelector(recyclerListView3.currentChildPosition, RecyclerListView.this.currentChildView);
                    if (RecyclerListView.this.selectorDrawable != null) {
                        Drawable d = RecyclerListView.this.selectorDrawable.getCurrent();
                        if (d instanceof TransitionDrawable) {
                            if (RecyclerListView.this.onItemLongClickListener != null || RecyclerListView.this.onItemClickListenerExtended != null) {
                                ((TransitionDrawable) d).startTransition(ViewConfiguration.getLongPressTimeout());
                            } else {
                                ((TransitionDrawable) d).resetTransition();
                            }
                        }
                        if (Build.VERSION.SDK_INT >= 21) {
                            RecyclerListView.this.selectorDrawable.setHotspot(event.getX(), event.getY());
                        }
                    }
                    RecyclerListView.this.updateSelectorState();
                    return false;
                }
                return false;
            }
            if ((action == 1 || action == 6 || action == 3 || !isScrollIdle) && RecyclerListView.this.currentChildView != null) {
                if (RecyclerListView.this.selectChildRunnable != null) {
                    AndroidUtilities.cancelRunOnUIThread(RecyclerListView.this.selectChildRunnable);
                    RecyclerListView.this.selectChildRunnable = null;
                }
                View pressedChild = RecyclerListView.this.currentChildView;
                RecyclerListView recyclerListView4 = RecyclerListView.this;
                recyclerListView4.onChildPressed(recyclerListView4.currentChildView, false);
                RecyclerListView.this.currentChildView = null;
                RecyclerListView.this.interceptedByChild = false;
                RecyclerListView.this.removeSelection(pressedChild, event);
                if ((action == 1 || action == 6 || action == 3) && RecyclerListView.this.onItemLongClickListenerExtended != null && RecyclerListView.this.longPressCalled) {
                    RecyclerListView.this.onItemLongClickListenerExtended.onLongClickRelease();
                    RecyclerListView.this.longPressCalled = false;
                    return false;
                }
                return false;
            }
            return false;
        }

        public /* synthetic */ void lambda$onInterceptTouchEvent$0$RecyclerListView$RecyclerListViewItemClickListener() {
            if (RecyclerListView.this.selectChildRunnable != null && RecyclerListView.this.currentChildView != null) {
                RecyclerListView recyclerListView = RecyclerListView.this;
                recyclerListView.onChildPressed(recyclerListView.currentChildView, true);
                RecyclerListView.this.selectChildRunnable = null;
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.OnItemTouchListener
        public void onTouchEvent(RecyclerView view, MotionEvent event) {
        }

        @Override // androidx.recyclerview.widget.RecyclerView.OnItemTouchListener
        public void onRequestDisallowInterceptTouchEvent(boolean disallowIntercept) {
            RecyclerListView.this.cancelClickRunnables(true);
        }
    }

    @Override // androidx.recyclerview.widget.RecyclerView
    public View findChildViewUnder(float x, float y) {
        int count = getChildCount();
        int a = 0;
        while (a < 2) {
            for (int i = count - 1; i >= 0; i--) {
                View child = getChildAt(i);
                float translationX = a == 0 ? child.getTranslationX() : 0.0f;
                float translationY = a == 0 ? child.getTranslationY() : 0.0f;
                if (x >= child.getLeft() + translationX && x <= child.getRight() + translationX && y >= child.getTop() + translationY && y <= child.getBottom() + translationY) {
                    return child;
                }
            }
            a++;
        }
        return null;
    }

    public void setDisableHighlightState(boolean value) {
        this.disableHighlightState = value;
    }

    protected View getPressedChildView() {
        return this.currentChildView;
    }

    protected void onChildPressed(View child, boolean pressed) {
        if (this.disableHighlightState) {
            return;
        }
        child.setPressed(pressed);
    }

    protected boolean allowSelectChildAtPosition(float x, float y) {
        return true;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void removeSelection(View pressedChild, MotionEvent event) {
        if (pressedChild == null) {
            return;
        }
        if (pressedChild != null && pressedChild.isEnabled()) {
            positionSelector(this.currentChildPosition, pressedChild);
            Drawable drawable = this.selectorDrawable;
            if (drawable != null) {
                Drawable d = drawable.getCurrent();
                if (d instanceof TransitionDrawable) {
                    ((TransitionDrawable) d).resetTransition();
                }
                if (event != null && Build.VERSION.SDK_INT >= 21) {
                    this.selectorDrawable.setHotspot(event.getX(), event.getY());
                }
            }
        } else {
            this.selectorRect.setEmpty();
        }
        updateSelectorState();
    }

    public void cancelClickRunnables(boolean uncheck) {
        Runnable runnable = this.selectChildRunnable;
        if (runnable != null) {
            AndroidUtilities.cancelRunOnUIThread(runnable);
            this.selectChildRunnable = null;
        }
        View view = this.currentChildView;
        if (view != null) {
            View child = this.currentChildView;
            if (uncheck) {
                onChildPressed(view, false);
            }
            this.currentChildView = null;
            removeSelection(child, null);
        }
        Runnable runnable2 = this.clickRunnable;
        if (runnable2 != null) {
            AndroidUtilities.cancelRunOnUIThread(runnable2);
            this.clickRunnable = null;
        }
        this.interceptedByChild = false;
    }

    public int[] getResourceDeclareStyleableIntArray(String packageName, String name) {
        try {
            Field f = Class.forName(packageName + ".R$styleable").getField(name);
            if (f != null) {
                return (int[]) f.get(null);
            }
        } catch (Throwable th) {
        }
        return null;
    }

    public RecyclerListView(Context context) {
        this(context, null);
    }

    public RecyclerListView(Context context, AttributeSet attrs) {
        this(context, attrs, 0);
    }

    public RecyclerListView(Context context, AttributeSet attrs, int defStyle) {
        super(context, attrs, defStyle);
        this.currentFirst = -1;
        this.currentVisible = -1;
        this.selectorRect = new android.graphics.Rect();
        this.scrollEnabled = true;
        this.observer = new RecyclerView.AdapterDataObserver() { // from class: im.uwrkaxlmjj.ui.components.RecyclerListView.1
            @Override // androidx.recyclerview.widget.RecyclerView.AdapterDataObserver
            public void onChanged() {
                RecyclerListView.this.checkIfEmpty();
                RecyclerListView.this.currentFirst = -1;
                if (RecyclerListView.this.removeHighlighSelectionRunnable == null) {
                    RecyclerListView.this.selectorRect.setEmpty();
                }
                RecyclerListView.this.invalidate();
            }

            @Override // androidx.recyclerview.widget.RecyclerView.AdapterDataObserver
            public void onItemRangeInserted(int positionStart, int itemCount) {
                RecyclerListView.this.checkIfEmpty();
            }

            @Override // androidx.recyclerview.widget.RecyclerView.AdapterDataObserver
            public void onItemRangeRemoved(int positionStart, int itemCount) {
                RecyclerListView.this.checkIfEmpty();
            }
        };
        this.foreIntercept = false;
        setGlowColor(Theme.getColor(Theme.key_actionBarDefault));
        Drawable selectorDrawable = Theme.getSelectorDrawable(false);
        this.selectorDrawable = selectorDrawable;
        selectorDrawable.setCallback(this);
        try {
            if (!gotAttributes) {
                attributes = getResourceDeclareStyleableIntArray("com.android.internal", "View");
                gotAttributes = true;
            }
            TypedArray a = context.getTheme().obtainStyledAttributes(attributes);
            Method initializeScrollbars = View.class.getDeclaredMethod("initializeScrollbars", TypedArray.class);
            initializeScrollbars.invoke(this, a);
            a.recycle();
        } catch (Throwable e) {
            FileLog.e(e);
        }
        super.setOnScrollListener(new RecyclerView.OnScrollListener() { // from class: im.uwrkaxlmjj.ui.components.RecyclerListView.2
            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrollStateChanged(RecyclerView recyclerView, int newState) {
                if (newState != 0 && RecyclerListView.this.currentChildView != null) {
                    if (RecyclerListView.this.selectChildRunnable != null) {
                        AndroidUtilities.cancelRunOnUIThread(RecyclerListView.this.selectChildRunnable);
                        RecyclerListView.this.selectChildRunnable = null;
                    }
                    MotionEvent event = MotionEvent.obtain(0L, 0L, 3, 0.0f, 0.0f, 0);
                    try {
                        RecyclerListView.this.gestureDetector.onTouchEvent(event);
                    } catch (Exception e2) {
                        FileLog.e(e2);
                    }
                    RecyclerListView.this.currentChildView.onTouchEvent(event);
                    event.recycle();
                    View child = RecyclerListView.this.currentChildView;
                    RecyclerListView recyclerListView = RecyclerListView.this;
                    recyclerListView.onChildPressed(recyclerListView.currentChildView, false);
                    RecyclerListView.this.currentChildView = null;
                    RecyclerListView.this.removeSelection(child, null);
                    RecyclerListView.this.interceptedByChild = false;
                }
                if (RecyclerListView.this.onScrollListener != null) {
                    RecyclerListView.this.onScrollListener.onScrollStateChanged(recyclerView, newState);
                }
                RecyclerListView.this.scrollingByUser = newState == 1 || newState == 2;
            }

            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrolled(RecyclerView recyclerView, int dx, int dy) {
                if (RecyclerListView.this.onScrollListener != null) {
                    RecyclerListView.this.onScrollListener.onScrolled(recyclerView, dx, dy);
                }
                if (RecyclerListView.this.selectorPosition != -1) {
                    RecyclerListView.this.selectorRect.offset(-dx, -dy);
                    RecyclerListView.this.selectorDrawable.setBounds(RecyclerListView.this.selectorRect);
                    RecyclerListView.this.invalidate();
                } else {
                    RecyclerListView.this.selectorRect.setEmpty();
                }
                RecyclerListView.this.checkSection();
            }
        });
        addOnItemTouchListener(new RecyclerListViewItemClickListener(context));
    }

    @Override // android.view.View
    public void setVerticalScrollBarEnabled(boolean verticalScrollBarEnabled) {
        if (attributes != null) {
            super.setVerticalScrollBarEnabled(verticalScrollBarEnabled);
        }
    }

    @Override // androidx.recyclerview.widget.RecyclerView, android.view.View
    protected void onMeasure(int widthSpec, int heightSpec) {
        super.onMeasure(widthSpec, heightSpec);
        if (this.fastScroll != null) {
            int height = (getMeasuredHeight() - getPaddingTop()) - getPaddingBottom();
            this.fastScroll.getLayoutParams().height = height;
            this.fastScroll.measure(View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(132.0f), 1073741824), View.MeasureSpec.makeMeasureSpec(height, 1073741824));
        }
    }

    @Override // androidx.recyclerview.widget.RecyclerView, android.view.ViewGroup, android.view.View
    protected void onLayout(boolean changed, int l, int t, int r, int b) {
        super.onLayout(changed, l, t, r, b);
        if (this.fastScroll != null) {
            this.selfOnLayout = true;
            int t2 = t + getPaddingTop();
            if (LocaleController.isRTL) {
                FastScroll fastScroll = this.fastScroll;
                fastScroll.layout(0, t2, fastScroll.getMeasuredWidth(), this.fastScroll.getMeasuredHeight() + t2);
            } else {
                int x = getMeasuredWidth() - this.fastScroll.getMeasuredWidth();
                FastScroll fastScroll2 = this.fastScroll;
                fastScroll2.layout(x, t2, fastScroll2.getMeasuredWidth() + x, this.fastScroll.getMeasuredHeight() + t2);
            }
            this.selfOnLayout = false;
        }
        checkSection();
        IntReturnCallback intReturnCallback = this.pendingHighlightPosition;
        if (intReturnCallback != null) {
            highlightRowInternal(intReturnCallback, false);
        }
    }

    @Override // androidx.recyclerview.widget.RecyclerView, android.view.ViewGroup
    public boolean drawChild(Canvas canvas, View child, long drawingTime) {
        return super.drawChild(canvas, child, drawingTime);
    }

    public void setSelectorDrawableColor(int color) {
        Drawable drawable = this.selectorDrawable;
        if (drawable != null) {
            drawable.setCallback(null);
        }
        Drawable selectorDrawable = Theme.getSelectorDrawable(color, false);
        this.selectorDrawable = selectorDrawable;
        selectorDrawable.setCallback(this);
    }

    public void checkSection() {
        RecyclerView.ViewHolder holder;
        int firstVisibleItem;
        int startSection;
        RecyclerView.ViewHolder holder2;
        int childCount;
        RecyclerView.ViewHolder holder3;
        int lastVisibleItem;
        if ((this.scrollingByUser && this.fastScroll != null) || (this.sectionsType != 0 && this.sectionsAdapter != null)) {
            RecyclerView.LayoutManager layoutManager = getLayoutManager();
            if (layoutManager instanceof LinearLayoutManager) {
                LinearLayoutManager linearLayoutManager = (LinearLayoutManager) layoutManager;
                if (linearLayoutManager.getOrientation() == 1) {
                    if (this.sectionsAdapter != null) {
                        int paddingTop = getPaddingTop();
                        int i = this.sectionsType;
                        if (i != 1) {
                            if (i == 2) {
                                this.pinnedHeaderShadowTargetAlpha = 0.0f;
                                if (this.sectionsAdapter.getItemCount() == 0) {
                                    return;
                                }
                                int childCount2 = getChildCount();
                                int maxBottom = 0;
                                int minBottom = Integer.MAX_VALUE;
                                View minChild = null;
                                int minBottomSection = Integer.MAX_VALUE;
                                View minChildSection = null;
                                for (int a = 0; a < childCount2; a++) {
                                    View child = getChildAt(a);
                                    int bottom = child.getBottom();
                                    if (bottom > this.sectionOffset + paddingTop) {
                                        if (bottom < minBottom) {
                                            minBottom = bottom;
                                            minChild = child;
                                        }
                                        maxBottom = Math.max(maxBottom, bottom);
                                        if (bottom >= this.sectionOffset + paddingTop + AndroidUtilities.dp(32.0f) && bottom < minBottomSection) {
                                            minBottomSection = bottom;
                                            minChildSection = child;
                                        }
                                    }
                                }
                                if (minChild == null || (holder = getChildViewHolder(minChild)) == null || (startSection = this.sectionsAdapter.getSectionForPosition((firstVisibleItem = holder.getAdapterPosition()))) < 0) {
                                    return;
                                }
                                if (this.currentFirst != startSection || this.pinnedHeader == null) {
                                    this.pinnedHeader = getSectionHeaderView(startSection, this.pinnedHeader);
                                    this.currentFirst = startSection;
                                }
                                if (this.pinnedHeader != null && minChildSection != null && minChildSection.getClass() != this.pinnedHeader.getClass()) {
                                    this.pinnedHeaderShadowTargetAlpha = 1.0f;
                                }
                                int count = this.sectionsAdapter.getCountForSection(startSection);
                                int pos = this.sectionsAdapter.getPositionInSectionForPosition(firstVisibleItem);
                                int sectionOffsetY = (maxBottom == 0 || maxBottom >= getMeasuredHeight() - getPaddingBottom()) ? this.sectionOffset : 0;
                                if (pos != count - 1) {
                                    this.pinnedHeader.setTag(Integer.valueOf(paddingTop + sectionOffsetY));
                                } else {
                                    int headerHeight = this.pinnedHeader.getHeight();
                                    int headerTop = paddingTop;
                                    if (minChild != null) {
                                        int top = minChild.getTop() - paddingTop;
                                        int childCount3 = this.sectionOffset;
                                        int available = (top - childCount3) + minChild.getHeight();
                                        if (available < headerHeight) {
                                            headerTop = available - headerHeight;
                                        }
                                    } else {
                                        headerTop = -AndroidUtilities.dp(100.0f);
                                    }
                                    if (headerTop >= 0) {
                                        this.pinnedHeader.setTag(Integer.valueOf(paddingTop + sectionOffsetY));
                                    } else {
                                        this.pinnedHeader.setTag(Integer.valueOf(paddingTop + sectionOffsetY + headerTop));
                                    }
                                }
                                invalidate();
                                return;
                            }
                            return;
                        }
                        int childCount4 = getChildCount();
                        int maxBottom2 = 0;
                        int minBottom2 = Integer.MAX_VALUE;
                        View minChild2 = null;
                        int minBottomSection2 = Integer.MAX_VALUE;
                        for (int a2 = 0; a2 < childCount4; a2++) {
                            View child2 = getChildAt(a2);
                            int bottom2 = child2.getBottom();
                            if (bottom2 > this.sectionOffset + paddingTop) {
                                if (bottom2 < minBottom2) {
                                    minBottom2 = bottom2;
                                    minChild2 = child2;
                                }
                                int maxBottom3 = Math.max(maxBottom2, bottom2);
                                int maxBottom4 = this.sectionOffset;
                                if (bottom2 < maxBottom4 + paddingTop + AndroidUtilities.dp(32.0f) || bottom2 >= minBottomSection2) {
                                    maxBottom2 = maxBottom3;
                                } else {
                                    minBottomSection2 = bottom2;
                                    maxBottom2 = maxBottom3;
                                }
                            }
                        }
                        if (minChild2 == null || (holder2 = getChildViewHolder(minChild2)) == null) {
                            return;
                        }
                        int firstVisibleItem2 = holder2.getAdapterPosition();
                        int lastVisibleItem2 = linearLayoutManager.findLastVisibleItemPosition();
                        int visibleItemCount = Math.abs(lastVisibleItem2 - firstVisibleItem2) + 1;
                        if (this.scrollingByUser && this.fastScroll != null) {
                            RecyclerView.Adapter adapter = getAdapter();
                            if (adapter instanceof FastScrollAdapter) {
                                this.fastScroll.setProgress(Math.min(1.0f, firstVisibleItem2 / ((adapter.getItemCount() - visibleItemCount) + 1)));
                            }
                        }
                        this.headersCache.addAll(this.headers);
                        this.headers.clear();
                        if (this.sectionsAdapter.getItemCount() == 0) {
                            return;
                        }
                        if (this.currentFirst != firstVisibleItem2 || this.currentVisible != visibleItemCount) {
                            this.currentFirst = firstVisibleItem2;
                            this.currentVisible = visibleItemCount;
                            this.sectionsCount = 1;
                            int sectionForPosition = this.sectionsAdapter.getSectionForPosition(firstVisibleItem2);
                            this.startSection = sectionForPosition;
                            int itemNum = (this.sectionsAdapter.getCountForSection(sectionForPosition) + firstVisibleItem2) - this.sectionsAdapter.getPositionInSectionForPosition(firstVisibleItem2);
                            while (itemNum < firstVisibleItem2 + visibleItemCount) {
                                itemNum += this.sectionsAdapter.getCountForSection(this.startSection + this.sectionsCount);
                                this.sectionsCount++;
                            }
                        }
                        int itemNum2 = firstVisibleItem2;
                        int a3 = this.startSection;
                        while (a3 < this.startSection + this.sectionsCount) {
                            View header = null;
                            if (this.headersCache.isEmpty()) {
                                childCount = childCount4;
                            } else {
                                View header2 = this.headersCache.get(0);
                                childCount = childCount4;
                                this.headersCache.remove(0);
                                header = header2;
                            }
                            View header3 = getSectionHeaderView(a3, header);
                            this.headers.add(header3);
                            int count2 = this.sectionsAdapter.getCountForSection(a3);
                            if (a3 == this.startSection) {
                                int pos2 = this.sectionsAdapter.getPositionInSectionForPosition(itemNum2);
                                holder3 = holder2;
                                if (pos2 == count2 - 1) {
                                    header3.setTag(Integer.valueOf((-header3.getHeight()) + paddingTop));
                                    lastVisibleItem = lastVisibleItem2;
                                } else if (pos2 == count2 - 2) {
                                    View child3 = getChildAt(itemNum2 - firstVisibleItem2);
                                    int headerTop2 = child3 != null ? child3.getTop() + paddingTop : -AndroidUtilities.dp(100.0f);
                                    if (headerTop2 < 0) {
                                        lastVisibleItem = lastVisibleItem2;
                                        header3.setTag(Integer.valueOf(headerTop2));
                                    } else {
                                        lastVisibleItem = lastVisibleItem2;
                                        header3.setTag(0);
                                    }
                                } else {
                                    lastVisibleItem = lastVisibleItem2;
                                    header3.setTag(0);
                                }
                                itemNum2 += count2 - this.sectionsAdapter.getPositionInSectionForPosition(firstVisibleItem2);
                            } else {
                                holder3 = holder2;
                                lastVisibleItem = lastVisibleItem2;
                                View child4 = getChildAt(itemNum2 - firstVisibleItem2);
                                if (child4 != null) {
                                    header3.setTag(Integer.valueOf(child4.getTop() + paddingTop));
                                } else {
                                    header3.setTag(Integer.valueOf(-AndroidUtilities.dp(100.0f)));
                                }
                                itemNum2 += count2;
                            }
                            a3++;
                            holder2 = holder3;
                            childCount4 = childCount;
                            lastVisibleItem2 = lastVisibleItem;
                        }
                        return;
                    }
                    int firstVisibleItem3 = linearLayoutManager.findFirstVisibleItemPosition();
                    int visibleItemCount2 = Math.abs(linearLayoutManager.findLastVisibleItemPosition() - firstVisibleItem3) + 1;
                    if (firstVisibleItem3 != -1 && this.scrollingByUser && this.fastScroll != null) {
                        RecyclerView.Adapter adapter2 = getAdapter();
                        if (adapter2 instanceof FastScrollAdapter) {
                            this.fastScroll.setProgress(Math.min(1.0f, firstVisibleItem3 / ((adapter2.getItemCount() - visibleItemCount2) + 1)));
                        }
                    }
                }
            }
        }
    }

    public void setListSelectorColor(int color) {
        Theme.setSelectorDrawableColor(this.selectorDrawable, color, true);
    }

    public void setOnItemClickListener(OnItemClickListener listener) {
        this.onItemClickListener = listener;
    }

    public void setOnItemClickListener(OnItemClickListenerExtended listener) {
        this.onItemClickListenerExtended = listener;
    }

    public OnItemClickListener getOnItemClickListener() {
        return this.onItemClickListener;
    }

    public void setOnItemLongClickListener(OnItemLongClickListener listener) {
        this.onItemLongClickListener = listener;
        this.gestureDetector.setIsLongpressEnabled(listener != null);
    }

    public void setOnItemLongClickListener(OnItemLongClickListenerExtended listener) {
        this.onItemLongClickListenerExtended = listener;
        this.gestureDetector.setIsLongpressEnabled(listener != null);
    }

    public void setEmptyView(View view) {
        if (this.emptyView == view) {
            return;
        }
        this.emptyView = view;
        checkIfEmpty();
    }

    public View getEmptyView() {
        return this.emptyView;
    }

    public void invalidateViews() {
        int count = getChildCount();
        for (int a = 0; a < count; a++) {
            getChildAt(a).invalidate();
        }
    }

    public void updateFastScrollColors() {
        FastScroll fastScroll = this.fastScroll;
        if (fastScroll != null) {
            fastScroll.updateColors();
        }
    }

    public void setPinnedHeaderShadowDrawable(Drawable drawable) {
        this.pinnedHeaderShadowDrawable = drawable;
    }

    @Override // android.view.View
    public boolean canScrollVertically(int direction) {
        return this.scrollEnabled && super.canScrollVertically(direction);
    }

    public void setScrollEnabled(boolean value) {
        this.scrollEnabled = value;
    }

    public void highlightRow(IntReturnCallback callback) {
        highlightRowInternal(callback, true);
    }

    private void highlightRowInternal(IntReturnCallback callback, boolean canHighlightLater) {
        Runnable runnable = this.removeHighlighSelectionRunnable;
        if (runnable != null) {
            AndroidUtilities.cancelRunOnUIThread(runnable);
            this.removeHighlighSelectionRunnable = null;
        }
        RecyclerView.ViewHolder holder = findViewHolderForAdapterPosition(callback.run());
        if (holder != null) {
            positionSelector(holder.getLayoutPosition(), holder.itemView);
            Drawable drawable = this.selectorDrawable;
            if (drawable != null) {
                Drawable d = drawable.getCurrent();
                if (d instanceof TransitionDrawable) {
                    if (this.onItemLongClickListener != null || this.onItemClickListenerExtended != null) {
                        ((TransitionDrawable) d).startTransition(ViewConfiguration.getLongPressTimeout());
                    } else {
                        ((TransitionDrawable) d).resetTransition();
                    }
                }
                if (Build.VERSION.SDK_INT >= 21) {
                    this.selectorDrawable.setHotspot(holder.itemView.getMeasuredWidth() / 2, holder.itemView.getMeasuredHeight() / 2);
                }
            }
            Drawable d2 = this.selectorDrawable;
            if (d2 != null && d2.isStateful() && this.selectorDrawable.setState(getDrawableStateForSelector())) {
                invalidateDrawable(this.selectorDrawable);
            }
            Runnable runnable2 = new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$RecyclerListView$C1Wn73ES0dA5O0naWhhdKJ6iW6Q
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$highlightRowInternal$0$RecyclerListView();
                }
            };
            this.removeHighlighSelectionRunnable = runnable2;
            AndroidUtilities.runOnUIThread(runnable2, 700L);
            return;
        }
        if (canHighlightLater) {
            this.pendingHighlightPosition = callback;
        }
    }

    public /* synthetic */ void lambda$highlightRowInternal$0$RecyclerListView() {
        this.removeHighlighSelectionRunnable = null;
        this.pendingHighlightPosition = null;
        Drawable drawable = this.selectorDrawable;
        if (drawable != null) {
            Drawable d = drawable.getCurrent();
            if (d instanceof TransitionDrawable) {
                ((TransitionDrawable) d).resetTransition();
            }
        }
        Drawable d2 = this.selectorDrawable;
        if (d2 != null && d2.isStateful()) {
            this.selectorDrawable.setState(StateSet.NOTHING);
        }
    }

    public void setForeIntercept(boolean force) {
        this.foreIntercept = false;
    }

    @Override // androidx.recyclerview.widget.RecyclerView, android.view.ViewGroup
    public boolean onInterceptTouchEvent(MotionEvent e) {
        if (!isEnabled() || this.foreIntercept) {
            return false;
        }
        if (this.disallowInterceptTouchEvents) {
            requestDisallowInterceptTouchEvent(true);
        }
        OnInterceptTouchListener onInterceptTouchListener = this.onInterceptTouchListener;
        return (onInterceptTouchListener != null && onInterceptTouchListener.onInterceptTouchEvent(e)) || super.onInterceptTouchEvent(e);
    }

    public void checkIfEmpty() {
        if (getAdapter() == null || this.emptyView == null) {
            if (this.hiddenByEmptyView && getVisibility() != 0) {
                setVisibility(0);
                this.hiddenByEmptyView = false;
                return;
            }
            return;
        }
        boolean emptyViewVisible = getAdapter().getItemCount() == 0;
        this.emptyView.setVisibility(emptyViewVisible ? 0 : 8);
        setVisibility(emptyViewVisible ? 4 : 0);
        this.hiddenByEmptyView = true;
    }

    @Override // android.view.View
    public void setVisibility(int visibility) {
        super.setVisibility(visibility);
        if (visibility != 0) {
            this.hiddenByEmptyView = false;
        }
    }

    @Override // androidx.recyclerview.widget.RecyclerView
    public void setOnScrollListener(RecyclerView.OnScrollListener listener) {
        this.onScrollListener = listener;
    }

    public RecyclerView.OnScrollListener getOnScrollListener() {
        return this.onScrollListener;
    }

    public void setOnInterceptTouchListener(OnInterceptTouchListener listener) {
        this.onInterceptTouchListener = listener;
    }

    public void setInstantClick(boolean value) {
        this.instantClick = value;
    }

    public void setDisallowInterceptTouchEvents(boolean value) {
        this.disallowInterceptTouchEvents = value;
    }

    public void setFastScrollEnabled() {
        this.fastScroll = new FastScroll(getContext());
        if (getParent() != null) {
            ((ViewGroup) getParent()).addView(this.fastScroll);
        }
    }

    public void setFastScrollVisible(boolean value) {
        FastScroll fastScroll = this.fastScroll;
        if (fastScroll == null) {
            return;
        }
        fastScroll.setVisibility(value ? 0 : 8);
    }

    public void setSectionsType(int type) {
        this.sectionsType = type;
        if (type == 1) {
            this.headers = new ArrayList<>();
            this.headersCache = new ArrayList<>();
        }
    }

    public void setPinnedSectionOffsetY(int offset) {
        this.sectionOffset = offset;
        invalidate();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void positionSelector(int position, View sel) {
        positionSelector(position, sel, false, -1.0f, -1.0f);
    }

    private void positionSelector(int position, View sel, boolean manageHotspot, float x, float y) {
        int bottomPadding;
        Runnable runnable = this.removeHighlighSelectionRunnable;
        if (runnable != null) {
            AndroidUtilities.cancelRunOnUIThread(runnable);
            this.removeHighlighSelectionRunnable = null;
            this.pendingHighlightPosition = null;
        }
        if (this.selectorDrawable == null) {
            return;
        }
        boolean positionChanged = position != this.selectorPosition;
        if (getAdapter() instanceof SelectionAdapter) {
            bottomPadding = ((SelectionAdapter) getAdapter()).getSelectionBottomPadding(sel);
        } else {
            bottomPadding = 0;
        }
        if (position != -1) {
            this.selectorPosition = position;
        }
        this.selectorRect.set(sel.getLeft(), sel.getTop(), sel.getRight(), sel.getBottom() - bottomPadding);
        boolean enabled = sel.isEnabled();
        if (this.isChildViewEnabled != enabled) {
            this.isChildViewEnabled = enabled;
        }
        if (positionChanged) {
            this.selectorDrawable.setVisible(false, false);
            this.selectorDrawable.setState(StateSet.NOTHING);
        }
        this.selectorDrawable.setBounds(this.selectorRect);
        if (positionChanged && getVisibility() == 0) {
            this.selectorDrawable.setVisible(true, false);
        }
        if (Build.VERSION.SDK_INT >= 21 && manageHotspot) {
            this.selectorDrawable.setHotspot(x, y);
        }
    }

    public void hideSelector() {
        View view = this.currentChildView;
        if (view != null) {
            View child = this.currentChildView;
            onChildPressed(view, false);
            this.currentChildView = null;
            removeSelection(child, null);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateSelectorState() {
        Drawable drawable = this.selectorDrawable;
        if (drawable != null && drawable.isStateful()) {
            if (this.currentChildView != null) {
                if (this.selectorDrawable.setState(getDrawableStateForSelector())) {
                    invalidateDrawable(this.selectorDrawable);
                }
            } else if (this.removeHighlighSelectionRunnable == null) {
                this.selectorDrawable.setState(StateSet.NOTHING);
            }
        }
    }

    private int[] getDrawableStateForSelector() {
        int[] state = onCreateDrawableState(1);
        state[state.length - 1] = 16842919;
        return state;
    }

    @Override // androidx.recyclerview.widget.RecyclerView
    public void onChildAttachedToWindow(View child) {
        if (getAdapter() instanceof SelectionAdapter) {
            RecyclerView.ViewHolder holder = findContainingViewHolder(child);
            if (holder != null) {
                child.setEnabled(((SelectionAdapter) getAdapter()).isEnabled(holder));
            }
        } else {
            child.setEnabled(false);
        }
        super.onChildAttachedToWindow(child);
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void drawableStateChanged() {
        super.drawableStateChanged();
        updateSelectorState();
    }

    @Override // android.view.View
    public boolean verifyDrawable(Drawable drawable) {
        return this.selectorDrawable == drawable || super.verifyDrawable(drawable);
    }

    @Override // android.view.ViewGroup, android.view.View
    public void jumpDrawablesToCurrentState() {
        super.jumpDrawablesToCurrentState();
        Drawable drawable = this.selectorDrawable;
        if (drawable != null) {
            drawable.jumpToCurrentState();
        }
    }

    @Override // androidx.recyclerview.widget.RecyclerView, android.view.ViewGroup, android.view.View
    protected void onAttachedToWindow() {
        super.onAttachedToWindow();
        FastScroll fastScroll = this.fastScroll;
        if (fastScroll != null && fastScroll.getParent() != getParent()) {
            ViewGroup parent = (ViewGroup) this.fastScroll.getParent();
            if (parent != null) {
                parent.removeView(this.fastScroll);
            }
            ((ViewGroup) getParent()).addView(this.fastScroll);
        }
    }

    @Override // androidx.recyclerview.widget.RecyclerView
    public void setAdapter(RecyclerView.Adapter adapter) {
        RecyclerView.Adapter oldAdapter = getAdapter();
        if (oldAdapter != null) {
            oldAdapter.unregisterAdapterDataObserver(this.observer);
        }
        ArrayList<View> arrayList = this.headers;
        if (arrayList != null) {
            arrayList.clear();
            this.headersCache.clear();
        }
        this.currentFirst = -1;
        this.selectorPosition = -1;
        this.selectorRect.setEmpty();
        this.pinnedHeader = null;
        if (adapter instanceof SectionsAdapter) {
            this.sectionsAdapter = (SectionsAdapter) adapter;
        } else {
            this.sectionsAdapter = null;
        }
        super.setAdapter(adapter);
        if (adapter != null) {
            adapter.registerAdapterDataObserver(this.observer);
        }
        checkIfEmpty();
    }

    @Override // androidx.recyclerview.widget.RecyclerView
    public void stopScroll() {
        try {
            super.stopScroll();
        } catch (NullPointerException e) {
        }
    }

    @Override // androidx.recyclerview.widget.RecyclerView, androidx.core.view.NestedScrollingChild2
    public boolean dispatchNestedPreScroll(int dx, int dy, int[] consumed, int[] offsetInWindow, int type) {
        if (this.longPressCalled) {
            OnItemLongClickListenerExtended onItemLongClickListenerExtended = this.onItemLongClickListenerExtended;
            if (onItemLongClickListenerExtended != null) {
                onItemLongClickListenerExtended.onMove(dx, dy);
            }
            consumed[0] = dx;
            consumed[1] = dy;
            return true;
        }
        return super.dispatchNestedPreScroll(dx, dy, consumed, offsetInWindow, type);
    }

    @Override // android.view.View
    public boolean hasOverlappingRendering() {
        return false;
    }

    private View getSectionHeaderView(int section, View oldView) {
        boolean shouldLayout = oldView == null;
        View view = this.sectionsAdapter.getSectionHeaderView(section, oldView);
        if (shouldLayout) {
            ensurePinnedHeaderLayout(view, false);
        }
        return view;
    }

    private void ensurePinnedHeaderLayout(View header, boolean forceLayout) {
        if (header.isLayoutRequested() || forceLayout) {
            int i = this.sectionsType;
            if (i == 1) {
                ViewGroup.LayoutParams layoutParams = header.getLayoutParams();
                int heightSpec = View.MeasureSpec.makeMeasureSpec(layoutParams.height, 1073741824);
                int widthSpec = View.MeasureSpec.makeMeasureSpec(layoutParams.width, 1073741824);
                try {
                    header.measure(widthSpec, heightSpec);
                } catch (Exception e) {
                    FileLog.e(e);
                }
            } else if (i == 2) {
                int widthSpec2 = View.MeasureSpec.makeMeasureSpec(getMeasuredWidth(), 1073741824);
                int heightSpec2 = View.MeasureSpec.makeMeasureSpec(0, 0);
                try {
                    header.measure(widthSpec2, heightSpec2);
                } catch (Exception e2) {
                    FileLog.e(e2);
                }
            }
            header.layout(0, 0, header.getMeasuredWidth(), header.getMeasuredHeight());
        }
    }

    @Override // androidx.recyclerview.widget.RecyclerView, android.view.View
    protected void onSizeChanged(int w, int h, int oldw, int oldh) {
        View view;
        super.onSizeChanged(w, h, oldw, oldh);
        int i = this.sectionsType;
        if (i == 1) {
            if (this.sectionsAdapter == null || this.headers.isEmpty()) {
                return;
            }
            for (int a = 0; a < this.headers.size(); a++) {
                View header = this.headers.get(a);
                ensurePinnedHeaderLayout(header, true);
            }
            return;
        }
        if (i != 2 || this.sectionsAdapter == null || (view = this.pinnedHeader) == null) {
            return;
        }
        ensurePinnedHeaderLayout(view, true);
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void dispatchDraw(Canvas canvas) {
        super.dispatchDraw(canvas);
        int i = this.sectionsType;
        if (i == 1) {
            if (this.sectionsAdapter == null || this.headers.isEmpty()) {
                return;
            }
            for (int a = 0; a < this.headers.size(); a++) {
                View header = this.headers.get(a);
                int saveCount = canvas.save();
                int top = ((Integer) header.getTag()).intValue();
                canvas.translate(LocaleController.isRTL ? getWidth() - header.getWidth() : 0.0f, top);
                canvas.clipRect(0, 0, getWidth(), header.getMeasuredHeight());
                header.draw(canvas);
                canvas.restoreToCount(saveCount);
            }
        } else if (i == 2) {
            if (this.sectionsAdapter == null || this.pinnedHeader == null) {
                return;
            }
            int saveCount2 = canvas.save();
            int top2 = ((Integer) this.pinnedHeader.getTag()).intValue();
            canvas.translate(LocaleController.isRTL ? getWidth() - this.pinnedHeader.getWidth() : 0.0f, top2);
            Drawable drawable = this.pinnedHeaderShadowDrawable;
            if (drawable != null) {
                drawable.setBounds(0, this.pinnedHeader.getMeasuredHeight(), getWidth(), this.pinnedHeader.getMeasuredHeight() + this.pinnedHeaderShadowDrawable.getIntrinsicHeight());
                this.pinnedHeaderShadowDrawable.setAlpha((int) (this.pinnedHeaderShadowAlpha * 255.0f));
                this.pinnedHeaderShadowDrawable.draw(canvas);
                long newTime = SystemClock.uptimeMillis();
                long dt = Math.min(20L, newTime - this.lastAlphaAnimationTime);
                this.lastAlphaAnimationTime = newTime;
                float f = this.pinnedHeaderShadowAlpha;
                float f2 = this.pinnedHeaderShadowTargetAlpha;
                if (f < f2) {
                    float f3 = f + (dt / 180.0f);
                    this.pinnedHeaderShadowAlpha = f3;
                    if (f3 > f2) {
                        this.pinnedHeaderShadowAlpha = f2;
                    }
                    invalidate();
                } else if (f > f2) {
                    float f4 = f - (dt / 180.0f);
                    this.pinnedHeaderShadowAlpha = f4;
                    if (f4 < f2) {
                        this.pinnedHeaderShadowAlpha = f2;
                    }
                    invalidate();
                }
            }
            canvas.clipRect(0, 0, getWidth(), this.pinnedHeader.getMeasuredHeight());
            this.pinnedHeader.draw(canvas);
            canvas.restoreToCount(saveCount2);
        }
        if (!this.selectorRect.isEmpty()) {
            this.selectorDrawable.setBounds(this.selectorRect);
            this.selectorDrawable.draw(canvas);
        }
    }

    @Override // androidx.recyclerview.widget.RecyclerView, android.view.ViewGroup, android.view.View
    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        this.selectorPosition = -1;
        this.selectorRect.setEmpty();
    }

    public ArrayList<View> getHeaders() {
        return this.headers;
    }

    public ArrayList<View> getHeadersCache() {
        return this.headersCache;
    }

    public View getPinnedHeader() {
        return this.pinnedHeader;
    }
}
