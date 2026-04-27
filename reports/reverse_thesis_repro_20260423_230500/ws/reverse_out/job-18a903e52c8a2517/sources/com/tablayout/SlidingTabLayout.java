package com.tablayout;

import android.R;
import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.Rect;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.os.Parcelable;
import android.util.AttributeSet;
import android.util.SparseArray;
import android.view.View;
import android.view.ViewGroup;
import android.widget.HorizontalScrollView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentActivity;
import androidx.fragment.app.FragmentManager;
import androidx.fragment.app.FragmentPagerAdapter;
import androidx.viewpager.widget.ViewPager;
import com.tablayout.listener.OnTabReleaseListener;
import com.tablayout.listener.OnTabSelectListener;
import com.tablayout.utils.UnreadMsgUtils;
import com.tablayout.widget.MsgView;
import java.util.ArrayList;
import java.util.Collections;

/* JADX INFO: loaded from: classes2.dex */
public class SlidingTabLayout extends HorizontalScrollView implements ViewPager.OnPageChangeListener {
    private static final int STYLE_BLOCK = 2;
    private static final int STYLE_NORMAL = 0;
    private static final int STYLE_TRIANGLE = 1;
    private static final int TEXT_BOLD_BOTH = 2;
    private static final int TEXT_BOLD_NONE = 0;
    private static final int TEXT_BOLD_WHEN_SELECT = 1;
    private Context mContext;
    private float mCurrentPositionOffset;
    private int mCurrentTab;
    private int mDividerColor;
    private float mDividerPadding;
    private Paint mDividerPaint;
    private float mDividerWidth;
    private int mEndIndicatorColor;
    private int mHeight;
    private int mIndicatorColor;
    private float mIndicatorCornerRadius;
    private GradientDrawable mIndicatorDrawable;
    private int mIndicatorGravity;
    private float mIndicatorHeight;
    private float mIndicatorMarginBottom;
    private float mIndicatorMarginLeft;
    private float mIndicatorMarginRight;
    private float mIndicatorMarginTop;
    private Rect mIndicatorRect;
    private int mIndicatorStyle;
    private float mIndicatorWidth;
    private boolean mIndicatorWidthEqualTitle;
    private SparseArray<Boolean> mInitSetMap;
    private int mLastScrollX;
    private OnTabSelectListener mListener;
    private int mMsgViewBackgroundColor;
    private int mMsgViewWidth;
    private Paint mRectPaint;
    private OnTabReleaseListener mReleaseListener;
    private boolean mSnapOnTabClick;
    private int mTabCount;
    private float mTabPadding;
    private float mTabPaddingBottom;
    private float mTabPaddingTop;
    private Rect mTabRect;
    private boolean mTabSpaceEqual;
    private float mTabWidth;
    private LinearLayout mTabsContainer;
    private boolean mTextAllCaps;
    private int mTextBold;
    private Paint mTextPaint;
    private int mTextSelectColor;
    private float mTextSelectSize;
    private int mTextUnselectColor;
    private float mTextsize;
    private ArrayList<String> mTitles;
    private Paint mTrianglePaint;
    private Path mTrianglePath;
    private int mUnderlineColor;
    private int mUnderlineGravity;
    private float mUnderlineHeight;
    private ViewPager mViewPager;
    private float margin;
    private int prevTab;

    public SlidingTabLayout(Context context) {
        this(context, null, 0);
    }

    public SlidingTabLayout(Context context, AttributeSet attrs) {
        this(context, attrs, 0);
    }

    public SlidingTabLayout(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        this.mIndicatorRect = new Rect();
        this.mTabRect = new Rect();
        this.mIndicatorDrawable = new GradientDrawable(GradientDrawable.Orientation.LEFT_RIGHT, null);
        this.mRectPaint = new Paint(1);
        this.mDividerPaint = new Paint(1);
        this.mTrianglePaint = new Paint(1);
        this.mTrianglePath = new Path();
        this.mIndicatorStyle = 0;
        this.mTabWidth = -1.0f;
        this.prevTab = -1;
        this.mTextPaint = new Paint(1);
        this.mInitSetMap = new SparseArray<>();
        setFillViewport(true);
        setWillNotDraw(false);
        setClipChildren(false);
        setClipToPadding(false);
        this.mContext = context;
        LinearLayout linearLayout = new LinearLayout(context);
        this.mTabsContainer = linearLayout;
        addView(linearLayout);
        if (attrs != null) {
            obtainAttributes(context, attrs);
            String height = attrs.getAttributeValue("http://schemas.android.com/apk/res/android", "layout_height");
            if (!height.equals("-1") && !height.equals("-2")) {
                int[] systemAttrs = {R.attr.layout_height};
                TypedArray a = context.obtainStyledAttributes(attrs, systemAttrs);
                this.mHeight = a.getDimensionPixelSize(0, -2);
                a.recycle();
            }
        }
    }

    private void obtainAttributes(Context context, AttributeSet attrs) {
        float f;
        TypedArray ta = context.obtainStyledAttributes(attrs, im.uwrkaxlmjj.messenger.R.styleable.SlidingTabLayout);
        int i = ta.getInt(12, 0);
        this.mIndicatorStyle = i;
        this.mIndicatorColor = ta.getColor(3, Color.parseColor(i == 2 ? "#4B6A87" : "#ffffff"));
        this.mEndIndicatorColor = ta.getColor(5, this.mIndicatorStyle == 2 ? Color.parseColor("#4B6A87") : 0);
        int i2 = this.mIndicatorStyle;
        if (i2 == 1) {
            f = 4.0f;
        } else {
            f = i2 == 2 ? -1 : 2;
        }
        this.mIndicatorHeight = ta.getDimension(7, dp2px(f));
        this.mIndicatorWidth = ta.getDimension(13, dp2px(this.mIndicatorStyle == 1 ? 10.0f : -1.0f));
        this.mIndicatorCornerRadius = ta.getDimension(4, dp2px(this.mIndicatorStyle == 2 ? -1.0f : 0.0f));
        this.mIndicatorMarginLeft = ta.getDimension(9, dp2px(0.0f));
        this.mIndicatorMarginTop = ta.getDimension(11, dp2px(this.mIndicatorStyle == 2 ? 7.0f : 0.0f));
        this.mIndicatorMarginRight = ta.getDimension(10, dp2px(0.0f));
        this.mIndicatorMarginBottom = ta.getDimension(8, dp2px(this.mIndicatorStyle != 2 ? 0.0f : 7.0f));
        this.mIndicatorGravity = ta.getInt(6, 80);
        this.mIndicatorWidthEqualTitle = ta.getBoolean(14, false);
        this.mUnderlineColor = ta.getColor(24, Color.parseColor("#ffffff"));
        this.mUnderlineHeight = ta.getDimension(26, dp2px(0.0f));
        this.mUnderlineGravity = ta.getInt(25, 80);
        this.mDividerColor = ta.getColor(0, Color.parseColor("#ffffff"));
        this.mDividerWidth = ta.getDimension(2, dp2px(0.0f));
        this.mDividerPadding = ta.getDimension(1, dp2px(12.0f));
        this.mTextsize = ta.getDimension(20, sp2px(14.0f));
        this.mTextSelectSize = ta.getDimension(22, 0.0f);
        this.mTextSelectColor = ta.getColor(21, Color.parseColor("#ffffff"));
        this.mTextUnselectColor = ta.getColor(23, Color.parseColor("#AAffffff"));
        this.mTextBold = ta.getInt(19, 0);
        this.mTextAllCaps = ta.getBoolean(18, false);
        this.mTabSpaceEqual = ta.getBoolean(16, false);
        float dimension = ta.getDimension(17, dp2px(-1.0f));
        this.mTabWidth = dimension;
        this.mTabPadding = ta.getDimension(15, (this.mTabSpaceEqual || dimension > 0.0f) ? dp2px(0.0f) : dp2px(20.0f));
        ta.recycle();
    }

    public void setViewPager(ViewPager vp) {
        if (vp == null || vp.getAdapter() == null) {
            throw new IllegalStateException("ViewPager or ViewPager adapter can not be NULL !");
        }
        this.mViewPager = vp;
        vp.removeOnPageChangeListener(this);
        this.mViewPager.addOnPageChangeListener(this);
        notifyDataSetChanged();
    }

    public void setViewPager(ViewPager vp, String[] titles) {
        if (vp == null || vp.getAdapter() == null) {
            throw new IllegalStateException("ViewPager or ViewPager adapter can not be NULL !");
        }
        if (titles == null || titles.length == 0) {
            throw new IllegalStateException("Titles can not be EMPTY !");
        }
        if (titles.length != vp.getAdapter().getCount()) {
            throw new IllegalStateException("Titles length must be the same as the page count !");
        }
        this.mViewPager = vp;
        ArrayList<String> arrayList = new ArrayList<>();
        this.mTitles = arrayList;
        Collections.addAll(arrayList, titles);
        this.mViewPager.removeOnPageChangeListener(this);
        this.mViewPager.addOnPageChangeListener(this);
        notifyDataSetChanged();
    }

    public void setViewPager(ViewPager vp, String[] titles, FragmentActivity fa, ArrayList<Fragment> fragments) {
        if (vp == null) {
            throw new IllegalStateException("ViewPager can not be NULL !");
        }
        if (titles == null || titles.length == 0) {
            throw new IllegalStateException("Titles can not be EMPTY !");
        }
        this.mViewPager = vp;
        vp.setAdapter(new InnerPagerAdapter(fa.getSupportFragmentManager(), fragments, titles));
        this.mViewPager.removeOnPageChangeListener(this);
        this.mViewPager.addOnPageChangeListener(this);
        notifyDataSetChanged();
    }

    public void notifyDataSetChanged() {
        this.mTabsContainer.removeAllViews();
        ArrayList<String> arrayList = this.mTitles;
        this.mTabCount = arrayList == null ? this.mViewPager.getAdapter().getCount() : arrayList.size();
        for (int i = 0; i < this.mTabCount; i++) {
            View tabView = View.inflate(this.mContext, mpEIGo.juqQQs.esbSDO.R.layout.layout_tab, null);
            ArrayList<String> arrayList2 = this.mTitles;
            String pageTitle = arrayList2 == null ? this.mViewPager.getAdapter().getPageTitle(i) : arrayList2.get(i);
            addTab(i, pageTitle.toString(), tabView);
        }
        updateTabStyles();
    }

    public void addNewTab(String title) {
        View tabView = View.inflate(this.mContext, mpEIGo.juqQQs.esbSDO.R.layout.layout_tab, null);
        ArrayList<String> arrayList = this.mTitles;
        if (arrayList != null) {
            arrayList.add(title);
        }
        ArrayList<String> arrayList2 = this.mTitles;
        String pageTitle = arrayList2 == null ? this.mViewPager.getAdapter().getPageTitle(this.mTabCount) : arrayList2.get(this.mTabCount);
        addTab(this.mTabCount, pageTitle.toString(), tabView);
        ArrayList<String> arrayList3 = this.mTitles;
        this.mTabCount = arrayList3 == null ? this.mViewPager.getAdapter().getCount() : arrayList3.size();
        updateTabStyles();
    }

    private void addTab(int position, String title, View tabView) {
        TextView tv_tab_title = (TextView) tabView.findViewById(mpEIGo.juqQQs.esbSDO.R.attr.tv_tab_title);
        if (tv_tab_title != null && title != null) {
            tv_tab_title.setText(title);
        }
        tabView.setOnClickListener(new View.OnClickListener() { // from class: com.tablayout.SlidingTabLayout.1
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                int position2 = SlidingTabLayout.this.mTabsContainer.indexOfChild(v);
                if (position2 != -1) {
                    if (SlidingTabLayout.this.mViewPager.getCurrentItem() != position2) {
                        if (SlidingTabLayout.this.mReleaseListener != null) {
                            SlidingTabLayout.this.mReleaseListener.onTabRelease(SlidingTabLayout.this.mViewPager.getCurrentItem(), false);
                        }
                        if (SlidingTabLayout.this.mSnapOnTabClick) {
                            SlidingTabLayout.this.mViewPager.setCurrentItem(position2, false);
                        } else {
                            SlidingTabLayout.this.mViewPager.setCurrentItem(position2);
                        }
                        if (SlidingTabLayout.this.mListener != null) {
                            SlidingTabLayout.this.mListener.onTabSelect(position2);
                            return;
                        }
                        return;
                    }
                    if (SlidingTabLayout.this.mListener != null) {
                        SlidingTabLayout.this.mListener.onTabReselect(position2);
                    }
                }
            }
        });
        MsgView msgView = (MsgView) tabView.findViewById(mpEIGo.juqQQs.esbSDO.R.attr.rtv_msg_tip);
        if (msgView != null) {
            int i = this.mMsgViewBackgroundColor;
            if (i != 0) {
                msgView.setBackgroundColor(i);
            }
            int i2 = this.mMsgViewWidth;
            if (i2 != 0) {
                msgView.setWidth(i2);
            }
        }
        LinearLayout.LayoutParams lp_tab = this.mTabSpaceEqual ? new LinearLayout.LayoutParams(0, -1, 1.0f) : new LinearLayout.LayoutParams(-2, -1);
        if (this.mTabWidth > 0.0f) {
            lp_tab = new LinearLayout.LayoutParams((int) this.mTabWidth, -1);
        }
        this.mTabsContainer.addView(tabView, position, lp_tab);
    }

    /* JADX WARN: Removed duplicated region for block: B:15:0x002d  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private void updateTabStyles() {
        /*
            r8 = this;
            r0 = 0
        L1:
            int r1 = r8.mTabCount
            if (r0 >= r1) goto L7d
            android.widget.LinearLayout r1 = r8.mTabsContainer
            android.view.View r1 = r1.getChildAt(r0)
            r2 = 2131297842(0x7f090632, float:1.821364E38)
            android.view.View r2 = r1.findViewById(r2)
            android.widget.TextView r2 = (android.widget.TextView) r2
            if (r2 == 0) goto L7a
            int r3 = r8.mCurrentTab
            if (r0 != r3) goto L1d
            int r3 = r8.mTextSelectColor
            goto L1f
        L1d:
            int r3 = r8.mTextUnselectColor
        L1f:
            r2.setTextColor(r3)
            int r3 = r8.mCurrentTab
            if (r0 != r3) goto L2d
            float r3 = r8.mTextSelectSize
            r4 = 0
            int r4 = (r3 > r4 ? 1 : (r3 == r4 ? 0 : -1))
            if (r4 != 0) goto L2f
        L2d:
            float r3 = r8.mTextsize
        L2f:
            r4 = 0
            r2.setTextSize(r4, r3)
            float r3 = r8.mTabPadding
            int r5 = (int) r3
            float r6 = r8.mTabPaddingTop
            int r6 = (int) r6
            int r3 = (int) r3
            float r7 = r8.mTabPaddingBottom
            int r7 = (int) r7
            r2.setPadding(r5, r6, r3, r7)
            boolean r3 = r8.mTextAllCaps
            if (r3 == 0) goto L53
            java.lang.CharSequence r3 = r2.getText()
            java.lang.String r3 = r3.toString()
            java.lang.String r3 = r3.toUpperCase()
            r2.setText(r3)
        L53:
            int r3 = r8.mTextBold
            r5 = 2
            r6 = 1
            if (r3 != r5) goto L61
            android.text.TextPaint r3 = r2.getPaint()
            r3.setFakeBoldText(r6)
            goto L7a
        L61:
            if (r3 != r6) goto L6f
            int r3 = r8.mCurrentTab
            if (r0 != r3) goto L6f
            android.text.TextPaint r3 = r2.getPaint()
            r3.setFakeBoldText(r6)
            goto L7a
        L6f:
            int r3 = r8.mTextBold
            if (r3 != 0) goto L7a
            android.text.TextPaint r3 = r2.getPaint()
            r3.setFakeBoldText(r4)
        L7a:
            int r0 = r0 + 1
            goto L1
        L7d:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.tablayout.SlidingTabLayout.updateTabStyles():void");
    }

    @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
    public void onPageScrolled(int position, float positionOffset, int positionOffsetPixels) {
        this.mCurrentTab = position;
        this.mCurrentPositionOffset = positionOffset;
        scrollToCurrentTab();
        invalidate();
    }

    @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
    public void onPageSelected(int position) {
        updateTabSelection(position);
    }

    @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
    public void onPageScrollStateChanged(int state) {
    }

    private void scrollToCurrentTab() {
        if (this.mTabCount <= 0) {
            return;
        }
        int offset = (int) (this.mCurrentPositionOffset * this.mTabsContainer.getChildAt(this.mCurrentTab).getWidth());
        int newScrollX = this.mTabsContainer.getChildAt(this.mCurrentTab).getLeft() + offset;
        if (this.mCurrentTab > 0 || offset > 0) {
            int newScrollX2 = newScrollX - ((getWidth() / 2) - getPaddingLeft());
            calcIndicatorRect();
            newScrollX = newScrollX2 + ((this.mTabRect.right - this.mTabRect.left) / 2);
        }
        if (newScrollX != this.mLastScrollX) {
            this.mLastScrollX = newScrollX;
            scrollTo(newScrollX, 0);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:15:0x0026  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private void updateTabSelection(int r12) {
        /*
            r11 = this;
            r0 = 0
        L1:
            int r1 = r11.mTabCount
            if (r0 >= r1) goto Laf
            android.widget.LinearLayout r1 = r11.mTabsContainer
            android.view.View r1 = r1.getChildAt(r0)
            r2 = 1
            r3 = 0
            if (r0 != r12) goto L11
            r4 = 1
            goto L12
        L11:
            r4 = 0
        L12:
            r5 = 2131297842(0x7f090632, float:1.821364E38)
            android.view.View r5 = r1.findViewById(r5)
            android.widget.TextView r5 = (android.widget.TextView) r5
            if (r5 == 0) goto Lab
            r6 = 0
            if (r4 == 0) goto L26
            float r7 = r11.mTextSelectSize
            int r8 = (r7 > r6 ? 1 : (r7 == r6 ? 0 : -1))
            if (r8 != 0) goto L28
        L26:
            float r7 = r11.mTextsize
        L28:
            r5.setTextSize(r3, r7)
            if (r4 == 0) goto L30
            int r7 = r11.mTextSelectColor
            goto L32
        L30:
            int r7 = r11.mTextUnselectColor
        L32:
            r5.setTextColor(r7)
            int r7 = r11.mTextBold
            if (r7 != r2) goto L40
            android.text.TextPaint r2 = r5.getPaint()
            r2.setFakeBoldText(r4)
        L40:
            com.tablayout.listener.OnTabReleaseListener r2 = r11.mReleaseListener
            if (r2 == 0) goto L47
            r2.onTabRelease(r0, r4)
        L47:
            r2 = 2131297227(0x7f0903cb, float:1.8212393E38)
            android.view.View r2 = r1.findViewById(r2)
            com.tablayout.widget.MsgView r2 = (com.tablayout.widget.MsgView) r2
            if (r2 == 0) goto Lab
            int r7 = r2.getVisibility()
            if (r7 != 0) goto Lab
            android.graphics.Paint r7 = r11.mTextPaint
            float r8 = r5.getTextSize()
            r7.setTextSize(r8)
            android.graphics.Paint r7 = r11.mTextPaint
            java.lang.CharSequence r8 = r5.getText()
            java.lang.String r8 = r8.toString()
            float r7 = r7.measureText(r8)
            android.graphics.Paint r8 = r11.mTextPaint
            float r8 = r8.descent()
            android.graphics.Paint r9 = r11.mTextPaint
            float r9 = r9.ascent()
            float r8 = r8 - r9
            android.view.ViewGroup$LayoutParams r9 = r2.getLayoutParams()
            android.view.ViewGroup$MarginLayoutParams r9 = (android.view.ViewGroup.MarginLayoutParams) r9
            float r10 = r11.mTabWidth
            int r6 = (r10 > r6 ? 1 : (r10 == r6 ? 0 : -1))
            if (r6 < 0) goto L90
            r6 = 1073741824(0x40000000, float:2.0)
            float r10 = r10 / r6
            float r6 = r7 / r6
            float r10 = r10 + r6
            int r6 = (int) r10
            goto L94
        L90:
            float r6 = r11.mTabPadding
            float r6 = r6 + r7
            int r6 = (int) r6
        L94:
            r9.leftMargin = r6
            int r6 = r11.mHeight
            if (r6 <= 0) goto La6
            float r3 = (float) r6
            float r3 = r3 - r8
            int r3 = (int) r3
            int r3 = r3 / 2
            r6 = 1065353216(0x3f800000, float:1.0)
            int r6 = r11.dp2px(r6)
            int r3 = r3 - r6
        La6:
            r9.topMargin = r3
            r2.setLayoutParams(r9)
        Lab:
            int r0 = r0 + 1
            goto L1
        Laf:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.tablayout.SlidingTabLayout.updateTabSelection(int):void");
    }

    private void calcIndicatorRect() {
        View currentTabView = this.mTabsContainer.getChildAt(this.mCurrentTab);
        float left = currentTabView.getLeft();
        float right = currentTabView.getRight();
        if (this.mIndicatorStyle == 0 && this.mIndicatorWidthEqualTitle) {
            TextView tab_title = (TextView) currentTabView.findViewById(mpEIGo.juqQQs.esbSDO.R.attr.tv_tab_title);
            this.mTextPaint.setTextSize(this.mTextsize);
            float textWidth = this.mTextPaint.measureText(tab_title.getText().toString());
            this.margin = ((right - left) - textWidth) / 2.0f;
        }
        int i = this.mCurrentTab;
        if (i < this.mTabCount - 1) {
            View nextTabView = this.mTabsContainer.getChildAt(i + 1);
            float nextTabLeft = nextTabView.getLeft();
            float nextTabRight = nextTabView.getRight();
            float f = this.mCurrentPositionOffset;
            left += (nextTabLeft - left) * f;
            right += f * (nextTabRight - right);
            if (this.mIndicatorStyle == 0 && this.mIndicatorWidthEqualTitle) {
                TextView next_tab_title = (TextView) nextTabView.findViewById(mpEIGo.juqQQs.esbSDO.R.attr.tv_tab_title);
                this.mTextPaint.setTextSize(this.mTextsize);
                float nextTextWidth = this.mTextPaint.measureText(next_tab_title.getText().toString());
                float nextMargin = ((nextTabRight - nextTabLeft) - nextTextWidth) / 2.0f;
                float f2 = this.margin;
                this.margin = f2 + (this.mCurrentPositionOffset * (nextMargin - f2));
            }
        }
        this.mIndicatorRect.left = (int) left;
        this.mIndicatorRect.right = (int) right;
        if (this.mIndicatorStyle == 0 && this.mIndicatorWidthEqualTitle) {
            this.mIndicatorRect.left = (int) ((this.margin + left) - 1.0f);
            this.mIndicatorRect.right = (int) ((right - this.margin) - 1.0f);
        }
        this.mTabRect.left = (int) left;
        this.mTabRect.right = (int) right;
        if (this.mIndicatorWidth >= 0.0f) {
            float indicatorLeft = currentTabView.getLeft() + ((currentTabView.getWidth() - this.mIndicatorWidth) / 2.0f);
            int i2 = this.mCurrentTab;
            if (i2 < this.mTabCount - 1) {
                View nextTab = this.mTabsContainer.getChildAt(i2 + 1);
                indicatorLeft += this.mCurrentPositionOffset * ((currentTabView.getWidth() / 2) + (nextTab.getWidth() / 2));
            }
            this.mIndicatorRect.left = (int) indicatorLeft;
            this.mIndicatorRect.right = (int) (r4.left + this.mIndicatorWidth);
        }
    }

    @Override // android.view.View
    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        if (isInEditMode() || this.mTabCount <= 0) {
            return;
        }
        int height = getHeight();
        int paddingLeft = getPaddingLeft();
        float f = this.mDividerWidth;
        if (f > 0.0f) {
            this.mDividerPaint.setStrokeWidth(f);
            this.mDividerPaint.setColor(this.mDividerColor);
            for (int i = 0; i < this.mTabCount - 1; i++) {
                View tab = this.mTabsContainer.getChildAt(i);
                canvas.drawLine(tab.getRight() + paddingLeft, this.mDividerPadding, tab.getRight() + paddingLeft, height - this.mDividerPadding, this.mDividerPaint);
            }
        }
        if (this.mUnderlineHeight > 0.0f) {
            this.mRectPaint.setColor(this.mUnderlineColor);
            if (this.mUnderlineGravity == 80) {
                canvas.drawRect(paddingLeft, height - this.mUnderlineHeight, this.mTabsContainer.getWidth() + paddingLeft, height, this.mRectPaint);
            } else {
                canvas.drawRect(paddingLeft, 0.0f, this.mTabsContainer.getWidth() + paddingLeft, this.mUnderlineHeight, this.mRectPaint);
            }
        }
        calcIndicatorRect();
        int i2 = this.mIndicatorStyle;
        if (i2 == 1) {
            if (this.mIndicatorHeight > 0.0f) {
                this.mTrianglePaint.setColor(this.mIndicatorColor);
                this.mTrianglePath.reset();
                this.mTrianglePath.moveTo(this.mIndicatorRect.left + paddingLeft, height);
                this.mTrianglePath.lineTo((this.mIndicatorRect.left / 2) + paddingLeft + (this.mIndicatorRect.right / 2), height - this.mIndicatorHeight);
                this.mTrianglePath.lineTo(this.mIndicatorRect.right + paddingLeft, height);
                this.mTrianglePath.close();
                canvas.drawPath(this.mTrianglePath, this.mTrianglePaint);
                return;
            }
            return;
        }
        if (i2 != 2) {
            if (this.mIndicatorHeight > 0.0f) {
                this.mIndicatorDrawable.setCornerRadius(this.mIndicatorCornerRadius);
                if (this.mEndIndicatorColor != 0) {
                    this.mIndicatorDrawable.setGradientType(0);
                    this.mIndicatorDrawable.setColors(new int[]{this.mIndicatorColor, this.mEndIndicatorColor});
                } else {
                    this.mIndicatorDrawable.setColor(this.mIndicatorColor);
                }
                if (this.mIndicatorGravity == 80) {
                    this.mIndicatorDrawable.setBounds(((int) this.mIndicatorMarginLeft) + paddingLeft + this.mIndicatorRect.left, (height - ((int) this.mIndicatorHeight)) - ((int) this.mIndicatorMarginBottom), (this.mIndicatorRect.right + paddingLeft) - ((int) this.mIndicatorMarginRight), height - ((int) this.mIndicatorMarginBottom));
                } else {
                    this.mIndicatorDrawable.setBounds(((int) this.mIndicatorMarginLeft) + paddingLeft + this.mIndicatorRect.left, (int) this.mIndicatorMarginTop, (this.mIndicatorRect.right + paddingLeft) - ((int) this.mIndicatorMarginRight), ((int) this.mIndicatorHeight) + ((int) this.mIndicatorMarginTop));
                }
                this.mIndicatorDrawable.draw(canvas);
                return;
            }
            return;
        }
        if (this.mIndicatorHeight < 0.0f) {
            this.mIndicatorHeight = (height - this.mIndicatorMarginTop) - this.mIndicatorMarginBottom;
        }
        float f2 = this.mIndicatorHeight;
        if (f2 > 0.0f) {
            float f3 = this.mIndicatorCornerRadius;
            if (f3 < 0.0f || f3 > f2 / 2.0f) {
                this.mIndicatorCornerRadius = this.mIndicatorHeight / 2.0f;
            }
            if (this.mEndIndicatorColor != 0) {
                this.mIndicatorDrawable.setGradientType(0);
                this.mIndicatorDrawable.setColors(new int[]{this.mIndicatorColor, this.mEndIndicatorColor});
            } else {
                this.mIndicatorDrawable.setColor(this.mIndicatorColor);
            }
            this.mIndicatorDrawable.setBounds(((int) this.mIndicatorMarginLeft) + paddingLeft + this.mIndicatorRect.left, (int) this.mIndicatorMarginTop, (int) ((this.mIndicatorRect.right + paddingLeft) - this.mIndicatorMarginRight), (int) (this.mIndicatorMarginTop + this.mIndicatorHeight));
            this.mIndicatorDrawable.setCornerRadius(this.mIndicatorCornerRadius);
            this.mIndicatorDrawable.draw(canvas);
        }
    }

    public void setCurrentTab(int currentTab) {
        this.mCurrentTab = currentTab;
        this.mViewPager.setCurrentItem(currentTab);
    }

    public void setCurrentTab(int currentTab, boolean smoothScroll) {
        this.mCurrentTab = currentTab;
        this.mViewPager.setCurrentItem(currentTab, smoothScroll);
    }

    public void setIndicatorStyle(int indicatorStyle) {
        this.mIndicatorStyle = indicatorStyle;
        invalidate();
    }

    public void setTabPadding(float tabPadding) {
        this.mTabPadding = dp2px(tabPadding);
        updateTabStyles();
    }

    public void setmTabPaddingBottom(float tabPadding) {
        this.mTabPaddingBottom = dp2px(tabPadding);
        updateTabStyles();
    }

    public void setmTabPaddingTop(float tabPadding) {
        this.mTabPaddingTop = dp2px(tabPadding);
        updateTabStyles();
    }

    public void setTabSpaceEqual(boolean tabSpaceEqual) {
        this.mTabSpaceEqual = tabSpaceEqual;
        updateTabStyles();
    }

    public void setTabWidth(float tabWidth) {
        this.mTabWidth = dp2px(tabWidth);
        updateTabStyles();
    }

    public void setIndicatorColor(int indicatorColor) {
        this.mIndicatorColor = indicatorColor;
        invalidate();
    }

    public void setIndicatorEndColor(int indicatorColor) {
        this.mEndIndicatorColor = indicatorColor;
        invalidate();
    }

    public void setIndicatorHeight(float indicatorHeight) {
        this.mIndicatorHeight = dp2px(indicatorHeight);
        invalidate();
    }

    public void setIndicatorWidth(float indicatorWidth) {
        this.mIndicatorWidth = dp2px(indicatorWidth);
        invalidate();
    }

    public void setIndicatorCornerRadius(float indicatorCornerRadius) {
        this.mIndicatorCornerRadius = dp2px(indicatorCornerRadius);
        invalidate();
    }

    public void setIndicatorGravity(int indicatorGravity) {
        this.mIndicatorGravity = indicatorGravity;
        invalidate();
    }

    public void setIndicatorMargin(float indicatorMarginLeft, float indicatorMarginTop, float indicatorMarginRight, float indicatorMarginBottom) {
        this.mIndicatorMarginLeft = dp2px(indicatorMarginLeft);
        this.mIndicatorMarginTop = dp2px(indicatorMarginTop);
        this.mIndicatorMarginRight = dp2px(indicatorMarginRight);
        this.mIndicatorMarginBottom = dp2px(indicatorMarginBottom);
        invalidate();
    }

    public void setIndicatorWidthEqualTitle(boolean indicatorWidthEqualTitle) {
        this.mIndicatorWidthEqualTitle = indicatorWidthEqualTitle;
        invalidate();
    }

    public void setUnderlineColor(int underlineColor) {
        this.mUnderlineColor = underlineColor;
        invalidate();
    }

    public void setUnderlineHeight(float underlineHeight) {
        this.mUnderlineHeight = dp2px(underlineHeight);
        invalidate();
    }

    public void setUnderlineGravity(int underlineGravity) {
        this.mUnderlineGravity = underlineGravity;
        invalidate();
    }

    public void setDividerColor(int dividerColor) {
        this.mDividerColor = dividerColor;
        invalidate();
    }

    public void setDividerWidth(float dividerWidth) {
        this.mDividerWidth = dp2px(dividerWidth);
        invalidate();
    }

    public void setDividerPadding(float dividerPadding) {
        this.mDividerPadding = dp2px(dividerPadding);
        invalidate();
    }

    public void setTextsize(float textsize) {
        this.mTextsize = sp2px(textsize);
        updateTabStyles();
    }

    public void setTextSelectSize(float textSize) {
        this.mTextSelectSize = sp2px(textSize);
        updateTabStyles();
    }

    public void setTextSelectColor(int textSelectColor) {
        this.mTextSelectColor = textSelectColor;
        updateTabStyles();
    }

    public void setTextUnselectColor(int textUnselectColor) {
        this.mTextUnselectColor = textUnselectColor;
        updateTabStyles();
    }

    public void setTextBold(int textBold) {
        this.mTextBold = textBold;
        updateTabStyles();
    }

    public void setTextAllCaps(boolean textAllCaps) {
        this.mTextAllCaps = textAllCaps;
        updateTabStyles();
    }

    public void setSnapOnTabClick(boolean snapOnTabClick) {
        this.mSnapOnTabClick = snapOnTabClick;
    }

    public void setMsgViewBackgroundColor(int mMsgViewBackgroundColor) {
        this.mMsgViewBackgroundColor = mMsgViewBackgroundColor;
    }

    public void setMsgViewWidth(int mMsgViewWidth) {
        if (mMsgViewWidth > 0) {
            this.mMsgViewWidth = dp2px(mMsgViewWidth);
        }
    }

    public int getTabCount() {
        return this.mTabCount;
    }

    public int getCurrentTab() {
        return this.mCurrentTab;
    }

    public int getIndicatorStyle() {
        return this.mIndicatorStyle;
    }

    public float getTabPadding() {
        return this.mTabPadding;
    }

    public boolean isTabSpaceEqual() {
        return this.mTabSpaceEqual;
    }

    public float getTabWidth() {
        return this.mTabWidth;
    }

    public int getIndicatorColor() {
        return this.mIndicatorColor;
    }

    public int getIndicatorEndColor() {
        return this.mEndIndicatorColor;
    }

    public float getIndicatorHeight() {
        return this.mIndicatorHeight;
    }

    public float getIndicatorWidth() {
        return this.mIndicatorWidth;
    }

    public float getIndicatorCornerRadius() {
        return this.mIndicatorCornerRadius;
    }

    public float getIndicatorMarginLeft() {
        return this.mIndicatorMarginLeft;
    }

    public float getIndicatorMarginTop() {
        return this.mIndicatorMarginTop;
    }

    public float getIndicatorMarginRight() {
        return this.mIndicatorMarginRight;
    }

    public float getIndicatorMarginBottom() {
        return this.mIndicatorMarginBottom;
    }

    public int getUnderlineColor() {
        return this.mUnderlineColor;
    }

    public float getUnderlineHeight() {
        return this.mUnderlineHeight;
    }

    public int getDividerColor() {
        return this.mDividerColor;
    }

    public float getDividerWidth() {
        return this.mDividerWidth;
    }

    public float getDividerPadding() {
        return this.mDividerPadding;
    }

    public float getTextSize() {
        return this.mTextsize;
    }

    public float getTextSelectSize() {
        return this.mTextSelectSize;
    }

    public int getTextSelectColor() {
        return this.mTextSelectColor;
    }

    public int getTextUnselectColor() {
        return this.mTextUnselectColor;
    }

    public int getTextBold() {
        return this.mTextBold;
    }

    public boolean isTextAllCaps() {
        return this.mTextAllCaps;
    }

    public TextView getTitleView(int tab) {
        View tabView = this.mTabsContainer.getChildAt(tab);
        TextView tv_tab_title = (TextView) tabView.findViewById(mpEIGo.juqQQs.esbSDO.R.attr.tv_tab_title);
        return tv_tab_title;
    }

    public void showMsg(int position, int num) {
        int i = this.mTabCount;
        if (position >= i) {
            position = i - 1;
        }
        View tabView = this.mTabsContainer.getChildAt(position);
        MsgView tipView = (MsgView) tabView.findViewById(mpEIGo.juqQQs.esbSDO.R.attr.rtv_msg_tip);
        if (tipView != null) {
            UnreadMsgUtils.show(tipView, num);
            if (this.mInitSetMap.get(position) != null && this.mInitSetMap.get(position).booleanValue()) {
                return;
            }
            setMsgMargin(position, 0.0f, 1.0f);
            this.mInitSetMap.put(position, true);
        }
    }

    public void showDot(int position) {
        int i = this.mTabCount;
        if (position >= i) {
            position = i - 1;
        }
        showMsg(position, 0);
    }

    public void hideMsg(int position) {
        int i = this.mTabCount;
        if (position >= i) {
            position = i - 1;
        }
        View tabView = this.mTabsContainer.getChildAt(position);
        MsgView tipView = (MsgView) tabView.findViewById(mpEIGo.juqQQs.esbSDO.R.attr.rtv_msg_tip);
        if (tipView != null && tipView.getVisibility() == 0) {
            tipView.setVisibility(8);
        }
    }

    public void setMsgMargin(int position, float leftPadding, float bottomPadding) {
        int i = this.mTabCount;
        if (position >= i) {
            position = i - 1;
        }
        View tabView = this.mTabsContainer.getChildAt(position);
        MsgView tipView = (MsgView) tabView.findViewById(mpEIGo.juqQQs.esbSDO.R.attr.rtv_msg_tip);
        if (tipView != null) {
            TextView tv_tab_title = (TextView) tabView.findViewById(mpEIGo.juqQQs.esbSDO.R.attr.tv_tab_title);
            this.mTextPaint.setTextSize(this.mTextsize);
            float textWidth = this.mTextPaint.measureText(tv_tab_title.getText().toString());
            float textHeight = this.mTextPaint.descent() - this.mTextPaint.ascent();
            ViewGroup.MarginLayoutParams lp = (ViewGroup.MarginLayoutParams) tipView.getLayoutParams();
            float f = this.mTabWidth;
            lp.leftMargin = (int) ((f >= 0.0f ? (f / 2.0f) + (textWidth / 2.0f) : this.mTabPadding + textWidth) + dp2px(leftPadding));
            int i2 = this.mHeight;
            lp.topMargin = i2 > 0 ? (((int) (i2 - textHeight)) / 2) - dp2px(bottomPadding) : 0;
            tipView.setLayoutParams(lp);
        }
    }

    public MsgView getMsgView(int position) {
        int i = this.mTabCount;
        if (position >= i) {
            position = i - 1;
        }
        View tabView = this.mTabsContainer.getChildAt(position);
        MsgView tipView = (MsgView) tabView.findViewById(mpEIGo.juqQQs.esbSDO.R.attr.rtv_msg_tip);
        return tipView;
    }

    public void setOnTabSelectListener(OnTabSelectListener listener) {
        this.mListener = listener;
    }

    public void setOnTabReleaseListener(OnTabReleaseListener listener) {
        this.mReleaseListener = listener;
    }

    class InnerPagerAdapter extends FragmentPagerAdapter {
        private ArrayList<Fragment> fragments;
        private String[] titles;

        public InnerPagerAdapter(FragmentManager fm, ArrayList<Fragment> fragments, String[] titles) {
            super(fm);
            this.fragments = new ArrayList<>();
            this.fragments = fragments;
            this.titles = titles;
        }

        @Override // androidx.viewpager.widget.PagerAdapter
        public int getCount() {
            return this.fragments.size();
        }

        @Override // androidx.viewpager.widget.PagerAdapter
        public CharSequence getPageTitle(int position) {
            return this.titles[position];
        }

        @Override // androidx.fragment.app.FragmentPagerAdapter
        public Fragment getItem(int position) {
            return this.fragments.get(position);
        }

        @Override // androidx.fragment.app.FragmentPagerAdapter, androidx.viewpager.widget.PagerAdapter
        public void destroyItem(ViewGroup container, int position, Object object) {
        }

        @Override // androidx.viewpager.widget.PagerAdapter
        public int getItemPosition(Object object) {
            return -2;
        }
    }

    @Override // android.widget.HorizontalScrollView, android.view.View
    protected Parcelable onSaveInstanceState() {
        Bundle bundle = new Bundle();
        bundle.putParcelable("instanceState", super.onSaveInstanceState());
        bundle.putInt("mCurrentTab", this.mCurrentTab);
        return bundle;
    }

    @Override // android.widget.HorizontalScrollView, android.view.View
    protected void onRestoreInstanceState(Parcelable state) {
        if (state instanceof Bundle) {
            Bundle bundle = (Bundle) state;
            this.mCurrentTab = bundle.getInt("mCurrentTab");
            state = bundle.getParcelable("instanceState");
            if (this.mCurrentTab != 0 && this.mTabsContainer.getChildCount() > 0) {
                updateTabSelection(this.mCurrentTab);
                scrollToCurrentTab();
            }
        }
        super.onRestoreInstanceState(state);
    }

    protected int dp2px(float dp) {
        float scale = this.mContext.getResources().getDisplayMetrics().density;
        return (int) ((dp * scale) + 0.5f);
    }

    protected int sp2px(float sp) {
        float scale = this.mContext.getResources().getDisplayMetrics().scaledDensity;
        return (int) ((sp * scale) + 0.5f);
    }
}
