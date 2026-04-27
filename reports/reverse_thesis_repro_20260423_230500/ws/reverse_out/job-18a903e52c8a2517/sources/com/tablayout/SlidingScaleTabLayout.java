package com.tablayout;

import android.R;
import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.Rect;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.os.Parcelable;
import android.text.TextUtils;
import android.util.AttributeSet;
import android.util.Log;
import android.util.SparseBooleanArray;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.HorizontalScrollView;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentActivity;
import androidx.fragment.app.FragmentManager;
import androidx.fragment.app.FragmentPagerAdapter;
import androidx.viewpager.widget.ViewPager;
import com.tablayout.listener.OnTabSelectListener;
import com.tablayout.transformer.ExtendTransformer;
import com.tablayout.transformer.ITabScaleTransformer;
import com.tablayout.transformer.IViewPagerTransformer;
import com.tablayout.transformer.TabScaleTransformer;
import com.tablayout.utils.SlidingTabLayoutUtils;
import com.tablayout.utils.UnreadMsgUtils;
import com.tablayout.widget.MsgView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.BuildVars;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/* JADX INFO: loaded from: classes2.dex */
public class SlidingScaleTabLayout extends HorizontalScrollView implements ViewPager.OnPageChangeListener {
    public static final int BOTTOM = 1;
    public static final int CENTER = 2;
    public static final int LEFT = 0;
    public static final int RIGHT = 1;
    protected static final int STYLE_BLOCK = 2;
    protected static final int STYLE_NORMAL = 0;
    protected static final int STYLE_TRIANGLE = 1;
    protected static final String TAG = "SlidingScaleTabLayout";
    protected static final int TEXT_BOLD_BOTH = 2;
    protected static final int TEXT_BOLD_NONE = 0;
    protected static final int TEXT_BOLD_WHEN_SELECT = 1;
    public static final int TOP = 0;
    protected CustomAdapter customAdapter;
    protected ExtendTransformer extendTransformer;
    protected ITabScaleTransformer iTabScaleTransformer;
    protected Context mContext;
    protected float mCurrentPositionOffset;
    protected int mCurrentTab;
    protected int mDividerColor;
    protected float mDividerPadding;
    protected Paint mDividerPaint;
    protected float mDividerWidth;
    protected int mEndIndicatorColor;
    protected int mHeight;
    protected int mIndicatorColor;
    protected float mIndicatorCornerRadius;
    protected float[] mIndicatorCornerRadiusArr;
    protected GradientDrawable mIndicatorDrawable;
    protected int mIndicatorGravity;
    protected float mIndicatorHeight;
    protected float mIndicatorMarginBottom;
    protected float mIndicatorMarginLeft;
    protected float mIndicatorMarginRight;
    protected float mIndicatorMarginTop;
    protected Rect mIndicatorRect;
    protected int mIndicatorStyle;
    protected float mIndicatorWidth;
    protected boolean mIndicatorWidthEqualTitle;
    protected boolean mIndicatorWidthFollowScrollOffset;
    protected SparseBooleanArray mInitSetMap;
    protected int mLastCurrentTab;
    protected int mLastScrollX;
    protected OnTabSelectListener mListener;
    protected Paint mRectPaint;
    protected boolean mSnapOnTabClick;
    protected int mTabBackgroundId;
    protected int mTabCount;
    protected int mTabDotMarginRight;
    protected int mTabDotMarginTop;
    protected int mTabHorizontalGravity;
    protected int mTabMarginBottom;
    protected int mTabMarginTop;
    protected int mTabMsgMarginRight;
    protected int mTabMsgMarginTop;
    protected float mTabPadding;
    protected float mTabPaddingBottom;
    protected Rect mTabRect;
    protected boolean mTabSpaceEqual;
    protected Typeface mTabTextSelectStyle;
    protected Typeface mTabTextUnSelectStyle;
    protected int mTabVerticalGravity;
    protected float mTabWidth;
    protected LinearLayout mTabsContainer;
    protected boolean mTextAllCaps;
    protected int mTextBold;
    protected Paint mTextPaint;
    protected int mTextSelectColor;
    protected float mTextSelectSize;
    protected int mTextUnSelectColor;
    protected float mTextUnSelectSize;
    protected ArrayList<String> mTitles;
    protected Paint mTrianglePaint;
    protected Path mTrianglePath;
    protected int mUnderlineColor;
    protected int mUnderlineGravity;
    protected float mUnderlineHeight;
    protected ViewPager mViewPager;
    protected boolean openDmg;

    public void setDotMargin(int top, int right) {
        this.mTabDotMarginTop = top;
        this.mTabDotMarginRight = right;
    }

    public SlidingScaleTabLayout(Context context) {
        this(context, null, 0);
    }

    public SlidingScaleTabLayout(Context context, AttributeSet attrs) {
        this(context, attrs, 0);
    }

    public SlidingScaleTabLayout(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        this.mIndicatorRect = new Rect();
        this.mTabRect = new Rect();
        this.mIndicatorDrawable = new GradientDrawable(GradientDrawable.Orientation.LEFT_RIGHT, null);
        this.mRectPaint = new Paint(1);
        this.mDividerPaint = new Paint(1);
        this.mTrianglePaint = new Paint(1);
        this.mTrianglePath = new Path();
        this.mIndicatorStyle = 0;
        this.mIndicatorWidthFollowScrollOffset = true;
        this.openDmg = false;
        this.mTabHorizontalGravity = 2;
        this.mTabVerticalGravity = 1;
        this.mTextPaint = new Paint(1);
        this.mInitSetMap = new SparseBooleanArray();
        setFillViewport(true);
        setWillNotDraw(false);
        setClipChildren(false);
        setClipToPadding(false);
        this.mContext = context;
        LinearLayout linearLayout = new LinearLayout(context);
        this.mTabsContainer = linearLayout;
        addView(linearLayout);
        if (attrs != null) {
            init(context, attrs);
            String height = attrs.getAttributeValue("http://schemas.android.com/apk/res/android", "layout_height");
            if (!height.equals("-1") && !height.equals("-2")) {
                int[] systemAttrs = {R.attr.layout_height};
                TypedArray a = context.obtainStyledAttributes(attrs, systemAttrs);
                this.mHeight = a.getDimensionPixelSize(0, -2);
                a.recycle();
            }
        }
    }

    protected void init(Context context, AttributeSet attrs) {
        float f;
        TypedArray ta = context.obtainStyledAttributes(attrs, im.uwrkaxlmjj.messenger.R.styleable.SlidingScaleTabLayout);
        int i = ta.getInt(15, 0);
        this.mIndicatorStyle = i;
        this.mIndicatorColor = ta.getColor(3, Color.parseColor(i == 2 ? "#4B6A87" : "#ffffff"));
        int i2 = this.mIndicatorStyle;
        if (i2 == 1) {
            f = 4.0f;
        } else {
            f = i2 == 2 ? -1 : 2;
        }
        this.mIndicatorHeight = ta.getDimension(10, dp2px(f));
        this.mIndicatorWidth = ta.getDimension(16, dp2px(this.mIndicatorStyle == 1 ? 10.0f : -1.0f));
        this.mIndicatorCornerRadius = ta.getDimension(4, dp2px(this.mIndicatorStyle == 2 ? -1.0f : 0.0f));
        float cornerRLT = ta.getDimension(6, dp2px(this.mIndicatorStyle == 2 ? -1.0f : 0.0f));
        float cornerRRT = ta.getDimension(8, dp2px(this.mIndicatorStyle == 2 ? -1.0f : 0.0f));
        float cornerRLB = ta.getDimension(5, dp2px(this.mIndicatorStyle == 2 ? -1.0f : 0.0f));
        float cornerRRB = ta.getDimension(7, dp2px(this.mIndicatorStyle == 2 ? -1.0f : 0.0f));
        setIndicatorCornerRadiusArr(cornerRLT, cornerRRT, cornerRLB, cornerRRB, false);
        this.mIndicatorMarginLeft = ta.getDimension(12, dp2px(0.0f));
        this.mIndicatorMarginTop = ta.getDimension(14, dp2px(this.mIndicatorStyle == 2 ? 7.0f : 0.0f));
        this.mIndicatorMarginRight = ta.getDimension(13, dp2px(0.0f));
        this.mIndicatorMarginBottom = ta.getDimension(11, dp2px(this.mIndicatorStyle != 2 ? 0.0f : 7.0f));
        this.mIndicatorGravity = ta.getInt(9, 80);
        this.mIndicatorWidthEqualTitle = ta.getBoolean(17, false);
        this.mUnderlineColor = ta.getColor(39, Color.parseColor("#ffffff"));
        this.mUnderlineHeight = ta.getDimension(41, dp2px(0.0f));
        this.mUnderlineGravity = ta.getInt(40, 80);
        this.mDividerColor = ta.getColor(0, Color.parseColor("#ffffff"));
        this.mDividerWidth = ta.getDimension(2, dp2px(0.0f));
        this.mDividerPadding = ta.getDimension(1, dp2px(12.0f));
        float dimension = ta.getDimension(38, sp2px(14.0f));
        this.mTextUnSelectSize = dimension;
        this.mTextSelectSize = ta.getDimension(36, dimension);
        this.mTextSelectColor = ta.getColor(35, Color.parseColor("#ffffff"));
        this.mTextUnSelectColor = ta.getColor(37, Color.parseColor("#AAffffff"));
        this.mTextBold = ta.getInt(34, 0);
        this.mTextAllCaps = ta.getBoolean(33, false);
        this.mTabSpaceEqual = ta.getBoolean(30, false);
        float dimension2 = ta.getDimension(32, dp2px(-1.0f));
        this.mTabWidth = dimension2;
        this.mTabPadding = ta.getDimension(29, (this.mTabSpaceEqual || dimension2 > 0.0f) ? dp2px(0.0f) : dp2px(20.0f));
        this.mTabMarginTop = ta.getDimensionPixelSize(26, 0);
        this.mTabMarginBottom = ta.getDimensionPixelSize(25, 0);
        this.mTabHorizontalGravity = ta.getInt(24, 2);
        this.mTabVerticalGravity = ta.getInt(31, 1);
        this.mTabMsgMarginTop = (int) ta.getDimension(28, 0.0f);
        this.mTabMsgMarginRight = (int) ta.getDimension(27, 0.0f);
        this.mTabDotMarginTop = (int) ta.getDimension(23, 0.0f);
        this.mTabDotMarginRight = (int) ta.getDimension(22, 0.0f);
        this.mTabBackgroundId = ta.getResourceId(21, 0);
        this.openDmg = ta.getBoolean(18, false);
        int tabTextSelectStyle = ta.getInt(19, 0);
        int tabTextUnSelectStyle = ta.getInt(20, 0);
        ta.recycle();
        this.extendTransformer = new ExtendTransformer();
        setTabTextStyle(tabTextSelectStyle, true);
        setTabTextStyle(tabTextUnSelectStyle, false);
    }

    protected void initViewPagerListener() {
        ViewPager viewPager = this.mViewPager;
        if (viewPager != null) {
            viewPager.removeOnPageChangeListener(this);
            this.mViewPager.addOnPageChangeListener(this);
            initTransformer();
        }
        notifyDataSetChanged();
    }

    protected void initTransformer() {
        ViewPager viewPager;
        if (this.mTextUnSelectSize != this.mTextSelectSize && (viewPager = this.mViewPager) != null) {
            viewPager.setPageTransformer(true, this.extendTransformer);
        }
    }

    public void notifyDataSetChanged() {
        this.mTabCount = 0;
        ArrayList<String> arrayList = this.mTitles;
        if (arrayList != null) {
            this.mTabCount = arrayList.size();
        } else {
            ViewPager viewPager = this.mViewPager;
            if (viewPager != null && viewPager.getAdapter() != null) {
                this.mTabCount = this.mViewPager.getAdapter().getCount();
            } else {
                CustomAdapter customAdapter = this.customAdapter;
                if (customAdapter != null) {
                    this.mTabCount = customAdapter.getTabCount();
                }
            }
        }
        this.mTabsContainer.removeAllViews();
        for (int i = 0; i < this.mTabCount; i++) {
            View tabView = this.customAdapter != null ? LayoutInflater.from(this.mContext).inflate(this.customAdapter.getTabResLayoutId(), (ViewGroup) this.mTabsContainer, false) : LayoutInflater.from(this.mContext).inflate(mpEIGo.juqQQs.esbSDO.R.layout.layout_scale_tab, (ViewGroup) this.mTabsContainer, false);
            TextView title = (TextView) tabView.findViewById(mpEIGo.juqQQs.esbSDO.R.attr.tv_tab_title);
            setTabLayoutParams(title);
            CharSequence pageTitle = "";
            ArrayList<String> arrayList2 = this.mTitles;
            if (arrayList2 != null) {
                pageTitle = arrayList2.get(i);
            } else {
                CustomAdapter customAdapter2 = this.customAdapter;
                if (customAdapter2 != null) {
                    pageTitle = customAdapter2.getTitle(tabView, i);
                } else {
                    ViewPager viewPager2 = this.mViewPager;
                    if (viewPager2 != null && viewPager2.getAdapter() != null) {
                        pageTitle = this.mViewPager.getAdapter().getPageTitle(i);
                    }
                }
            }
            if (pageTitle == null) {
                pageTitle = "";
            }
            addTab(i, pageTitle.toString(), tabView);
        }
        updateTabStyles();
    }

    protected void setTabLayoutParams(TextView title) {
        ImageView imageView;
        RelativeLayout.LayoutParams params = (RelativeLayout.LayoutParams) title.getLayoutParams();
        params.topMargin = this.mTabMarginTop;
        params.bottomMargin = this.mTabMarginBottom;
        int i = this.mTabVerticalGravity;
        if (i == 0) {
            params.addRule(10);
        } else if (i == 1) {
            params.addRule(12);
        } else {
            params.addRule(15);
        }
        int i2 = this.mTabHorizontalGravity;
        if (i2 == 0) {
            params.addRule(9);
        } else if (i2 == 1) {
            params.addRule(11);
        } else {
            params.addRule(14);
        }
        title.setLayoutParams(params);
        if (!isDmgOpen() || (imageView = (ImageView) SlidingTabLayoutUtils.findBrotherView(title, mpEIGo.juqQQs.esbSDO.R.attr.tv_tab_title_dmg, 3)) == null) {
            return;
        }
        RelativeLayout.LayoutParams params2 = (RelativeLayout.LayoutParams) imageView.getLayoutParams();
        params2.topMargin = this.mTabMarginTop;
        params2.bottomMargin = this.mTabMarginBottom;
        int i3 = this.mTabVerticalGravity;
        if (i3 == 0) {
            params2.addRule(10);
            imageView.setScaleType(ImageView.ScaleType.FIT_START);
        } else if (i3 == 1) {
            params2.addRule(12);
            imageView.setScaleType(ImageView.ScaleType.FIT_END);
        } else {
            params2.addRule(15);
            imageView.setScaleType(ImageView.ScaleType.FIT_CENTER);
        }
        int i4 = this.mTabHorizontalGravity;
        if (i4 == 0) {
            params2.addRule(9);
        } else if (i4 == 1) {
            params2.addRule(11);
        } else {
            params2.addRule(14);
        }
        imageView.setLayoutParams(params2);
    }

    protected void addTab(int position, String title, View tabView) {
        TextView tv_tab_title = (TextView) tabView.findViewById(mpEIGo.juqQQs.esbSDO.R.attr.tv_tab_title);
        if (tv_tab_title != null) {
            tv_tab_title.setText(title);
            if (position == this.mCurrentTab) {
                tv_tab_title.setTypeface(this.mTabTextSelectStyle);
            } else {
                tv_tab_title.setTypeface(this.mTabTextUnSelectStyle);
            }
            int i = this.mTabBackgroundId;
            if (i != 0) {
                tv_tab_title.setBackgroundResource(i);
            }
        }
        tabView.setOnClickListener(new View.OnClickListener() { // from class: com.tablayout.-$$Lambda$SlidingScaleTabLayout$Ue2n2A2NXpEbGXpE_w9eXoPhSns
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$addTab$0$SlidingScaleTabLayout(view);
            }
        });
        updateTabWidth(tabView);
        this.mTabsContainer.addView(tabView, position);
        CustomAdapter customAdapter = this.customAdapter;
        if (customAdapter != null) {
            customAdapter.bindView(position, tabView, this.mCurrentTab == position);
        }
    }

    public /* synthetic */ void lambda$addTab$0$SlidingScaleTabLayout(View v) {
        int position1 = this.mTabsContainer.indexOfChild(v);
        if (position1 != -1) {
            setCurrentTab(position1);
        }
    }

    protected void updateTabStyles() {
        updateTabStyles(false);
    }

    protected void updateTabStyles(boolean updateTabWidth) {
        int i = 0;
        while (i < this.mTabCount) {
            View tabView = this.mTabsContainer.getChildAt(i);
            if (updateTabWidth) {
                updateTabWidth(tabView);
            }
            TextView tv_tab_title = (TextView) tabView.findViewById(mpEIGo.juqQQs.esbSDO.R.attr.tv_tab_title);
            if (tv_tab_title != null) {
                float f = this.mTabPadding;
                tabView.setPadding((int) f, 0, (int) f, (int) this.mTabPaddingBottom);
                tv_tab_title.setTextSize(0, i == this.mCurrentTab ? this.mTextSelectSize : this.mTextUnSelectSize);
                tv_tab_title.setTextColor(i == this.mCurrentTab ? this.mTextSelectColor : this.mTextUnSelectColor);
                tv_tab_title.setSelected(i == this.mCurrentTab);
                if (i == this.mCurrentTab) {
                    tv_tab_title.setTypeface(this.mTabTextSelectStyle);
                } else {
                    tv_tab_title.setTypeface(this.mTabTextUnSelectStyle);
                }
                if (this.mTextAllCaps) {
                    tv_tab_title.setText(tv_tab_title.getText().toString().toUpperCase());
                }
                int i2 = this.mTextBold;
                if (i2 == 2) {
                    tv_tab_title.getPaint().setFakeBoldText(true);
                } else if (i2 == 1) {
                    tv_tab_title.getPaint().setFakeBoldText(i == this.mCurrentTab);
                } else if (i2 == 0) {
                    tv_tab_title.getPaint().setFakeBoldText(false);
                }
                if (isDmgOpen()) {
                    generateTitleDmg(tabView, tv_tab_title, i);
                }
            }
            i++;
        }
    }

    private void updateTabWidth(View tabView) {
        if (tabView == null) {
            return;
        }
        ViewGroup.LayoutParams lp_tab = tabView.getLayoutParams();
        boolean setLayoutParams = lp_tab == null;
        float f = this.mTabWidth;
        if (f > 0.0f) {
            if (lp_tab == null) {
                lp_tab = new LinearLayout.LayoutParams((int) this.mTabWidth, -1);
            } else {
                lp_tab.width = (int) f;
                lp_tab.height = -1;
                ((LinearLayout.LayoutParams) lp_tab).weight = 0.0f;
            }
        } else if (this.mTabSpaceEqual) {
            if (lp_tab == null) {
                lp_tab = new LinearLayout.LayoutParams(0, -1, 1.0f);
            } else {
                lp_tab.width = 0;
                lp_tab.height = -1;
                ((LinearLayout.LayoutParams) lp_tab).weight = 1.0f;
            }
        } else if (lp_tab == null) {
            lp_tab = new LinearLayout.LayoutParams(-2, -1);
        } else {
            lp_tab.width = -2;
            lp_tab.height = -1;
            ((LinearLayout.LayoutParams) lp_tab).weight = 0.0f;
        }
        if (setLayoutParams) {
            tabView.setLayoutParams(lp_tab);
        }
    }

    protected void generateTitleDmg(View tabView, TextView textView, int position) {
        if (TextUtils.isEmpty(textView.getText())) {
            return;
        }
        ImageView imageView = (ImageView) tabView.findViewById(mpEIGo.juqQQs.esbSDO.R.attr.tv_tab_title_dmg);
        float f = this.mTextSelectSize;
        float f2 = this.mTextUnSelectSize;
        if (f >= f2) {
            textView.setTextSize(0, f);
            imageView.setImageBitmap(SlidingTabLayoutUtils.generateViewCacheBitmap(textView));
            int drawableWidth = imageView.getDrawable().getIntrinsicWidth();
            imageView.setMinimumWidth((int) ((drawableWidth * this.mTextUnSelectSize) / this.mTextSelectSize));
            imageView.setMaxWidth(drawableWidth);
        } else {
            textView.setTextSize(0, f2);
            imageView.setImageBitmap(SlidingTabLayoutUtils.generateViewCacheBitmap(textView));
            int drawableWidth2 = imageView.getDrawable().getIntrinsicWidth();
            imageView.setMinimumWidth((int) ((drawableWidth2 * this.mTextSelectSize) / this.mTextUnSelectSize));
            imageView.setMaxWidth(drawableWidth2);
        }
        textView.setVisibility(8);
    }

    protected void scrollToCurrentTab() {
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

    protected void updateTabSelection(int position) {
        int i = 0;
        while (i < this.mTabCount) {
            View tabView = this.mTabsContainer.getChildAt(i);
            boolean isSelect = i == position;
            CustomAdapter customAdapter = this.customAdapter;
            if (customAdapter != null) {
                customAdapter.bindView(i, tabView, isSelect);
            }
            final TextView tab_title = (TextView) tabView.findViewById(mpEIGo.juqQQs.esbSDO.R.attr.tv_tab_title);
            if (tab_title != null) {
                tab_title.setTextColor(isSelect ? this.mTextSelectColor : this.mTextUnSelectColor);
                tab_title.setSelected(isSelect);
                if (position == this.mCurrentTab) {
                    tab_title.setTypeface(this.mTabTextSelectStyle);
                } else {
                    tab_title.setTypeface(this.mTabTextUnSelectStyle);
                }
                int i2 = this.mTextBold;
                if (i2 == 2) {
                    tab_title.getPaint().setFakeBoldText(true);
                } else if (i2 != 1 || i != position) {
                    tab_title.getPaint().setFakeBoldText(false);
                } else {
                    tab_title.getPaint().setFakeBoldText(true);
                }
                if (isDmgOpen() && (this.mTextSelectColor != this.mTextUnSelectColor || this.mTextBold == 1)) {
                    tab_title.setVisibility(0);
                    generateTitleDmg(tabView, tab_title, i);
                } else {
                    final int finalI = i;
                    tab_title.post(new Runnable() { // from class: com.tablayout.SlidingScaleTabLayout.1
                        @Override // java.lang.Runnable
                        public void run() {
                            tab_title.setTextSize(0, finalI == SlidingScaleTabLayout.this.mCurrentTab ? SlidingScaleTabLayout.this.mTextSelectSize : SlidingScaleTabLayout.this.mTextUnSelectSize);
                            tab_title.requestLayout();
                        }
                    });
                }
            }
            i++;
        }
    }

    protected void calcIndicatorRect() {
        boolean setDefaultIndicator;
        boolean setDefaultIndicator2;
        View currentTabView = this.mTabsContainer.getChildAt(this.mCurrentTab);
        float left = currentTabView.getLeft();
        float right = currentTabView.getRight();
        boolean setIndicatorWidthWhenBiggerThan0 = false;
        int i = this.mCurrentTab;
        if (i < this.mTabCount - 1) {
            View nextTabView = this.mTabsContainer.getChildAt(i + 1);
            float nextTabLeft = nextTabView.getLeft();
            float nextTabRight = nextTabView.getRight();
            float f = this.mCurrentPositionOffset;
            left += (nextTabLeft - left) * f;
            right += f * (nextTabRight - right);
            if (this.mIndicatorStyle != 0) {
                setDefaultIndicator2 = true;
            } else if (this.mIndicatorWidthEqualTitle) {
                TextView tab_title = (TextView) currentTabView.findViewById(mpEIGo.juqQQs.esbSDO.R.attr.tv_tab_title);
                float textWidth = this.mTextPaint.measureText(tab_title.getText().toString());
                float margin = ((right - left) - textWidth) / 2.0f;
                TextView next_tab_title = (TextView) nextTabView.findViewById(mpEIGo.juqQQs.esbSDO.R.attr.tv_tab_title);
                float nextTextWidth = this.mTextPaint.measureText(next_tab_title.getText().toString());
                float nextMargin = ((nextTabRight - nextTabLeft) - nextTextWidth) / 2.0f;
                float margin2 = margin + (this.mCurrentPositionOffset * (nextMargin - margin));
                this.mIndicatorRect.left = (int) ((left + margin2) - 1.0f);
                this.mIndicatorRect.right = (int) ((right - margin2) - 1.0f);
                setDefaultIndicator = false;
            } else {
                setDefaultIndicator2 = true;
                boolean setDefaultIndicator3 = this.mIndicatorWidthFollowScrollOffset;
                if (setDefaultIndicator3) {
                    TextView tab_title2 = (TextView) currentTabView.findViewById(mpEIGo.juqQQs.esbSDO.R.attr.tv_tab_title);
                    float textWidth2 = this.mTextPaint.measureText(tab_title2.getText().toString());
                    float margin3 = ((right - left) - textWidth2) / 2.0f;
                    this.mIndicatorRect.left = (int) (currentTabView.getLeft() + ((currentTabView.getWidth() - this.mIndicatorWidth) / 2.0f) + (this.mCurrentPositionOffset * ((currentTabView.getWidth() / 2.0f) + (nextTabView.getWidth() / 2.0f))));
                    if (this.mCurrentPositionOffset <= 0.5f) {
                        Rect rect = this.mIndicatorRect;
                        rect.right = rect.left + ((int) this.mIndicatorWidth) + ((int) (this.mCurrentPositionOffset * margin3));
                    } else {
                        Rect rect2 = this.mIndicatorRect;
                        rect2.right = rect2.left + ((int) this.mIndicatorWidth) + ((int) ((1.0f - this.mCurrentPositionOffset) * margin3));
                    }
                    setDefaultIndicator = false;
                } else if (this.mIndicatorWidth >= 0.0f) {
                    setIndicatorWidthWhenBiggerThan0 = true;
                    setDefaultIndicator = true;
                }
            }
            setDefaultIndicator = setDefaultIndicator2;
        } else {
            setIndicatorWidthWhenBiggerThan0 = this.mIndicatorWidth >= 0.0f;
            setDefaultIndicator = true;
        }
        if (setIndicatorWidthWhenBiggerThan0) {
            float indicatorLeft = currentTabView.getLeft() + ((currentTabView.getWidth() - this.mIndicatorWidth) / 2.0f);
            int i2 = this.mCurrentTab;
            if (i2 < this.mTabCount - 1) {
                View nextTab = this.mTabsContainer.getChildAt(i2 + 1);
                indicatorLeft += this.mCurrentPositionOffset * ((currentTabView.getWidth() / 2.0f) + (nextTab.getWidth() / 2.0f));
            }
            this.mIndicatorRect.left = (int) indicatorLeft;
            this.mIndicatorRect.right = (int) (r8.left + this.mIndicatorWidth);
        } else if (setDefaultIndicator) {
            this.mIndicatorRect.left = (int) left;
            this.mIndicatorRect.right = (int) right;
        }
        this.mTabRect.left = (int) left;
        this.mTabRect.right = (int) right;
    }

    protected void setTabTextStyle(int style, boolean isTabTextSelectStyle) {
        if (style != 0) {
            if (style == 1) {
                if (isTabTextSelectStyle) {
                    this.mTabTextSelectStyle = AndroidUtilities.getTypeface("fonts/rmedium.ttf");
                    return;
                } else {
                    this.mTabTextUnSelectStyle = AndroidUtilities.getTypeface("fonts/rmedium.ttf");
                    return;
                }
            }
            if (style == 2) {
                if (isTabTextSelectStyle) {
                    this.mTabTextSelectStyle = AndroidUtilities.getTypeface("fonts/ritalic.ttf");
                    return;
                } else {
                    this.mTabTextUnSelectStyle = AndroidUtilities.getTypeface("fonts/ritalic.ttf");
                    return;
                }
            }
            if (style == 3) {
                if (isTabTextSelectStyle) {
                    this.mTabTextSelectStyle = AndroidUtilities.getTypeface("fonts/rmediumitalic.ttf");
                    return;
                } else {
                    this.mTabTextUnSelectStyle = AndroidUtilities.getTypeface("fonts/rmediumitalic.ttf");
                    return;
                }
            }
            if (style == 4) {
                if (isTabTextSelectStyle) {
                    this.mTabTextSelectStyle = AndroidUtilities.getTypeface("fonts/rmono.ttf");
                    return;
                } else {
                    this.mTabTextUnSelectStyle = AndroidUtilities.getTypeface("fonts/rmono.ttf");
                    return;
                }
            }
            if (style == 5) {
                if (isTabTextSelectStyle) {
                    this.mTabTextSelectStyle = AndroidUtilities.getTypeface("fonts/DINPro_BlackItalic.ttf");
                } else {
                    this.mTabTextUnSelectStyle = AndroidUtilities.getTypeface("fonts/DINPro_BlackItalic.ttf");
                }
            }
        }
    }

    @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
    public void onPageScrolled(int position, float positionOffset, int positionOffsetPixels) {
        this.mCurrentTab = position;
        this.mCurrentPositionOffset = positionOffset;
        ITabScaleTransformer iTabScaleTransformer = this.iTabScaleTransformer;
        if (iTabScaleTransformer != null) {
            iTabScaleTransformer.onPageScrolled(position, positionOffset, positionOffsetPixels);
        }
        scrollToCurrentTab();
        invalidate();
        if (BuildVars.DEBUG_VERSION) {
            Log.d(TAG, "onPageScrolled ===>  , mCurrentTab = " + this.mCurrentTab + " , positionOffset = " + positionOffset + " , positionOffsetPixels = " + positionOffsetPixels);
        }
        if (this.mCurrentPositionOffset == 0.0f) {
            updateTabSelection(this.mCurrentTab);
        }
    }

    @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
    public void onPageSelected(int position) {
        LinearLayout linearLayout;
        if (this.customAdapter != null && (linearLayout = this.mTabsContainer) != null && position < linearLayout.getChildCount() && this.mLastCurrentTab < this.mTabsContainer.getChildCount()) {
            this.customAdapter.pageSelected(this.mTabsContainer.getChildAt(position), this.mCurrentTab, this.mTabsContainer.getChildAt(this.mLastCurrentTab), this.mLastCurrentTab);
        }
        this.mLastCurrentTab = position;
    }

    @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
    public void onPageScrollStateChanged(int state) {
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
                float f2 = this.mIndicatorCornerRadius;
                if (f2 > 0.0f) {
                    this.mIndicatorDrawable.setCornerRadius(f2);
                } else {
                    float[] fArr = this.mIndicatorCornerRadiusArr;
                    if (fArr != null) {
                        this.mIndicatorDrawable.setCornerRadii(fArr);
                    }
                }
                this.mIndicatorDrawable.draw(canvas);
                return;
            }
            return;
        }
        if (this.mIndicatorHeight < 0.0f) {
            this.mIndicatorHeight = (height - this.mIndicatorMarginTop) - this.mIndicatorMarginBottom;
        }
        float f3 = this.mIndicatorHeight;
        if (f3 > 0.0f) {
            float f4 = this.mIndicatorCornerRadius;
            if (f4 < 0.0f || f4 > f3 / 2.0f) {
                this.mIndicatorCornerRadius = this.mIndicatorHeight / 2.0f;
            }
            if (this.mEndIndicatorColor != 0) {
                this.mIndicatorDrawable.setGradientType(0);
                this.mIndicatorDrawable.setColors(new int[]{this.mIndicatorColor, this.mEndIndicatorColor});
            } else {
                this.mIndicatorDrawable.setColor(this.mIndicatorColor);
            }
            this.mIndicatorDrawable.setBounds(((int) this.mIndicatorMarginLeft) + paddingLeft + this.mIndicatorRect.left, (int) this.mIndicatorMarginTop, (int) ((this.mIndicatorRect.right + paddingLeft) - this.mIndicatorMarginRight), (int) (this.mIndicatorMarginTop + this.mIndicatorHeight));
            float f5 = this.mIndicatorCornerRadius;
            if (f5 > 0.0f) {
                this.mIndicatorDrawable.setCornerRadius(f5);
            } else {
                float[] fArr2 = this.mIndicatorCornerRadiusArr;
                if (fArr2 != null) {
                    this.mIndicatorDrawable.setCornerRadii(fArr2);
                }
            }
            this.mIndicatorDrawable.draw(canvas);
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

    public void setTitle(String[] titles) {
        ArrayList<String> arrayList = new ArrayList<>();
        this.mTitles = arrayList;
        Collections.addAll(arrayList, titles);
        initViewPagerListener();
    }

    public void setViewPager(ViewPager vp) {
        if (vp == null || vp.getAdapter() == null) {
            throw new IllegalStateException("ViewPager or ViewPager adapter can not be NULL !");
        }
        this.mViewPager = vp;
        initViewPagerListener();
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
        initViewPagerListener();
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
        initViewPagerListener();
    }

    protected boolean isDmgOpen() {
        return this.openDmg && this.mTextSelectSize != this.mTextUnSelectSize;
    }

    public void useNormalTabScaleTransformer() {
        setITabScaleTransformer(new TabScaleTransformer(this, this.mTextSelectSize, this.mTextUnSelectSize, this.openDmg));
    }

    public void setCurrentTab(int currentTab) {
        setCurrentTab(currentTab, !this.mSnapOnTabClick);
    }

    public void setCurrentTab(int currentTab, boolean smoothScroll) {
        if (this.mCurrentTab != currentTab) {
            this.mCurrentTab = currentTab;
            ViewPager viewPager = this.mViewPager;
            if (viewPager != null) {
                viewPager.setCurrentItem(currentTab, smoothScroll);
            } else {
                scrollToCurrentTab();
                invalidate();
                updateTabSelection(this.mCurrentTab);
            }
            OnTabSelectListener onTabSelectListener = this.mListener;
            if (onTabSelectListener != null) {
                onTabSelectListener.onTabSelect(currentTab);
                return;
            }
            return;
        }
        OnTabSelectListener onTabSelectListener2 = this.mListener;
        if (onTabSelectListener2 != null) {
            onTabSelectListener2.onTabReselect(currentTab);
        }
    }

    public void setTabMarginBottom(int offset) {
        this.mTabMarginBottom = offset;
    }

    public void setTabPaddingBottom(float paddingBottom) {
        this.mTabPaddingBottom = paddingBottom;
    }

    public void setIndicatorStyle(int indicatorStyle) {
        this.mIndicatorStyle = indicatorStyle;
        invalidate();
    }

    public void setTabPadding(float tabPadding) {
        this.mTabPadding = dp2px(tabPadding);
        updateTabStyles();
    }

    public void setTabSpaceEqual(boolean tabSpaceEqual) {
        this.mTabSpaceEqual = tabSpaceEqual;
        updateTabStyles(true);
    }

    public void setTabWidth(float tabWidth) {
        setTabWidth(tabWidth, true);
    }

    public void setTabWidth(float tabWidth, boolean isDpValue) {
        this.mTabWidth = isDpValue ? dp2px(tabWidth) : tabWidth;
        updateTabStyles(true);
    }

    public void setTabVerticalGravity(int gravity) {
        this.mTabVerticalGravity = gravity;
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
        this.mIndicatorCornerRadiusArr = null;
        invalidate();
    }

    public void setIndicatorCornerRadiusArr(float lt, float rt, float lb, float rb) {
        setIndicatorCornerRadiusArr(lt, rt, lb, rb, true);
    }

    protected void setIndicatorCornerRadiusArr(float lt, float rt, float lb, float rb, boolean invalidate) {
        if (lt > 0.0f || rt > 0.0f || lb > 0.0f || rb > 0.0f) {
            this.mIndicatorCornerRadius = 0.0f;
            this.mIndicatorCornerRadiusArr = new float[]{dp2px(lt), dp2px(lt), dp2px(rt), dp2px(rt), dp2px(lb), dp2px(lb), dp2px(rb), dp2px(rb)};
            if (invalidate) {
                invalidate();
            }
        }
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

    public void setTextSelectSize(float textsize) {
        this.mTextSelectSize = sp2px(textsize);
        initTransformer();
        updateTabStyles();
    }

    public void setTextUnSelectSize(int textSize) {
        this.mTextUnSelectSize = sp2px(textSize);
        initTransformer();
        updateTabStyles();
    }

    public void setTextSelectColor(int textSelectColor) {
        this.mTextSelectColor = textSelectColor;
        updateTabStyles();
    }

    public void setTextUnSelectColor(int textUnselectColor) {
        this.mTextUnSelectColor = textUnselectColor;
        updateTabStyles();
    }

    public void setTextBold(int textBold) {
        this.mTextBold = textBold;
        updateTabStyles();
    }

    public void setIndicatorWidthFollowScrollOffset(boolean mIndicatorWidthFollowScrollOffset) {
        this.mIndicatorWidthFollowScrollOffset = mIndicatorWidthFollowScrollOffset;
    }

    public void setTextAllCaps(boolean textAllCaps) {
        this.mTextAllCaps = textAllCaps;
        updateTabStyles();
    }

    public void setSnapOnTabClick(boolean snapOnTabClick) {
        this.mSnapOnTabClick = snapOnTabClick;
    }

    public void setITabScaleTransformer(ITabScaleTransformer iTabScaleTransformer) {
        this.iTabScaleTransformer = iTabScaleTransformer;
    }

    public void addViewPagerTransformer(IViewPagerTransformer transformer) {
        this.extendTransformer.addViewPagerTransformer(transformer);
    }

    public void removeViewPagerTransformer(IViewPagerTransformer transformer) {
        this.extendTransformer.removeViewPagerTransformer(transformer);
    }

    public void setTabTextStyle(Typeface textSelectStyle, Typeface textUnSelectStyle) {
        this.mTabTextSelectStyle = textSelectStyle;
        this.mTabTextUnSelectStyle = textUnSelectStyle;
        updateTabStyles();
    }

    public void setOnTabSelectListener(OnTabSelectListener listener) {
        this.mListener = listener;
    }

    public void setCustomAdapter(CustomAdapter customAdapter) {
        this.customAdapter = customAdapter;
    }

    public View getTabView(int position) {
        int i = this.mTabCount;
        if (position >= i) {
            position = i - 1;
        }
        return this.mTabsContainer.getChildAt(position);
    }

    public TextView getTitleView(int tab) {
        View tabView = this.mTabsContainer.getChildAt(tab);
        return (TextView) tabView.findViewById(mpEIGo.juqQQs.esbSDO.R.attr.tv_tab_title);
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

    public float getTextSelectSize() {
        return this.mTextSelectSize;
    }

    public float getTextUnSelectSize() {
        return this.mTextUnSelectSize;
    }

    public int getTextSelectColor() {
        return this.mTextSelectColor;
    }

    public int getTextUnSelectColor() {
        return this.mTextUnSelectColor;
    }

    public int getTextBold() {
        return this.mTextBold;
    }

    public boolean isTextAllCaps() {
        return this.mTextAllCaps;
    }

    public List<IViewPagerTransformer> getTransformers() {
        return this.extendTransformer.getTransformers();
    }

    public void setTransformers(List<IViewPagerTransformer> transformers) {
        this.extendTransformer.setTransformers(transformers);
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
            RelativeLayout.LayoutParams params = (RelativeLayout.LayoutParams) tipView.getLayoutParams();
            if (this.openDmg) {
                params.addRule(19, mpEIGo.juqQQs.esbSDO.R.attr.tv_tab_title_dmg);
                params.addRule(6, mpEIGo.juqQQs.esbSDO.R.attr.tv_tab_title_dmg);
            } else {
                params.addRule(19, mpEIGo.juqQQs.esbSDO.R.attr.tv_tab_title);
                params.addRule(6, mpEIGo.juqQQs.esbSDO.R.attr.tv_tab_title);
            }
            if (num <= 0) {
                params.topMargin = this.mTabDotMarginTop;
                params.rightMargin = this.mTabDotMarginRight;
            } else {
                params.topMargin = this.mTabMsgMarginTop;
                params.rightMargin = this.mTabMsgMarginRight;
            }
            tipView.setLayoutParams(params);
            if (this.mInitSetMap.get(position)) {
                return;
            }
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
        if (tipView != null) {
            tipView.setVisibility(8);
        }
    }

    public MsgView getMsgView(int position) {
        int i = this.mTabCount;
        if (position >= i) {
            position = i - 1;
        }
        View tabView = this.mTabsContainer.getChildAt(position);
        return (MsgView) tabView.findViewById(mpEIGo.juqQQs.esbSDO.R.attr.rtv_msg_tip);
    }

    public TextView getTitle(int position) {
        int i = this.mTabCount;
        if (position >= i) {
            position = i - 1;
        }
        View tabView = this.mTabsContainer.getChildAt(position);
        if (tabView == null) {
            return null;
        }
        return (TextView) tabView.findViewById(mpEIGo.juqQQs.esbSDO.R.attr.tv_tab_title);
    }

    public ImageView getDmgView(int position) {
        int i = this.mTabCount;
        if (position >= i) {
            position = i - 1;
        }
        View tabView = this.mTabsContainer.getChildAt(position);
        if (tabView == null) {
            return null;
        }
        return (ImageView) tabView.findViewById(mpEIGo.juqQQs.esbSDO.R.attr.tv_tab_title_dmg);
    }

    public class InnerPagerAdapter extends FragmentPagerAdapter {
        protected ArrayList<Fragment> fragments;
        protected String[] titles;

        public InnerPagerAdapter(FragmentManager fm, ArrayList<Fragment> fragments, String[] titles) {
            super(fm);
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

    protected int dp2px(float dp) {
        return AndroidUtilities.dp(dp);
    }

    protected float sp2px(float sp) {
        return AndroidUtilities.sp2px(sp);
    }

    public static abstract class CustomAdapter {
        public abstract void bindView(int i, View view, boolean z);

        public abstract int getTabCount();

        public abstract CharSequence getTitle(View view, int i);

        public int getTabResLayoutId() {
            return mpEIGo.juqQQs.esbSDO.R.layout.layout_scale_tab;
        }

        public void pageSelected(View currentTab, int position, View currentLastTab, int lastSelectPosition) {
        }

        Drawable getTabDrawable() {
            return null;
        }
    }
}
