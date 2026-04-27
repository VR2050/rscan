package im.uwrkaxlmjj.ui.hviews.slidemenu;

import android.R;
import android.content.Context;
import android.content.res.AssetManager;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.os.Handler;
import android.util.AttributeSet;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewConfiguration;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.view.animation.Animation;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.core.content.ContextCompat;
import androidx.core.view.ViewCompat;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.ui.actionbar.Theme;

/* JADX INFO: loaded from: classes5.dex */
public class SwipeLayout extends FrameLayout implements View.OnTouchListener, View.OnClickListener {
    private static final long ANIMATION_MAX_DURATION = 300;
    private static final long ANIMATION_MIN_DURATION = 100;
    public static final int ITEM_STATE_COLLAPSED = 2;
    public static final int ITEM_STATE_LEFT_EXPAND = 0;
    public static final int ITEM_STATE_RIGHT_EXPAND = 1;
    private static final int NO_ID = 0;
    private static final String TAG = "SwipeLayout";
    private static Typeface typeface;
    private boolean autoHideSwipe;
    private boolean canFullSwipeFromLeft;
    private boolean canFullSwipeFromRight;
    private WeightAnimation collapseAnim;
    private Animation.AnimationListener collapseListener;
    boolean directionLeft;
    private int dividerWidth;
    float downRawX;
    long downTime;
    float downX;
    float downY;
    private WeightAnimation expandAnim;
    private int fullSwipeEdgePadding;
    private int iconSize;
    int id;
    boolean invokedFromLeft;
    private int itemWidth;
    long lastTime;
    private int layoutId;
    private int[] leftColors;
    private int[] leftIconColors;
    private int[] leftIcons;
    private int leftLayoutMaxWidth;
    private LinearLayout leftLinear;
    private LinearLayout leftLinearWithoutFirst;
    private int[] leftTextColors;
    private String[] leftTexts;
    private View[] leftViews;
    private Handler longClickHandler;
    boolean longClickPerformed;
    private Runnable longClickRunnable;
    private View mainLayout;
    boolean movementStarted;
    private boolean needDivderBetweenMainAndMenu;
    private RecyclerView.OnScrollListener onScrollListener;
    private OnSwipeItemClickListener onSwipeItemClickListener;
    private boolean onlyOneSwipe;
    float prevRawX;
    private int[] rightColors;
    private int[] rightIconColors;
    private int[] rightIcons;
    private int rightLayoutMaxWidth;
    private LinearLayout rightLinear;
    private LinearLayout rightLinearWithoutLast;
    private int[] rightTextColors;
    private String[] rightTexts;
    private View[] rightViews;
    boolean shouldPerformLongClick;
    float speed;
    private boolean swipeEnabled;
    private float textSize;
    private int textTopMargin;

    public interface OnSwipeItemClickListener {
        void onSwipeItemClick(boolean z, int i);
    }

    public void setLeftColors(int[] leftColors) {
        this.leftColors = leftColors;
    }

    public SwipeLayout(Context context) {
        this(context, null);
    }

    public void setOnSwipeItemClickListener(OnSwipeItemClickListener onSwipeItemClickListener) {
        this.onSwipeItemClickListener = onSwipeItemClickListener;
    }

    public SwipeLayout(Context context, AttributeSet attrs) {
        super(context, attrs);
        this.itemWidth = 100;
        this.textTopMargin = 20;
        this.swipeEnabled = true;
        this.autoHideSwipe = true;
        this.onlyOneSwipe = true;
        this.needDivderBetweenMainAndMenu = true;
        this.dividerWidth = AndroidUtilities.dp(10.0f);
        this.prevRawX = -1.0f;
        this.longClickHandler = new Handler();
        this.longClickRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.hviews.slidemenu.SwipeLayout.1
            @Override // java.lang.Runnable
            public void run() {
                if (SwipeLayout.this.shouldPerformLongClick && SwipeLayout.this.performLongClick()) {
                    SwipeLayout.this.longClickPerformed = true;
                    SwipeLayout.this.setPressed(false);
                }
            }
        };
        this.collapseListener = new Animation.AnimationListener() { // from class: im.uwrkaxlmjj.ui.hviews.slidemenu.SwipeLayout.2
            @Override // android.view.animation.Animation.AnimationListener
            public void onAnimationStart(Animation animation) {
            }

            @Override // android.view.animation.Animation.AnimationListener
            public void onAnimationEnd(Animation animation) {
                SwipeLayout.this.clickBySwipe();
            }

            @Override // android.view.animation.Animation.AnimationListener
            public void onAnimationRepeat(Animation animation) {
            }
        };
        this.fullSwipeEdgePadding = AndroidUtilities.dp(100.0f);
        if (attrs != null) {
            setUpAttrs(attrs);
        }
        setUpView();
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onAttachedToWindow() {
        super.onAttachedToWindow();
        setAutoHideSwipe(this.autoHideSwipe);
        setOnlyOneSwipe(this.onlyOneSwipe);
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onDetachedFromWindow() {
        setItemState(2, false);
        super.onDetachedFromWindow();
    }

    @Override // android.view.ViewGroup
    public void addView(View child, int index, ViewGroup.LayoutParams params) {
        if (this.mainLayout == null) {
            this.mainLayout = child;
            setUpView();
        } else {
            super.addView(child, index, params);
        }
    }

    public void setUpView(View layout) {
        this.mainLayout = layout;
        compareArrays(this.leftColors, this.leftIcons);
        compareArrays(this.rightColors, this.rightIcons);
        compareArrays(this.leftIconColors, this.leftIcons);
        compareArrays(this.rightIconColors, this.rightIcons);
        addView(this.mainLayout);
        createItemLayouts();
        this.mainLayout.bringToFront();
        this.mainLayout.setOnTouchListener(this);
    }

    public View getMainLayout() {
        return this.mainLayout;
    }

    private void setUpView() {
        if (this.layoutId != 0) {
            this.mainLayout = LayoutInflater.from(getContext()).inflate(this.layoutId, (ViewGroup) null);
        }
        if (this.mainLayout != null) {
            compareArrays(this.leftColors, this.leftIcons);
            compareArrays(this.rightColors, this.rightIcons);
            compareArrays(this.leftIconColors, this.leftIcons);
            compareArrays(this.rightIconColors, this.rightIcons);
            addView(this.mainLayout);
            createItemLayouts();
            this.mainLayout.bringToFront();
            this.mainLayout.setOnTouchListener(this);
        }
    }

    private void compareArrays(int[] arr1, int[] arr2) {
        if (arr1 != null && arr2 != null && arr1.length < arr2.length) {
            throw new IllegalStateException("Drawable array shouldn't be bigger than color array");
        }
    }

    public void invalidateSwipeItems() {
        createItemLayouts();
    }

    public void setItemWidth(int width) {
        this.itemWidth = width;
    }

    public void rebuildLayout() {
        createItemLayouts();
        this.mainLayout.bringToFront();
        this.mainLayout.setOnTouchListener(this);
    }

    private void createItemLayouts() {
        int leftSize;
        int rightSize;
        int[] iArr = this.leftIcons;
        if (iArr != null) {
            leftSize = iArr.length;
        } else {
            String[] strArr = this.leftTexts;
            if (strArr != null) {
                leftSize = strArr.length;
            } else {
                leftSize = 0;
            }
        }
        int[] iArr2 = this.rightIcons;
        if (iArr2 != null) {
            rightSize = iArr2.length;
        } else {
            String[] strArr2 = this.rightTexts;
            if (strArr2 != null) {
                rightSize = strArr2.length;
            } else {
                rightSize = 0;
            }
        }
        if (this.rightIcons != null || this.rightTexts != null) {
            this.rightLayoutMaxWidth = this.itemWidth * rightSize;
            LinearLayout linearLayout = this.rightLinear;
            if (linearLayout != null) {
                removeView(linearLayout);
            }
            LinearLayout linearLayoutCreateLinearLayout = createLinearLayout(5);
            this.rightLinear = linearLayoutCreateLinearLayout;
            if (this.needDivderBetweenMainAndMenu) {
                linearLayoutCreateLinearLayout.addView(getDividerView());
                this.rightLayoutMaxWidth += this.dividerWidth;
            }
            LinearLayout linearLayoutCreateLinearLayout2 = createLinearLayout(5);
            this.rightLinearWithoutLast = linearLayoutCreateLinearLayout2;
            linearLayoutCreateLinearLayout2.setLayoutParams(new LinearLayout.LayoutParams(0, -1, rightSize - 1));
            addView(this.rightLinear);
            this.rightViews = new View[rightSize];
            this.rightLinear.addView(this.rightLinearWithoutLast);
            addSwipeItems(rightSize, this.rightIcons, this.rightIconColors, this.rightColors, this.rightTexts, this.rightTextColors, this.rightLinear, this.rightLinearWithoutLast, this.rightViews, false);
        }
        if (this.leftIcons != null || this.leftTexts != null) {
            this.leftLayoutMaxWidth = this.itemWidth * leftSize;
            LinearLayout linearLayout2 = this.leftLinear;
            if (linearLayout2 != null) {
                removeView(linearLayout2);
            }
            this.leftLinear = createLinearLayout(3);
            LinearLayout linearLayoutCreateLinearLayout3 = createLinearLayout(3);
            this.leftLinearWithoutFirst = linearLayoutCreateLinearLayout3;
            linearLayoutCreateLinearLayout3.setLayoutParams(new LinearLayout.LayoutParams(0, -1, leftSize - 1));
            this.leftViews = new View[leftSize];
            addView(this.leftLinear);
            addSwipeItems(leftSize, this.leftIcons, this.leftIconColors, this.leftColors, this.leftTexts, this.leftTextColors, this.leftLinear, this.leftLinearWithoutFirst, this.leftViews, true);
            this.leftLinear.addView(this.leftLinearWithoutFirst);
            if (this.needDivderBetweenMainAndMenu) {
                this.leftLinear.addView(getDividerView());
                this.leftLayoutMaxWidth += this.dividerWidth;
            }
        }
    }

    private View getDividerView() {
        View diverView = new View(getContext());
        FrameLayout.LayoutParams lp = new FrameLayout.LayoutParams(this.dividerWidth, -1);
        diverView.setLayoutParams(lp);
        diverView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        return diverView;
    }

    public void setDividerWidth(int dividerWidth) {
        this.dividerWidth = dividerWidth;
    }

    private void addSwipeItems(int size, int[] icons, int[] iconColors, int[] backgroundColors, String[] texts, int[] textColors, LinearLayout layout, LinearLayout layoutWithout, View[] views, boolean left) {
        int backgroundColor;
        int iconColor;
        String txt;
        int textColor;
        for (int i = 0; i < size; i++) {
            int icon = 0;
            if (icons != null) {
                icon = icons[i];
            }
            if (backgroundColors == null) {
                backgroundColor = 0;
            } else {
                int backgroundColor2 = backgroundColors[i];
                backgroundColor = backgroundColor2;
            }
            if (iconColors == null) {
                iconColor = 0;
            } else {
                int iconColor2 = iconColors[i];
                iconColor = iconColor2;
            }
            if (texts == null) {
                txt = null;
            } else {
                String txt2 = texts[i];
                txt = txt2;
            }
            if (textColors == null) {
                textColor = 0;
            } else {
                int textColor2 = textColors[i];
                textColor = textColor2;
            }
            ViewGroup swipeItem = createSwipeItem(icon, iconColor, backgroundColor, txt, textColor, left);
            int i2 = 1;
            swipeItem.setClickable(true);
            swipeItem.setFocusable(true);
            swipeItem.setOnClickListener(this);
            views[i] = swipeItem;
            if (left) {
                i2 = size;
            }
            if (i == size - i2) {
                layout.addView(swipeItem);
            } else {
                layoutWithout.addView(swipeItem);
            }
        }
    }

    public void setAlphaAtIndex(boolean left, int index, float alpha) {
        View[] views = left ? this.leftViews : this.rightViews;
        if (index <= views.length - 1) {
            views[index].setAlpha(alpha);
        }
    }

    public void setEnableAtIndex(boolean left, int index, boolean enabled) {
        View[] views = left ? this.leftViews : this.rightViews;
        if (index <= views.length - 1) {
            views[index].setEnabled(enabled);
        }
    }

    public void setTextAtIndex(boolean left, int index, String text) {
        View[] views = left ? this.leftViews : this.rightViews;
        if (index <= views.length - 1) {
            TextView textViews = (TextView) views[index].findViewWithTag("text");
            textViews.setText(text);
        }
    }

    public void setIconAtIndex(boolean left, int index, int resId) {
        View[] views = left ? this.leftViews : this.rightViews;
        if (index <= views.length - 1) {
            ImageView imageView = (ImageView) views[index].findViewWithTag("icon");
            imageView.setImageResource(resId);
        }
    }

    public void setbackgroudAtIndex(boolean left, int index, int color) {
        View[] views = left ? this.leftViews : this.rightViews;
        if (index <= views.length - 1) {
            View view = views[index];
            view.setBackgroundColor(color);
        }
    }

    public float getAlphaAtIndex(boolean left, int index) {
        View[] views = left ? this.leftViews : this.rightViews;
        if (index <= views.length - 1) {
            return views[index].getAlpha();
        }
        return 1.0f;
    }

    public void setTexts(boolean left, String[] texts) {
        View[] views = left ? this.leftViews : this.rightViews;
        if (views != null) {
            if (views != null && views.length <= 0) {
                return;
            }
            for (int i = 0; i < views.length; i++) {
                TextView textView = (TextView) views[i].findViewWithTag("text");
                textView.setText(texts[i]);
            }
        }
    }

    public void setIcons(boolean left, int[] icons) {
        View[] views = left ? this.leftViews : this.rightViews;
        if (views != null) {
            if (views != null && views.length <= 0) {
                return;
            }
            for (int i = 0; i < views.length; i++) {
                ImageView imageView = (ImageView) views[i].findViewWithTag("icon");
                imageView.setImageResource(icons[i]);
            }
        }
    }

    public boolean isEnabledAtIndex(boolean left, int index) {
        View[] views = left ? this.leftViews : this.rightViews;
        if (index <= views.length - 1) {
            return views[index].isEnabled();
        }
        return true;
    }

    public View[] getRightViews() {
        return this.rightViews;
    }

    public View[] getLeftViews() {
        return this.leftViews;
    }

    @Override // android.view.View
    public void setOnClickListener(View.OnClickListener l) {
        this.mainLayout.setOnClickListener(l);
    }

    public void setBackgroundSelector(int color) {
        this.mainLayout.setBackground(Theme.getSelectorDrawable(false));
    }

    private Drawable getRippleDrawable() {
        int[] attrs = {R.attr.selectableItemBackground};
        TypedArray ta = getContext().obtainStyledAttributes(attrs);
        Drawable ripple = ta.getDrawable(0);
        ta.recycle();
        return ripple;
    }

    private ViewGroup createSwipeItem(int icon, int iconColor, int backgroundColor, String text, int textColor, boolean left) {
        int gravity;
        FrameLayout frameLayout = new FrameLayout(getContext());
        frameLayout.setLayoutParams(new LinearLayout.LayoutParams(0, -1, 1.0f));
        if (Build.VERSION.SDK_INT >= 16) {
            View view = new View(getContext());
            view.setLayoutParams(new FrameLayout.LayoutParams(-1, -1));
            view.setBackground(getRippleDrawable());
            frameLayout.addView(view);
        }
        if (backgroundColor != 0) {
            frameLayout.setBackgroundColor(backgroundColor);
        }
        ImageView imageView = null;
        if (icon != 0) {
            imageView = new ImageView(getContext());
            imageView.setTag("icon");
            Drawable drawable = ContextCompat.getDrawable(getContext(), icon);
            if (iconColor != 0) {
                drawable = Utils.setTint(drawable, iconColor);
            }
            imageView.setImageDrawable(drawable);
        }
        RelativeLayout relativeLayout = new RelativeLayout(getContext());
        if (left) {
            gravity = 16 | 5;
        } else {
            gravity = 16 | 3;
        }
        relativeLayout.setLayoutParams(new FrameLayout.LayoutParams(this.itemWidth, -2, gravity));
        if (imageView != null) {
            int i = this.iconSize;
            RelativeLayout.LayoutParams imageViewParams = new RelativeLayout.LayoutParams(i, i);
            imageViewParams.addRule(14, -1);
            imageView.setLayoutParams(imageViewParams);
            int i2 = this.id + 1;
            this.id = i2;
            imageView.setId(i2);
            relativeLayout.addView(imageView);
        }
        if (text != null) {
            TextView textView = new TextView(getContext());
            textView.setMaxLines(2);
            float f = this.textSize;
            if (f > 0.0f) {
                textView.setTextSize(0, f);
            }
            if (textColor != 0) {
                textView.setTextColor(textColor);
            }
            Typeface typeface2 = typeface;
            if (typeface2 != null) {
                textView.setTypeface(typeface2);
            }
            textView.setText(text);
            textView.setTag("text");
            textView.setGravity(17);
            RelativeLayout.LayoutParams textViewParams = new RelativeLayout.LayoutParams(this.itemWidth, -2);
            if (imageView != null) {
                textViewParams.addRule(3, this.id);
                textViewParams.topMargin = this.textTopMargin;
            } else {
                textViewParams.addRule(13, this.id);
            }
            relativeLayout.addView(textView, textViewParams);
        }
        frameLayout.setOnTouchListener(this);
        frameLayout.addView(relativeLayout);
        return frameLayout;
    }

    private LinearLayout createLinearLayout(int gravity) {
        LinearLayout linearLayout = new LinearLayout(getContext());
        linearLayout.setOrientation(0);
        FrameLayout.LayoutParams params = new FrameLayout.LayoutParams(0, -1);
        params.gravity = gravity;
        linearLayout.setLayoutParams(params);
        return linearLayout;
    }

    private void setUpAttrs(AttributeSet attrs) {
        TypedArray array = getContext().obtainStyledAttributes(attrs, im.uwrkaxlmjj.messenger.R.styleable.SwipeLayout);
        if (array != null) {
            this.layoutId = array.getResourceId(4, 0);
            this.itemWidth = array.getDimensionPixelSize(17, 100);
            this.iconSize = array.getDimensionPixelSize(5, -1);
            this.textSize = array.getDimensionPixelSize(18, 0);
            this.textTopMargin = array.getDimensionPixelSize(19, 14);
            this.canFullSwipeFromRight = array.getBoolean(2, false);
            this.canFullSwipeFromLeft = array.getBoolean(1, false);
            this.onlyOneSwipe = array.getBoolean(11, true);
            this.autoHideSwipe = array.getBoolean(0, true);
            int rightIconsRes = array.getResourceId(14, 0);
            int rightIconColors = array.getResourceId(12, 0);
            int rightTextRes = array.getResourceId(15, 0);
            int rightTextColorRes = array.getResourceId(16, 0);
            int rightColorsRes = array.getResourceId(13, 0);
            int leftIconsRes = array.getResourceId(8, 0);
            int leftIconColors = array.getResourceId(6, 0);
            int leftTextRes = array.getResourceId(9, 0);
            int leftTextColorRes = array.getResourceId(10, 0);
            int leftColorsRes = array.getResourceId(7, 0);
            String typefaceAssetPath = array.getString(3);
            if (typefaceAssetPath != null && typeface == null) {
                AssetManager assetManager = getContext().getAssets();
                typeface = Typeface.createFromAsset(assetManager, typefaceAssetPath);
            }
            initiateArrays(rightColorsRes, rightIconsRes, leftColorsRes, leftIconsRes, leftTextRes, rightTextRes, leftTextColorRes, rightTextColorRes, leftIconColors, rightIconColors);
            array.recycle();
        }
    }

    private void initiateArrays(int rightColorsRes, int rightIconsRes, int leftColorsRes, int leftIconsRes, int leftTextRes, int rightTextRes, int leftTextColorRes, int rightTextColorRes, int leftIconColorsRes, int rightIconColorsRes) {
        Resources res = getResources();
        if (rightColorsRes != 0) {
            this.rightColors = res.getIntArray(rightColorsRes);
        }
        if (rightIconsRes != 0 && !isInEditMode()) {
            this.rightIcons = fillDrawables(res.obtainTypedArray(rightIconsRes));
        }
        if (leftColorsRes != 0) {
            this.leftColors = res.getIntArray(leftColorsRes);
        }
        if (leftIconsRes != 0 && !isInEditMode()) {
            this.leftIcons = fillDrawables(res.obtainTypedArray(leftIconsRes));
        }
        if (leftTextRes != 0) {
            this.leftTexts = res.getStringArray(leftTextRes);
        }
        if (rightTextRes != 0) {
            this.rightTexts = res.getStringArray(rightTextRes);
        }
        if (leftTextColorRes != 0) {
            this.leftTextColors = res.getIntArray(leftTextColorRes);
        }
        if (rightTextColorRes != 0) {
            this.rightTextColors = res.getIntArray(rightTextColorRes);
        }
        if (leftIconColorsRes != 0) {
            this.leftIconColors = res.getIntArray(leftIconColorsRes);
        }
        if (rightIconColorsRes != 0) {
            this.rightIconColors = res.getIntArray(rightIconColorsRes);
        }
    }

    public void setLeftIcons(int... leftIcons) {
        this.leftIcons = leftIcons;
    }

    public void setLeftIconColors(int... leftIconColors) {
        this.leftIconColors = leftIconColors;
    }

    public void setRightColors(int... rightColors) {
        this.rightColors = rightColors;
    }

    public void setRightIcons(int... rightIcons) {
        this.rightIcons = rightIcons;
    }

    public void setIconSize(int size) {
        this.iconSize = size;
    }

    public void setRightIconColors(int... rightIconColors) {
        this.rightIconColors = rightIconColors;
    }

    public void setRightTextColors(int... rightTextColors) {
        this.rightTextColors = rightTextColors;
    }

    public void setLeftTextColors(int... leftTextColors) {
        this.leftTextColors = leftTextColors;
    }

    public void setLeftTexts(String... leftTexts) {
        this.leftTexts = leftTexts;
    }

    public void setRightTexts(String... rightTexts) {
        this.rightTexts = rightTexts;
    }

    public void setTextSize(float size) {
        this.textSize = size;
    }

    private int[] fillDrawables(TypedArray ta) {
        int[] drawableArr = new int[ta.length()];
        for (int i = 0; i < ta.length(); i++) {
            drawableArr[i] = ta.getResourceId(i, 0);
        }
        ta.recycle();
        return drawableArr;
    }

    private void clearAnimations() {
        this.mainLayout.clearAnimation();
        LinearLayout linearLayout = this.rightLinear;
        if (linearLayout != null) {
            linearLayout.clearAnimation();
        }
        LinearLayout linearLayout2 = this.leftLinear;
        if (linearLayout2 != null) {
            linearLayout2.clearAnimation();
        }
        LinearLayout linearLayout3 = this.rightLinearWithoutLast;
        if (linearLayout3 != null) {
            linearLayout3.clearAnimation();
        }
        LinearLayout linearLayout4 = this.leftLinearWithoutFirst;
        if (linearLayout4 != null) {
            linearLayout4.clearAnimation();
        }
    }

    @Override // android.view.View
    public void setPressed(boolean pressed) {
        super.setPressed(pressed);
        if (Build.VERSION.SDK_INT >= 21) {
            drawableHotspotChanged(this.downX, this.downY);
        }
    }

    private View[] getCollapsibleViews() {
        return this.invokedFromLeft ? this.leftViews : this.rightViews;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void clickBySwipe() {
        OnSwipeItemClickListener onSwipeItemClickListener = this.onSwipeItemClickListener;
        if (onSwipeItemClickListener != null) {
            boolean z = this.invokedFromLeft;
            onSwipeItemClickListener.onSwipeItemClick(z, z ? 0 : this.rightViews.length - 1);
        }
    }

    @Override // android.view.View.OnTouchListener
    public boolean onTouch(View view, MotionEvent event) {
        int leftSize;
        int rightSize;
        WeightAnimation weightAnimation;
        WeightAnimation weightAnimation2;
        boolean z;
        WeightAnimation weightAnimation3;
        WeightAnimation weightAnimation4;
        if (this.swipeEnabled && (this.leftIcons != null || this.leftTexts != null || this.rightIcons != null || this.rightTexts != null)) {
            int[] iArr = this.leftIcons;
            if (iArr != null) {
                leftSize = iArr.length;
            } else {
                String[] strArr = this.leftTexts;
                if (strArr != null) {
                    leftSize = strArr.length;
                } else {
                    leftSize = 0;
                }
            }
            int[] iArr2 = this.rightIcons;
            if (iArr2 != null) {
                rightSize = iArr2.length;
            } else {
                String[] strArr2 = this.rightTexts;
                if (strArr2 != null) {
                    rightSize = strArr2.length;
                } else {
                    rightSize = 0;
                }
            }
            int action = event.getAction();
            if (action == 0) {
                this.downX = event.getX();
                this.downY = event.getY();
                long jCurrentTimeMillis = System.currentTimeMillis();
                this.lastTime = jCurrentTimeMillis;
                this.downTime = jCurrentTimeMillis;
                float rawX = event.getRawX();
                this.prevRawX = rawX;
                this.downRawX = rawX;
                if (ViewCompat.getTranslationX(this.mainLayout) != 0.0f) {
                    return true;
                }
                LinearLayout linearLayout = this.rightLinearWithoutLast;
                if (linearLayout != null) {
                    Utils.setViewWeight(linearLayout, this.rightViews.length - 1);
                }
                LinearLayout linearLayout2 = this.leftLinearWithoutFirst;
                if (linearLayout2 == null) {
                    return true;
                }
                Utils.setViewWeight(linearLayout2, this.leftViews.length - 1);
                return true;
            }
            if (action == 1) {
                finishMotion(event);
                if (this.movementStarted) {
                    finishSwipeAnimated();
                } else {
                    view.setPressed(false);
                    if (System.currentTimeMillis() - this.downTime < ViewConfiguration.getTapTimeout()) {
                        view.setPressed(true);
                        view.performClick();
                        view.setPressed(false);
                    }
                }
                return false;
            }
            if (action == 2) {
                if (Math.abs(this.prevRawX - event.getRawX()) < 20.0f && !this.movementStarted) {
                    if (System.currentTimeMillis() - this.lastTime >= 50 && !isPressed() && !isExpanding() && !this.longClickPerformed) {
                        view.setPressed(true);
                        if (!this.shouldPerformLongClick) {
                            this.shouldPerformLongClick = true;
                            this.longClickHandler.postDelayed(this.longClickRunnable, ViewConfiguration.getLongPressTimeout());
                        }
                    }
                    return false;
                }
                if (view.isPressed()) {
                    view.setPressed(false);
                }
                this.shouldPerformLongClick = false;
                this.movementStarted = true;
                collapseOthersIfNeeded();
                clearAnimations();
                this.directionLeft = this.prevRawX - event.getRawX() > 0.0f;
                float delta = Math.abs(this.prevRawX - event.getRawX());
                this.speed = (System.currentTimeMillis() - this.lastTime) / delta;
                if (this.directionLeft) {
                    float left = ViewCompat.getTranslationX(this.mainLayout) - delta;
                    int i = this.rightLayoutMaxWidth;
                    if (left < (-i)) {
                        if (!this.canFullSwipeFromRight) {
                            left = -i;
                        } else if (left < (-getWidth())) {
                            left = -getWidth();
                        }
                    }
                    if (this.canFullSwipeFromRight) {
                        if (ViewCompat.getTranslationX(this.mainLayout) <= (-(getWidth() - this.fullSwipeEdgePadding))) {
                            if (Utils.getViewWeight(this.rightLinearWithoutLast) > 0.0f && ((weightAnimation4 = this.collapseAnim) == null || weightAnimation4.hasEnded())) {
                                view.setPressed(false);
                                this.rightLinearWithoutLast.clearAnimation();
                                if (this.expandAnim != null) {
                                    this.expandAnim = null;
                                }
                                this.collapseAnim = new WeightAnimation(0.0f, this.rightLinearWithoutLast);
                                Log.d("WeightAnim", "onTouch - Collapse");
                                view.performHapticFeedback(3, 2);
                                startAnimation(this.collapseAnim);
                            }
                        } else if (Utils.getViewWeight(this.rightLinearWithoutLast) < rightSize - 1.0f && ((weightAnimation3 = this.expandAnim) == null || weightAnimation3.hasEnded())) {
                            Log.d("WeightAnim", "onTouch - Expand");
                            view.setPressed(false);
                            this.rightLinearWithoutLast.clearAnimation();
                            if (this.collapseAnim != null) {
                                this.collapseAnim = null;
                            }
                            WeightAnimation weightAnimation5 = new WeightAnimation(rightSize - 1, this.rightLinearWithoutLast);
                            this.expandAnim = weightAnimation5;
                            startAnimation(weightAnimation5);
                        }
                    }
                    ViewCompat.setTranslationX(this.mainLayout, left);
                    if (this.rightLinear != null) {
                        int rightLayoutWidth = (int) Math.abs(left);
                        Utils.setViewWidth(this.rightLinear, rightLayoutWidth);
                    }
                    if (this.leftLinear != null && left > 0.0f) {
                        int leftLayoutWidth = (int) Math.abs(ViewCompat.getTranslationX(this.mainLayout));
                        Utils.setViewWidth(this.leftLinear, leftLayoutWidth);
                    }
                } else {
                    float right = ViewCompat.getTranslationX(this.mainLayout) + delta;
                    int i2 = this.leftLayoutMaxWidth;
                    if (right > i2) {
                        if (!this.canFullSwipeFromLeft) {
                            right = i2;
                        } else if (right >= getWidth()) {
                            right = getWidth();
                        }
                    }
                    if (this.canFullSwipeFromLeft) {
                        if (ViewCompat.getTranslationX(this.mainLayout) >= getWidth() - this.fullSwipeEdgePadding) {
                            if (Utils.getViewWeight(this.leftLinearWithoutFirst) > 0.0f && ((weightAnimation2 = this.collapseAnim) == null || weightAnimation2.hasEnded())) {
                                this.leftLinearWithoutFirst.clearAnimation();
                                if (this.expandAnim != null) {
                                    this.expandAnim = null;
                                }
                                this.collapseAnim = new WeightAnimation(0.0f, this.leftLinearWithoutFirst);
                                view.performHapticFeedback(3, 2);
                                startAnimation(this.collapseAnim);
                            }
                        } else if (Utils.getViewWeight(this.leftLinearWithoutFirst) < leftSize - 1.0f && ((weightAnimation = this.expandAnim) == null || weightAnimation.hasEnded())) {
                            this.leftLinearWithoutFirst.clearAnimation();
                            if (this.collapseAnim != null) {
                                this.collapseAnim = null;
                            }
                            WeightAnimation weightAnimation6 = new WeightAnimation(leftSize - 1, this.leftLinearWithoutFirst);
                            this.expandAnim = weightAnimation6;
                            startAnimation(weightAnimation6);
                        }
                    }
                    ViewCompat.setTranslationX(this.mainLayout, right);
                    if (this.leftLinear != null && right > 0.0f) {
                        int leftLayoutWidth2 = (int) Math.abs(right);
                        Utils.setViewWidth(this.leftLinear, leftLayoutWidth2);
                    }
                    if (this.rightLinear != null) {
                        int rightLayoutWidth2 = (int) Math.abs(ViewCompat.getTranslationX(this.mainLayout));
                        Utils.setViewWidth(this.rightLinear, rightLayoutWidth2);
                    }
                }
                if (Math.abs(ViewCompat.getTranslationX(this.mainLayout)) <= this.itemWidth / 5) {
                    z = true;
                } else {
                    z = true;
                    getParent().requestDisallowInterceptTouchEvent(true);
                }
                this.prevRawX = event.getRawX();
                this.lastTime = System.currentTimeMillis();
                return z;
            }
            if (action == 3) {
                finishMotion(event);
                if (this.movementStarted) {
                    finishSwipeAnimated();
                }
                return false;
            }
        }
        return false;
    }

    private void collapseOthersIfNeeded() {
        ViewParent parent;
        if (this.onlyOneSwipe && (parent = getParent()) != null && (parent instanceof RecyclerView)) {
            RecyclerView recyclerView = (RecyclerView) parent;
            int count = recyclerView.getChildCount();
            for (int i = 0; i < count; i++) {
                View item = recyclerView.getChildAt(i);
                if (item != this && (item instanceof SwipeLayout)) {
                    SwipeLayout swipeLayout = (SwipeLayout) item;
                    if (ViewCompat.getTranslationX(swipeLayout.getSwipeableView()) != 0.0f && !swipeLayout.inAnimatedState()) {
                        swipeLayout.setItemState(2, true);
                    }
                }
            }
        }
    }

    public View getSwipeableView() {
        return this.mainLayout;
    }

    private void finishMotion(MotionEvent event) {
        this.directionLeft = event.getRawX() - this.downRawX < 0.0f;
        this.longClickHandler.removeCallbacks(this.longClickRunnable);
        this.shouldPerformLongClick = false;
        this.longClickPerformed = false;
    }

    private void finishSwipeAnimated() {
        int reqWidth;
        int reqWidth2;
        this.shouldPerformLongClick = false;
        setPressed(false);
        getParent().requestDisallowInterceptTouchEvent(false);
        this.movementStarted = false;
        LinearLayout animateView = null;
        boolean left = false;
        int requiredWidth = 0;
        if (ViewCompat.getTranslationX(this.mainLayout) > 0.0f) {
            animateView = this.leftLinear;
            left = true;
            if (this.leftLinear != null) {
                if (this.directionLeft) {
                    int i = this.leftLayoutMaxWidth;
                    reqWidth2 = i - (i / 3);
                } else {
                    reqWidth2 = this.leftLayoutMaxWidth / 3;
                }
                LinearLayout linearLayout = this.rightLinear;
                if (linearLayout != null) {
                    Utils.setViewWidth(linearLayout, 0);
                }
                if (this.leftLinear.getWidth() >= reqWidth2) {
                    requiredWidth = this.leftLayoutMaxWidth;
                }
                if (requiredWidth == this.leftLayoutMaxWidth && !this.directionLeft && ViewCompat.getTranslationX(this.mainLayout) >= getWidth() - this.fullSwipeEdgePadding) {
                    requiredWidth = getWidth();
                    this.invokedFromLeft = true;
                }
                ViewCompat.setTranslationX(this.mainLayout, this.leftLinear.getWidth());
            }
        } else if (ViewCompat.getTranslationX(this.mainLayout) < 0.0f) {
            left = false;
            animateView = this.rightLinear;
            if (this.rightLinear != null) {
                LinearLayout linearLayout2 = this.leftLinear;
                if (linearLayout2 != null) {
                    Utils.setViewWidth(linearLayout2, 0);
                }
                if (this.directionLeft) {
                    reqWidth = this.rightLayoutMaxWidth / 3;
                } else {
                    int i2 = this.rightLayoutMaxWidth;
                    reqWidth = i2 - (i2 / 3);
                }
                if (this.rightLinear.getWidth() >= reqWidth) {
                    requiredWidth = this.rightLayoutMaxWidth;
                }
                if (requiredWidth == this.rightLayoutMaxWidth && this.directionLeft && ViewCompat.getTranslationX(this.mainLayout) <= (-(getWidth() - this.fullSwipeEdgePadding))) {
                    requiredWidth = getWidth();
                    this.invokedFromLeft = false;
                }
                ViewCompat.setTranslationX(this.mainLayout, -this.rightLinear.getWidth());
            }
        }
        long duration = (long) (this.speed * 100.0f);
        if (animateView != null) {
            SwipeAnimation swipeAnim = new SwipeAnimation(animateView, requiredWidth, this.mainLayout, left);
            if (duration < ANIMATION_MIN_DURATION) {
                duration = ANIMATION_MIN_DURATION;
            } else if (duration > ANIMATION_MAX_DURATION) {
                duration = ANIMATION_MAX_DURATION;
            }
            swipeAnim.setDuration(duration);
            LinearLayout layoutWithout = animateView == this.leftLinear ? this.leftLinearWithoutFirst : this.rightLinearWithoutLast;
            View[] views = animateView == this.leftLinear ? this.leftViews : this.rightViews;
            this.invokedFromLeft = animateView == this.leftLinear;
            if (requiredWidth != getWidth()) {
                WeightAnimation weightAnimation = new WeightAnimation(views.length - 1, layoutWithout);
                layoutWithout.startAnimation(weightAnimation);
            } else if (Utils.getViewWeight(layoutWithout) == 0.0f && getWidth() != Math.abs(ViewCompat.getTranslationX(this.mainLayout))) {
                swipeAnim.setAnimationListener(this.collapseListener);
            } else {
                WeightAnimation weightAnimation2 = this.collapseAnim;
                if (weightAnimation2 != null && !weightAnimation2.hasEnded()) {
                    this.collapseAnim.setAnimationListener(this.collapseListener);
                } else if (Utils.getViewWeight(layoutWithout) == 0.0f || getWidth() == Math.abs(ViewCompat.getTranslationX(this.mainLayout))) {
                    clickBySwipe();
                } else {
                    layoutWithout.clearAnimation();
                    WeightAnimation weightAnimation3 = this.collapseAnim;
                    if (weightAnimation3 != null) {
                        weightAnimation3.cancel();
                    }
                    WeightAnimation weightAnimation4 = new WeightAnimation(0.0f, layoutWithout);
                    this.collapseAnim = weightAnimation4;
                    weightAnimation4.setAnimationListener(this.collapseListener);
                    layoutWithout.startAnimation(this.collapseAnim);
                }
            }
            animateView.startAnimation(swipeAnim);
        }
    }

    @Deprecated
    public void closeItem() {
        collapseItem(true);
    }

    private void collapseItem(boolean animated) {
        LinearLayout linearLayout = this.leftLinear;
        if (linearLayout != null && linearLayout.getWidth() > 0) {
            Utils.setViewWidth(this.leftLinearWithoutFirst, this.leftViews.length - 1);
            if (animated) {
                SwipeAnimation swipeAnim = new SwipeAnimation(this.leftLinear, 0, this.mainLayout, true);
                this.leftLinear.startAnimation(swipeAnim);
                return;
            } else {
                ViewCompat.setTranslationX(this.mainLayout, 0.0f);
                Utils.setViewWidth(this.leftLinear, 0);
                return;
            }
        }
        LinearLayout linearLayout2 = this.rightLinear;
        if (linearLayout2 != null && linearLayout2.getWidth() > 0) {
            Utils.setViewWidth(this.rightLinearWithoutLast, this.rightViews.length - 1);
            if (animated) {
                SwipeAnimation swipeAnim2 = new SwipeAnimation(this.rightLinear, 0, this.mainLayout, false);
                this.rightLinear.startAnimation(swipeAnim2);
            } else {
                ViewCompat.setTranslationX(this.mainLayout, 0.0f);
                Utils.setViewWidth(this.rightLinear, 0);
            }
        }
    }

    public void setItemState(int state, boolean animated) {
        if (state != 0) {
            if (state != 1) {
                if (state == 2) {
                    collapseItem(animated);
                    return;
                }
                return;
            }
            int requiredWidthRight = this.rightIcons.length * this.itemWidth;
            if (animated) {
                SwipeAnimation swipeAnim = new SwipeAnimation(this.rightLinear, requiredWidthRight, this.mainLayout, false);
                this.rightLinear.startAnimation(swipeAnim);
                return;
            } else {
                ViewCompat.setTranslationX(this.mainLayout, -requiredWidthRight);
                Utils.setViewWidth(this.rightLinear, requiredWidthRight);
                return;
            }
        }
        int requiredWidthLeft = this.leftIcons.length * this.itemWidth;
        if (animated) {
            SwipeAnimation swipeAnim2 = new SwipeAnimation(this.leftLinear, requiredWidthLeft, this.mainLayout, true);
            this.leftLinear.startAnimation(swipeAnim2);
        } else {
            ViewCompat.setTranslationX(this.mainLayout, requiredWidthLeft);
            Utils.setViewWidth(this.leftLinear, requiredWidthLeft);
        }
    }

    public void setSwipeEnabled(boolean enabled) {
        this.swipeEnabled = enabled;
    }

    public boolean isSwipeEnabled() {
        return this.swipeEnabled;
    }

    public boolean inAnimatedState() {
        Animation anim;
        Animation anim2;
        LinearLayout linearLayout = this.leftLinear;
        if (linearLayout != null && (anim2 = linearLayout.getAnimation()) != null && !anim2.hasEnded()) {
            return true;
        }
        LinearLayout linearLayout2 = this.rightLinear;
        return (linearLayout2 == null || (anim = linearLayout2.getAnimation()) == null || anim.hasEnded()) ? false : true;
    }

    public void setAutoHideSwipe(boolean autoHideSwipe) {
        this.autoHideSwipe = autoHideSwipe;
        ViewParent parent = getParent();
        if (parent != null && (parent instanceof RecyclerView)) {
            RecyclerView recyclerView = (RecyclerView) parent;
            RecyclerView.OnScrollListener onScrollListener = this.onScrollListener;
            if (onScrollListener != null) {
                recyclerView.removeOnScrollListener(onScrollListener);
            }
            if (autoHideSwipe) {
                RecyclerView.OnScrollListener onScrollListener2 = new RecyclerView.OnScrollListener() { // from class: im.uwrkaxlmjj.ui.hviews.slidemenu.SwipeLayout.3
                    @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
                    public void onScrollStateChanged(RecyclerView recyclerView2, int newState) {
                        super.onScrollStateChanged(recyclerView2, newState);
                        if (newState == 1 && ViewCompat.getTranslationX(SwipeLayout.this.mainLayout) != 0.0f) {
                            SwipeLayout.this.setItemState(2, true);
                        }
                    }
                };
                this.onScrollListener = onScrollListener2;
                recyclerView.addOnScrollListener(onScrollListener2);
            }
        }
    }

    public void setOnlyOneSwipe(boolean onlyOneSwipe) {
        this.onlyOneSwipe = onlyOneSwipe;
    }

    public boolean isLeftExpanding() {
        return ViewCompat.getTranslationX(this.mainLayout) > 0.0f;
    }

    public boolean isRightExpanding() {
        return ViewCompat.getTranslationX(this.mainLayout) < 0.0f;
    }

    public boolean isExpanding() {
        return isRightExpanding() || isLeftExpanding();
    }

    public boolean isRightExpanded() {
        LinearLayout linearLayout = this.rightLinear;
        return linearLayout != null && linearLayout.getWidth() >= this.rightLayoutMaxWidth;
    }

    public boolean isLeftExpanded() {
        LinearLayout linearLayout = this.leftLinear;
        return linearLayout != null && linearLayout.getWidth() >= this.leftLayoutMaxWidth;
    }

    public boolean isExpanded() {
        return isLeftExpanded() || isRightExpanded();
    }

    public void setNeedDivderBetweenMainAndMenu(boolean needDivderBetweenMainAndMenu) {
        this.needDivderBetweenMainAndMenu = needDivderBetweenMainAndMenu;
    }

    public SwipeLayout getExpandLayout() {
        ViewParent parent = getParent();
        if (parent != null && (parent instanceof RecyclerView)) {
            RecyclerView recyclerView = (RecyclerView) parent;
            int count = recyclerView.getChildCount();
            for (int i = 0; i < count; i++) {
                View item = recyclerView.getChildAt(i);
                if (item instanceof SwipeLayout) {
                    SwipeLayout swipeLayout = (SwipeLayout) item;
                    if (swipeLayout.isExpanded() || swipeLayout.isExpanding()) {
                        return swipeLayout;
                    }
                }
            }
            return null;
        }
        return null;
    }

    @Override // android.view.View.OnClickListener
    public void onClick(View view) {
        if (this.onSwipeItemClickListener != null) {
            if (this.leftViews != null) {
                int i = 0;
                while (true) {
                    View[] viewArr = this.leftViews;
                    if (i >= viewArr.length) {
                        break;
                    }
                    View v = viewArr[i];
                    if (v != view) {
                        i++;
                    } else {
                        if (viewArr.length == 1 || Utils.getViewWeight(this.leftLinearWithoutFirst) > 0.0f) {
                            this.onSwipeItemClickListener.onSwipeItemClick(true, i);
                            return;
                        }
                        return;
                    }
                }
            }
            if (this.rightViews != null) {
                int i2 = 0;
                while (true) {
                    View[] viewArr2 = this.rightViews;
                    if (i2 < viewArr2.length) {
                        View v2 = viewArr2[i2];
                        if (v2 != view) {
                            i2++;
                        } else {
                            if (viewArr2.length == 1 || Utils.getViewWeight(this.rightLinearWithoutLast) > 0.0f) {
                                this.onSwipeItemClickListener.onSwipeItemClick(false, i2);
                                return;
                            }
                            return;
                        }
                    } else {
                        return;
                    }
                }
            }
        }
    }

    public void collapseAll(boolean animated) {
        ViewParent parent = getParent();
        if (parent != null && (parent instanceof RecyclerView)) {
            RecyclerView recyclerView = (RecyclerView) parent;
            int count = recyclerView.getChildCount();
            for (int i = 0; i < count; i++) {
                View item = recyclerView.getChildAt(i);
                if (item instanceof SwipeLayout) {
                    SwipeLayout swipeLayout = (SwipeLayout) item;
                    if (ViewCompat.getTranslationX(swipeLayout.getSwipeableView()) != 0.0f) {
                        swipeLayout.setItemState(2, animated);
                    }
                }
            }
        }
    }

    public void setCanFullSwipeFromLeft(boolean fullSwipeFromLeft) {
        this.canFullSwipeFromLeft = fullSwipeFromLeft;
    }

    public void setCanFullSwipeFromRight(boolean fullSwipeFromRight) {
        this.canFullSwipeFromRight = fullSwipeFromRight;
    }
}
