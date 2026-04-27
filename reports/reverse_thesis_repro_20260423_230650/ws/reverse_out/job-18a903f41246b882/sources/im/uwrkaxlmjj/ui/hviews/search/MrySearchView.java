package im.uwrkaxlmjj.ui.hviews.search;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.ObjectAnimator;
import android.animation.ValueAnimator;
import android.content.Context;
import android.graphics.drawable.Drawable;
import android.text.Editable;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.text.method.DigitsKeyListener;
import android.util.AttributeSet;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.View;
import android.view.inputmethod.InputMethodManager;
import android.widget.EditText;
import android.widget.RelativeLayout;
import android.widget.TextView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.utils.DrawableUtils;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.EditTextBoldCursor;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class MrySearchView extends RelativeLayout {
    private boolean cancelAnimator;
    private MryCancelView cancelTextView;
    private Drawable clearImgX;
    private boolean enableAnimation;
    private ISearchViewDelegate iSearchViewDelegate;
    private boolean isSearching;
    private EditTextBoldCursor mEditText;
    private int mEditTextOffsetWidth;
    private String mHint;
    private float mLeftEdge;
    private int mPadding;
    private MrySearchTextView mTextView;
    private boolean translationAnimator;

    public interface ISearchViewDelegate {
        boolean canCollapseSearch();

        void onActionSearch(String str);

        void onSearchCollapse();

        void onSearchExpand();

        void onStart(boolean z);

        void onTextChange(String str);
    }

    public MrySearchView(Context context) {
        this(context, null);
    }

    public MrySearchView(Context context, AttributeSet attrs) {
        this(context, attrs, 0);
    }

    public MrySearchView(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        this.isSearching = false;
        init();
    }

    private void init() {
        setEnableAnimation(true);
        Drawable search = getResources().getDrawable(R.id.ic_index_search);
        search.setBounds(0, 0, search.getIntrinsicWidth(), search.getIntrinsicHeight());
        this.mPadding = dip2px(10.0f);
        EditTextBoldCursor editTextBoldCursor = new EditTextBoldCursor(getContext());
        this.mEditText = editTextBoldCursor;
        editTextBoldCursor.setHint("");
        this.mEditText.setInputType(524464);
        this.mEditText.setTextSize(14.0f);
        this.mEditText.setSingleLine(true);
        this.mEditText.setGravity(16);
        this.mEditText.setImeOptions(3);
        this.mEditText.setBackground(DrawableUtils.createLayerDrawable(Theme.getColor(Theme.key_searchview_solidColor), Theme.getColor(Theme.key_searchview_strokeColor), AndroidUtilities.dp(5.0f)));
        this.mEditText.setCursorSize(AndroidUtilities.dp(15.0f));
        this.mEditText.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        this.mEditText.setCursorColor(Theme.getColor(Theme.key_windowBackgroundValueText1));
        this.mEditText.setCursorWidth(1.0f);
        this.mEditText.setMinHeight(dip2px(45.0f));
        EditTextBoldCursor editTextBoldCursor2 = this.mEditText;
        int intrinsicWidth = search.getIntrinsicWidth();
        int i = this.mPadding;
        editTextBoldCursor2.setPadding(intrinsicWidth + ((int) (i * 2.0f)), 0, (int) (i * 2.0f), 0);
        this.mEditText.setCompoundDrawablePadding(this.mPadding / 2);
        RelativeLayout.LayoutParams layoutParams = new RelativeLayout.LayoutParams(-1, -2);
        layoutParams.addRule(15);
        addView(this.mEditText, layoutParams);
        Drawable drawable = getResources().getDrawable(R.drawable.delete);
        this.clearImgX = drawable;
        Drawable drawableTintDrawable = DrawableUtils.tintDrawable(drawable, Theme.getColor(Theme.key_windowBackgroundValueText1));
        this.clearImgX = drawableTintDrawable;
        drawableTintDrawable.setBounds(0, 0, drawableTintDrawable.getIntrinsicWidth(), this.clearImgX.getIntrinsicHeight());
        MrySearchTextView mrySearchTextView = new MrySearchTextView(getContext());
        this.mTextView = mrySearchTextView;
        mrySearchTextView.setText("");
        this.mTextView.setHint(LocaleController.getString("Search", R.string.Search));
        this.mTextView.setHintTextColor(Theme.getColor(Theme.key_windowBackgroundValueText1));
        this.mTextView.setTextSize(12.0f);
        this.mTextView.setGravity(16);
        this.mTextView.setBackgroundColor(0);
        this.mTextView.setCompoundDrawables(search, null, null, null);
        this.mTextView.setCompoundDrawablePadding(this.mPadding / 2);
        this.mTextView.setEnabled(false);
        this.mTextView.setPadding(this.mPadding / 2, 0, 0, 0);
        RelativeLayout.LayoutParams params = new RelativeLayout.LayoutParams(-1, -2);
        params.addRule(13);
        addView(this.mTextView, params);
        if (!isInEditMode() && !TextUtils.isEmpty(this.mTextView.getHint())) {
            this.mHint = this.mTextView.getHint().toString();
        }
        manageClearXButton();
        this.mEditText.setOnFocusChangeListener(new View.OnFocusChangeListener() { // from class: im.uwrkaxlmjj.ui.hviews.search.-$$Lambda$MrySearchView$KiLbfCAHDyHgWdT0ROwycmLMsYo
            @Override // android.view.View.OnFocusChangeListener
            public final void onFocusChange(View view, boolean z) {
                this.f$0.lambda$init$0$MrySearchView(view, z);
            }
        });
        this.mEditText.addTextChangedListener(new TextWatcher() { // from class: im.uwrkaxlmjj.ui.hviews.search.MrySearchView.1
            @Override // android.text.TextWatcher
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            @Override // android.text.TextWatcher
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                if (s.length() <= 0) {
                    MrySearchView.this.mTextView.setHint(MrySearchView.this.mHint);
                } else {
                    MrySearchView.this.mTextView.setHint("");
                }
                MrySearchView.this.manageClearXButton();
                if (MrySearchView.this.iSearchViewDelegate != null) {
                    if (start != 0 || before != 0 || count != 0) {
                        MrySearchView.this.iSearchViewDelegate.onTextChange(s.toString());
                    }
                }
            }

            @Override // android.text.TextWatcher
            public void afterTextChanged(Editable s) {
            }
        });
        this.mEditText.setOnEditorActionListener(new TextView.OnEditorActionListener() { // from class: im.uwrkaxlmjj.ui.hviews.search.MrySearchView.2
            @Override // android.widget.TextView.OnEditorActionListener
            public boolean onEditorAction(TextView v, int actionId, KeyEvent event) {
                if (actionId == 3) {
                    if (MrySearchView.this.iSearchViewDelegate != null) {
                        MrySearchView.this.iSearchViewDelegate.onActionSearch(MrySearchView.this.mEditText.getText().toString().trim());
                        return true;
                    }
                    return true;
                }
                return false;
            }
        });
        MryCancelView mryCancelView = new MryCancelView(this, getContext());
        this.cancelTextView = mryCancelView;
        int i2 = this.mPadding;
        mryCancelView.setPadding(i2, 0, i2, 0);
        this.cancelTextView.setText(LocaleController.getString("Cancel", R.string.Cancel));
        this.cancelTextView.setGravity(16);
        float size = this.mTextView.getTextSize() / getContext().getResources().getDisplayMetrics().density;
        this.cancelTextView.setTextSize(2, size);
        if (!isInEditMode()) {
            addClickEffect(this.cancelTextView).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hviews.search.-$$Lambda$MrySearchView$qZsCVhXClMQaShYB3giPGGfYOtU
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    this.f$0.lambda$init$1$MrySearchView(view);
                }
            });
        }
        RelativeLayout.LayoutParams params2 = new RelativeLayout.LayoutParams(-2, -1);
        params2.addRule(11);
        params2.addRule(15);
        addView(this.cancelTextView, params2);
        setFocusable(true);
        setFocusableInTouchMode(true);
        requestFocusFromTouch();
        this.mEditText.setOnTouchListener(new View.OnTouchListener() { // from class: im.uwrkaxlmjj.ui.hviews.search.-$$Lambda$MrySearchView$RSRFYSAs2Mo3_6V8hObTrHj_f_c
            @Override // android.view.View.OnTouchListener
            public final boolean onTouch(View view, MotionEvent motionEvent) {
                return this.f$0.lambda$init$2$MrySearchView(view, motionEvent);
            }
        });
    }

    public /* synthetic */ void lambda$init$0$MrySearchView(View v, boolean hasFocus) {
        ISearchViewDelegate iSearchViewDelegate = this.iSearchViewDelegate;
        if (iSearchViewDelegate != null) {
            iSearchViewDelegate.onStart(hasFocus);
        }
        if (hasFocus) {
            focused("");
            ISearchViewDelegate iSearchViewDelegate2 = this.iSearchViewDelegate;
            if (iSearchViewDelegate2 != null) {
                iSearchViewDelegate2.onTextChange("");
                this.iSearchViewDelegate.onSearchExpand();
            }
        } else {
            cancelFocus();
            ISearchViewDelegate iSearchViewDelegate3 = this.iSearchViewDelegate;
            if (iSearchViewDelegate3 != null && iSearchViewDelegate3.canCollapseSearch()) {
                this.iSearchViewDelegate.onSearchCollapse();
            }
        }
        manageClearXButton();
    }

    public /* synthetic */ void lambda$init$1$MrySearchView(View v) {
        cancelFocus();
    }

    public /* synthetic */ boolean lambda$init$2$MrySearchView(View v, MotionEvent event) {
        if (event.getAction() == 0 && event.getX() > ((this.mEditText.getWidth() - this.mEditText.getPaddingRight()) - this.clearImgX.getIntrinsicWidth()) - AndroidUtilities.dp(5.0f)) {
            this.mEditText.setText("");
            rmClearX();
            if (this.cancelTextView.getTranslationX() != 0.0f) {
                setFocusable(true);
                setFocusableInTouchMode(true);
                requestFocusFromTouch();
                if (this.enableAnimation) {
                    MrySearchTextView mrySearchTextView = this.mTextView;
                    ObjectAnimator.ofFloat(mrySearchTextView, "translationX", mrySearchTextView.getTranslationX(), 0.0f).start();
                } else {
                    this.mTextView.setTranslationX(0.0f);
                }
                return true;
            }
            return true;
        }
        return false;
    }

    public void setSearchType(int type) {
        if (type == 1) {
            this.mEditText.setKeyListener(DigitsKeyListener.getInstance("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"));
        }
    }

    public void setHintText(String text) {
        this.mTextView.setHint(text);
        this.mHint = text;
    }

    public void setFieldBackground(int resId) {
        this.mEditText.setBackgroundResource(resId);
    }

    public void setEditFieldBackground(int color) {
        this.mEditText.setBackgroundColor(color);
    }

    public void setEditTextBackground(Drawable drawable) {
        this.mEditText.setBackground(drawable);
    }

    public void setCancelBackground(int resId) {
        this.cancelTextView.setBackgroundResource(resId);
    }

    public void setCancelTextColor(int iColor) {
        this.cancelTextView.setTextColor(iColor);
    }

    public EditText getEditor() {
        return this.mEditText;
    }

    public boolean isSearchFieldVisible() {
        return this.mEditText.isFocused() || this.isSearching;
    }

    public void closeSearchField() {
        closeSearchField(true);
    }

    public void closeSearchField(boolean animation) {
        this.enableAnimation = animation;
        cancelFocus();
    }

    public void openSearchField(String value) {
        focused(value);
    }

    public void setEnableAnimation(boolean value) {
        this.enableAnimation = value;
    }

    public void setiSearchViewDelegate(ISearchViewDelegate delegate) {
        this.iSearchViewDelegate = delegate;
    }

    public View addClickEffect(View v) {
        v.setOnTouchListener(new View.OnTouchListener() { // from class: im.uwrkaxlmjj.ui.hviews.search.MrySearchView.3
            @Override // android.view.View.OnTouchListener
            public boolean onTouch(View v1, MotionEvent event) {
                int action = event.getAction();
                if (action == 0) {
                    ObjectAnimator.ofFloat(v1, "alpha", 1.0f, 0.3f).start();
                    return false;
                }
                if (action == 1 || action == 3) {
                    ObjectAnimator.ofFloat(v1, "alpha", 0.3f, 1.0f).start();
                    return false;
                }
                return false;
            }
        });
        return v;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void manageClearXButton() {
        if (TextUtils.isEmpty(this.mEditText.getText().toString())) {
            rmClearX();
        } else {
            addClearX();
        }
    }

    private void addClearX() {
        EditTextBoldCursor editTextBoldCursor = this.mEditText;
        editTextBoldCursor.setCompoundDrawables(editTextBoldCursor.getCompoundDrawables()[0], this.mEditText.getCompoundDrawables()[1], this.clearImgX, this.mEditText.getCompoundDrawables()[3]);
    }

    private void rmClearX() {
        EditTextBoldCursor editTextBoldCursor = this.mEditText;
        editTextBoldCursor.setCompoundDrawables(editTextBoldCursor.getCompoundDrawables()[0], this.mEditText.getCompoundDrawables()[1], null, this.mEditText.getCompoundDrawables()[3]);
    }

    private void focused(String value) {
        if (this.cancelTextView.getTranslationX() != 0.0f) {
            MryCancelView mryCancelView = this.cancelTextView;
            ObjectAnimator animator = ObjectAnimator.ofFloat(mryCancelView, "translationX", mryCancelView.getTranslationX(), 0.0f);
            final int width = this.mEditText.getWidth();
            int mEditTextRealWidth = width - this.cancelTextView.getWidth();
            this.mEditTextOffsetWidth = width - mEditTextRealWidth;
            final RelativeLayout.LayoutParams params = (RelativeLayout.LayoutParams) this.mEditText.getLayoutParams();
            animator.addUpdateListener(new ValueAnimator.AnimatorUpdateListener() { // from class: im.uwrkaxlmjj.ui.hviews.search.MrySearchView.4
                @Override // android.animation.ValueAnimator.AnimatorUpdateListener
                public void onAnimationUpdate(ValueAnimator animation) {
                    params.width = (int) (width - (animation.getAnimatedFraction() * MrySearchView.this.mEditTextOffsetWidth));
                    MrySearchView.this.mEditText.requestLayout();
                }
            });
            if (this.enableAnimation) {
                animator.start();
            } else {
                params.width = (int) (width - (this.mEditTextOffsetWidth * 1.0f));
                this.cancelTextView.setTranslationX(0.0f);
            }
        }
        if (this.mTextView.getTranslationX() == (-this.mLeftEdge) || this.translationAnimator) {
            return;
        }
        MrySearchTextView mrySearchTextView = this.mTextView;
        ObjectAnimator objectAnimator = ObjectAnimator.ofFloat(mrySearchTextView, "translationX", mrySearchTextView.getTranslationY(), -this.mLeftEdge);
        objectAnimator.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.hviews.search.MrySearchView.5
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                super.onAnimationEnd(animation);
                MrySearchView.this.translationAnimator = false;
                MrySearchView.this.mEditText.setAllowDrawCursor(true);
            }

            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationStart(Animator animation) {
                super.onAnimationStart(animation);
                MrySearchView.this.translationAnimator = true;
                MrySearchView.this.mEditText.setAllowDrawCursor(false);
            }
        });
        if (this.enableAnimation) {
            objectAnimator.start();
        } else {
            this.mTextView.setTranslationX(-this.mLeftEdge);
        }
        if (!TextUtils.isEmpty(value)) {
            this.mEditText.setText(value);
        }
        this.isSearching = true;
    }

    public void cancelFocus() {
        if (this.isSearching && !this.cancelAnimator) {
            this.mEditText.setText("");
            if (TextUtils.isEmpty(this.mEditText.getText().toString())) {
                MrySearchTextView mrySearchTextView = this.mTextView;
                ObjectAnimator objectAnimator = ObjectAnimator.ofFloat(mrySearchTextView, "translationX", mrySearchTextView.getTranslationX(), 0.0f);
                objectAnimator.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.hviews.search.MrySearchView.6
                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationEnd(Animator animation) {
                        super.onAnimationEnd(animation);
                        MrySearchView.this.translationAnimator = false;
                    }

                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationStart(Animator animation) {
                        super.onAnimationStart(animation);
                        MrySearchView.this.translationAnimator = true;
                    }
                });
                if (this.enableAnimation) {
                    objectAnimator.start();
                } else {
                    this.mTextView.setTranslationX(0.0f);
                }
            }
        }
        if (this.cancelTextView.getTranslationX() == 0.0f) {
            ObjectAnimator objectAnimator2 = ObjectAnimator.ofFloat(this.cancelTextView, "translationX", 0.0f, r0.getWidth());
            final int mWidth = this.mEditText.getWidth();
            final RelativeLayout.LayoutParams params = (RelativeLayout.LayoutParams) this.mEditText.getLayoutParams();
            objectAnimator2.addUpdateListener(new ValueAnimator.AnimatorUpdateListener() { // from class: im.uwrkaxlmjj.ui.hviews.search.MrySearchView.7
                @Override // android.animation.ValueAnimator.AnimatorUpdateListener
                public void onAnimationUpdate(ValueAnimator valueAnimator) {
                    params.width = (int) (mWidth + (valueAnimator.getAnimatedFraction() * MrySearchView.this.mEditTextOffsetWidth));
                    MrySearchView.this.mEditText.requestLayout();
                }
            });
            if (this.enableAnimation) {
                objectAnimator2.start();
            } else {
                this.cancelTextView.setTranslationX(r5.getWidth());
                params.width = (int) (mWidth + (this.mEditTextOffsetWidth * 1.0f));
            }
            setFocusable(true);
            setFocusableInTouchMode(true);
            requestFocus();
            hiddenKeybord();
        }
        this.isSearching = false;
    }

    @Override // android.widget.RelativeLayout, android.view.View
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        super.onMeasure(widthMeasureSpec, heightMeasureSpec);
    }

    private int dip2px(float dp) {
        float scala = getContext().getResources().getDisplayMetrics().density;
        return (int) ((dp * scala) + 0.5f);
    }

    private void hiddenKeybord() {
        InputMethodManager manager = (InputMethodManager) getContext().getSystemService("input_method");
        boolean isOpen = manager.isActive();
        if (isOpen && manager != null) {
            manager.hideSoftInputFromWindow(this.mEditText.getWindowToken(), 2);
        } else {
            manager.showSoftInputFromInputMethod(this.mEditText.getWindowToken(), 0);
        }
    }

    private class MrySearchTextView extends TextView {
        private int mWidth;

        public MrySearchTextView(Context context) {
            super(context);
        }

        public MrySearchTextView(Context context, AttributeSet attrs) {
            super(context, attrs);
        }

        public MrySearchTextView(Context context, AttributeSet attrs, int defStyleAttr) {
            super(context, attrs, defStyleAttr);
        }

        public int getViewWidth() {
            return this.mWidth;
        }

        @Override // android.view.View
        protected void onSizeChanged(int w, int h, int oldw, int oldh) {
            super.onSizeChanged(w, h, oldw, oldh);
            this.mWidth = w;
            MrySearchView.this.mLeftEdge = getLeft() - (MrySearchView.this.mPadding * 1.5f);
            MrySearchView.this.mTextView.setMinWidth(MrySearchView.this.mTextView.getViewWidth());
        }
    }

    private class MryCancelView extends TextView {
        public MryCancelView(MrySearchView mrySearchView, Context context) {
            this(mrySearchView, context, null);
        }

        public MryCancelView(MrySearchView mrySearchView, Context context, AttributeSet attrs) {
            this(context, attrs, 0);
        }

        public MryCancelView(Context context, AttributeSet attrs, int defStyleAttr) {
            super(context, attrs, defStyleAttr);
            setTextColor(Theme.getColor(Theme.key_actionBarTabActiveText));
        }

        @Override // android.widget.TextView, android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            super.onMeasure(widthMeasureSpec, heightMeasureSpec);
        }

        @Override // android.view.View
        protected void onSizeChanged(int w, int h, int oldw, int oldh) {
            super.onSizeChanged(w, h, oldw, oldh);
            setTranslationX(w);
        }
    }
}
