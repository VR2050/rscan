package im.uwrkaxlmjj.ui.actionbar;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.graphics.Canvas;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.Rect;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewTreeObserver;
import android.view.Window;
import android.view.WindowManager;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.LineProgressView;
import im.uwrkaxlmjj.ui.components.RadialProgressView;
import java.util.ArrayList;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class XAlertDialog extends Dialog implements Drawable.Callback {
    private Rect backgroundPaddings;
    protected FrameLayout buttonsLayout;
    private boolean canCacnel;
    private XAlertDialog cancelDialog;
    private ScrollView contentScrollView;
    private int currentProgress;
    private View customView;
    private int customViewOffset;
    private boolean dismissDialogByButtons;
    private Runnable dismissRunnable;
    private int[] itemIcons;
    private ArrayList<AlertDialogCell> itemViews;
    private CharSequence[] items;
    private int lastScreenWidth;
    private LineProgressView lineProgressView;
    private TextView lineProgressViewPercent;
    private ProgressBar loadingProgressView;
    private CharSequence loadingText;
    private CharSequence message;
    private TextView messageTextView;
    private boolean messageTextViewClickable;
    private DialogInterface.OnClickListener negativeButtonListener;
    private CharSequence negativeButtonText;
    private DialogInterface.OnClickListener neutralButtonListener;
    private CharSequence neutralButtonText;
    private DialogInterface.OnClickListener onBackButtonListener;
    private DialogInterface.OnCancelListener onCancelListener;
    private DialogInterface.OnClickListener onClickListener;
    private DialogInterface.OnDismissListener onDismissListener;
    private ViewTreeObserver.OnScrollChangedListener onScrollChangedListener;
    private DialogInterface.OnClickListener positiveButtonListener;
    private CharSequence positiveButtonText;
    private FrameLayout progressViewContainer;
    private int progressViewStyle;
    private TextView progressViewTextView;
    private LinearLayout scrollContainer;
    private CharSequence secondTitle;
    private TextView secondTitleTextView;
    private BitmapDrawable[] shadow;
    private AnimatorSet[] shadowAnimation;
    private Drawable shadowDrawable;
    private boolean[] shadowVisibility;
    private CharSequence subtitle;
    private TextView subtitleTextView;
    private CharSequence title;
    private FrameLayout titleContainer;
    private TextView titleTextView;
    private int topBackgroundColor;
    private Drawable topDrawable;
    private int topHeight;
    private ImageView topImageView;
    private int topResId;
    private TextView tvLoadingView;

    public static class AlertDialogCell extends FrameLayout {
        private ImageView imageView;
        private TextView textView;

        public AlertDialogCell(Context context) {
            super(context);
            setBackgroundDrawable(Theme.createSelectorDrawable(Theme.getColor(Theme.key_dialogButtonSelector), 2));
            setPadding(AndroidUtilities.dp(23.0f), 0, AndroidUtilities.dp(23.0f), 0);
            ImageView imageView = new ImageView(context);
            this.imageView = imageView;
            imageView.setScaleType(ImageView.ScaleType.CENTER);
            this.imageView.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_dialogIcon), PorterDuff.Mode.MULTIPLY));
            addView(this.imageView, LayoutHelper.createFrame(-2, 40, (LocaleController.isRTL ? 5 : 3) | 16));
            TextView textView = new TextView(context);
            this.textView = textView;
            textView.setLines(1);
            this.textView.setSingleLine(true);
            this.textView.setGravity(1);
            this.textView.setEllipsize(TextUtils.TruncateAt.END);
            this.textView.setTextColor(Theme.getColor(Theme.key_dialogTextBlack));
            this.textView.setTextSize(1, 16.0f);
            addView(this.textView, LayoutHelper.createFrame(-2, -2, (LocaleController.isRTL ? 5 : 3) | 16));
        }

        @Override // android.widget.FrameLayout, android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            super.onMeasure(widthMeasureSpec, View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(48.0f), 1073741824));
        }

        public void setTextColor(int color) {
            this.textView.setTextColor(color);
        }

        public void setGravity(int gravity) {
            this.textView.setGravity(gravity);
        }

        public void setTextAndIcon(CharSequence text, int icon) {
            this.textView.setText(text);
            if (icon != 0) {
                this.imageView.setImageResource(icon);
                this.imageView.setVisibility(0);
                this.textView.setPadding(LocaleController.isRTL ? 0 : AndroidUtilities.dp(56.0f), 0, LocaleController.isRTL ? AndroidUtilities.dp(56.0f) : 0, 0);
            } else {
                this.imageView.setVisibility(4);
                this.textView.setPadding(0, 0, 0, 0);
            }
        }
    }

    public XAlertDialog(Context context, int progressStyle) {
        super(context, R.plurals.TransparentDialog);
        this.shadow = new BitmapDrawable[2];
        this.shadowVisibility = new boolean[2];
        this.shadowAnimation = new AnimatorSet[2];
        this.customViewOffset = 20;
        this.topHeight = 132;
        this.messageTextViewClickable = true;
        this.canCacnel = true;
        this.dismissDialogByButtons = true;
        this.dismissRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$obqWDt1VQzMsPJnUeWeEucNzhUY
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.dismiss();
            }
        };
        this.itemViews = new ArrayList<>();
        this.backgroundPaddings = new Rect();
        if (progressStyle != 3 && progressStyle != 4) {
            Drawable drawableMutate = context.getResources().getDrawable(R.drawable.popup_fixed_alert).mutate();
            this.shadowDrawable = drawableMutate;
            drawableMutate.setColorFilter(new PorterDuffColorFilter(getThemeColor(Theme.key_dialogBackground), PorterDuff.Mode.MULTIPLY));
            this.shadowDrawable.getPadding(this.backgroundPaddings);
        }
        this.progressViewStyle = progressStyle;
    }

    @Override // android.app.Dialog
    protected void onCreate(Bundle savedInstanceState) {
        int maxWidth;
        int i;
        super.onCreate(savedInstanceState);
        LinearLayout containerView = new AnonymousClass1(getContext());
        containerView.setOrientation(1);
        int i2 = this.progressViewStyle;
        if (i2 == 3 || i2 == 4 || i2 == 5) {
            containerView.setBackgroundDrawable(null);
        } else {
            containerView.setBackgroundDrawable(this.shadowDrawable);
        }
        containerView.setFitsSystemWindows(Build.VERSION.SDK_INT >= 21);
        setContentView(containerView);
        boolean hasButtons = (this.positiveButtonText == null && this.negativeButtonText == null && this.neutralButtonText == null) ? false : true;
        if (this.topResId != 0 || this.topDrawable != null) {
            ImageView imageView = new ImageView(getContext());
            this.topImageView = imageView;
            Drawable drawable = this.topDrawable;
            if (drawable != null) {
                imageView.setImageDrawable(drawable);
            } else {
                imageView.setImageResource(this.topResId);
            }
            this.topImageView.setScaleType(ImageView.ScaleType.CENTER);
            this.topImageView.setBackgroundDrawable(getContext().getResources().getDrawable(R.drawable.popup_fixed_top));
            this.topImageView.getBackground().setColorFilter(new PorterDuffColorFilter(this.topBackgroundColor, PorterDuff.Mode.MULTIPLY));
            this.topImageView.setPadding(0, 0, 0, 0);
            containerView.addView(this.topImageView, LayoutHelper.createLinear(-1, this.topHeight, 51, -8, -8, 0, 0));
        }
        if (this.title != null) {
            FrameLayout frameLayout = new FrameLayout(getContext());
            this.titleContainer = frameLayout;
            containerView.addView(frameLayout, LayoutHelper.createLinear(-2, -2, 24.0f, 0.0f, 24.0f, 0.0f));
            TextView textView = new TextView(getContext());
            this.titleTextView = textView;
            textView.setText(this.title);
            this.titleTextView.setTextColor(getThemeColor(Theme.key_dialogTextBlack));
            this.titleTextView.setTextSize(1, 20.0f);
            this.titleTextView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
            this.titleTextView.setGravity((LocaleController.isRTL ? 5 : 3) | 48);
            FrameLayout frameLayout2 = this.titleContainer;
            TextView textView2 = this.titleTextView;
            int i3 = (LocaleController.isRTL ? 5 : 3) | 48;
            if (this.subtitle != null) {
                i = 2;
            } else {
                i = this.items != null ? 14 : 10;
            }
            frameLayout2.addView(textView2, LayoutHelper.createFrame(-2.0f, -2.0f, i3, 0.0f, 19.0f, 0.0f, i));
        }
        if (this.secondTitle != null && this.title != null) {
            TextView textView3 = new TextView(getContext());
            this.secondTitleTextView = textView3;
            textView3.setText(this.secondTitle);
            this.secondTitleTextView.setTextColor(getThemeColor(Theme.key_dialogTextGray3));
            this.secondTitleTextView.setTextSize(1, 18.0f);
            this.secondTitleTextView.setGravity((LocaleController.isRTL ? 3 : 5) | 48);
            this.titleContainer.addView(this.secondTitleTextView, LayoutHelper.createFrame(-2.0f, -2.0f, (LocaleController.isRTL ? 3 : 5) | 48, 0.0f, 21.0f, 0.0f, 0.0f));
        }
        if (this.subtitle != null) {
            TextView textView4 = new TextView(getContext());
            this.subtitleTextView = textView4;
            textView4.setText(this.subtitle);
            this.subtitleTextView.setTextColor(getThemeColor(Theme.key_dialogIcon));
            this.subtitleTextView.setTextSize(1, 14.0f);
            this.subtitleTextView.setGravity((LocaleController.isRTL ? 5 : 3) | 48);
            containerView.addView(this.subtitleTextView, LayoutHelper.createLinear(-2, -2, (LocaleController.isRTL ? 5 : 3) | 48, 24, 0, 24, this.items != null ? 14 : 10));
        }
        if (this.progressViewStyle == 0) {
            this.shadow[0] = (BitmapDrawable) getContext().getResources().getDrawable(R.drawable.header_shadow).mutate();
            this.shadow[1] = (BitmapDrawable) getContext().getResources().getDrawable(R.drawable.header_shadow_reverse).mutate();
            this.shadow[0].setAlpha(0);
            this.shadow[1].setAlpha(0);
            this.shadow[0].setCallback(this);
            this.shadow[1].setCallback(this);
            ScrollView scrollView = new ScrollView(getContext()) { // from class: im.uwrkaxlmjj.ui.actionbar.XAlertDialog.2
                @Override // android.view.ViewGroup
                protected boolean drawChild(Canvas canvas, View child, long drawingTime) {
                    boolean result = super.drawChild(canvas, child, drawingTime);
                    if (XAlertDialog.this.shadow[0].getPaint().getAlpha() != 0) {
                        XAlertDialog.this.shadow[0].setBounds(0, getScrollY(), getMeasuredWidth(), getScrollY() + AndroidUtilities.dp(3.0f));
                        XAlertDialog.this.shadow[0].draw(canvas);
                    }
                    if (XAlertDialog.this.shadow[1].getPaint().getAlpha() != 0) {
                        XAlertDialog.this.shadow[1].setBounds(0, (getScrollY() + getMeasuredHeight()) - AndroidUtilities.dp(3.0f), getMeasuredWidth(), getScrollY() + getMeasuredHeight());
                        XAlertDialog.this.shadow[1].draw(canvas);
                    }
                    return result;
                }
            };
            this.contentScrollView = scrollView;
            scrollView.setVerticalScrollBarEnabled(false);
            AndroidUtilities.setScrollViewEdgeEffectColor(this.contentScrollView, getThemeColor(Theme.key_dialogScrollGlow));
            containerView.addView(this.contentScrollView, LayoutHelper.createLinear(-1, -2, 0.0f, 0.0f, 0.0f, 0.0f));
            LinearLayout linearLayout = new LinearLayout(getContext());
            this.scrollContainer = linearLayout;
            linearLayout.setOrientation(1);
            this.contentScrollView.addView(this.scrollContainer, new FrameLayout.LayoutParams(-1, -2));
        }
        TextView textView5 = new TextView(getContext());
        this.messageTextView = textView5;
        textView5.setTextColor(getThemeColor(Theme.key_dialogTextBlack));
        this.messageTextView.setTextSize(1, 16.0f);
        this.messageTextView.setMovementMethod(new AndroidUtilities.LinkMovementMethodMy());
        this.messageTextView.setLinkTextColor(getThemeColor(Theme.key_dialogTextLink));
        if (!this.messageTextViewClickable) {
            this.messageTextView.setClickable(false);
            this.messageTextView.setEnabled(false);
        }
        this.messageTextView.setGravity((LocaleController.isRTL ? 5 : 3) | 48);
        int i4 = this.progressViewStyle;
        if (i4 == 1) {
            FrameLayout frameLayout3 = new FrameLayout(getContext());
            this.progressViewContainer = frameLayout3;
            containerView.addView(frameLayout3, LayoutHelper.createLinear(-1, 44, 51, 23, this.title == null ? 24 : 0, 23, 24));
            RadialProgressView progressView = new RadialProgressView(getContext());
            progressView.setProgressColor(getThemeColor(Theme.key_dialogProgressCircle));
            this.progressViewContainer.addView(progressView, LayoutHelper.createFrame(44, 44, (LocaleController.isRTL ? 5 : 3) | 48));
            this.messageTextView.setLines(1);
            this.messageTextView.setEllipsize(TextUtils.TruncateAt.END);
            this.progressViewContainer.addView(this.messageTextView, LayoutHelper.createFrame(-2.0f, -2.0f, (LocaleController.isRTL ? 5 : 3) | 16, LocaleController.isRTL ? 0 : 62, 0.0f, LocaleController.isRTL ? 62 : 0, 0.0f));
        } else if (i4 == 2) {
            containerView.addView(this.messageTextView, LayoutHelper.createLinear(-2, -2, (LocaleController.isRTL ? 5 : 3) | 48, 24, this.title == null ? 19 : 0, 24, 20));
            LineProgressView lineProgressView = new LineProgressView(getContext());
            this.lineProgressView = lineProgressView;
            lineProgressView.setProgress(this.currentProgress / 100.0f, false);
            this.lineProgressView.setProgressColor(getThemeColor(Theme.key_dialogLineProgress));
            this.lineProgressView.setBackColor(getThemeColor(Theme.key_dialogLineProgressBackground));
            containerView.addView(this.lineProgressView, LayoutHelper.createLinear(-1, 4, 19, 24, 0, 24, 0));
            TextView textView6 = new TextView(getContext());
            this.lineProgressViewPercent = textView6;
            textView6.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
            this.lineProgressViewPercent.setGravity((LocaleController.isRTL ? 5 : 3) | 48);
            this.lineProgressViewPercent.setTextColor(getThemeColor(Theme.key_dialogTextGray2));
            this.lineProgressViewPercent.setTextSize(1, 14.0f);
            containerView.addView(this.lineProgressViewPercent, LayoutHelper.createLinear(-2, -2, (LocaleController.isRTL ? 5 : 3) | 48, 23, 4, 23, 24));
            updateLineProgressTextView();
        } else if (i4 == 3 || i4 == 4) {
            setCanceledOnTouchOutside(false);
            setCancelable(false);
            FrameLayout frameLayout4 = new FrameLayout(getContext());
            this.progressViewContainer = frameLayout4;
            int i5 = this.progressViewStyle;
            if (i5 == 3) {
                frameLayout4.setBackgroundDrawable(Theme.createRoundRectDrawable(AndroidUtilities.dp(18.0f), Theme.getColor(Theme.key_dialog_inlineProgressBackground)));
            } else if (i5 == 4) {
                frameLayout4.setBackgroundDrawable(Theme.createRoundRectDrawable(AndroidUtilities.dp(12.0f), -1895825408));
            }
            containerView.addView(this.progressViewContainer, LayoutHelper.createLinear(86, 86, 17));
            int i6 = this.progressViewStyle;
            if (i6 == 3) {
                RadialProgressView progressView2 = new RadialProgressView(getContext());
                progressView2.setProgressColor(getThemeColor(Theme.key_dialog_inlineProgress));
                this.progressViewContainer.addView(progressView2, LayoutHelper.createFrame(86, 86.0f));
            } else if (i6 == 4) {
                LinearLayout loadingViewContainer = new LinearLayout(getContext());
                loadingViewContainer.setGravity(17);
                loadingViewContainer.setOrientation(1);
                this.progressViewContainer.addView(loadingViewContainer, LayoutHelper.createFrame(-1, -1.0f));
                ProgressBar progressBar = new ProgressBar(getContext());
                this.loadingProgressView = progressBar;
                progressBar.setIndeterminateDrawable(getContext().getResources().getDrawable(R.drawable.rotate_anim));
                loadingViewContainer.addView(this.loadingProgressView, LayoutHelper.createFrame(38, 38.0f));
                TextView textView7 = new TextView(getContext());
                this.tvLoadingView = textView7;
                textView7.setTextColor(-1);
                this.tvLoadingView.setGravity(17);
                this.tvLoadingView.setText(this.loadingText);
                this.tvLoadingView.setVisibility(TextUtils.isEmpty(this.loadingText) ? 8 : 0);
                loadingViewContainer.addView(this.tvLoadingView, LayoutHelper.createFrame(-2, -2, 0, AndroidUtilities.dp(10.0f), 0, 0));
            }
        } else {
            if (i4 != 5) {
                this.scrollContainer.addView(this.messageTextView, LayoutHelper.createLinear(-2, -2, (LocaleController.isRTL ? 5 : 3) | 48, 24, 0, 24, (this.customView == null && this.items == null) ? 0 : this.customViewOffset));
            } else {
                setCanceledOnTouchOutside(false);
                setCancelable(false);
                FrameLayout frameLayout5 = new FrameLayout(getContext());
                this.progressViewContainer = frameLayout5;
                frameLayout5.setBackgroundDrawable(Theme.createRoundRectDrawable(AndroidUtilities.dp(12.0f), -1895825408));
                containerView.addView(this.progressViewContainer, LayoutHelper.createLinear(-2, -2, 17));
                LinearLayout loadingLayout = new LinearLayout(getContext());
                loadingLayout.setOrientation(0);
                this.progressViewContainer.addView(loadingLayout, LayoutHelper.createFrame(-2, -2, 16));
                RadialProgressView progressView3 = new RadialProgressView(getContext());
                progressView3.setSize(AndroidUtilities.dp(38.0f));
                progressView3.setStrokeWidth(1.5f);
                progressView3.setProgressColor(-3355444);
                loadingLayout.addView(progressView3, LayoutHelper.createLinear(40, 40, 16, 25, 0, 0, 0));
                TextView textView8 = new TextView(getContext());
                this.tvLoadingView = textView8;
                textView8.setText(LocaleController.getString("Loading", R.string.NowLoading));
                loadingLayout.addView(this.tvLoadingView, LayoutHelper.createLinear(-2, -2, 16, 10, 0, 0, 0));
            }
        }
        if (!TextUtils.isEmpty(this.message)) {
            this.messageTextView.setText(this.message);
            this.messageTextView.setVisibility(0);
        } else {
            this.messageTextView.setVisibility(8);
        }
        if (this.items != null) {
            int a = 0;
            while (true) {
                CharSequence[] charSequenceArr = this.items;
                if (a >= charSequenceArr.length) {
                    break;
                }
                if (charSequenceArr[a] != null) {
                    AlertDialogCell cell = new AlertDialogCell(getContext());
                    CharSequence charSequence = this.items[a];
                    int[] iArr = this.itemIcons;
                    cell.setTextAndIcon(charSequence, iArr != null ? iArr[a] : 0);
                    cell.setTag(Integer.valueOf(a));
                    this.itemViews.add(cell);
                    this.scrollContainer.addView(cell, LayoutHelper.createLinear(-1, 50));
                    cell.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$XAlertDialog$OPwWRJ9fgC_g-XvtZKpDTU2DTKg
                        @Override // android.view.View.OnClickListener
                        public final void onClick(View view) {
                            this.f$0.lambda$onCreate$0$XAlertDialog(view);
                        }
                    });
                }
                a++;
            }
        }
        View view = this.customView;
        if (view != null) {
            if (view.getParent() != null) {
                ViewGroup viewGroup = (ViewGroup) this.customView.getParent();
                viewGroup.removeView(this.customView);
            }
            this.scrollContainer.addView(this.customView, LayoutHelper.createLinear(-1, -2));
        }
        if (hasButtons) {
            FrameLayout frameLayout6 = new FrameLayout(getContext()) { // from class: im.uwrkaxlmjj.ui.actionbar.XAlertDialog.3
                @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
                protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
                    int l;
                    int t;
                    int count = getChildCount();
                    View positiveButton = null;
                    int width = right - left;
                    for (int a2 = 0; a2 < count; a2++) {
                        View child = getChildAt(a2);
                        Integer tag = (Integer) child.getTag();
                        if (tag != null) {
                            if (tag.intValue() == -1) {
                                positiveButton = child;
                                if (LocaleController.isRTL) {
                                    child.layout(getPaddingLeft(), getPaddingTop(), getPaddingLeft() + child.getMeasuredWidth(), getPaddingTop() + child.getMeasuredHeight());
                                } else {
                                    child.layout((width - getPaddingRight()) - child.getMeasuredWidth(), getPaddingTop(), width - getPaddingRight(), getPaddingTop() + child.getMeasuredHeight());
                                }
                            } else if (tag.intValue() == -2) {
                                if (LocaleController.isRTL) {
                                    int x = getPaddingLeft();
                                    if (positiveButton != null) {
                                        x += positiveButton.getMeasuredWidth() + AndroidUtilities.dp(8.0f);
                                    }
                                    child.layout(x, getPaddingTop(), child.getMeasuredWidth() + x, getPaddingTop() + child.getMeasuredHeight());
                                } else {
                                    int x2 = (width - getPaddingRight()) - child.getMeasuredWidth();
                                    if (positiveButton != null) {
                                        x2 -= positiveButton.getMeasuredWidth() + AndroidUtilities.dp(8.0f);
                                    }
                                    child.layout(x2, getPaddingTop(), child.getMeasuredWidth() + x2, getPaddingTop() + child.getMeasuredHeight());
                                }
                            } else if (tag.intValue() == -3) {
                                if (LocaleController.isRTL) {
                                    child.layout((width - getPaddingRight()) - child.getMeasuredWidth(), getPaddingTop(), width - getPaddingRight(), getPaddingTop() + child.getMeasuredHeight());
                                } else {
                                    child.layout(getPaddingLeft(), getPaddingTop(), getPaddingLeft() + child.getMeasuredWidth(), getPaddingTop() + child.getMeasuredHeight());
                                }
                            }
                        } else {
                            int w = child.getMeasuredWidth();
                            int h = child.getMeasuredHeight();
                            if (positiveButton != null) {
                                l = positiveButton.getLeft() + ((positiveButton.getMeasuredWidth() - w) / 2);
                                t = positiveButton.getTop() + ((positiveButton.getMeasuredHeight() - h) / 2);
                            } else {
                                l = 0;
                                t = 0;
                            }
                            child.layout(l, t, l + w, t + h);
                        }
                    }
                }

                @Override // android.widget.FrameLayout, android.view.View
                protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                    super.onMeasure(widthMeasureSpec, heightMeasureSpec);
                    int totalWidth = 0;
                    int availableWidth = (getMeasuredWidth() - getPaddingLeft()) - getPaddingRight();
                    int count = getChildCount();
                    for (int a2 = 0; a2 < count; a2++) {
                        View child = getChildAt(a2);
                        if ((child instanceof TextView) && child.getTag() != null) {
                            totalWidth += child.getMeasuredWidth();
                        }
                    }
                    if (totalWidth > availableWidth) {
                        View negative = findViewWithTag(-2);
                        View neuntral = findViewWithTag(-3);
                        if (negative != null && neuntral != null) {
                            if (negative.getMeasuredWidth() < neuntral.getMeasuredWidth()) {
                                neuntral.measure(View.MeasureSpec.makeMeasureSpec(neuntral.getMeasuredWidth() - (totalWidth - availableWidth), 1073741824), View.MeasureSpec.makeMeasureSpec(neuntral.getMeasuredHeight(), 1073741824));
                            } else {
                                negative.measure(View.MeasureSpec.makeMeasureSpec(negative.getMeasuredWidth() - (totalWidth - availableWidth), 1073741824), View.MeasureSpec.makeMeasureSpec(negative.getMeasuredHeight(), 1073741824));
                            }
                        }
                    }
                }
            };
            this.buttonsLayout = frameLayout6;
            frameLayout6.setPadding(AndroidUtilities.dp(8.0f), AndroidUtilities.dp(8.0f), AndroidUtilities.dp(8.0f), AndroidUtilities.dp(8.0f));
            containerView.addView(this.buttonsLayout, LayoutHelper.createLinear(-1, 52));
            if (this.positiveButtonText != null) {
                TextView textView9 = new TextView(getContext()) { // from class: im.uwrkaxlmjj.ui.actionbar.XAlertDialog.4
                    @Override // android.widget.TextView, android.view.View
                    public void setEnabled(boolean enabled) {
                        super.setEnabled(enabled);
                        setAlpha(enabled ? 1.0f : 0.5f);
                    }

                    @Override // android.widget.TextView
                    public void setTextColor(int color) {
                        super.setTextColor(color);
                        setBackgroundDrawable(Theme.getRoundRectSelectorDrawable(color));
                    }
                };
                textView9.setMinWidth(AndroidUtilities.dp(64.0f));
                textView9.setTag(-1);
                textView9.setTextSize(1, 14.0f);
                textView9.setTextColor(getThemeColor(Theme.key_dialogButton));
                textView9.setGravity(17);
                textView9.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
                textView9.setText(this.positiveButtonText.toString().toUpperCase());
                textView9.setBackgroundDrawable(Theme.getRoundRectSelectorDrawable(getThemeColor(Theme.key_dialogButton)));
                textView9.setPadding(AndroidUtilities.dp(10.0f), 0, AndroidUtilities.dp(10.0f), 0);
                this.buttonsLayout.addView(textView9, LayoutHelper.createFrame(-2, 36, 53));
                textView9.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$XAlertDialog$EWKn9xeW_BzilHR3YczMjFocfY0
                    @Override // android.view.View.OnClickListener
                    public final void onClick(View view2) {
                        this.f$0.lambda$onCreate$1$XAlertDialog(view2);
                    }
                });
            }
            if (this.negativeButtonText != null) {
                TextView textView10 = new TextView(getContext()) { // from class: im.uwrkaxlmjj.ui.actionbar.XAlertDialog.5
                    @Override // android.widget.TextView, android.view.View
                    public void setEnabled(boolean enabled) {
                        super.setEnabled(enabled);
                        setAlpha(enabled ? 1.0f : 0.5f);
                    }

                    @Override // android.widget.TextView
                    public void setTextColor(int color) {
                        super.setTextColor(color);
                        setBackgroundDrawable(Theme.getRoundRectSelectorDrawable(color));
                    }
                };
                textView10.setMinWidth(AndroidUtilities.dp(64.0f));
                textView10.setTag(-2);
                textView10.setTextSize(1, 14.0f);
                textView10.setTextColor(getThemeColor(Theme.key_dialogButton));
                textView10.setGravity(17);
                textView10.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
                textView10.setEllipsize(TextUtils.TruncateAt.END);
                textView10.setSingleLine(true);
                textView10.setText(this.negativeButtonText.toString().toUpperCase());
                textView10.setBackgroundDrawable(Theme.getRoundRectSelectorDrawable(getThemeColor(Theme.key_dialogButton)));
                textView10.setPadding(AndroidUtilities.dp(10.0f), 0, AndroidUtilities.dp(10.0f), 0);
                this.buttonsLayout.addView(textView10, LayoutHelper.createFrame(-2, 36, 53));
                textView10.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$XAlertDialog$r-UB_oplUv6r7Z5VotFQqIcvvNY
                    @Override // android.view.View.OnClickListener
                    public final void onClick(View view2) {
                        this.f$0.lambda$onCreate$2$XAlertDialog(view2);
                    }
                });
            }
            if (this.neutralButtonText != null) {
                TextView textView11 = new TextView(getContext()) { // from class: im.uwrkaxlmjj.ui.actionbar.XAlertDialog.6
                    @Override // android.widget.TextView, android.view.View
                    public void setEnabled(boolean enabled) {
                        super.setEnabled(enabled);
                        setAlpha(enabled ? 1.0f : 0.5f);
                    }

                    @Override // android.widget.TextView
                    public void setTextColor(int color) {
                        super.setTextColor(color);
                        setBackgroundDrawable(Theme.getRoundRectSelectorDrawable(color));
                    }
                };
                textView11.setMinWidth(AndroidUtilities.dp(64.0f));
                textView11.setTag(-3);
                textView11.setTextSize(1, 14.0f);
                textView11.setTextColor(getThemeColor(Theme.key_dialogButton));
                textView11.setGravity(17);
                textView11.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
                textView11.setEllipsize(TextUtils.TruncateAt.END);
                textView11.setSingleLine(true);
                textView11.setText(this.neutralButtonText.toString().toUpperCase());
                textView11.setBackgroundDrawable(Theme.getRoundRectSelectorDrawable(getThemeColor(Theme.key_dialogButton)));
                textView11.setPadding(AndroidUtilities.dp(10.0f), 0, AndroidUtilities.dp(10.0f), 0);
                this.buttonsLayout.addView(textView11, LayoutHelper.createFrame(-2, 36, 51));
                textView11.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$XAlertDialog$Vw9ffrVmKQrs9qmtY0ljLueX0BM
                    @Override // android.view.View.OnClickListener
                    public final void onClick(View view2) {
                        this.f$0.lambda$onCreate$3$XAlertDialog(view2);
                    }
                });
            }
        }
        Window window = getWindow();
        WindowManager.LayoutParams params = new WindowManager.LayoutParams();
        params.copyFrom(window.getAttributes());
        int i7 = this.progressViewStyle;
        if (i7 == 3 || i7 == 4) {
            params.width = -1;
        } else {
            params.dimAmount = 0.6f;
            params.flags |= 2;
            this.lastScreenWidth = AndroidUtilities.displaySize.x;
            int calculatedWidth = AndroidUtilities.displaySize.x - AndroidUtilities.dp(48.0f);
            if (AndroidUtilities.isTablet()) {
                if (AndroidUtilities.isSmallTablet()) {
                    maxWidth = AndroidUtilities.dp(446.0f);
                } else {
                    maxWidth = AndroidUtilities.dp(496.0f);
                }
            } else {
                maxWidth = AndroidUtilities.dp(356.0f);
            }
            params.width = Math.min(maxWidth, calculatedWidth) + this.backgroundPaddings.left + this.backgroundPaddings.right;
        }
        View view2 = this.customView;
        if (view2 == null || !canTextInput(view2)) {
            params.flags |= 131072;
        } else {
            params.softInputMode = 4;
        }
        if (Build.VERSION.SDK_INT >= 28) {
            params.layoutInDisplayCutoutMode = 0;
        }
        window.setAttributes(params);
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.actionbar.XAlertDialog$1, reason: invalid class name */
    class AnonymousClass1 extends LinearLayout {
        private boolean inLayout;

        AnonymousClass1(Context x0) {
            super(x0);
        }

        @Override // android.view.View
        public boolean onTouchEvent(MotionEvent event) {
            return super.onTouchEvent(event);
        }

        @Override // android.view.ViewGroup
        public boolean onInterceptTouchEvent(MotionEvent ev) {
            return super.onInterceptTouchEvent(ev);
        }

        @Override // android.widget.LinearLayout, android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            if (XAlertDialog.this.progressViewStyle == 3 || XAlertDialog.this.progressViewStyle == 4) {
                XAlertDialog.this.progressViewContainer.measure(View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(86.0f), 1073741824), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(86.0f), 1073741824));
                setMeasuredDimension(View.MeasureSpec.getSize(widthMeasureSpec), View.MeasureSpec.getSize(heightMeasureSpec));
                return;
            }
            if (XAlertDialog.this.progressViewStyle == 5) {
                XAlertDialog.this.progressViewContainer.measure(View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(220.0f), 1073741824), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(66.0f), 1073741824));
                setMeasuredDimension(View.MeasureSpec.getSize(widthMeasureSpec), View.MeasureSpec.getSize(heightMeasureSpec));
                return;
            }
            this.inLayout = true;
            int width = View.MeasureSpec.getSize(widthMeasureSpec);
            int height = View.MeasureSpec.getSize(heightMeasureSpec);
            int availableHeight = (height - getPaddingTop()) - getPaddingBottom();
            int availableWidth = (width - getPaddingLeft()) - getPaddingRight();
            int childWidthMeasureSpec = View.MeasureSpec.makeMeasureSpec(availableWidth - AndroidUtilities.dp(48.0f), 1073741824);
            int childFullWidthMeasureSpec = View.MeasureSpec.makeMeasureSpec(availableWidth, 1073741824);
            if (XAlertDialog.this.buttonsLayout != null) {
                int count = XAlertDialog.this.buttonsLayout.getChildCount();
                for (int a = 0; a < count; a++) {
                    View child = XAlertDialog.this.buttonsLayout.getChildAt(a);
                    if (child instanceof TextView) {
                        TextView button = (TextView) child;
                        button.setMaxWidth(AndroidUtilities.dp((availableWidth - AndroidUtilities.dp(24.0f)) / 2));
                    }
                }
                XAlertDialog.this.buttonsLayout.measure(childFullWidthMeasureSpec, heightMeasureSpec);
                LinearLayout.LayoutParams layoutParams = (LinearLayout.LayoutParams) XAlertDialog.this.buttonsLayout.getLayoutParams();
                availableHeight -= (XAlertDialog.this.buttonsLayout.getMeasuredHeight() + layoutParams.bottomMargin) + layoutParams.topMargin;
            }
            if (XAlertDialog.this.secondTitleTextView != null) {
                XAlertDialog.this.secondTitleTextView.measure(View.MeasureSpec.makeMeasureSpec(View.MeasureSpec.getSize(childWidthMeasureSpec), Integer.MIN_VALUE), heightMeasureSpec);
            }
            if (XAlertDialog.this.titleTextView != null) {
                if (XAlertDialog.this.secondTitleTextView != null) {
                    XAlertDialog.this.titleTextView.measure(View.MeasureSpec.makeMeasureSpec((View.MeasureSpec.getSize(childWidthMeasureSpec) - XAlertDialog.this.secondTitleTextView.getMeasuredWidth()) - AndroidUtilities.dp(8.0f), 1073741824), heightMeasureSpec);
                } else {
                    XAlertDialog.this.titleTextView.measure(childWidthMeasureSpec, heightMeasureSpec);
                }
            }
            if (XAlertDialog.this.titleContainer != null) {
                XAlertDialog.this.titleContainer.measure(childWidthMeasureSpec, heightMeasureSpec);
                LinearLayout.LayoutParams layoutParams2 = (LinearLayout.LayoutParams) XAlertDialog.this.titleContainer.getLayoutParams();
                availableHeight -= (XAlertDialog.this.titleContainer.getMeasuredHeight() + layoutParams2.bottomMargin) + layoutParams2.topMargin;
            }
            if (XAlertDialog.this.subtitleTextView != null) {
                XAlertDialog.this.subtitleTextView.measure(childWidthMeasureSpec, heightMeasureSpec);
                LinearLayout.LayoutParams layoutParams3 = (LinearLayout.LayoutParams) XAlertDialog.this.subtitleTextView.getLayoutParams();
                availableHeight -= (XAlertDialog.this.subtitleTextView.getMeasuredHeight() + layoutParams3.bottomMargin) + layoutParams3.topMargin;
            }
            if (XAlertDialog.this.topImageView != null) {
                XAlertDialog.this.topImageView.measure(View.MeasureSpec.makeMeasureSpec(width, 1073741824), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(XAlertDialog.this.topHeight), 1073741824));
                availableHeight -= XAlertDialog.this.topImageView.getMeasuredHeight() - AndroidUtilities.dp(8.0f);
            }
            if (XAlertDialog.this.progressViewStyle == 0) {
                LinearLayout.LayoutParams layoutParams4 = (LinearLayout.LayoutParams) XAlertDialog.this.contentScrollView.getLayoutParams();
                if (XAlertDialog.this.customView != null) {
                    layoutParams4.topMargin = (XAlertDialog.this.titleTextView == null && XAlertDialog.this.messageTextView.getVisibility() == 8 && XAlertDialog.this.items == null) ? AndroidUtilities.dp(16.0f) : 0;
                    layoutParams4.bottomMargin = XAlertDialog.this.buttonsLayout == null ? AndroidUtilities.dp(8.0f) : 0;
                } else if (XAlertDialog.this.items != null) {
                    layoutParams4.topMargin = (XAlertDialog.this.titleTextView == null && XAlertDialog.this.messageTextView.getVisibility() == 8) ? AndroidUtilities.dp(8.0f) : 0;
                    layoutParams4.bottomMargin = AndroidUtilities.dp(8.0f);
                } else if (XAlertDialog.this.messageTextView.getVisibility() == 0) {
                    layoutParams4.topMargin = XAlertDialog.this.titleTextView == null ? AndroidUtilities.dp(19.0f) : 0;
                    layoutParams4.bottomMargin = AndroidUtilities.dp(20.0f);
                }
                int availableHeight2 = availableHeight - (layoutParams4.bottomMargin + layoutParams4.topMargin);
                XAlertDialog.this.contentScrollView.measure(childFullWidthMeasureSpec, View.MeasureSpec.makeMeasureSpec(availableHeight2, Integer.MIN_VALUE));
                availableHeight = availableHeight2 - XAlertDialog.this.contentScrollView.getMeasuredHeight();
            } else {
                if (XAlertDialog.this.progressViewContainer != null) {
                    XAlertDialog.this.progressViewContainer.measure(childWidthMeasureSpec, View.MeasureSpec.makeMeasureSpec(availableHeight, Integer.MIN_VALUE));
                    LinearLayout.LayoutParams layoutParams5 = (LinearLayout.LayoutParams) XAlertDialog.this.progressViewContainer.getLayoutParams();
                    availableHeight -= (XAlertDialog.this.progressViewContainer.getMeasuredHeight() + layoutParams5.bottomMargin) + layoutParams5.topMargin;
                } else if (XAlertDialog.this.messageTextView != null) {
                    XAlertDialog.this.messageTextView.measure(childWidthMeasureSpec, View.MeasureSpec.makeMeasureSpec(availableHeight, Integer.MIN_VALUE));
                    if (XAlertDialog.this.messageTextView.getVisibility() != 8) {
                        LinearLayout.LayoutParams layoutParams6 = (LinearLayout.LayoutParams) XAlertDialog.this.messageTextView.getLayoutParams();
                        availableHeight -= (XAlertDialog.this.messageTextView.getMeasuredHeight() + layoutParams6.bottomMargin) + layoutParams6.topMargin;
                    }
                }
                if (XAlertDialog.this.lineProgressView != null) {
                    XAlertDialog.this.lineProgressView.measure(childWidthMeasureSpec, View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(4.0f), 1073741824));
                    LinearLayout.LayoutParams layoutParams7 = (LinearLayout.LayoutParams) XAlertDialog.this.lineProgressView.getLayoutParams();
                    int availableHeight3 = availableHeight - ((XAlertDialog.this.lineProgressView.getMeasuredHeight() + layoutParams7.bottomMargin) + layoutParams7.topMargin);
                    XAlertDialog.this.lineProgressViewPercent.measure(childWidthMeasureSpec, View.MeasureSpec.makeMeasureSpec(availableHeight3, Integer.MIN_VALUE));
                    LinearLayout.LayoutParams layoutParams8 = (LinearLayout.LayoutParams) XAlertDialog.this.lineProgressViewPercent.getLayoutParams();
                    availableHeight = availableHeight3 - ((XAlertDialog.this.lineProgressViewPercent.getMeasuredHeight() + layoutParams8.bottomMargin) + layoutParams8.topMargin);
                }
            }
            setMeasuredDimension(width, (availableHeight - availableHeight) + getPaddingTop() + getPaddingBottom());
            this.inLayout = false;
            if (XAlertDialog.this.lastScreenWidth != AndroidUtilities.displaySize.x) {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$XAlertDialog$1$gqo0Cq9mhso5G-LYtAc_a8bcOXU
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$onMeasure$0$XAlertDialog$1();
                    }
                });
            }
        }

        public /* synthetic */ void lambda$onMeasure$0$XAlertDialog$1() {
            int maxWidth;
            XAlertDialog.this.lastScreenWidth = AndroidUtilities.displaySize.x;
            int calculatedWidth = AndroidUtilities.displaySize.x - AndroidUtilities.dp(56.0f);
            if (AndroidUtilities.isTablet()) {
                if (AndroidUtilities.isSmallTablet()) {
                    maxWidth = AndroidUtilities.dp(446.0f);
                } else {
                    maxWidth = AndroidUtilities.dp(496.0f);
                }
            } else {
                maxWidth = AndroidUtilities.dp(356.0f);
            }
            Window window = XAlertDialog.this.getWindow();
            WindowManager.LayoutParams params = new WindowManager.LayoutParams();
            params.copyFrom(window.getAttributes());
            params.width = Math.min(maxWidth, calculatedWidth) + XAlertDialog.this.backgroundPaddings.left + XAlertDialog.this.backgroundPaddings.right;
            window.setAttributes(params);
        }

        @Override // android.widget.LinearLayout, android.view.ViewGroup, android.view.View
        protected void onLayout(boolean changed, int l, int t, int r, int b) {
            super.onLayout(changed, l, t, r, b);
            if (XAlertDialog.this.progressViewStyle == 3 || XAlertDialog.this.progressViewStyle == 4 || XAlertDialog.this.progressViewStyle == 5) {
                int x = ((r - l) - XAlertDialog.this.progressViewContainer.getMeasuredWidth()) / 2;
                int y = ((b - t) - XAlertDialog.this.progressViewContainer.getMeasuredHeight()) / 2;
                XAlertDialog.this.progressViewContainer.layout(x, y, XAlertDialog.this.progressViewContainer.getMeasuredWidth() + x, XAlertDialog.this.progressViewContainer.getMeasuredHeight() + y);
            } else if (XAlertDialog.this.contentScrollView != null) {
                if (XAlertDialog.this.onScrollChangedListener == null) {
                    XAlertDialog.this.onScrollChangedListener = new ViewTreeObserver.OnScrollChangedListener() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$XAlertDialog$1$Nfi1O4xSK367QPFdaEpXibDW9sY
                        @Override // android.view.ViewTreeObserver.OnScrollChangedListener
                        public final void onScrollChanged() {
                            this.f$0.lambda$onLayout$1$XAlertDialog$1();
                        }
                    };
                    XAlertDialog.this.contentScrollView.getViewTreeObserver().addOnScrollChangedListener(XAlertDialog.this.onScrollChangedListener);
                }
                XAlertDialog.this.onScrollChangedListener.onScrollChanged();
            }
        }

        public /* synthetic */ void lambda$onLayout$1$XAlertDialog$1() {
            XAlertDialog xAlertDialog = XAlertDialog.this;
            boolean z = false;
            xAlertDialog.runShadowAnimation(0, xAlertDialog.titleTextView != null && XAlertDialog.this.contentScrollView.getScrollY() > XAlertDialog.this.scrollContainer.getTop());
            XAlertDialog xAlertDialog2 = XAlertDialog.this;
            if (xAlertDialog2.buttonsLayout != null && XAlertDialog.this.contentScrollView.getScrollY() + XAlertDialog.this.contentScrollView.getHeight() < XAlertDialog.this.scrollContainer.getBottom()) {
                z = true;
            }
            xAlertDialog2.runShadowAnimation(1, z);
            XAlertDialog.this.contentScrollView.invalidate();
        }

        @Override // android.view.View, android.view.ViewParent
        public void requestLayout() {
            if (this.inLayout) {
                return;
            }
            super.requestLayout();
        }

        @Override // android.view.View
        public boolean hasOverlappingRendering() {
            return false;
        }
    }

    public /* synthetic */ void lambda$onCreate$0$XAlertDialog(View v) {
        DialogInterface.OnClickListener onClickListener = this.onClickListener;
        if (onClickListener != null) {
            onClickListener.onClick(this, ((Integer) v.getTag()).intValue());
        }
        dismiss();
    }

    public /* synthetic */ void lambda$onCreate$1$XAlertDialog(View v) {
        DialogInterface.OnClickListener onClickListener = this.positiveButtonListener;
        if (onClickListener != null) {
            onClickListener.onClick(this, -1);
        }
        if (this.dismissDialogByButtons) {
            dismiss();
        }
    }

    public /* synthetic */ void lambda$onCreate$2$XAlertDialog(View v) {
        DialogInterface.OnClickListener onClickListener = this.negativeButtonListener;
        if (onClickListener != null) {
            onClickListener.onClick(this, -2);
        }
        if (this.dismissDialogByButtons) {
            cancel();
        }
    }

    public /* synthetic */ void lambda$onCreate$3$XAlertDialog(View v) {
        DialogInterface.OnClickListener onClickListener = this.neutralButtonListener;
        if (onClickListener != null) {
            onClickListener.onClick(this, -2);
        }
        if (this.dismissDialogByButtons) {
            dismiss();
        }
    }

    @Override // android.app.Dialog
    public void onBackPressed() {
        super.onBackPressed();
        DialogInterface.OnClickListener onClickListener = this.onBackButtonListener;
        if (onClickListener != null) {
            onClickListener.onClick(this, -2);
        }
    }

    private void showCancelAlert() {
        if (!this.canCacnel || this.cancelDialog != null) {
            return;
        }
        Builder builder = new Builder(getContext());
        builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
        builder.setMessage(LocaleController.getString("StopLoading", R.string.StopLoading));
        builder.setPositiveButton(LocaleController.getString("WaitMore", R.string.WaitMore), null);
        builder.setNegativeButton(LocaleController.getString("Stop", R.string.Stop), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$XAlertDialog$YV4kTJ9qBBwR1mZ1s-PHRTdnqPg
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$showCancelAlert$4$XAlertDialog(dialogInterface, i);
            }
        });
        builder.setOnDismissListener(new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$XAlertDialog$nxF5QJKV-SgUptqRZ-JKqpMxrx4
            @Override // android.content.DialogInterface.OnDismissListener
            public final void onDismiss(DialogInterface dialogInterface) {
                this.f$0.lambda$showCancelAlert$5$XAlertDialog(dialogInterface);
            }
        });
        this.cancelDialog = builder.show();
    }

    public /* synthetic */ void lambda$showCancelAlert$4$XAlertDialog(DialogInterface dialogInterface, int i) {
        DialogInterface.OnCancelListener onCancelListener = this.onCancelListener;
        if (onCancelListener != null) {
            onCancelListener.onCancel(this);
        }
        dismiss();
    }

    public /* synthetic */ void lambda$showCancelAlert$5$XAlertDialog(DialogInterface dialog) {
        this.cancelDialog = null;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void runShadowAnimation(final int num, boolean show) {
        if ((show && !this.shadowVisibility[num]) || (!show && this.shadowVisibility[num])) {
            this.shadowVisibility[num] = show;
            AnimatorSet[] animatorSetArr = this.shadowAnimation;
            if (animatorSetArr[num] != null) {
                animatorSetArr[num].cancel();
            }
            this.shadowAnimation[num] = new AnimatorSet();
            BitmapDrawable[] bitmapDrawableArr = this.shadow;
            if (bitmapDrawableArr[num] != null) {
                AnimatorSet animatorSet = this.shadowAnimation[num];
                Animator[] animatorArr = new Animator[1];
                BitmapDrawable bitmapDrawable = bitmapDrawableArr[num];
                int[] iArr = new int[1];
                iArr[0] = show ? 255 : 0;
                animatorArr[0] = ObjectAnimator.ofInt(bitmapDrawable, "alpha", iArr);
                animatorSet.playTogether(animatorArr);
            }
            this.shadowAnimation[num].setDuration(150L);
            this.shadowAnimation[num].addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.actionbar.XAlertDialog.7
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation) {
                    if (XAlertDialog.this.shadowAnimation[num] != null && XAlertDialog.this.shadowAnimation[num].equals(animation)) {
                        XAlertDialog.this.shadowAnimation[num] = null;
                    }
                }

                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationCancel(Animator animation) {
                    if (XAlertDialog.this.shadowAnimation[num] != null && XAlertDialog.this.shadowAnimation[num].equals(animation)) {
                        XAlertDialog.this.shadowAnimation[num] = null;
                    }
                }
            });
            try {
                this.shadowAnimation[num].start();
            } catch (Exception e) {
                FileLog.e(e);
            }
        }
    }

    public void setProgressStyle(int style) {
        this.progressViewStyle = style;
    }

    public void setDismissDialogByButtons(boolean value) {
        this.dismissDialogByButtons = value;
    }

    public void setProgress(int progress) {
        this.currentProgress = progress;
        LineProgressView lineProgressView = this.lineProgressView;
        if (lineProgressView != null) {
            lineProgressView.setProgress(progress / 100.0f, true);
            updateLineProgressTextView();
        }
    }

    private void updateLineProgressTextView() {
        this.lineProgressViewPercent.setText(String.format("%d%%", Integer.valueOf(this.currentProgress)));
    }

    public void setCanCacnel(boolean value) {
        this.canCacnel = value;
    }

    private boolean canTextInput(View v) {
        if (v.onCheckIsTextEditor()) {
            return true;
        }
        if (!(v instanceof ViewGroup)) {
            return false;
        }
        ViewGroup vg = (ViewGroup) v;
        int i = vg.getChildCount();
        while (i > 0) {
            i--;
            if (canTextInput(vg.getChildAt(i))) {
                return true;
            }
        }
        return false;
    }

    @Override // android.app.Dialog
    public void show() {
        try {
            super.show();
        } catch (Exception e) {
            FileLog.e("XAlertDailog show e: " + e.getMessage());
        }
    }

    @Override // android.app.Dialog, android.content.DialogInterface
    public void dismiss() {
        XAlertDialog xAlertDialog = this.cancelDialog;
        if (xAlertDialog != null) {
            xAlertDialog.dismiss();
        }
        try {
            super.dismiss();
        } catch (Throwable th) {
        }
    }

    @Override // android.app.Dialog
    public void setCanceledOnTouchOutside(boolean cancel) {
        super.setCanceledOnTouchOutside(cancel);
    }

    @Override // android.app.Dialog
    public void setCancelable(boolean flag) {
        super.setCancelable(flag);
    }

    public void setTopImage(int resId, int backgroundColor) {
        this.topResId = resId;
        this.topBackgroundColor = backgroundColor;
    }

    public void setLoadingText(CharSequence text) {
        this.loadingText = text;
        TextView textView = this.tvLoadingView;
        if (textView != null) {
            textView.setText(text);
            this.tvLoadingView.setVisibility(TextUtils.isEmpty(this.loadingText) ? 8 : 0);
        }
    }

    public void setLoadingImage(Drawable drawable, int width, int height) {
        ProgressBar progressBar = this.loadingProgressView;
        if (progressBar != null) {
            drawable.setBounds((progressBar.getMeasuredWidth() - width) / 2, (this.loadingProgressView.getMeasuredHeight() - height) / 2, (this.loadingProgressView.getMeasuredWidth() + width) / 2, (this.loadingProgressView.getMeasuredHeight() + height) / 2);
            this.loadingProgressView.setIndeterminateDrawable(drawable);
        }
    }

    public void setTopHeight(int value) {
        this.topHeight = value;
    }

    public void setTopImage(Drawable drawable, int backgroundColor) {
        this.topDrawable = drawable;
        this.topBackgroundColor = backgroundColor;
    }

    @Override // android.app.Dialog
    public void setTitle(CharSequence text) {
        this.title = text;
        TextView textView = this.titleTextView;
        if (textView != null) {
            textView.setText(text);
        }
    }

    public void setSecondTitle(CharSequence text) {
        this.secondTitle = text;
    }

    public void setPositiveButton(CharSequence text, DialogInterface.OnClickListener listener) {
        this.positiveButtonText = text;
        this.positiveButtonListener = listener;
    }

    public void setNegativeButton(CharSequence text, DialogInterface.OnClickListener listener) {
        this.negativeButtonText = text;
        this.negativeButtonListener = listener;
    }

    public void setNeutralButton(CharSequence text, DialogInterface.OnClickListener listener) {
        this.neutralButtonText = text;
        this.neutralButtonListener = listener;
    }

    public void setItemColor(int item, int color, int icon) {
        if (item < 0 || item >= this.itemViews.size()) {
            return;
        }
        AlertDialogCell cell = this.itemViews.get(item);
        cell.textView.setTextColor(color);
        cell.imageView.setColorFilter(new PorterDuffColorFilter(icon, PorterDuff.Mode.MULTIPLY));
    }

    public int getItemsCount() {
        return this.itemViews.size();
    }

    public void setMessage(CharSequence text) {
        this.message = text;
        if (this.messageTextView != null) {
            if (!TextUtils.isEmpty(text)) {
                this.messageTextView.setText(this.message);
                this.messageTextView.setVisibility(0);
            } else {
                this.messageTextView.setVisibility(8);
            }
        }
    }

    public void setMessageTextViewClickable(boolean value) {
        this.messageTextViewClickable = value;
    }

    public void setButton(int type, CharSequence text, DialogInterface.OnClickListener listener) {
        if (type == -3) {
            this.neutralButtonText = text;
            this.neutralButtonListener = listener;
        } else if (type == -2) {
            this.negativeButtonText = text;
            this.negativeButtonListener = listener;
        } else if (type == -1) {
            this.positiveButtonText = text;
            this.positiveButtonListener = listener;
        }
    }

    public View getButton(int type) {
        FrameLayout frameLayout = this.buttonsLayout;
        if (frameLayout != null) {
            return frameLayout.findViewWithTag(Integer.valueOf(type));
        }
        return null;
    }

    @Override // android.graphics.drawable.Drawable.Callback
    public void invalidateDrawable(Drawable who) {
        this.contentScrollView.invalidate();
        this.scrollContainer.invalidate();
    }

    @Override // android.graphics.drawable.Drawable.Callback
    public void scheduleDrawable(Drawable who, Runnable what, long when) {
        ScrollView scrollView = this.contentScrollView;
        if (scrollView != null) {
            scrollView.postDelayed(what, when);
        }
    }

    @Override // android.graphics.drawable.Drawable.Callback
    public void unscheduleDrawable(Drawable who, Runnable what) {
        ScrollView scrollView = this.contentScrollView;
        if (scrollView != null) {
            scrollView.removeCallbacks(what);
        }
    }

    @Override // android.app.Dialog
    public void setOnCancelListener(DialogInterface.OnCancelListener listener) {
        this.onCancelListener = listener;
        super.setOnCancelListener(listener);
    }

    public void setPositiveButtonListener(DialogInterface.OnClickListener listener) {
        this.positiveButtonListener = listener;
    }

    protected int getThemeColor(String key) {
        return Theme.getColor(key);
    }

    public static class Builder {
        private XAlertDialog alertDialog;

        protected Builder(XAlertDialog alert) {
            this.alertDialog = alert;
        }

        public Builder(Context context) {
            this.alertDialog = new XAlertDialog(context, 0);
        }

        public Builder(Context context, int progressViewStyle) {
            this.alertDialog = new XAlertDialog(context, progressViewStyle);
        }

        public Context getContext() {
            return this.alertDialog.getContext();
        }

        public Builder setItems(CharSequence[] items, DialogInterface.OnClickListener onClickListener) {
            this.alertDialog.items = items;
            this.alertDialog.onClickListener = onClickListener;
            return this;
        }

        public Builder setItems(CharSequence[] items, int[] icons, DialogInterface.OnClickListener onClickListener) {
            this.alertDialog.items = items;
            this.alertDialog.itemIcons = icons;
            this.alertDialog.onClickListener = onClickListener;
            return this;
        }

        public Builder setView(View view) {
            this.alertDialog.customView = view;
            return this;
        }

        public Builder setTitle(CharSequence title) {
            this.alertDialog.title = title;
            return this;
        }

        public Builder setSubtitle(CharSequence subtitle) {
            this.alertDialog.subtitle = subtitle;
            return this;
        }

        public Builder setTopImage(int resId, int backgroundColor) {
            this.alertDialog.topResId = resId;
            this.alertDialog.topBackgroundColor = backgroundColor;
            return this;
        }

        public Builder setTopImage(Drawable drawable, int backgroundColor) {
            this.alertDialog.topDrawable = drawable;
            this.alertDialog.topBackgroundColor = backgroundColor;
            return this;
        }

        public Builder setMessage(CharSequence message) {
            this.alertDialog.message = message;
            return this;
        }

        public Builder setPositiveButton(CharSequence text, DialogInterface.OnClickListener listener) {
            this.alertDialog.positiveButtonText = text;
            this.alertDialog.positiveButtonListener = listener;
            return this;
        }

        public Builder setNegativeButton(CharSequence text, DialogInterface.OnClickListener listener) {
            this.alertDialog.negativeButtonText = text;
            this.alertDialog.negativeButtonListener = listener;
            return this;
        }

        public Builder setNeutralButton(CharSequence text, DialogInterface.OnClickListener listener) {
            this.alertDialog.neutralButtonText = text;
            this.alertDialog.neutralButtonListener = listener;
            return this;
        }

        public Builder setOnBackButtonListener(DialogInterface.OnClickListener listener) {
            this.alertDialog.onBackButtonListener = listener;
            return this;
        }

        public Builder setOnCancelListener(DialogInterface.OnCancelListener listener) {
            this.alertDialog.setOnCancelListener(listener);
            return this;
        }

        public Builder setCustomViewOffset(int offset) {
            this.alertDialog.customViewOffset = offset;
            return this;
        }

        public Builder setMessageTextViewClickable(boolean value) {
            this.alertDialog.messageTextViewClickable = value;
            return this;
        }

        public XAlertDialog create() {
            return this.alertDialog;
        }

        public XAlertDialog show() {
            this.alertDialog.show();
            return this.alertDialog;
        }

        public Runnable getDismissRunnable() {
            return this.alertDialog.dismissRunnable;
        }

        public Builder setOnDismissListener(DialogInterface.OnDismissListener onDismissListener) {
            this.alertDialog.setOnDismissListener(onDismissListener);
            return this;
        }
    }
}
