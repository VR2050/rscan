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
import android.util.Log;
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
public class AlertDialog extends Dialog implements Drawable.Callback {
    private Rect backgroundPaddings;
    protected FrameLayout buttonsLayout;
    private boolean canCancel;
    private AlertDialog cancelDialog;
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
    private Object tag;
    private CharSequence title;
    private FrameLayout titleContainer;
    private TextView titleTextView;
    private int topBackgroundColor;
    private Drawable topDrawable;
    private int topHeight;
    private ImageView topImageView;
    private int topResId;

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

    public AlertDialog(Context context, int progressStyle) {
        super(context, R.plurals.TransparentDialog);
        this.shadow = new BitmapDrawable[2];
        this.shadowVisibility = new boolean[2];
        this.shadowAnimation = new AnimatorSet[2];
        this.customViewOffset = 20;
        this.topHeight = 132;
        this.messageTextViewClickable = true;
        this.canCancel = true;
        this.dismissDialogByButtons = true;
        this.dismissRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$hDR2jWSqY2grYhJBL-uQNfTXkaA
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
        if (i2 == 3 || i2 == 4) {
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
            ScrollView scrollView = new ScrollView(getContext()) { // from class: im.uwrkaxlmjj.ui.actionbar.AlertDialog.2
                @Override // android.view.ViewGroup
                protected boolean drawChild(Canvas canvas, View child, long drawingTime) {
                    boolean result = super.drawChild(canvas, child, drawingTime);
                    if (AlertDialog.this.shadow[0].getPaint().getAlpha() != 0) {
                        AlertDialog.this.shadow[0].setBounds(0, getScrollY(), getMeasuredWidth(), getScrollY() + AndroidUtilities.dp(3.0f));
                        AlertDialog.this.shadow[0].draw(canvas);
                    }
                    if (AlertDialog.this.shadow[1].getPaint().getAlpha() != 0) {
                        AlertDialog.this.shadow[1].setBounds(0, (getScrollY() + getMeasuredHeight()) - AndroidUtilities.dp(3.0f), getMeasuredWidth(), getScrollY() + getMeasuredHeight());
                        AlertDialog.this.shadow[1].draw(canvas);
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
        } else if (i4 != 3 && i4 != 4) {
            this.scrollContainer.addView(this.messageTextView, LayoutHelper.createLinear(-2, -2, (LocaleController.isRTL ? 5 : 3) | 48, 24, 0, 24, (this.customView == null && this.items == null) ? 0 : this.customViewOffset));
        } else {
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
                ProgressBar progressView3 = new ProgressBar(getContext());
                progressView3.setIndeterminateDrawable(getContext().getResources().getDrawable(R.drawable.rotate_anim));
                this.progressViewContainer.addView(progressView3, LayoutHelper.createFrame(38, 38, 17));
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
                    cell.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$AlertDialog$CQHBM5lWfKbQYy6a--7FVpZdDhk
                        @Override // android.view.View.OnClickListener
                        public final void onClick(View view) {
                            this.f$0.lambda$onCreate$0$AlertDialog(view);
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
            FrameLayout frameLayout5 = new FrameLayout(getContext()) { // from class: im.uwrkaxlmjj.ui.actionbar.AlertDialog.3
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
            this.buttonsLayout = frameLayout5;
            frameLayout5.setPadding(AndroidUtilities.dp(8.0f), AndroidUtilities.dp(8.0f), AndroidUtilities.dp(8.0f), AndroidUtilities.dp(8.0f));
            containerView.addView(this.buttonsLayout, LayoutHelper.createLinear(-1, 52));
            if (this.positiveButtonText != null) {
                TextView textView7 = new TextView(getContext()) { // from class: im.uwrkaxlmjj.ui.actionbar.AlertDialog.4
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
                textView7.setMinWidth(AndroidUtilities.dp(64.0f));
                textView7.setTag(-1);
                textView7.setTextSize(1, 14.0f);
                textView7.setTextColor(getThemeColor(Theme.key_dialogButton));
                textView7.setGravity(17);
                textView7.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
                textView7.setText(this.positiveButtonText.toString().toUpperCase());
                textView7.setBackgroundDrawable(Theme.getRoundRectSelectorDrawable(getThemeColor(Theme.key_dialogButton)));
                textView7.setPadding(AndroidUtilities.dp(10.0f), 0, AndroidUtilities.dp(10.0f), 0);
                this.buttonsLayout.addView(textView7, LayoutHelper.createFrame(-2, 36, 53));
                textView7.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$AlertDialog$dthVmK042idIW82L1MoCYFiso4Q
                    @Override // android.view.View.OnClickListener
                    public final void onClick(View view2) {
                        this.f$0.lambda$onCreate$1$AlertDialog(view2);
                    }
                });
            }
            if (this.negativeButtonText != null) {
                TextView textView8 = new TextView(getContext()) { // from class: im.uwrkaxlmjj.ui.actionbar.AlertDialog.5
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
                textView8.setMinWidth(AndroidUtilities.dp(64.0f));
                textView8.setTag(-2);
                textView8.setTextSize(1, 14.0f);
                textView8.setTextColor(getThemeColor(Theme.key_dialogButton));
                textView8.setGravity(17);
                textView8.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
                textView8.setEllipsize(TextUtils.TruncateAt.END);
                textView8.setSingleLine(true);
                textView8.setText(this.negativeButtonText.toString().toUpperCase());
                textView8.setBackgroundDrawable(Theme.getRoundRectSelectorDrawable(getThemeColor(Theme.key_dialogButton)));
                textView8.setPadding(AndroidUtilities.dp(10.0f), 0, AndroidUtilities.dp(10.0f), 0);
                this.buttonsLayout.addView(textView8, LayoutHelper.createFrame(-2, 36, 53));
                textView8.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$AlertDialog$ThPlCBFCuavJtlamXGth8b8qc88
                    @Override // android.view.View.OnClickListener
                    public final void onClick(View view2) {
                        this.f$0.lambda$onCreate$2$AlertDialog(view2);
                    }
                });
            }
            if (this.neutralButtonText != null) {
                TextView textView9 = new TextView(getContext()) { // from class: im.uwrkaxlmjj.ui.actionbar.AlertDialog.6
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
                textView9.setTag(-3);
                textView9.setTextSize(1, 14.0f);
                textView9.setTextColor(getThemeColor(Theme.key_dialogButton));
                textView9.setGravity(17);
                textView9.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
                textView9.setEllipsize(TextUtils.TruncateAt.END);
                textView9.setSingleLine(true);
                textView9.setText(this.neutralButtonText.toString().toUpperCase());
                textView9.setBackgroundDrawable(Theme.getRoundRectSelectorDrawable(getThemeColor(Theme.key_dialogButton)));
                textView9.setPadding(AndroidUtilities.dp(10.0f), 0, AndroidUtilities.dp(10.0f), 0);
                this.buttonsLayout.addView(textView9, LayoutHelper.createFrame(-2, 36, 51));
                textView9.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$AlertDialog$hOSADJ10S-43fHJR_oxVtq6Dz48
                    @Override // android.view.View.OnClickListener
                    public final void onClick(View view2) {
                        this.f$0.lambda$onCreate$3$AlertDialog(view2);
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

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.actionbar.AlertDialog$1, reason: invalid class name */
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
            if (AlertDialog.this.progressViewStyle == 3 || AlertDialog.this.progressViewStyle == 4) {
                AlertDialog.this.progressViewContainer.measure(View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(86.0f), 1073741824), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(86.0f), 1073741824));
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
            if (AlertDialog.this.buttonsLayout != null) {
                int count = AlertDialog.this.buttonsLayout.getChildCount();
                for (int a = 0; a < count; a++) {
                    View child = AlertDialog.this.buttonsLayout.getChildAt(a);
                    if (child instanceof TextView) {
                        TextView button = (TextView) child;
                        button.setMaxWidth(AndroidUtilities.dp((availableWidth - AndroidUtilities.dp(24.0f)) / 2));
                    }
                }
                AlertDialog.this.buttonsLayout.measure(childFullWidthMeasureSpec, heightMeasureSpec);
                LinearLayout.LayoutParams layoutParams = (LinearLayout.LayoutParams) AlertDialog.this.buttonsLayout.getLayoutParams();
                availableHeight -= (AlertDialog.this.buttonsLayout.getMeasuredHeight() + layoutParams.bottomMargin) + layoutParams.topMargin;
            }
            if (AlertDialog.this.secondTitleTextView != null) {
                AlertDialog.this.secondTitleTextView.measure(View.MeasureSpec.makeMeasureSpec(View.MeasureSpec.getSize(childWidthMeasureSpec), Integer.MIN_VALUE), heightMeasureSpec);
            }
            if (AlertDialog.this.titleTextView != null) {
                if (AlertDialog.this.secondTitleTextView != null) {
                    AlertDialog.this.titleTextView.measure(View.MeasureSpec.makeMeasureSpec((View.MeasureSpec.getSize(childWidthMeasureSpec) - AlertDialog.this.secondTitleTextView.getMeasuredWidth()) - AndroidUtilities.dp(8.0f), 1073741824), heightMeasureSpec);
                } else {
                    AlertDialog.this.titleTextView.measure(childWidthMeasureSpec, heightMeasureSpec);
                }
            }
            if (AlertDialog.this.titleContainer != null) {
                AlertDialog.this.titleContainer.measure(childWidthMeasureSpec, heightMeasureSpec);
                LinearLayout.LayoutParams layoutParams2 = (LinearLayout.LayoutParams) AlertDialog.this.titleContainer.getLayoutParams();
                availableHeight -= (AlertDialog.this.titleContainer.getMeasuredHeight() + layoutParams2.bottomMargin) + layoutParams2.topMargin;
            }
            if (AlertDialog.this.subtitleTextView != null) {
                AlertDialog.this.subtitleTextView.measure(childWidthMeasureSpec, heightMeasureSpec);
                LinearLayout.LayoutParams layoutParams3 = (LinearLayout.LayoutParams) AlertDialog.this.subtitleTextView.getLayoutParams();
                availableHeight -= (AlertDialog.this.subtitleTextView.getMeasuredHeight() + layoutParams3.bottomMargin) + layoutParams3.topMargin;
            }
            if (AlertDialog.this.topImageView != null) {
                AlertDialog.this.topImageView.measure(View.MeasureSpec.makeMeasureSpec(width, 1073741824), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(AlertDialog.this.topHeight), 1073741824));
                availableHeight -= AlertDialog.this.topImageView.getMeasuredHeight() - AndroidUtilities.dp(8.0f);
            }
            if (AlertDialog.this.progressViewStyle == 0) {
                LinearLayout.LayoutParams layoutParams4 = (LinearLayout.LayoutParams) AlertDialog.this.contentScrollView.getLayoutParams();
                if (AlertDialog.this.customView != null) {
                    layoutParams4.topMargin = (AlertDialog.this.titleTextView == null && AlertDialog.this.messageTextView.getVisibility() == 8 && AlertDialog.this.items == null) ? AndroidUtilities.dp(16.0f) : 0;
                    layoutParams4.bottomMargin = AlertDialog.this.buttonsLayout == null ? AndroidUtilities.dp(8.0f) : 0;
                } else if (AlertDialog.this.items != null) {
                    layoutParams4.topMargin = (AlertDialog.this.titleTextView == null && AlertDialog.this.messageTextView.getVisibility() == 8) ? AndroidUtilities.dp(8.0f) : 0;
                    layoutParams4.bottomMargin = AndroidUtilities.dp(8.0f);
                } else if (AlertDialog.this.messageTextView.getVisibility() == 0) {
                    layoutParams4.topMargin = AlertDialog.this.titleTextView == null ? AndroidUtilities.dp(19.0f) : 0;
                    layoutParams4.bottomMargin = AndroidUtilities.dp(20.0f);
                }
                int availableHeight2 = availableHeight - (layoutParams4.bottomMargin + layoutParams4.topMargin);
                AlertDialog.this.contentScrollView.measure(childFullWidthMeasureSpec, View.MeasureSpec.makeMeasureSpec(availableHeight2, Integer.MIN_VALUE));
                availableHeight = availableHeight2 - AlertDialog.this.contentScrollView.getMeasuredHeight();
            } else {
                if (AlertDialog.this.progressViewContainer != null) {
                    AlertDialog.this.progressViewContainer.measure(childWidthMeasureSpec, View.MeasureSpec.makeMeasureSpec(availableHeight, Integer.MIN_VALUE));
                    LinearLayout.LayoutParams layoutParams5 = (LinearLayout.LayoutParams) AlertDialog.this.progressViewContainer.getLayoutParams();
                    availableHeight -= (AlertDialog.this.progressViewContainer.getMeasuredHeight() + layoutParams5.bottomMargin) + layoutParams5.topMargin;
                } else if (AlertDialog.this.messageTextView != null) {
                    AlertDialog.this.messageTextView.measure(childWidthMeasureSpec, View.MeasureSpec.makeMeasureSpec(availableHeight, Integer.MIN_VALUE));
                    if (AlertDialog.this.messageTextView.getVisibility() != 8) {
                        LinearLayout.LayoutParams layoutParams6 = (LinearLayout.LayoutParams) AlertDialog.this.messageTextView.getLayoutParams();
                        availableHeight -= (AlertDialog.this.messageTextView.getMeasuredHeight() + layoutParams6.bottomMargin) + layoutParams6.topMargin;
                    }
                }
                if (AlertDialog.this.lineProgressView != null) {
                    AlertDialog.this.lineProgressView.measure(childWidthMeasureSpec, View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(4.0f), 1073741824));
                    LinearLayout.LayoutParams layoutParams7 = (LinearLayout.LayoutParams) AlertDialog.this.lineProgressView.getLayoutParams();
                    int availableHeight3 = availableHeight - ((AlertDialog.this.lineProgressView.getMeasuredHeight() + layoutParams7.bottomMargin) + layoutParams7.topMargin);
                    AlertDialog.this.lineProgressViewPercent.measure(childWidthMeasureSpec, View.MeasureSpec.makeMeasureSpec(availableHeight3, Integer.MIN_VALUE));
                    LinearLayout.LayoutParams layoutParams8 = (LinearLayout.LayoutParams) AlertDialog.this.lineProgressViewPercent.getLayoutParams();
                    availableHeight = availableHeight3 - ((AlertDialog.this.lineProgressViewPercent.getMeasuredHeight() + layoutParams8.bottomMargin) + layoutParams8.topMargin);
                }
            }
            setMeasuredDimension(width, (availableHeight - availableHeight) + getPaddingTop() + getPaddingBottom());
            this.inLayout = false;
            if (AlertDialog.this.lastScreenWidth != AndroidUtilities.displaySize.x) {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$AlertDialog$1$Hw4bG0SieONN8T9zdmHi2O-Rw4Q
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$onMeasure$0$AlertDialog$1();
                    }
                });
            }
        }

        public /* synthetic */ void lambda$onMeasure$0$AlertDialog$1() {
            int maxWidth;
            AlertDialog.this.lastScreenWidth = AndroidUtilities.displaySize.x;
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
            Window window = AlertDialog.this.getWindow();
            WindowManager.LayoutParams params = new WindowManager.LayoutParams();
            params.copyFrom(window.getAttributes());
            params.width = Math.min(maxWidth, calculatedWidth) + AlertDialog.this.backgroundPaddings.left + AlertDialog.this.backgroundPaddings.right;
            window.setAttributes(params);
        }

        @Override // android.widget.LinearLayout, android.view.ViewGroup, android.view.View
        protected void onLayout(boolean changed, int l, int t, int r, int b) {
            super.onLayout(changed, l, t, r, b);
            if (AlertDialog.this.progressViewStyle == 3 || AlertDialog.this.progressViewStyle == 4) {
                int x = ((r - l) - AlertDialog.this.progressViewContainer.getMeasuredWidth()) / 2;
                int y = ((b - t) - AlertDialog.this.progressViewContainer.getMeasuredHeight()) / 2;
                AlertDialog.this.progressViewContainer.layout(x, y, AlertDialog.this.progressViewContainer.getMeasuredWidth() + x, AlertDialog.this.progressViewContainer.getMeasuredHeight() + y);
            } else if (AlertDialog.this.contentScrollView != null) {
                if (AlertDialog.this.onScrollChangedListener == null) {
                    AlertDialog.this.onScrollChangedListener = new ViewTreeObserver.OnScrollChangedListener() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$AlertDialog$1$7o23jVs5NAomxV78rnBUxbINTUs
                        @Override // android.view.ViewTreeObserver.OnScrollChangedListener
                        public final void onScrollChanged() {
                            this.f$0.lambda$onLayout$1$AlertDialog$1();
                        }
                    };
                    AlertDialog.this.contentScrollView.getViewTreeObserver().addOnScrollChangedListener(AlertDialog.this.onScrollChangedListener);
                }
                AlertDialog.this.onScrollChangedListener.onScrollChanged();
            }
        }

        public /* synthetic */ void lambda$onLayout$1$AlertDialog$1() {
            AlertDialog alertDialog = AlertDialog.this;
            boolean z = false;
            alertDialog.runShadowAnimation(0, alertDialog.titleTextView != null && AlertDialog.this.contentScrollView.getScrollY() > AlertDialog.this.scrollContainer.getTop());
            AlertDialog alertDialog2 = AlertDialog.this;
            if (alertDialog2.buttonsLayout != null && AlertDialog.this.contentScrollView.getScrollY() + AlertDialog.this.contentScrollView.getHeight() < AlertDialog.this.scrollContainer.getBottom()) {
                z = true;
            }
            alertDialog2.runShadowAnimation(1, z);
            AlertDialog.this.contentScrollView.invalidate();
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

    public /* synthetic */ void lambda$onCreate$0$AlertDialog(View v) {
        DialogInterface.OnClickListener onClickListener = this.onClickListener;
        if (onClickListener != null) {
            onClickListener.onClick(this, ((Integer) v.getTag()).intValue());
        }
        dismiss();
    }

    public /* synthetic */ void lambda$onCreate$1$AlertDialog(View v) {
        DialogInterface.OnClickListener onClickListener = this.positiveButtonListener;
        if (onClickListener != null) {
            onClickListener.onClick(this, -1);
        }
        if (this.dismissDialogByButtons) {
            dismiss();
        }
    }

    public /* synthetic */ void lambda$onCreate$2$AlertDialog(View v) {
        DialogInterface.OnClickListener onClickListener = this.negativeButtonListener;
        if (onClickListener != null) {
            onClickListener.onClick(this, -2);
        }
        if (this.dismissDialogByButtons) {
            cancel();
        }
    }

    public /* synthetic */ void lambda$onCreate$3$AlertDialog(View v) {
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
        if (!this.canCancel || this.cancelDialog != null) {
            return;
        }
        Log.d("bond", " 222222");
        Builder builder = new Builder(getContext());
        builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
        builder.setMessage(LocaleController.getString("StopLoading", R.string.StopLoading));
        builder.setPositiveButton(LocaleController.getString("WaitMore", R.string.WaitMore), null);
        builder.setNegativeButton(LocaleController.getString("Stop", R.string.Stop), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$AlertDialog$TbNQZK0S_QFDfSijl5GOWPrDeFo
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$showCancelAlert$4$AlertDialog(dialogInterface, i);
            }
        });
        builder.setOnDismissListener(new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$AlertDialog$bI20AgxfEcgTs1rDN2zaLaLSZfI
            @Override // android.content.DialogInterface.OnDismissListener
            public final void onDismiss(DialogInterface dialogInterface) {
                this.f$0.lambda$showCancelAlert$5$AlertDialog(dialogInterface);
            }
        });
        this.cancelDialog = builder.show();
    }

    public /* synthetic */ void lambda$showCancelAlert$4$AlertDialog(DialogInterface dialogInterface, int i) {
        DialogInterface.OnCancelListener onCancelListener = this.onCancelListener;
        if (onCancelListener != null) {
            onCancelListener.onCancel(this);
        }
        dismiss();
    }

    public /* synthetic */ void lambda$showCancelAlert$5$AlertDialog(DialogInterface dialog) {
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
            this.shadowAnimation[num].addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.actionbar.AlertDialog.7
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation) {
                    if (AlertDialog.this.shadowAnimation[num] != null && AlertDialog.this.shadowAnimation[num].equals(animation)) {
                        AlertDialog.this.shadowAnimation[num] = null;
                    }
                }

                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationCancel(Animator animation) {
                    if (AlertDialog.this.shadowAnimation[num] != null && AlertDialog.this.shadowAnimation[num].equals(animation)) {
                        AlertDialog.this.shadowAnimation[num] = null;
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

    public void setCanCancel(boolean value) {
        this.canCancel = value;
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

    @Override // android.app.Dialog, android.content.DialogInterface
    public void dismiss() {
        AlertDialog alertDialog = this.cancelDialog;
        if (alertDialog != null) {
            alertDialog.dismiss();
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

    public void setTag(Object tag) {
        this.tag = tag;
    }

    public Object getTag() {
        return this.tag;
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
        private AlertDialog alertDialog;

        protected Builder(AlertDialog alert) {
            this.alertDialog = alert;
        }

        public Builder(Context context) {
            this.alertDialog = new AlertDialog(context, 0);
        }

        public Builder(Context context, int progressViewStyle) {
            this.alertDialog = new AlertDialog(context, progressViewStyle);
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

        public AlertDialog create() {
            return this.alertDialog;
        }

        public AlertDialog show() {
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
