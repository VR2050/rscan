package im.uwrkaxlmjj.ui.cells;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.ColorFilter;
import android.graphics.Paint;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.drawable.Drawable;
import android.text.TextUtils;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.FileLoader;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MediaDataController;
import im.uwrkaxlmjj.messenger.MessageObject;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.hviews.MryAlphaImageView;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class FeaturedStickerSetCell extends FrameLayout {
    private int angle;
    private ImageView checkImage;
    private int currentAccount;
    private AnimatorSet currentAnimation;
    private boolean drawProgress;
    private BackupImageView imageView;
    private boolean isInstalled;
    private MryAlphaImageView ivAdd;
    private long lastUpdateTime;
    private boolean needDivider;
    private float progressAlpha;
    private Paint progressPaint;
    private RectF progressRect;
    private Rect rect;
    private TLRPC.StickerSetCovered stickersSet;
    private TextView textView;
    private TextView valueTextView;
    private boolean wasLayout;

    public FeaturedStickerSetCell(Context context) {
        super(context);
        this.rect = new Rect();
        this.currentAccount = UserConfig.selectedAccount;
        this.progressRect = new RectF();
        Paint paint = new Paint(1);
        this.progressPaint = paint;
        paint.setColor(Theme.getColor(Theme.key_featuredStickers_buttonProgress));
        this.progressPaint.setStrokeCap(Paint.Cap.ROUND);
        this.progressPaint.setStyle(Paint.Style.STROKE);
        this.progressPaint.setStrokeWidth(AndroidUtilities.dp(2.0f));
        TextView textView = new TextView(context);
        this.textView = textView;
        textView.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        this.textView.setTextSize(1, 14.0f);
        this.textView.setLines(1);
        this.textView.setMaxLines(1);
        this.textView.setSingleLine(true);
        this.textView.setEllipsize(TextUtils.TruncateAt.END);
        this.textView.setGravity(LocaleController.isRTL ? 5 : 3);
        addView(this.textView, LayoutHelper.createFrame(-2.0f, -2.0f, LocaleController.isRTL ? 5 : 3, LocaleController.isRTL ? 22.0f : 71.0f, 10.0f, LocaleController.isRTL ? 71.0f : 22.0f, 0.0f));
        TextView textView2 = new TextView(context);
        this.valueTextView = textView2;
        textView2.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText2));
        this.valueTextView.setTextSize(1, 13.0f);
        this.valueTextView.setLines(1);
        this.valueTextView.setMaxLines(1);
        this.valueTextView.setSingleLine(true);
        this.valueTextView.setEllipsize(TextUtils.TruncateAt.END);
        this.valueTextView.setGravity(LocaleController.isRTL ? 5 : 3);
        addView(this.valueTextView, LayoutHelper.createFrame(-2.0f, -2.0f, LocaleController.isRTL ? 5 : 3, LocaleController.isRTL ? 100.0f : 71.0f, 35.0f, LocaleController.isRTL ? 71.0f : 100.0f, 0.0f));
        BackupImageView backupImageView = new BackupImageView(context);
        this.imageView = backupImageView;
        backupImageView.setAspectFit(true);
        this.imageView.setLayerNum(1);
        addView(this.imageView, LayoutHelper.createFrame(48.0f, 48.0f, (LocaleController.isRTL ? 5 : 3) | 48, LocaleController.isRTL ? 0.0f : 12.0f, 8.0f, LocaleController.isRTL ? 12.0f : 0.0f, 0.0f));
        MryAlphaImageView mryAlphaImageView = new MryAlphaImageView(context) { // from class: im.uwrkaxlmjj.ui.cells.FeaturedStickerSetCell.1
            @Override // android.widget.ImageView, android.view.View
            protected void onDraw(Canvas canvas) {
                if (FeaturedStickerSetCell.this.drawProgress || (!FeaturedStickerSetCell.this.drawProgress && FeaturedStickerSetCell.this.progressAlpha != 0.0f)) {
                    FeaturedStickerSetCell.this.progressPaint.setAlpha(Math.min(255, (int) (FeaturedStickerSetCell.this.progressAlpha * 255.0f)));
                    int x = getMeasuredWidth() - AndroidUtilities.dp(11.0f);
                    FeaturedStickerSetCell.this.progressRect.set(x, AndroidUtilities.dp(10.0f), AndroidUtilities.dp(10.0f) + x, AndroidUtilities.dp(20.0f));
                    canvas.drawArc(FeaturedStickerSetCell.this.progressRect, FeaturedStickerSetCell.this.angle, 220.0f, false, FeaturedStickerSetCell.this.progressPaint);
                    invalidate(((int) FeaturedStickerSetCell.this.progressRect.left) - AndroidUtilities.dp(2.0f), ((int) FeaturedStickerSetCell.this.progressRect.top) - AndroidUtilities.dp(2.0f), ((int) FeaturedStickerSetCell.this.progressRect.right) + AndroidUtilities.dp(2.0f), ((int) FeaturedStickerSetCell.this.progressRect.bottom) + AndroidUtilities.dp(2.0f));
                    long newTime = System.currentTimeMillis();
                    if (Math.abs(FeaturedStickerSetCell.this.lastUpdateTime - System.currentTimeMillis()) < 1000) {
                        long delta = newTime - FeaturedStickerSetCell.this.lastUpdateTime;
                        float dt = (360 * delta) / 2000.0f;
                        FeaturedStickerSetCell.this.angle = (int) (r7.angle + dt);
                        FeaturedStickerSetCell.this.angle -= (FeaturedStickerSetCell.this.angle / 360) * 360;
                        if (FeaturedStickerSetCell.this.drawProgress) {
                            if (FeaturedStickerSetCell.this.progressAlpha < 1.0f) {
                                FeaturedStickerSetCell.this.progressAlpha += delta / 200.0f;
                                if (FeaturedStickerSetCell.this.progressAlpha > 1.0f) {
                                    FeaturedStickerSetCell.this.progressAlpha = 1.0f;
                                }
                            }
                        } else if (FeaturedStickerSetCell.this.progressAlpha > 0.0f) {
                            FeaturedStickerSetCell.this.progressAlpha -= delta / 200.0f;
                            if (FeaturedStickerSetCell.this.progressAlpha < 0.0f) {
                                FeaturedStickerSetCell.this.progressAlpha = 0.0f;
                            }
                        }
                    }
                    FeaturedStickerSetCell.this.lastUpdateTime = newTime;
                    invalidate();
                    return;
                }
                super.onDraw(canvas);
            }
        };
        this.ivAdd = mryAlphaImageView;
        mryAlphaImageView.setScaleType(ImageView.ScaleType.FIT_CENTER);
        this.ivAdd.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_featuredStickers_addedIcon), PorterDuff.Mode.SRC_IN));
        this.ivAdd.setImageResource(R.id.icon_add);
        addView(this.ivAdd, LayoutHelper.createFrame(-2.0f, 28.0f, (LocaleController.isRTL ? 3 : 5) | 48, LocaleController.isRTL ? 14.0f : 0.0f, 18.0f, LocaleController.isRTL ? 0.0f : 14.0f, 0.0f));
        ImageView imageView = new ImageView(context);
        this.checkImage = imageView;
        imageView.setColorFilter(new PorterDuffColorFilter(Color.parseColor("#A7A7A7"), PorterDuff.Mode.SRC_IN));
        this.checkImage.setImageResource(R.id.ic_selected);
        addView(this.checkImage, LayoutHelper.createFrame(19, 14.0f));
    }

    @Override // android.widget.FrameLayout, android.view.View
    protected void onMeasure(int i, int i2) {
        super.onMeasure(View.MeasureSpec.makeMeasureSpec(View.MeasureSpec.getSize(i), 1073741824), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(64.0f) + (this.needDivider ? 1 : 0), 1073741824));
        measureChildWithMargins(this.textView, i, this.ivAdd.getMeasuredWidth(), i2, 0);
    }

    @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
    protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
        super.onLayout(changed, left, top, right, bottom);
        int l = (this.ivAdd.getLeft() + (this.ivAdd.getMeasuredWidth() / 2)) - (this.checkImage.getMeasuredWidth() / 2);
        int t = (this.ivAdd.getTop() + (this.ivAdd.getMeasuredHeight() / 2)) - (this.checkImage.getMeasuredHeight() / 2);
        ImageView imageView = this.checkImage;
        imageView.layout(l, t, imageView.getMeasuredWidth() + l, this.checkImage.getMeasuredHeight() + t);
        this.wasLayout = true;
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        this.wasLayout = false;
    }

    public void setStickersSet(TLRPC.StickerSetCovered set, boolean divider, boolean unread) {
        TLRPC.Document sticker;
        TLObject object;
        ImageLocation imageLocation;
        boolean sameSet = set == this.stickersSet && this.wasLayout;
        this.needDivider = divider;
        this.stickersSet = set;
        this.lastUpdateTime = System.currentTimeMillis();
        setWillNotDraw(!this.needDivider);
        AnimatorSet animatorSet = this.currentAnimation;
        if (animatorSet != null) {
            animatorSet.cancel();
            this.currentAnimation = null;
        }
        this.textView.setText(this.stickersSet.set.title);
        if (unread) {
            Drawable drawable = new Drawable() { // from class: im.uwrkaxlmjj.ui.cells.FeaturedStickerSetCell.2
                Paint paint = new Paint(1);

                @Override // android.graphics.drawable.Drawable
                public void draw(Canvas canvas) {
                    this.paint.setColor(-12277526);
                    canvas.drawCircle(AndroidUtilities.dp(4.0f), AndroidUtilities.dp(5.0f), AndroidUtilities.dp(3.0f), this.paint);
                }

                @Override // android.graphics.drawable.Drawable
                public void setAlpha(int alpha) {
                }

                @Override // android.graphics.drawable.Drawable
                public void setColorFilter(ColorFilter colorFilter) {
                }

                @Override // android.graphics.drawable.Drawable
                public int getOpacity() {
                    return -2;
                }

                @Override // android.graphics.drawable.Drawable
                public int getIntrinsicWidth() {
                    return AndroidUtilities.dp(12.0f);
                }

                @Override // android.graphics.drawable.Drawable
                public int getIntrinsicHeight() {
                    return AndroidUtilities.dp(8.0f);
                }
            };
            this.textView.setCompoundDrawablesWithIntrinsicBounds(LocaleController.isRTL ? null : drawable, (Drawable) null, LocaleController.isRTL ? drawable : null, (Drawable) null);
        } else {
            this.textView.setCompoundDrawablesWithIntrinsicBounds(0, 0, 0, 0);
        }
        this.valueTextView.setText(LocaleController.formatPluralString("Stickers", set.set.count));
        if (set.cover != null) {
            sticker = set.cover;
        } else if (!set.covers.isEmpty()) {
            sticker = set.covers.get(0);
        } else {
            sticker = null;
        }
        if (sticker != null) {
            if (set.set.thumb instanceof TLRPC.TL_photoSize) {
                object = set.set.thumb;
            } else {
                TLObject object2 = sticker;
                object = object2;
            }
            if (object instanceof TLRPC.Document) {
                TLRPC.PhotoSize thumb = FileLoader.getClosestPhotoSizeWithSize(sticker.thumbs, 90);
                ImageLocation imageLocation2 = ImageLocation.getForDocument(thumb, sticker);
                imageLocation = imageLocation2;
            } else {
                TLRPC.PhotoSize thumb2 = (TLRPC.PhotoSize) object;
                imageLocation = ImageLocation.getForSticker(thumb2, sticker);
            }
            if ((object instanceof TLRPC.Document) && MessageObject.isAnimatedStickerDocument(sticker)) {
                this.imageView.setImage(ImageLocation.getForDocument(sticker), "50_50", imageLocation, null, 0, set);
            } else if (imageLocation != null && imageLocation.lottieAnimation) {
                this.imageView.setImage(imageLocation, "50_50", "tgs", (Drawable) null, set);
            } else {
                this.imageView.setImage(imageLocation, "50_50", "webp", (Drawable) null, set);
            }
        } else {
            this.imageView.setImage((ImageLocation) null, (String) null, "webp", (Drawable) null, set);
        }
        if (sameSet) {
            boolean wasInstalled = this.isInstalled;
            boolean zIsStickerPackInstalled = MediaDataController.getInstance(this.currentAccount).isStickerPackInstalled(set.set.id);
            this.isInstalled = zIsStickerPackInstalled;
            if (zIsStickerPackInstalled) {
                if (!wasInstalled) {
                    this.checkImage.setVisibility(0);
                    this.ivAdd.setEnabled(false);
                    AnimatorSet animatorSet2 = new AnimatorSet();
                    this.currentAnimation = animatorSet2;
                    animatorSet2.setDuration(200L);
                    this.currentAnimation.playTogether(ObjectAnimator.ofFloat(this.ivAdd, "alpha", 1.0f, 0.0f), ObjectAnimator.ofFloat(this.ivAdd, "scaleX", 1.0f, 0.01f), ObjectAnimator.ofFloat(this.ivAdd, "scaleY", 1.0f, 0.01f), ObjectAnimator.ofFloat(this.checkImage, "alpha", 0.0f, 1.0f), ObjectAnimator.ofFloat(this.checkImage, "scaleX", 0.01f, 1.0f), ObjectAnimator.ofFloat(this.checkImage, "scaleY", 0.01f, 1.0f));
                    this.currentAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.cells.FeaturedStickerSetCell.3
                        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                        public void onAnimationEnd(Animator animator) {
                            if (FeaturedStickerSetCell.this.currentAnimation != null && FeaturedStickerSetCell.this.currentAnimation.equals(animator)) {
                                FeaturedStickerSetCell.this.ivAdd.setVisibility(4);
                            }
                        }

                        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                        public void onAnimationCancel(Animator animator) {
                            if (FeaturedStickerSetCell.this.currentAnimation != null && FeaturedStickerSetCell.this.currentAnimation.equals(animator)) {
                                FeaturedStickerSetCell.this.currentAnimation = null;
                            }
                        }
                    });
                    this.currentAnimation.start();
                    return;
                }
                return;
            }
            if (wasInstalled) {
                this.ivAdd.setVisibility(0);
                this.ivAdd.setEnabled(true);
                AnimatorSet animatorSet3 = new AnimatorSet();
                this.currentAnimation = animatorSet3;
                animatorSet3.setDuration(200L);
                this.currentAnimation.playTogether(ObjectAnimator.ofFloat(this.checkImage, "alpha", 1.0f, 0.0f), ObjectAnimator.ofFloat(this.checkImage, "scaleX", 1.0f, 0.01f), ObjectAnimator.ofFloat(this.checkImage, "scaleY", 1.0f, 0.01f), ObjectAnimator.ofFloat(this.ivAdd, "alpha", 0.0f, 1.0f), ObjectAnimator.ofFloat(this.ivAdd, "scaleX", 0.01f, 1.0f), ObjectAnimator.ofFloat(this.ivAdd, "scaleY", 0.01f, 1.0f));
                this.currentAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.cells.FeaturedStickerSetCell.4
                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationEnd(Animator animator) {
                        if (FeaturedStickerSetCell.this.currentAnimation != null && FeaturedStickerSetCell.this.currentAnimation.equals(animator)) {
                            FeaturedStickerSetCell.this.checkImage.setVisibility(4);
                        }
                    }

                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationCancel(Animator animator) {
                        if (FeaturedStickerSetCell.this.currentAnimation != null && FeaturedStickerSetCell.this.currentAnimation.equals(animator)) {
                            FeaturedStickerSetCell.this.currentAnimation = null;
                        }
                    }
                });
                this.currentAnimation.start();
                return;
            }
            return;
        }
        boolean zIsStickerPackInstalled2 = MediaDataController.getInstance(this.currentAccount).isStickerPackInstalled(set.set.id);
        this.isInstalled = zIsStickerPackInstalled2;
        if (zIsStickerPackInstalled2) {
            this.ivAdd.setVisibility(4);
            this.ivAdd.setEnabled(false);
            this.checkImage.setVisibility(0);
            this.checkImage.setScaleX(1.0f);
            this.checkImage.setScaleY(1.0f);
            this.checkImage.setAlpha(1.0f);
            return;
        }
        this.ivAdd.setVisibility(0);
        this.ivAdd.setEnabled(true);
        this.checkImage.setVisibility(4);
        this.ivAdd.setScaleX(1.0f);
        this.ivAdd.setScaleY(1.0f);
        this.ivAdd.setAlpha(1.0f);
    }

    public TLRPC.StickerSetCovered getStickerSet() {
        return this.stickersSet;
    }

    public void setAddOnClickListener(View.OnClickListener onClickListener) {
        this.ivAdd.setOnClickListener(onClickListener);
    }

    public void setDrawProgress(boolean value) {
        this.drawProgress = value;
        this.lastUpdateTime = System.currentTimeMillis();
        this.ivAdd.invalidate();
    }

    public boolean isInstalled() {
        return this.isInstalled;
    }

    @Override // android.view.View
    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        if (this.needDivider) {
            canvas.drawLine(0.0f, getHeight() - 1, getWidth() - getPaddingRight(), getHeight() - 1, Theme.dividerPaint);
        }
    }
}
