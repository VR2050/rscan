package im.uwrkaxlmjj.ui.cells;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.os.Bundle;
import android.os.SystemClock;
import android.util.Property;
import android.view.MotionEvent;
import android.view.View;
import android.view.accessibility.AccessibilityNodeInfo;
import android.view.animation.DecelerateInterpolator;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.RelativeLayout;
import android.widget.TextView;
import com.king.zxing.util.LogUtils;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.FileLoader;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MediaController;
import im.uwrkaxlmjj.messenger.MessageObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.PhotoViewer;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.CheckBox2;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class PhotoAttachPhotoCell extends FrameLayout {
    private static Rect rect = new Rect();
    private AnimatorSet animator;
    private AnimatorSet animatorSet;
    private Paint backgroundPaint;
    private CheckBox2 checkBox;
    private FrameLayout checkFrame;
    private FrameLayout container;
    private PhotoAttachPhotoCellDelegate delegate;
    private BackupImageView imageView;
    private boolean isLast;
    private boolean isVertical;
    private int itemSize;
    private boolean itemSizeChanged;
    private boolean mblnNewStyle;
    private RelativeLayout mediaInfoContainer;
    private final ImageView mediaInfoDrawableRight;
    private boolean needCheckShow;
    private MediaController.PhotoEntry photoEntry;
    private boolean pressed;
    private MediaController.SearchImage searchEntry;
    private TextView videoTextView;
    private boolean zoomOnSelect;

    public interface PhotoAttachPhotoCellDelegate {
        void onCheckClick(PhotoAttachPhotoCell photoAttachPhotoCell);
    }

    public PhotoAttachPhotoCell(Context context) {
        super(context);
        this.mblnNewStyle = false;
        this.zoomOnSelect = true;
        this.backgroundPaint = new Paint();
        setWillNotDraw(false);
        FrameLayout frameLayout = new FrameLayout(context);
        this.container = frameLayout;
        addView(frameLayout, LayoutHelper.createFrame(80, 80.0f));
        BackupImageView backupImageView = new BackupImageView(context);
        this.imageView = backupImageView;
        this.container.addView(backupImageView, LayoutHelper.createFrame(-1, -1.0f));
        RelativeLayout relativeLayout = new RelativeLayout(context) { // from class: im.uwrkaxlmjj.ui.cells.PhotoAttachPhotoCell.1
            private RectF rect = new RectF();

            @Override // android.view.View
            protected void onDraw(Canvas canvas) {
                this.rect.set(0.0f, 0.0f, getMeasuredWidth(), getMeasuredHeight());
                canvas.drawRoundRect(this.rect, AndroidUtilities.dp(4.0f), AndroidUtilities.dp(4.0f), Theme.chat_timeBackgroundPaint);
            }
        };
        this.mediaInfoContainer = relativeLayout;
        relativeLayout.setWillNotDraw(false);
        this.mediaInfoContainer.setPadding(AndroidUtilities.dp(5.0f), 0, AndroidUtilities.dp(5.0f), 0);
        this.container.addView(this.mediaInfoContainer, LayoutHelper.createFrame(-2.0f, 17.0f, 83, 4.0f, 0.0f, 0.0f, 4.0f));
        ImageView imageView = new ImageView(context);
        this.mediaInfoDrawableRight = imageView;
        imageView.setId(imageView.hashCode());
        this.mediaInfoDrawableRight.setImageResource(R.drawable.play_mini_video);
        this.mediaInfoContainer.addView(this.mediaInfoDrawableRight, LayoutHelper.createRelative(-2, -2, 15));
        TextView textView = new TextView(context);
        this.videoTextView = textView;
        textView.setTextColor(-1);
        this.videoTextView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        this.videoTextView.setTextSize(1, 12.0f);
        this.videoTextView.setImportantForAccessibility(2);
        this.mediaInfoContainer.addView(this.videoTextView, LayoutHelper.createRelative(-2.0f, -2.0f, 4, 0, 0, 0, 15, 1, this.mediaInfoDrawableRight.getId()));
        CheckBox2 checkBox2 = new CheckBox2(context, 24);
        this.checkBox = checkBox2;
        checkBox2.setDrawBackgroundAsArc(7);
        this.checkBox.setColor(Theme.key_chat_attachCheckBoxBackground, Theme.key_chat_attachPhotoBackground, Theme.key_chat_attachCheckBoxCheck);
        addView(this.checkBox, LayoutHelper.createFrame(26.0f, 26.0f, 51, 52.0f, 4.0f, 0.0f, 0.0f));
        this.checkBox.setVisibility(0);
        setFocusable(true);
        FrameLayout frameLayout2 = new FrameLayout(context);
        this.checkFrame = frameLayout2;
        addView(frameLayout2, LayoutHelper.createFrame(42.0f, 42.0f, 51, 38.0f, 0.0f, 0.0f, 0.0f));
        this.itemSize = AndroidUtilities.dp(80.0f);
    }

    public void setIsVertical(boolean value) {
        this.isVertical = value;
    }

    public void setItemSize(int size) {
        this.itemSize = size;
        FrameLayout.LayoutParams layoutParams = (FrameLayout.LayoutParams) this.container.getLayoutParams();
        int i = this.itemSize;
        layoutParams.height = i;
        layoutParams.width = i;
        FrameLayout.LayoutParams layoutParams2 = (FrameLayout.LayoutParams) this.checkFrame.getLayoutParams();
        layoutParams2.gravity = 53;
        layoutParams2.leftMargin = 0;
        FrameLayout.LayoutParams layoutParams3 = (FrameLayout.LayoutParams) this.checkBox.getLayoutParams();
        layoutParams3.gravity = 53;
        layoutParams3.leftMargin = 0;
        int iDp = AndroidUtilities.dp(5.0f);
        layoutParams3.topMargin = iDp;
        layoutParams3.rightMargin = iDp;
        this.checkBox.setDrawBackgroundAsArc(6);
        this.itemSizeChanged = true;
    }

    @Override // android.widget.FrameLayout, android.view.View
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        if (this.itemSizeChanged) {
            super.onMeasure(View.MeasureSpec.makeMeasureSpec(this.itemSize, 1073741824), View.MeasureSpec.makeMeasureSpec(this.itemSize + AndroidUtilities.dp(5.0f), 1073741824));
            return;
        }
        if (this.isVertical) {
            super.onMeasure(View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(80.0f), 1073741824), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp((this.isLast ? 0 : 6) + 80), 1073741824));
        } else {
            super.onMeasure(View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp((this.isLast ? 0 : 6) + 80), 1073741824), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(80.0f), 1073741824));
        }
    }

    public MediaController.PhotoEntry getPhotoEntry() {
        return this.photoEntry;
    }

    public BackupImageView getImageView() {
        return this.imageView;
    }

    public float getScale() {
        return this.container.getScaleX();
    }

    public CheckBox2 getCheckBox() {
        return this.checkBox;
    }

    public FrameLayout getCheckFrame() {
        return this.checkFrame;
    }

    public View getVideoInfoContainer() {
        return this.mediaInfoContainer;
    }

    public void setPhotoEntry(MediaController.PhotoEntry entry, boolean needCheckShow, boolean last) {
        this.pressed = false;
        this.photoEntry = entry;
        this.isLast = last;
        if (entry.isVideo) {
            this.imageView.setOrientation(0, true);
            this.mediaInfoContainer.setVisibility(0);
            int minutes = this.photoEntry.duration / 60;
            int seconds = this.photoEntry.duration - (minutes * 60);
            if (minutes == 0 && seconds == 0) {
                seconds = 1;
            }
            this.videoTextView.setText(String.format("%d:%02d", Integer.valueOf(minutes), Integer.valueOf(seconds)));
        } else if (this.photoEntry.path.endsWith(".gif")) {
            this.mediaInfoContainer.setVisibility(0);
            this.mediaInfoDrawableRight.setVisibility(8);
            this.videoTextView.setText("GIF");
        } else {
            this.mediaInfoContainer.setVisibility(4);
        }
        if (this.photoEntry.thumbPath != null) {
            this.imageView.setImage(this.photoEntry.thumbPath, null, Theme.chat_attachEmptyDrawable);
        } else if (this.photoEntry.path != null) {
            if (this.photoEntry.isVideo) {
                this.imageView.setImage("vthumb://" + this.photoEntry.imageId + LogUtils.COLON + this.photoEntry.path, null, Theme.chat_attachEmptyDrawable);
            } else {
                this.imageView.setOrientation(this.photoEntry.orientation, true);
                this.imageView.setImage("thumb://" + this.photoEntry.imageId + LogUtils.COLON + this.photoEntry.path, null, Theme.chat_attachEmptyDrawable);
            }
        } else {
            this.imageView.setImageDrawable(Theme.chat_attachEmptyDrawable);
        }
        boolean showing = needCheckShow && PhotoViewer.isShowingImage(this.photoEntry.path);
        this.imageView.getImageReceiver().setVisible(showing ? false : true, true);
        this.checkBox.setAlpha(showing ? 0.0f : 1.0f);
        this.mediaInfoContainer.setAlpha(showing ? 0.0f : 1.0f);
        if (this.mblnNewStyle) {
            this.imageView.setAlpha(this.checkBox.isChecked() ? 1.0f : 0.3f);
        }
        requestLayout();
    }

    public void setPhotoEntry(MediaController.SearchImage searchImage, boolean needCheckShow, boolean last) {
        this.pressed = false;
        this.searchEntry = searchImage;
        this.isLast = last;
        Drawable thumb = this.zoomOnSelect ? Theme.chat_attachEmptyDrawable : getResources().getDrawable(R.drawable.nophotos);
        if (searchImage.thumbPhotoSize != null) {
            this.imageView.setImage(ImageLocation.getForPhoto(searchImage.thumbPhotoSize, searchImage.photo), (String) null, thumb, searchImage);
        } else if (searchImage.photoSize != null) {
            this.imageView.setImage(ImageLocation.getForPhoto(searchImage.photoSize, searchImage.photo), "80_80", thumb, searchImage);
        } else if (searchImage.thumbPath != null) {
            this.imageView.setImage(searchImage.thumbPath, null, thumb);
        } else if (searchImage.thumbUrl != null && searchImage.thumbUrl.length() > 0) {
            this.imageView.setImage(searchImage.thumbUrl, null, thumb);
        } else if (MessageObject.isDocumentHasThumb(searchImage.document)) {
            TLRPC.PhotoSize photoSize = FileLoader.getClosestPhotoSizeWithSize(searchImage.document.thumbs, 320);
            this.imageView.setImage(ImageLocation.getForDocument(photoSize, searchImage.document), (String) null, thumb, searchImage);
        } else {
            this.imageView.setImageDrawable(thumb);
        }
        boolean showing = needCheckShow && PhotoViewer.isShowingImage(searchImage.getPathToAttach());
        this.imageView.getImageReceiver().setVisible(showing ? false : true, true);
        this.checkBox.setAlpha(showing ? 0.0f : 1.0f);
        this.mediaInfoContainer.setAlpha(showing ? 0.0f : 1.0f);
        if (this.mblnNewStyle) {
            this.imageView.setAlpha(this.checkBox.isChecked() ? 1.0f : 0.3f);
        }
        requestLayout();
    }

    public boolean isChecked() {
        return this.checkBox.isChecked();
    }

    public void setChecked(int num, final boolean checked, boolean animated) {
        if (this.checkBox.getVisibility() == 0) {
            this.checkBox.setChecked(num, checked, animated);
            if (this.itemSizeChanged) {
                float fScale = 0.787f;
                if (this.mblnNewStyle) {
                    fScale = 1.0f;
                }
                AnimatorSet animatorSet = this.animator;
                if (animatorSet != null) {
                    animatorSet.cancel();
                    this.animator = null;
                }
                if (animated) {
                    AnimatorSet animatorSet2 = new AnimatorSet();
                    this.animator = animatorSet2;
                    Animator[] animatorArr = new Animator[2];
                    FrameLayout frameLayout = this.container;
                    Property property = View.SCALE_X;
                    float[] fArr = new float[1];
                    fArr[0] = checked ? fScale : 1.0f;
                    animatorArr[0] = ObjectAnimator.ofFloat(frameLayout, (Property<FrameLayout, Float>) property, fArr);
                    FrameLayout frameLayout2 = this.container;
                    Property property2 = View.SCALE_Y;
                    float[] fArr2 = new float[1];
                    fArr2[0] = checked ? fScale : 1.0f;
                    animatorArr[1] = ObjectAnimator.ofFloat(frameLayout2, (Property<FrameLayout, Float>) property2, fArr2);
                    animatorSet2.playTogether(animatorArr);
                    this.animator.setDuration(200L);
                    this.animator.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.cells.PhotoAttachPhotoCell.2
                        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                        public void onAnimationEnd(Animator animation) {
                            if (PhotoAttachPhotoCell.this.animator != null && PhotoAttachPhotoCell.this.animator.equals(animation)) {
                                PhotoAttachPhotoCell.this.animator = null;
                                if (!checked) {
                                    PhotoAttachPhotoCell.this.setBackgroundColor(0);
                                }
                            }
                        }

                        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                        public void onAnimationCancel(Animator animation) {
                            if (PhotoAttachPhotoCell.this.animator != null && PhotoAttachPhotoCell.this.animator.equals(animation)) {
                                PhotoAttachPhotoCell.this.animator = null;
                            }
                        }
                    });
                    this.animator.start();
                } else {
                    this.container.setScaleX(checked ? fScale : 1.0f);
                    this.container.setScaleY(checked ? fScale : 1.0f);
                }
            }
            if (this.mblnNewStyle) {
                this.imageView.setAlpha(this.checkBox.isChecked() ? 1.0f : 0.3f);
            }
        }
    }

    public void setNum(int num) {
        this.checkBox.setNum(num);
    }

    public void setOnCheckClickLisnener(View.OnClickListener onCheckClickLisnener) {
        this.checkFrame.setOnClickListener(onCheckClickLisnener);
    }

    public void setDelegate(PhotoAttachPhotoCellDelegate delegate) {
        this.delegate = delegate;
    }

    public void callDelegate() {
        this.delegate.onCheckClick(this);
    }

    public void showImage() {
        this.imageView.getImageReceiver().setVisible(true, true);
    }

    public void showCheck(boolean show) {
        if (show && this.checkBox.getVisibility() == 8) {
            return;
        }
        if (this.checkBox.getAlpha() != 1.0f) {
            if (!show && this.checkBox.getAlpha() == 0.0f) {
                return;
            }
            AnimatorSet animatorSet = this.animatorSet;
            if (animatorSet != null) {
                animatorSet.cancel();
                this.animatorSet = null;
            }
            AnimatorSet animatorSet2 = new AnimatorSet();
            this.animatorSet = animatorSet2;
            animatorSet2.setInterpolator(new DecelerateInterpolator());
            this.animatorSet.setDuration(180L);
            AnimatorSet animatorSet3 = this.animatorSet;
            Animator[] animatorArr = new Animator[2];
            RelativeLayout relativeLayout = this.mediaInfoContainer;
            Property property = View.ALPHA;
            float[] fArr = new float[1];
            fArr[0] = show ? 1.0f : 0.0f;
            animatorArr[0] = ObjectAnimator.ofFloat(relativeLayout, (Property<RelativeLayout, Float>) property, fArr);
            CheckBox2 checkBox2 = this.checkBox;
            Property property2 = View.ALPHA;
            float[] fArr2 = new float[1];
            fArr2[0] = show ? 1.0f : 0.0f;
            animatorArr[1] = ObjectAnimator.ofFloat(checkBox2, (Property<CheckBox2, Float>) property2, fArr2);
            animatorSet3.playTogether(animatorArr);
            this.animatorSet.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.cells.PhotoAttachPhotoCell.3
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation) {
                    if (animation.equals(PhotoAttachPhotoCell.this.animatorSet)) {
                        PhotoAttachPhotoCell.this.animatorSet = null;
                    }
                }
            });
            this.animatorSet.start();
        }
    }

    @Override // android.view.View
    public void clearAnimation() {
        super.clearAnimation();
        AnimatorSet animatorSet = this.animator;
        if (animatorSet != null) {
            animatorSet.cancel();
            this.animator = null;
            this.container.setScaleX(this.checkBox.isChecked() ? 0.787f : 1.0f);
            this.container.setScaleY(this.checkBox.isChecked() ? 0.787f : 1.0f);
        }
    }

    @Override // android.view.View
    public boolean onTouchEvent(MotionEvent event) {
        boolean result = false;
        this.checkFrame.getHitRect(rect);
        if (event.getAction() == 0) {
            if (rect.contains((int) event.getX(), (int) event.getY())) {
                this.pressed = true;
                invalidate();
                result = true;
            }
        } else if (this.pressed) {
            if (event.getAction() == 1) {
                getParent().requestDisallowInterceptTouchEvent(true);
                this.pressed = false;
                playSoundEffect(0);
                sendAccessibilityEvent(1);
                this.delegate.onCheckClick(this);
                invalidate();
            } else if (event.getAction() == 3) {
                this.pressed = false;
                invalidate();
            } else if (event.getAction() == 2 && !rect.contains((int) event.getX(), (int) event.getY())) {
                this.pressed = false;
                invalidate();
            }
        }
        if (!result) {
            return super.onTouchEvent(event);
        }
        return result;
    }

    @Override // android.view.View
    protected void onDraw(Canvas canvas) {
        MediaController.PhotoEntry photoEntry;
        MediaController.SearchImage searchImage;
        if (this.checkBox.isChecked() || this.container.getScaleX() != 1.0f || !this.imageView.getImageReceiver().hasNotThumb() || this.imageView.getImageReceiver().getCurrentAlpha() != 1.0f || (((photoEntry = this.photoEntry) != null && PhotoViewer.isShowingImage(photoEntry.path)) || ((searchImage = this.searchEntry) != null && PhotoViewer.isShowingImage(searchImage.getPathToAttach())))) {
            this.backgroundPaint.setColor(Theme.getColor(Theme.key_chat_attachPhotoBackground));
            canvas.drawRect(0.0f, 0.0f, this.imageView.getMeasuredWidth(), this.imageView.getMeasuredHeight(), this.backgroundPaint);
        }
    }

    @Override // android.view.View
    public void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo info) {
        super.onInitializeAccessibilityNodeInfo(info);
        info.setEnabled(true);
        MediaController.PhotoEntry photoEntry = this.photoEntry;
        if (photoEntry != null && photoEntry.isVideo) {
            info.setText(LocaleController.getString("AttachVideo", R.string.AttachVideo) + ", " + LocaleController.formatCallDuration(this.photoEntry.duration));
        } else {
            info.setText(LocaleController.getString("AttachPhoto", R.string.AttachPhoto));
        }
        if (this.checkBox.isChecked()) {
            info.setSelected(true);
        }
        if (Build.VERSION.SDK_INT >= 21) {
            info.addAction(new AccessibilityNodeInfo.AccessibilityAction(R.attr.acc_action_open_photo, LocaleController.getString("Open", R.string.Open)));
        }
    }

    @Override // android.view.View
    public boolean performAccessibilityAction(int action, Bundle arguments) {
        if (action == R.attr.acc_action_open_photo) {
            View parent = (View) getParent();
            parent.dispatchTouchEvent(MotionEvent.obtain(SystemClock.uptimeMillis(), SystemClock.uptimeMillis(), 0, getLeft(), (getTop() + getHeight()) - 1, 0));
            parent.dispatchTouchEvent(MotionEvent.obtain(SystemClock.uptimeMillis(), SystemClock.uptimeMillis(), 1, getLeft(), (getTop() + getHeight()) - 1, 0));
        }
        return super.performAccessibilityAction(action, arguments);
    }

    public void setNewStyle(boolean blnNewStyle) {
        this.mblnNewStyle = blnNewStyle;
    }
}
