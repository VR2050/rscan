package im.uwrkaxlmjj.ui.cells;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.view.MotionEvent;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.ImageView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.FileLoader;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.MediaController;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.WallpapersListActivity;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.CheckBox;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class WallpaperCell extends FrameLayout {
    private Paint backgroundPaint;
    private Drawable checkDrawable;
    private Paint circlePaint;
    private int currentType;
    private Paint framePaint;
    private boolean isBottom;
    private boolean isTop;
    private int spanCount;
    private WallpaperView[] wallpaperViews;

    /* JADX INFO: Access modifiers changed from: private */
    class WallpaperView extends FrameLayout {
        private AnimatorSet animator;
        private AnimatorSet animatorSet;
        private CheckBox checkBox;
        private Object currentWallpaper;
        private BackupImageView imageView;
        private ImageView imageView2;
        private boolean isSelected;
        private View selector;

        public WallpaperView(Context context) {
            super(context);
            setWillNotDraw(false);
            BackupImageView backupImageView = new BackupImageView(context) { // from class: im.uwrkaxlmjj.ui.cells.WallpaperCell.WallpaperView.1
                @Override // im.uwrkaxlmjj.ui.components.BackupImageView, android.view.View
                protected void onDraw(Canvas canvas) {
                    super.onDraw(canvas);
                    if (WallpaperView.this.currentWallpaper instanceof WallpapersListActivity.ColorWallpaper) {
                        canvas.drawLine(1.0f, 0.0f, getMeasuredWidth() - 1, 0.0f, WallpaperCell.this.framePaint);
                        canvas.drawLine(0.0f, 0.0f, 0.0f, getMeasuredHeight(), WallpaperCell.this.framePaint);
                        canvas.drawLine(getMeasuredWidth() - 1, 0.0f, getMeasuredWidth() - 1, getMeasuredHeight(), WallpaperCell.this.framePaint);
                        canvas.drawLine(1.0f, getMeasuredHeight() - 1, getMeasuredWidth() - 1, getMeasuredHeight() - 1, WallpaperCell.this.framePaint);
                    }
                    if (WallpaperView.this.isSelected) {
                        WallpaperCell.this.circlePaint.setColor(Theme.serviceMessageColorBackup);
                        int cx = getMeasuredWidth() / 2;
                        int cy = getMeasuredHeight() / 2;
                        canvas.drawCircle(cx, cy, AndroidUtilities.dp(20.0f), WallpaperCell.this.circlePaint);
                        WallpaperCell.this.checkDrawable.setBounds(cx - (WallpaperCell.this.checkDrawable.getIntrinsicWidth() / 2), cy - (WallpaperCell.this.checkDrawable.getIntrinsicHeight() / 2), (WallpaperCell.this.checkDrawable.getIntrinsicWidth() / 2) + cx, (WallpaperCell.this.checkDrawable.getIntrinsicHeight() / 2) + cy);
                        WallpaperCell.this.checkDrawable.draw(canvas);
                    }
                }
            };
            this.imageView = backupImageView;
            addView(backupImageView, LayoutHelper.createFrame(-1, -1, 51));
            ImageView imageView = new ImageView(context);
            this.imageView2 = imageView;
            imageView.setImageResource(R.drawable.ic_gallery_background);
            this.imageView2.setScaleType(ImageView.ScaleType.CENTER);
            addView(this.imageView2, LayoutHelper.createFrame(-1, -1, 51));
            View view = new View(context);
            this.selector = view;
            view.setBackgroundDrawable(Theme.getSelectorDrawable(false));
            addView(this.selector, LayoutHelper.createFrame(-1, -1.0f));
            CheckBox checkBox = new CheckBox(context, R.drawable.round_check2);
            this.checkBox = checkBox;
            checkBox.setVisibility(4);
            this.checkBox.setColor(Theme.getColor(Theme.key_checkbox), Theme.getColor(Theme.key_checkboxCheck));
            addView(this.checkBox, LayoutHelper.createFrame(22.0f, 22.0f, 53, 0.0f, 2.0f, 2.0f, 0.0f));
        }

        @Override // android.view.View
        public boolean onTouchEvent(MotionEvent event) {
            if (Build.VERSION.SDK_INT >= 21) {
                this.selector.drawableHotspotChanged(event.getX(), event.getY());
            }
            return super.onTouchEvent(event);
        }

        public void setWallpaper(Object object, long selectedBackground, Drawable themedWallpaper, boolean themed) {
            this.currentWallpaper = object;
            if (object != null) {
                this.imageView.setVisibility(0);
                this.imageView2.setVisibility(4);
                this.imageView.setBackgroundDrawable(null);
                this.imageView.getImageReceiver().setColorFilter(null);
                this.imageView.getImageReceiver().setAlpha(1.0f);
                if (object instanceof TLRPC.TL_wallPaper) {
                    TLRPC.TL_wallPaper wallPaper = (TLRPC.TL_wallPaper) object;
                    this.isSelected = wallPaper.id == selectedBackground;
                    TLRPC.PhotoSize thumb = FileLoader.getClosestPhotoSizeWithSize(wallPaper.document.thumbs, 100);
                    TLRPC.PhotoSize image = FileLoader.getClosestPhotoSizeWithSize(wallPaper.document.thumbs, 320);
                    if (image == thumb) {
                        image = null;
                    }
                    int size = image != null ? image.size : wallPaper.document.size;
                    if (wallPaper.pattern) {
                        this.imageView.setBackgroundColor(wallPaper.settings.background_color | (-16777216));
                        this.imageView.setImage(ImageLocation.getForDocument(image, wallPaper.document), "100_100", ImageLocation.getForDocument(thumb, wallPaper.document), null, "jpg", size, 1, wallPaper);
                        this.imageView.getImageReceiver().setColorFilter(new PorterDuffColorFilter(AndroidUtilities.getPatternColor(wallPaper.settings.background_color), PorterDuff.Mode.SRC_IN));
                        this.imageView.getImageReceiver().setAlpha(wallPaper.settings.intensity / 100.0f);
                        return;
                    }
                    if (image != null) {
                        this.imageView.setImage(ImageLocation.getForDocument(image, wallPaper.document), "100_100", ImageLocation.getForDocument(thumb, wallPaper.document), "100_100_b", "jpg", size, 1, wallPaper);
                        return;
                    } else {
                        this.imageView.setImage(ImageLocation.getForDocument(wallPaper.document), "100_100", ImageLocation.getForDocument(thumb, wallPaper.document), "100_100_b", "jpg", size, 1, wallPaper);
                        return;
                    }
                }
                if (object instanceof WallpapersListActivity.ColorWallpaper) {
                    WallpapersListActivity.ColorWallpaper wallPaper2 = (WallpapersListActivity.ColorWallpaper) object;
                    if (wallPaper2.path != null) {
                        this.imageView.setImage(wallPaper2.path.getAbsolutePath(), "100_100", null);
                    } else {
                        this.imageView.setImageBitmap(null);
                        this.imageView.setBackgroundColor(wallPaper2.color | (-16777216));
                    }
                    this.isSelected = wallPaper2.id == selectedBackground;
                    return;
                }
                if (object instanceof WallpapersListActivity.FileWallpaper) {
                    WallpapersListActivity.FileWallpaper wallPaper3 = (WallpapersListActivity.FileWallpaper) object;
                    this.isSelected = wallPaper3.id == selectedBackground;
                    if (wallPaper3.originalPath != null) {
                        this.imageView.setImage(wallPaper3.originalPath.getAbsolutePath(), "100_100", null);
                        return;
                    }
                    if (wallPaper3.path != null) {
                        this.imageView.setImage(wallPaper3.path.getAbsolutePath(), "100_100", null);
                        return;
                    } else if (wallPaper3.resId == -2) {
                        this.imageView.setImageDrawable(Theme.getThemedWallpaper(true));
                        return;
                    } else {
                        this.imageView.setImageResource(wallPaper3.thumbResId);
                        return;
                    }
                }
                if (object instanceof MediaController.SearchImage) {
                    MediaController.SearchImage wallPaper4 = (MediaController.SearchImage) object;
                    if (wallPaper4.photo != null) {
                        TLRPC.PhotoSize thumb2 = FileLoader.getClosestPhotoSizeWithSize(wallPaper4.photo.sizes, 100);
                        TLRPC.PhotoSize image2 = FileLoader.getClosestPhotoSizeWithSize(wallPaper4.photo.sizes, 320);
                        if (image2 == thumb2) {
                            image2 = null;
                        }
                        this.imageView.setImage(ImageLocation.getForPhoto(image2, wallPaper4.photo), "100_100", ImageLocation.getForPhoto(thumb2, wallPaper4.photo), "100_100_b", "jpg", image2 != null ? image2.size : 0, 1, wallPaper4);
                        return;
                    }
                    this.imageView.setImage(wallPaper4.thumbUrl, "100_100", null);
                    return;
                }
                this.isSelected = false;
                return;
            }
            this.imageView.setVisibility(4);
            this.imageView2.setVisibility(0);
            if (!themed) {
                this.imageView2.setBackgroundColor((selectedBackground == -1 || selectedBackground == Theme.DEFAULT_BACKGROUND_ID) ? 1514625126 : 1509949440);
                this.imageView2.setScaleType(ImageView.ScaleType.CENTER);
                this.imageView2.setImageResource(R.drawable.ic_gallery_background);
            } else {
                this.imageView2.setImageDrawable(themedWallpaper);
                this.imageView2.setScaleType(ImageView.ScaleType.CENTER_CROP);
            }
        }

        public void setChecked(final boolean checked, boolean animated) {
            if (this.checkBox.getVisibility() != 0) {
                this.checkBox.setVisibility(0);
            }
            this.checkBox.setChecked(checked, animated);
            AnimatorSet animatorSet = this.animator;
            if (animatorSet != null) {
                animatorSet.cancel();
                this.animator = null;
            }
            if (animated) {
                AnimatorSet animatorSet2 = new AnimatorSet();
                this.animator = animatorSet2;
                Animator[] animatorArr = new Animator[2];
                BackupImageView backupImageView = this.imageView;
                float[] fArr = new float[1];
                fArr[0] = checked ? 0.8875f : 1.0f;
                animatorArr[0] = ObjectAnimator.ofFloat(backupImageView, "scaleX", fArr);
                BackupImageView backupImageView2 = this.imageView;
                float[] fArr2 = new float[1];
                fArr2[0] = checked ? 0.8875f : 1.0f;
                animatorArr[1] = ObjectAnimator.ofFloat(backupImageView2, "scaleY", fArr2);
                animatorSet2.playTogether(animatorArr);
                this.animator.setDuration(200L);
                this.animator.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.cells.WallpaperCell.WallpaperView.2
                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationEnd(Animator animation) {
                        if (WallpaperView.this.animator != null && WallpaperView.this.animator.equals(animation)) {
                            WallpaperView.this.animator = null;
                            if (!checked) {
                                WallpaperView.this.setBackgroundColor(0);
                            }
                        }
                    }

                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationCancel(Animator animation) {
                        if (WallpaperView.this.animator != null && WallpaperView.this.animator.equals(animation)) {
                            WallpaperView.this.animator = null;
                        }
                    }
                });
                this.animator.start();
            } else {
                this.imageView.setScaleX(checked ? 0.8875f : 1.0f);
                this.imageView.setScaleY(checked ? 0.8875f : 1.0f);
            }
            invalidate();
        }

        @Override // android.view.View
        public void invalidate() {
            super.invalidate();
            this.imageView.invalidate();
        }

        @Override // android.view.View
        public void clearAnimation() {
            super.clearAnimation();
            AnimatorSet animatorSet = this.animator;
            if (animatorSet != null) {
                animatorSet.cancel();
                this.animator = null;
            }
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            if (this.checkBox.isChecked() || !this.imageView.getImageReceiver().hasBitmapImage() || this.imageView.getImageReceiver().getCurrentAlpha() != 1.0f) {
                canvas.drawRect(0.0f, 0.0f, getMeasuredWidth(), getMeasuredHeight(), WallpaperCell.this.backgroundPaint);
            }
        }
    }

    public WallpaperCell(Context context) {
        super(context);
        this.spanCount = 3;
        this.wallpaperViews = new WallpaperView[5];
        int a = 0;
        while (true) {
            WallpaperView[] wallpaperViewArr = this.wallpaperViews;
            if (a < wallpaperViewArr.length) {
                final WallpaperView wallpaperView = new WallpaperView(context);
                wallpaperViewArr[a] = wallpaperView;
                final int num = a;
                addView(wallpaperView);
                wallpaperView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.cells.-$$Lambda$WallpaperCell$RqW6X-CuNihJ0NAOqTlHxFfJAQQ
                    @Override // android.view.View.OnClickListener
                    public final void onClick(View view) {
                        this.f$0.lambda$new$0$WallpaperCell(wallpaperView, num, view);
                    }
                });
                wallpaperView.setOnLongClickListener(new View.OnLongClickListener() { // from class: im.uwrkaxlmjj.ui.cells.-$$Lambda$WallpaperCell$XlWAY_mqptwxxVV91sHQTYDJkSk
                    @Override // android.view.View.OnLongClickListener
                    public final boolean onLongClick(View view) {
                        return this.f$0.lambda$new$1$WallpaperCell(wallpaperView, num, view);
                    }
                });
                a++;
            } else {
                Paint paint = new Paint();
                this.framePaint = paint;
                paint.setColor(Theme.value_blackAlpha80);
                this.circlePaint = new Paint(1);
                this.checkDrawable = context.getResources().getDrawable(R.drawable.background_selected).mutate();
                Paint paint2 = new Paint();
                this.backgroundPaint = paint2;
                paint2.setColor(Theme.getColor(Theme.key_sharedMedia_photoPlaceholder));
                return;
            }
        }
    }

    public /* synthetic */ void lambda$new$0$WallpaperCell(WallpaperView wallpaperView, int num, View v) {
        onWallpaperClick(wallpaperView.currentWallpaper, num);
    }

    public /* synthetic */ boolean lambda$new$1$WallpaperCell(WallpaperView wallpaperView, int num, View v) {
        return onWallpaperLongClick(wallpaperView.currentWallpaper, num);
    }

    protected void onWallpaperClick(Object wallPaper, int index) {
    }

    protected boolean onWallpaperLongClick(Object wallPaper, int index) {
        return false;
    }

    @Override // android.widget.FrameLayout, android.view.View
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        int width = View.MeasureSpec.getSize(widthMeasureSpec);
        int availableWidth = width - AndroidUtilities.dp(((this.spanCount - 1) * 6) + 28);
        int itemWidth = availableWidth / this.spanCount;
        int height = this.currentType == 0 ? AndroidUtilities.dp(180.0f) : itemWidth;
        setMeasuredDimension(width, (this.isTop ? AndroidUtilities.dp(14.0f) : 0) + height + AndroidUtilities.dp(this.isBottom ? 14.0f : 6.0f));
        int a = 0;
        while (true) {
            int i = this.spanCount;
            if (a < i) {
                this.wallpaperViews[a].measure(View.MeasureSpec.makeMeasureSpec(a == i + (-1) ? availableWidth : itemWidth, 1073741824), View.MeasureSpec.makeMeasureSpec(height, 1073741824));
                availableWidth -= itemWidth;
                a++;
            } else {
                return;
            }
        }
    }

    @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
    protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
        int l = AndroidUtilities.dp(14.0f);
        int t = this.isTop ? AndroidUtilities.dp(14.0f) : 0;
        for (int a = 0; a < this.spanCount; a++) {
            int w = this.wallpaperViews[a].getMeasuredWidth();
            WallpaperView[] wallpaperViewArr = this.wallpaperViews;
            wallpaperViewArr[a].layout(l, t, l + w, wallpaperViewArr[a].getMeasuredHeight() + t);
            l += AndroidUtilities.dp(6.0f) + w;
        }
    }

    public void setParams(int columns, boolean top, boolean bottom) {
        this.spanCount = columns;
        this.isTop = top;
        this.isBottom = bottom;
        int a = 0;
        while (true) {
            WallpaperView[] wallpaperViewArr = this.wallpaperViews;
            if (a < wallpaperViewArr.length) {
                wallpaperViewArr[a].setVisibility(a < columns ? 0 : 8);
                this.wallpaperViews[a].clearAnimation();
                a++;
            } else {
                return;
            }
        }
    }

    public void setWallpaper(int type, int index, Object wallpaper, long selectedBackground, Drawable themedWallpaper, boolean themed) {
        this.currentType = type;
        if (wallpaper == null) {
            this.wallpaperViews[index].setVisibility(8);
            this.wallpaperViews[index].clearAnimation();
        } else {
            this.wallpaperViews[index].setVisibility(0);
            this.wallpaperViews[index].setWallpaper(wallpaper, selectedBackground, themedWallpaper, themed);
        }
    }

    public void setChecked(int index, boolean checked, boolean animated) {
        this.wallpaperViews[index].setChecked(checked, animated);
    }

    @Override // android.view.View
    public void invalidate() {
        super.invalidate();
        for (int a = 0; a < this.spanCount; a++) {
            this.wallpaperViews[a].invalidate();
        }
    }
}
