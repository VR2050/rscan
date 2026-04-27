package im.uwrkaxlmjj.ui;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.content.Context;
import android.content.SharedPreferences;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.PorterDuffXfermode;
import android.graphics.RectF;
import android.graphics.drawable.Drawable;
import android.text.TextPaint;
import android.text.TextUtils;
import android.text.style.CharacterStyle;
import android.util.Property;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.TextView;
import androidx.core.app.NotificationCompat;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.DownloadController;
import im.uwrkaxlmjj.messenger.FileLoader;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.ImageLoader;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.ImageReceiver;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MediaController;
import im.uwrkaxlmjj.messenger.MessageObject;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.Utilities;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.WallpapersListActivity;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.ThemeDescription;
import im.uwrkaxlmjj.ui.cells.ChatActionCell;
import im.uwrkaxlmjj.ui.cells.ChatMessageCell;
import im.uwrkaxlmjj.ui.cells.HeaderCell;
import im.uwrkaxlmjj.ui.components.AnimationProperties;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.ColorPicker;
import im.uwrkaxlmjj.ui.components.CubicBezierInterpolator;
import im.uwrkaxlmjj.ui.components.RadialProgress2;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.SeekBarView;
import im.uwrkaxlmjj.ui.components.WallpaperParallaxEffect;
import java.io.File;
import java.io.FileOutputStream;
import java.util.ArrayList;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class WallpaperActivity extends BaseFragment implements DownloadController.FileDownloadProgressListener, NotificationCenter.NotificationCenterDelegate {
    private static final int share_item = 1;
    private int TAG;
    private int backgroundColor;
    private BackupImageView backgroundImage;
    private Paint backgroundPaint;
    private Bitmap blurredBitmap;
    private FrameLayout bottomOverlayChat;
    private TextView bottomOverlayChatText;
    private FrameLayout buttonsContainer;
    private CheckBoxView[] checkBoxView;
    private Paint checkPaint;
    private ColorPicker colorPicker;
    private float currentIntensity;
    private Object currentWallpaper;
    private Bitmap currentWallpaperBitmap;
    private WallpaperActivityDelegate delegate;
    private Paint eraserPaint;
    private HeaderCell intensityCell;
    private SeekBarView intensitySeekBar;
    private boolean isBlurred;
    private boolean isMotion;
    private RecyclerListView listView;
    private AnimatorSet motionAnimation;
    private WallpaperParallaxEffect parallaxEffect;
    private int patternColor;
    private ArrayList<Object> patterns;
    private PatternsAdapter patternsAdapter;
    private LinearLayoutManager patternsLayoutManager;
    private RecyclerListView patternsListView;
    private int previousBackgroundColor;
    private float previousIntensity;
    private TLRPC.TL_wallPaper previousSelectedPattern;
    private boolean progressVisible;
    private RadialProgress2 radialProgress;
    private TLRPC.TL_wallPaper selectedPattern;
    private TextPaint textPaint;
    private FrameLayout[] patternLayout = new FrameLayout[3];
    private TextView[] patternsCancelButton = new TextView[2];
    private TextView[] patternsSaveButton = new TextView[2];
    private FrameLayout[] patternsButtonsContainer = new FrameLayout[2];
    private PorterDuff.Mode blendMode = PorterDuff.Mode.SRC_IN;
    private float parallaxScale = 1.0f;
    private String loadingFile = null;
    private File loadingFileObject = null;
    private TLRPC.PhotoSize loadingSize = null;
    private String imageFilter = "640_360";
    private int maxWallpaperSize = 1920;

    public interface WallpaperActivityDelegate {
        void didSetNewBackground();
    }

    private class PatternCell extends BackupImageView implements DownloadController.FileDownloadProgressListener {
        private int TAG;
        private TLRPC.TL_wallPaper currentPattern;
        private RadialProgress2 radialProgress;
        private RectF rect;
        private boolean wasSelected;

        public PatternCell(Context context) {
            super(context);
            this.rect = new RectF();
            setRoundRadius(AndroidUtilities.dp(6.0f));
            RadialProgress2 radialProgress2 = new RadialProgress2(this);
            this.radialProgress = radialProgress2;
            radialProgress2.setProgressRect(AndroidUtilities.dp(30.0f), AndroidUtilities.dp(30.0f), AndroidUtilities.dp(70.0f), AndroidUtilities.dp(70.0f));
            this.TAG = DownloadController.getInstance(WallpaperActivity.this.currentAccount).generateObserverTag();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setPattern(TLRPC.TL_wallPaper wallPaper) {
            this.currentPattern = wallPaper;
            if (wallPaper != null) {
                TLRPC.PhotoSize thumb = FileLoader.getClosestPhotoSizeWithSize(wallPaper.document.thumbs, 100);
                setImage(ImageLocation.getForDocument(thumb, wallPaper.document), "100_100", null, null, "jpg", 0, 1, wallPaper);
            } else {
                setImageDrawable(null);
            }
            updateSelected(false);
        }

        @Override // im.uwrkaxlmjj.ui.components.BackupImageView, android.view.View
        protected void onAttachedToWindow() {
            super.onAttachedToWindow();
            updateSelected(false);
        }

        public void updateSelected(boolean animated) {
            TLRPC.TL_wallPaper tL_wallPaper;
            boolean isSelected = (this.currentPattern == null && WallpaperActivity.this.selectedPattern == null) || !(WallpaperActivity.this.selectedPattern == null || (tL_wallPaper = this.currentPattern) == null || tL_wallPaper.id != WallpaperActivity.this.selectedPattern.id);
            if (isSelected) {
                WallpaperActivity wallpaperActivity = WallpaperActivity.this;
                wallpaperActivity.updateButtonState(this.radialProgress, wallpaperActivity.selectedPattern, this, false, animated);
            } else {
                this.radialProgress.setIcon(4, false, animated);
            }
            invalidate();
        }

        @Override // im.uwrkaxlmjj.ui.components.BackupImageView, android.view.View
        protected void onDraw(Canvas canvas) {
            getImageReceiver().setAlpha(0.8f);
            WallpaperActivity.this.backgroundPaint.setColor(WallpaperActivity.this.backgroundColor);
            this.rect.set(0.0f, 0.0f, getMeasuredWidth(), getMeasuredHeight());
            canvas.drawRoundRect(this.rect, AndroidUtilities.dp(6.0f), AndroidUtilities.dp(6.0f), WallpaperActivity.this.backgroundPaint);
            super.onDraw(canvas);
            this.radialProgress.setColors(WallpaperActivity.this.patternColor, WallpaperActivity.this.patternColor, -1, -1);
            this.radialProgress.draw(canvas);
        }

        @Override // android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            setMeasuredDimension(AndroidUtilities.dp(100.0f), AndroidUtilities.dp(100.0f));
        }

        @Override // im.uwrkaxlmjj.messenger.DownloadController.FileDownloadProgressListener
        public void onFailedDownload(String fileName, boolean canceled) {
            WallpaperActivity.this.updateButtonState(this.radialProgress, this.currentPattern, this, true, canceled);
        }

        @Override // im.uwrkaxlmjj.messenger.DownloadController.FileDownloadProgressListener
        public void onSuccessDownload(String fileName) {
            this.radialProgress.setProgress(1.0f, WallpaperActivity.this.progressVisible);
            WallpaperActivity.this.updateButtonState(this.radialProgress, this.currentPattern, this, false, true);
        }

        @Override // im.uwrkaxlmjj.messenger.DownloadController.FileDownloadProgressListener
        public void onProgressDownload(String fileName, float progress) {
            this.radialProgress.setProgress(progress, WallpaperActivity.this.progressVisible);
            if (this.radialProgress.getIcon() != 10) {
                WallpaperActivity.this.updateButtonState(this.radialProgress, this.currentPattern, this, false, true);
            }
        }

        @Override // im.uwrkaxlmjj.messenger.DownloadController.FileDownloadProgressListener
        public void onProgressUpload(String fileName, float progress, boolean isEncrypted) {
        }

        @Override // im.uwrkaxlmjj.messenger.DownloadController.FileDownloadProgressListener
        public int getObserverTag() {
            return this.TAG;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    class CheckBoxView extends View {
        private static final float progressBounceDiff = 0.2f;
        public final Property<CheckBoxView, Float> PROGRESS_PROPERTY;
        private ObjectAnimator checkAnimator;
        private String currentText;
        private int currentTextSize;
        private Bitmap drawBitmap;
        private Canvas drawCanvas;
        private boolean isChecked;
        private int maxTextSize;
        private float progress;
        private RectF rect;

        public CheckBoxView(Context context, boolean check) {
            super(context);
            this.PROGRESS_PROPERTY = new AnimationProperties.FloatProperty<CheckBoxView>(NotificationCompat.CATEGORY_PROGRESS) { // from class: im.uwrkaxlmjj.ui.WallpaperActivity.CheckBoxView.1
                @Override // im.uwrkaxlmjj.ui.components.AnimationProperties.FloatProperty
                public void setValue(CheckBoxView object, float value) {
                    CheckBoxView.this.progress = value;
                    CheckBoxView.this.invalidate();
                }

                @Override // android.util.Property
                public Float get(CheckBoxView object) {
                    return Float.valueOf(CheckBoxView.this.progress);
                }
            };
            this.rect = new RectF();
            if (check) {
                this.drawBitmap = Bitmap.createBitmap(AndroidUtilities.dp(18.0f), AndroidUtilities.dp(18.0f), Bitmap.Config.ARGB_4444);
                this.drawCanvas = new Canvas(this.drawBitmap);
            }
        }

        public void setText(String text, int current, int max) {
            this.currentText = text;
            this.currentTextSize = current;
            this.maxTextSize = max;
        }

        @Override // android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            super.onMeasure(View.MeasureSpec.makeMeasureSpec(this.maxTextSize + AndroidUtilities.dp(56.0f), 1073741824), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(32.0f), 1073741824));
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            float bounceProgress;
            float checkProgress;
            this.rect.set(0.0f, 0.0f, getMeasuredWidth(), getMeasuredHeight());
            canvas.drawRoundRect(this.rect, AndroidUtilities.dp(4.0f), AndroidUtilities.dp(4.0f), Theme.chat_actionBackgroundPaint);
            int x = ((getMeasuredWidth() - this.currentTextSize) - AndroidUtilities.dp(28.0f)) / 2;
            canvas.drawText(this.currentText, AndroidUtilities.dp(28.0f) + x, AndroidUtilities.dp(21.0f), WallpaperActivity.this.textPaint);
            canvas.save();
            canvas.translate(x, AndroidUtilities.dp(7.0f));
            if (this.drawBitmap == null) {
                WallpaperActivity.this.backgroundPaint.setColor(WallpaperActivity.this.backgroundColor);
                this.rect.set(0.0f, 0.0f, AndroidUtilities.dp(18.0f), AndroidUtilities.dp(18.0f));
                RectF rectF = this.rect;
                canvas.drawRoundRect(rectF, rectF.width() / 2.0f, this.rect.height() / 2.0f, WallpaperActivity.this.backgroundPaint);
            } else {
                float bounceProgress2 = this.progress;
                if (bounceProgress2 <= 0.5f) {
                    bounceProgress = bounceProgress2 / 0.5f;
                    checkProgress = bounceProgress;
                } else {
                    bounceProgress = 2.0f - (bounceProgress2 / 0.5f);
                    checkProgress = 1.0f;
                }
                float bounce = AndroidUtilities.dp(1.0f) * bounceProgress;
                this.rect.set(bounce, bounce, AndroidUtilities.dp(18.0f) - bounce, AndroidUtilities.dp(18.0f) - bounce);
                this.drawBitmap.eraseColor(0);
                WallpaperActivity.this.backgroundPaint.setColor(-1);
                Canvas canvas2 = this.drawCanvas;
                RectF rectF2 = this.rect;
                canvas2.drawRoundRect(rectF2, rectF2.width() / 2.0f, this.rect.height() / 2.0f, WallpaperActivity.this.backgroundPaint);
                if (checkProgress != 1.0f) {
                    float rad = Math.min(AndroidUtilities.dp(7.0f), (AndroidUtilities.dp(7.0f) * checkProgress) + bounce);
                    this.rect.set(AndroidUtilities.dp(2.0f) + rad, AndroidUtilities.dp(2.0f) + rad, AndroidUtilities.dp(16.0f) - rad, AndroidUtilities.dp(16.0f) - rad);
                    Canvas canvas3 = this.drawCanvas;
                    RectF rectF3 = this.rect;
                    canvas3.drawRoundRect(rectF3, rectF3.width() / 2.0f, this.rect.height() / 2.0f, WallpaperActivity.this.eraserPaint);
                }
                if (this.progress > 0.5f) {
                    int endX = (int) (AndroidUtilities.dp(7.3f) - (AndroidUtilities.dp(2.5f) * (1.0f - bounceProgress)));
                    int endY = (int) (AndroidUtilities.dp(13.0f) - (AndroidUtilities.dp(2.5f) * (1.0f - bounceProgress)));
                    this.drawCanvas.drawLine(AndroidUtilities.dp(7.3f), AndroidUtilities.dp(13.0f), endX, endY, WallpaperActivity.this.checkPaint);
                    int endX2 = (int) (AndroidUtilities.dp(7.3f) + (AndroidUtilities.dp(6.0f) * (1.0f - bounceProgress)));
                    int endY2 = (int) (AndroidUtilities.dp(13.0f) - (AndroidUtilities.dp(6.0f) * (1.0f - bounceProgress)));
                    this.drawCanvas.drawLine(AndroidUtilities.dp(7.3f), AndroidUtilities.dp(13.0f), endX2, endY2, WallpaperActivity.this.checkPaint);
                }
                canvas.drawBitmap(this.drawBitmap, 0.0f, 0.0f, (Paint) null);
            }
            canvas.restore();
        }

        private void setProgress(float value) {
            if (this.progress == value) {
                return;
            }
            this.progress = value;
            invalidate();
        }

        private void cancelCheckAnimator() {
            ObjectAnimator objectAnimator = this.checkAnimator;
            if (objectAnimator != null) {
                objectAnimator.cancel();
            }
        }

        private void animateToCheckedState(boolean newCheckedState) {
            Property<CheckBoxView, Float> property = this.PROGRESS_PROPERTY;
            float[] fArr = new float[1];
            fArr[0] = newCheckedState ? 1.0f : 0.0f;
            ObjectAnimator objectAnimatorOfFloat = ObjectAnimator.ofFloat(this, property, fArr);
            this.checkAnimator = objectAnimatorOfFloat;
            objectAnimatorOfFloat.setDuration(300L);
            this.checkAnimator.start();
        }

        @Override // android.view.View
        protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
            super.onLayout(changed, left, top, right, bottom);
        }

        public void setChecked(boolean checked, boolean animated) {
            if (checked == this.isChecked) {
                return;
            }
            this.isChecked = checked;
            if (animated) {
                animateToCheckedState(checked);
                return;
            }
            cancelCheckAnimator();
            this.progress = checked ? 1.0f : 0.0f;
            invalidate();
        }

        public boolean isChecked() {
            return this.isChecked;
        }
    }

    public WallpaperActivity(Object wallPaper, Bitmap bitmap) {
        this.currentIntensity = 0.4f;
        this.currentWallpaper = wallPaper;
        this.currentWallpaperBitmap = bitmap;
        if (wallPaper instanceof TLRPC.TL_wallPaper) {
            return;
        }
        if (wallPaper instanceof WallpapersListActivity.ColorWallpaper) {
            WallpapersListActivity.ColorWallpaper object = (WallpapersListActivity.ColorWallpaper) wallPaper;
            this.isMotion = object.motion;
            TLRPC.TL_wallPaper tL_wallPaper = object.pattern;
            this.selectedPattern = tL_wallPaper;
            if (tL_wallPaper != null) {
                this.currentIntensity = object.intensity;
            }
        }
    }

    public void setInitialModes(boolean blur, boolean motion) {
        this.isBlurred = blur;
        this.isMotion = motion;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        super.onFragmentCreate();
        this.imageFilter = ((int) (1080.0f / AndroidUtilities.density)) + "_" + ((int) (1920.0f / AndroidUtilities.density)) + "_f";
        this.maxWallpaperSize = Math.min(1920, Math.max(AndroidUtilities.displaySize.x, AndroidUtilities.displaySize.y));
        NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.wallpapersNeedReload);
        this.TAG = DownloadController.getInstance(this.currentAccount).generateObserverTag();
        TextPaint textPaint = new TextPaint(1);
        this.textPaint = textPaint;
        textPaint.setColor(-1);
        this.textPaint.setTextSize(AndroidUtilities.dp(14.0f));
        this.textPaint.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        Paint paint = new Paint(1);
        this.checkPaint = paint;
        paint.setStyle(Paint.Style.STROKE);
        this.checkPaint.setStrokeWidth(AndroidUtilities.dp(2.0f));
        this.checkPaint.setColor(0);
        this.checkPaint.setStrokeCap(Paint.Cap.ROUND);
        this.checkPaint.setXfermode(new PorterDuffXfermode(PorterDuff.Mode.CLEAR));
        Paint paint2 = new Paint(1);
        this.eraserPaint = paint2;
        paint2.setColor(0);
        this.eraserPaint.setXfermode(new PorterDuffXfermode(PorterDuff.Mode.CLEAR));
        this.backgroundPaint = new Paint(1);
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        Bitmap bitmap = this.blurredBitmap;
        if (bitmap != null) {
            bitmap.recycle();
            this.blurredBitmap = null;
        }
        Theme.applyChatServiceMessageColor();
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.wallpapersNeedReload);
    }

    /* JADX WARN: Incorrect condition in loop: B:32:0x01be */
    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public android.view.View createView(android.content.Context r37) {
        /*
            Method dump skipped, instruction units count: 1363
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.WallpaperActivity.createView(android.content.Context):android.view.View");
    }

    public /* synthetic */ void lambda$createView$0$WallpaperActivity(ImageReceiver imageReceiver, boolean set, boolean thumb) {
        if (!(this.currentWallpaper instanceof WallpapersListActivity.ColorWallpaper)) {
            Drawable drawable = imageReceiver.getDrawable();
            if (set && drawable != null) {
                Theme.applyChatServiceMessageColor(AndroidUtilities.calcDrawableColor(drawable));
                this.listView.invalidateViews();
                int N = this.buttonsContainer.getChildCount();
                for (int a = 0; a < N; a++) {
                    this.buttonsContainer.getChildAt(a).invalidate();
                }
                RadialProgress2 radialProgress2 = this.radialProgress;
                if (radialProgress2 != null) {
                    radialProgress2.setColors(Theme.key_chat_serviceBackground, Theme.key_chat_serviceBackground, Theme.key_chat_serviceText, Theme.key_chat_serviceText);
                }
                if (!thumb && this.isBlurred && this.blurredBitmap == null) {
                    this.backgroundImage.getImageReceiver().setCrossfadeWithOldImage(false);
                    updateBlurred();
                    this.backgroundImage.getImageReceiver().setCrossfadeWithOldImage(true);
                }
            }
        }
    }

    public /* synthetic */ void lambda$createView$1$WallpaperActivity(View view) {
        boolean done;
        long id;
        int color;
        int color2;
        long saveId;
        long id2;
        File f;
        boolean done2;
        boolean sameFile = false;
        File toFile = new File(ApplicationLoader.getFilesDirFixed(), this.isBlurred ? "wallpaper_original.jpg" : "wallpaper.jpg");
        Object obj = this.currentWallpaper;
        if (obj instanceof TLRPC.TL_wallPaper) {
            try {
                Bitmap bitmap = this.backgroundImage.getImageReceiver().getBitmap();
                FileOutputStream stream = new FileOutputStream(toFile);
                bitmap.compress(Bitmap.CompressFormat.JPEG, 87, stream);
                stream.close();
                done = true;
            } catch (Exception e) {
                done = false;
                FileLog.e(e);
            }
            if (!done) {
                File f2 = FileLoader.getPathToAttach(((TLRPC.TL_wallPaper) this.currentWallpaper).document, true);
                try {
                    boolean done3 = AndroidUtilities.copyFile(f2, toFile);
                    done = done3;
                } catch (Exception e2) {
                    done = false;
                    FileLog.e(e2);
                }
            }
        } else {
            boolean done4 = obj instanceof WallpapersListActivity.ColorWallpaper;
            if (done4) {
                if (this.selectedPattern != null) {
                    try {
                        Bitmap bitmap2 = this.backgroundImage.getImageReceiver().getBitmap();
                        Bitmap dst = Bitmap.createBitmap(bitmap2.getWidth(), bitmap2.getHeight(), Bitmap.Config.ARGB_8888);
                        Canvas canvas = new Canvas(dst);
                        canvas.drawColor(this.backgroundColor);
                        Paint paint = new Paint(2);
                        paint.setColorFilter(new PorterDuffColorFilter(this.patternColor, this.blendMode));
                        paint.setAlpha((int) (this.currentIntensity * 255.0f));
                        canvas.drawBitmap(bitmap2, 0.0f, 0.0f, paint);
                        FileOutputStream stream2 = new FileOutputStream(toFile);
                        dst.compress(Bitmap.CompressFormat.JPEG, 87, stream2);
                        stream2.close();
                        done = true;
                    } catch (Throwable e3) {
                        FileLog.e(e3);
                        done = false;
                    }
                } else {
                    done = true;
                }
            } else {
                boolean done5 = obj instanceof WallpapersListActivity.FileWallpaper;
                if (done5) {
                    WallpapersListActivity.FileWallpaper wallpaper = (WallpapersListActivity.FileWallpaper) obj;
                    if (wallpaper.resId != 0 || wallpaper.resId == -2) {
                        done = true;
                    } else {
                        try {
                            File fromFile = wallpaper.originalPath != null ? wallpaper.originalPath : wallpaper.path;
                            boolean zEquals = fromFile.equals(toFile);
                            sameFile = zEquals;
                            if (zEquals) {
                                done2 = true;
                            } else {
                                done2 = AndroidUtilities.copyFile(fromFile, toFile);
                            }
                            done = done2;
                        } catch (Exception e4) {
                            FileLog.e(e4);
                            done = false;
                        }
                    }
                } else {
                    boolean done6 = obj instanceof MediaController.SearchImage;
                    if (done6) {
                        MediaController.SearchImage wallpaper2 = (MediaController.SearchImage) obj;
                        if (wallpaper2.photo != null) {
                            TLRPC.PhotoSize image = FileLoader.getClosestPhotoSizeWithSize(wallpaper2.photo.sizes, this.maxWallpaperSize, true);
                            File f3 = FileLoader.getPathToAttach(image, true);
                            f = f3;
                        } else {
                            f = ImageLoader.getHttpFilePath(wallpaper2.imageUrl, "jpg");
                        }
                        try {
                            boolean done7 = AndroidUtilities.copyFile(f, toFile);
                            done = done7;
                        } catch (Exception e5) {
                            FileLog.e(e5);
                            done = false;
                        }
                    } else {
                        done = false;
                    }
                }
            }
        }
        if (this.isBlurred) {
            try {
                File blurredFile = new File(ApplicationLoader.getFilesDirFixed(), "wallpaper.jpg");
                FileOutputStream stream3 = new FileOutputStream(blurredFile);
                this.blurredBitmap.compress(Bitmap.CompressFormat.JPEG, 87, stream3);
                stream3.close();
                done = true;
            } catch (Throwable e6) {
                FileLog.e(e6);
                done = false;
            }
        }
        String slug = null;
        long saveId2 = 0;
        long access_hash = 0;
        long pattern = 0;
        File path = null;
        Object obj2 = this.currentWallpaper;
        if (obj2 instanceof TLRPC.TL_wallPaper) {
            TLRPC.TL_wallPaper wallPaper = (TLRPC.TL_wallPaper) obj2;
            long id3 = wallPaper.id;
            saveId2 = id3;
            access_hash = wallPaper.access_hash;
            slug = wallPaper.slug;
            color = 0;
            id = id3;
        } else if (obj2 instanceof WallpapersListActivity.ColorWallpaper) {
            WallpapersListActivity.ColorWallpaper wallPaper2 = (WallpapersListActivity.ColorWallpaper) obj2;
            TLRPC.TL_wallPaper tL_wallPaper = this.selectedPattern;
            if (tL_wallPaper != null) {
                long saveId3 = tL_wallPaper.id;
                access_hash = this.selectedPattern.access_hash;
                if (wallPaper2.id == wallPaper2.patternId && this.backgroundColor == wallPaper2.color && wallPaper2.intensity - this.currentIntensity <= 0.001f) {
                    id2 = this.selectedPattern.id;
                } else {
                    id2 = -1;
                }
                pattern = this.selectedPattern.id;
                slug = this.selectedPattern.slug;
                saveId2 = saveId3;
                saveId = id2;
            } else {
                saveId = -1;
            }
            int color3 = this.backgroundColor;
            color = color3;
            id = saveId;
        } else if (obj2 instanceof WallpapersListActivity.FileWallpaper) {
            WallpapersListActivity.FileWallpaper wallPaper3 = (WallpapersListActivity.FileWallpaper) obj2;
            long id4 = wallPaper3.id;
            path = wallPaper3.path;
            id = id4;
            color = 0;
        } else if (obj2 instanceof MediaController.SearchImage) {
            MediaController.SearchImage wallPaper4 = (MediaController.SearchImage) obj2;
            if (wallPaper4.photo != null) {
                color2 = 0;
                TLRPC.PhotoSize image2 = FileLoader.getClosestPhotoSizeWithSize(wallPaper4.photo.sizes, this.maxWallpaperSize, true);
                path = FileLoader.getPathToAttach(image2, true);
            } else {
                color2 = 0;
                path = ImageLoader.getHttpFilePath(wallPaper4.imageUrl, "jpg");
            }
            id = -1;
            color = color2;
        } else {
            id = 0;
            color = 0;
        }
        boolean sameFile2 = sameFile;
        MessagesController.getInstance(this.currentAccount).saveWallpaperToServer(path, saveId2, slug, access_hash, this.isBlurred, this.isMotion, color, this.currentIntensity, access_hash != 0, 0L);
        if (done) {
            Theme.serviceMessageColorBackup = Theme.getColor(Theme.key_chat_serviceBackground);
            SharedPreferences preferences = MessagesController.getGlobalMainSettings();
            SharedPreferences.Editor editor = preferences.edit();
            editor.putLong("selectedBackground2", id);
            if (!TextUtils.isEmpty(slug)) {
                editor.putString("selectedBackgroundSlug", slug);
            } else {
                editor.remove("selectedBackgroundSlug");
            }
            editor.putBoolean("selectedBackgroundBlurred", this.isBlurred);
            editor.putBoolean("selectedBackgroundMotion", this.isMotion);
            editor.putInt("selectedColor", color);
            editor.putFloat("selectedIntensity", this.currentIntensity);
            editor.putLong("selectedPattern", pattern);
            editor.putBoolean("overrideThemeWallpaper", id != -2);
            editor.commit();
            Theme.reloadWallpaper();
            if (!sameFile2) {
                ImageLoader.getInstance().removeImage(ImageLoader.getHttpFileName(toFile.getAbsolutePath()) + "@100_100");
            }
        }
        WallpaperActivityDelegate wallpaperActivityDelegate = this.delegate;
        if (wallpaperActivityDelegate != null) {
            wallpaperActivityDelegate.didSetNewBackground();
        }
        finishFragment();
    }

    public /* synthetic */ void lambda$createView$2$WallpaperActivity(int num, CheckBoxView view, View v) {
        if (this.buttonsContainer.getAlpha() != 1.0f) {
            return;
        }
        if (this.currentWallpaper instanceof WallpapersListActivity.ColorWallpaper) {
            if (num == 2) {
                view.setChecked(!view.isChecked(), true);
                boolean zIsChecked = view.isChecked();
                this.isMotion = zIsChecked;
                this.parallaxEffect.setEnabled(zIsChecked);
                animateMotionChange();
                return;
            }
            if (num == 1 && this.patternLayout[num].getVisibility() == 0) {
                this.backgroundImage.setImageDrawable(null);
                this.selectedPattern = null;
                this.isMotion = false;
                updateButtonState(this.radialProgress, null, this, false, true);
                updateSelectedPattern(true);
                this.checkBoxView[1].setChecked(false, true);
                this.patternsListView.invalidateViews();
            }
            showPatternsView(num, this.patternLayout[num].getVisibility() != 0);
            return;
        }
        view.setChecked(!view.isChecked(), true);
        if (num == 0) {
            this.isBlurred = view.isChecked();
            updateBlurred();
        } else {
            boolean zIsChecked2 = view.isChecked();
            this.isMotion = zIsChecked2;
            this.parallaxEffect.setEnabled(zIsChecked2);
            animateMotionChange();
        }
    }

    public /* synthetic */ void lambda$createView$3$WallpaperActivity(int offsetX, int offsetY) {
        float progress;
        if (!this.isMotion) {
            return;
        }
        if (this.motionAnimation != null) {
            progress = (this.backgroundImage.getScaleX() - 1.0f) / (this.parallaxScale - 1.0f);
        } else {
            progress = 1.0f;
        }
        this.backgroundImage.setTranslationX(offsetX * progress);
        this.backgroundImage.setTranslationY(offsetY * progress);
    }

    public /* synthetic */ void lambda$createView$4$WallpaperActivity(int num, View v) {
        if (num == 0) {
            setBackgroundColor(this.previousBackgroundColor);
        } else {
            TLRPC.TL_wallPaper tL_wallPaper = this.previousSelectedPattern;
            this.selectedPattern = tL_wallPaper;
            if (tL_wallPaper == null) {
                this.backgroundImage.setImageDrawable(null);
            } else {
                this.backgroundImage.setImage(ImageLocation.getForDocument(tL_wallPaper.document), this.imageFilter, null, null, "jpg", this.selectedPattern.document.size, 1, this.selectedPattern);
            }
            this.checkBoxView[1].setChecked(this.selectedPattern != null, false);
            float f = this.previousIntensity;
            this.currentIntensity = f;
            this.intensitySeekBar.setProgress(f);
            this.backgroundImage.getImageReceiver().setAlpha(this.currentIntensity);
            updateButtonState(this.radialProgress, null, this, false, true);
            updateSelectedPattern(true);
        }
        showPatternsView(num, false);
    }

    public /* synthetic */ void lambda$createView$5$WallpaperActivity(int num, View v) {
        showPatternsView(num, false);
    }

    public /* synthetic */ void lambda$createView$6$WallpaperActivity(View view, int position) {
        boolean previousMotion = this.selectedPattern != null;
        if (position == 0) {
            this.backgroundImage.setImageDrawable(null);
            this.selectedPattern = null;
            this.isMotion = false;
            updateButtonState(this.radialProgress, null, this, false, true);
        } else {
            TLRPC.TL_wallPaper wallPaper = (TLRPC.TL_wallPaper) this.patterns.get(position - 1);
            this.backgroundImage.setImage(ImageLocation.getForDocument(wallPaper.document), this.imageFilter, null, null, "jpg", wallPaper.document.size, 1, wallPaper);
            this.selectedPattern = wallPaper;
            this.isMotion = this.checkBoxView[2].isChecked();
            updateButtonState(this.radialProgress, null, this, false, true);
        }
        if (previousMotion == (this.selectedPattern == null)) {
            animateMotionChange();
            updateMotionButton();
        }
        updateSelectedPattern(true);
        this.checkBoxView[1].setChecked(this.selectedPattern != null, true);
        this.patternsListView.invalidateViews();
    }

    public /* synthetic */ void lambda$createView$7$WallpaperActivity(float progress) {
        this.currentIntensity = progress;
        this.backgroundImage.getImageReceiver().setAlpha(this.currentIntensity);
        this.backgroundImage.invalidate();
        this.patternsListView.invalidateViews();
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id == NotificationCenter.wallpapersNeedReload) {
            Object obj = this.currentWallpaper;
            if (obj instanceof WallpapersListActivity.FileWallpaper) {
                WallpapersListActivity.FileWallpaper fileWallpaper = (WallpapersListActivity.FileWallpaper) obj;
                if (fileWallpaper.id == -1) {
                    fileWallpaper.id = ((Long) args[0]).longValue();
                }
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        if (this.isMotion) {
            this.parallaxEffect.setEnabled(true);
        }
        AndroidUtilities.requestAdjustResize(getParentActivity(), this.classGuid);
        AndroidUtilities.removeAdjustResize(getParentActivity(), this.classGuid);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onPause() {
        super.onPause();
        if (this.isMotion) {
            this.parallaxEffect.setEnabled(false);
        }
    }

    @Override // im.uwrkaxlmjj.messenger.DownloadController.FileDownloadProgressListener
    public void onFailedDownload(String fileName, boolean canceled) {
        updateButtonState(this.radialProgress, null, this, true, canceled);
    }

    @Override // im.uwrkaxlmjj.messenger.DownloadController.FileDownloadProgressListener
    public void onSuccessDownload(String fileName) {
        this.radialProgress.setProgress(1.0f, this.progressVisible);
        updateButtonState(this.radialProgress, null, this, false, true);
    }

    @Override // im.uwrkaxlmjj.messenger.DownloadController.FileDownloadProgressListener
    public void onProgressDownload(String fileName, float progress) {
        this.radialProgress.setProgress(progress, this.progressVisible);
        if (this.radialProgress.getIcon() != 10) {
            updateButtonState(this.radialProgress, null, this, false, true);
        }
    }

    @Override // im.uwrkaxlmjj.messenger.DownloadController.FileDownloadProgressListener
    public void onProgressUpload(String fileName, float progress, boolean isEncrypted) {
    }

    @Override // im.uwrkaxlmjj.messenger.DownloadController.FileDownloadProgressListener
    public int getObserverTag() {
        return this.TAG;
    }

    private void updateBlurred() {
        if (this.isBlurred && this.blurredBitmap == null) {
            Bitmap bitmap = this.currentWallpaperBitmap;
            if (bitmap != null) {
                this.blurredBitmap = Utilities.blurWallpaper(bitmap);
            } else {
                ImageReceiver imageReceiver = this.backgroundImage.getImageReceiver();
                if (imageReceiver.hasNotThumb() || imageReceiver.hasStaticThumb()) {
                    this.blurredBitmap = Utilities.blurWallpaper(imageReceiver.getBitmap());
                }
            }
        }
        if (this.isBlurred) {
            Bitmap bitmap2 = this.blurredBitmap;
            if (bitmap2 != null) {
                this.backgroundImage.setImageBitmap(bitmap2);
                return;
            }
            return;
        }
        setCurrentImage(false);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateButtonState(RadialProgress2 radial, Object image, DownloadController.FileDownloadProgressListener listener, boolean ifSame, boolean animated) {
        Object object;
        File path;
        String fileName;
        int size;
        int size2;
        String fileName2;
        boolean animated2 = animated;
        if (listener == this) {
            if (this.selectedPattern != null) {
                object = this.selectedPattern;
            } else {
                object = this.currentWallpaper;
            }
        } else {
            object = image;
        }
        if ((object instanceof TLRPC.TL_wallPaper) || (object instanceof MediaController.SearchImage)) {
            if (image == null && animated2 && !this.progressVisible) {
                animated2 = false;
            }
            if (object instanceof TLRPC.TL_wallPaper) {
                TLRPC.TL_wallPaper wallPaper = (TLRPC.TL_wallPaper) object;
                fileName2 = FileLoader.getAttachFileName(wallPaper.document);
                if (TextUtils.isEmpty(fileName2)) {
                    return;
                }
                path = FileLoader.getPathToAttach(wallPaper.document, true);
                size2 = wallPaper.document.size;
            } else {
                MediaController.SearchImage wallPaper2 = (MediaController.SearchImage) object;
                if (wallPaper2.photo != null) {
                    TLRPC.PhotoSize photoSize = FileLoader.getClosestPhotoSizeWithSize(wallPaper2.photo.sizes, this.maxWallpaperSize, true);
                    path = FileLoader.getPathToAttach(photoSize, true);
                    fileName = FileLoader.getAttachFileName(photoSize);
                    size = photoSize.size;
                } else {
                    path = ImageLoader.getHttpFilePath(wallPaper2.imageUrl, "jpg");
                    String fileName3 = path.getName();
                    fileName = fileName3;
                    size = wallPaper2.size;
                }
                if (!TextUtils.isEmpty(fileName)) {
                    size2 = size;
                    fileName2 = fileName;
                } else {
                    return;
                }
            }
            boolean fileExists = path.exists();
            if (fileExists) {
                DownloadController.getInstance(this.currentAccount).removeLoadingFileObserver(listener);
                radial.setProgress(1.0f, animated2);
                radial.setIcon(image != null ? 6 : 4, ifSame, animated2);
                if (image == null) {
                    this.backgroundImage.invalidate();
                    if (size2 != 0) {
                        this.actionBar.setSubtitle(AndroidUtilities.formatFileSize(size2));
                    } else {
                        this.actionBar.setSubtitle(null);
                    }
                }
            } else {
                DownloadController.getInstance(this.currentAccount).addLoadingFileObserver(fileName2, null, listener);
                FileLoader.getInstance(this.currentAccount).isLoadingFile(fileName2);
                Float progress = ImageLoader.getInstance().getFileProgress(fileName2);
                if (progress != null) {
                    radial.setProgress(progress.floatValue(), animated2);
                } else {
                    radial.setProgress(0.0f, animated2);
                }
                radial.setIcon(10, ifSame, animated2);
                if (image == null) {
                    this.actionBar.setSubtitle(LocaleController.getString("LoadingFullImage", R.string.LoadingFullImage));
                    this.backgroundImage.invalidate();
                }
            }
            if (image == null) {
                if (this.selectedPattern == null) {
                    this.buttonsContainer.setAlpha(fileExists ? 1.0f : 0.5f);
                }
                this.bottomOverlayChat.setEnabled(fileExists);
                this.bottomOverlayChatText.setAlpha(fileExists ? 1.0f : 0.5f);
                return;
            }
            return;
        }
        radial.setIcon(listener != this ? 6 : 4, ifSame, animated2);
    }

    public void setDelegate(WallpaperActivityDelegate wallpaperActivityDelegate) {
        this.delegate = wallpaperActivityDelegate;
    }

    public void setPatterns(ArrayList<Object> arrayList) {
        this.patterns = arrayList;
        Object obj = this.currentWallpaper;
        if (obj instanceof WallpapersListActivity.ColorWallpaper) {
            WallpapersListActivity.ColorWallpaper wallPaper = (WallpapersListActivity.ColorWallpaper) obj;
            if (wallPaper.patternId != 0) {
                int a = 0;
                int N = this.patterns.size();
                while (true) {
                    if (a >= N) {
                        break;
                    }
                    TLRPC.TL_wallPaper pattern = (TLRPC.TL_wallPaper) this.patterns.get(a);
                    if (pattern.id != wallPaper.patternId) {
                        a++;
                    } else {
                        this.selectedPattern = pattern;
                        break;
                    }
                }
                this.currentIntensity = wallPaper.intensity;
            }
        }
    }

    private void updateSelectedPattern(boolean animated) {
        int count = this.patternsListView.getChildCount();
        for (int a = 0; a < count; a++) {
            View child = this.patternsListView.getChildAt(a);
            if (child instanceof PatternCell) {
                ((PatternCell) child).updateSelected(animated);
            }
        }
    }

    private void updateMotionButton() {
        this.checkBoxView[this.selectedPattern != null ? (char) 2 : (char) 0].setVisibility(0);
        AnimatorSet animatorSet = new AnimatorSet();
        Animator[] animatorArr = new Animator[2];
        CheckBoxView checkBoxView = this.checkBoxView[2];
        Property property = View.ALPHA;
        float[] fArr = new float[1];
        fArr[0] = this.selectedPattern != null ? 1.0f : 0.0f;
        animatorArr[0] = ObjectAnimator.ofFloat(checkBoxView, (Property<CheckBoxView, Float>) property, fArr);
        CheckBoxView checkBoxView2 = this.checkBoxView[0];
        Property property2 = View.ALPHA;
        float[] fArr2 = new float[1];
        fArr2[0] = this.selectedPattern != null ? 0.0f : 1.0f;
        animatorArr[1] = ObjectAnimator.ofFloat(checkBoxView2, (Property<CheckBoxView, Float>) property2, fArr2);
        animatorSet.playTogether(animatorArr);
        animatorSet.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.WallpaperActivity.9
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                WallpaperActivity.this.checkBoxView[WallpaperActivity.this.selectedPattern != null ? (char) 0 : (char) 2].setVisibility(4);
            }
        });
        animatorSet.setInterpolator(CubicBezierInterpolator.EASE_OUT);
        animatorSet.setDuration(200L);
        animatorSet.start();
    }

    private void showPatternsView(final int num, final boolean show) {
        int index;
        final boolean showMotion = show && num == 1 && this.selectedPattern != null;
        if (show) {
            if (num != 0) {
                this.previousSelectedPattern = this.selectedPattern;
                this.previousIntensity = this.currentIntensity;
                this.patternsAdapter.notifyDataSetChanged();
                ArrayList<Object> arrayList = this.patterns;
                if (arrayList != null) {
                    TLRPC.TL_wallPaper tL_wallPaper = this.selectedPattern;
                    if (tL_wallPaper == null) {
                        index = 0;
                    } else {
                        int index2 = arrayList.indexOf(tL_wallPaper);
                        index = index2 + 1;
                    }
                    this.patternsLayoutManager.scrollToPositionWithOffset(index, ((this.patternsListView.getMeasuredWidth() - AndroidUtilities.dp(100.0f)) - AndroidUtilities.dp(12.0f)) / 2);
                }
            } else {
                int i = this.backgroundColor;
                this.previousBackgroundColor = i;
                this.colorPicker.setColor(i);
            }
        }
        this.checkBoxView[showMotion ? (char) 2 : (char) 0].setVisibility(0);
        AnimatorSet animatorSet = new AnimatorSet();
        ArrayList<Animator> animators = new ArrayList<>();
        final int otherNum = num == 0 ? 1 : 0;
        if (show) {
            this.patternLayout[num].setVisibility(0);
            animators.add(ObjectAnimator.ofFloat(this.listView, (Property<RecyclerListView, Float>) View.TRANSLATION_Y, (-this.patternLayout[num].getMeasuredHeight()) + AndroidUtilities.dp(48.0f)));
            animators.add(ObjectAnimator.ofFloat(this.buttonsContainer, (Property<FrameLayout, Float>) View.TRANSLATION_Y, (-this.patternLayout[num].getMeasuredHeight()) + AndroidUtilities.dp(48.0f)));
            CheckBoxView checkBoxView = this.checkBoxView[2];
            Property property = View.ALPHA;
            float[] fArr = new float[1];
            fArr[0] = showMotion ? 1.0f : 0.0f;
            animators.add(ObjectAnimator.ofFloat(checkBoxView, (Property<CheckBoxView, Float>) property, fArr));
            CheckBoxView checkBoxView2 = this.checkBoxView[0];
            Property property2 = View.ALPHA;
            float[] fArr2 = new float[1];
            fArr2[0] = showMotion ? 0.0f : 1.0f;
            animators.add(ObjectAnimator.ofFloat(checkBoxView2, (Property<CheckBoxView, Float>) property2, fArr2));
            animators.add(ObjectAnimator.ofFloat(this.backgroundImage, (Property<BackupImageView, Float>) View.ALPHA, 0.0f));
            if (this.patternLayout[otherNum].getVisibility() == 0) {
                animators.add(ObjectAnimator.ofFloat(this.patternLayout[otherNum], (Property<FrameLayout, Float>) View.ALPHA, 0.0f));
                animators.add(ObjectAnimator.ofFloat(this.patternLayout[num], (Property<FrameLayout, Float>) View.ALPHA, 0.0f, 1.0f));
                this.patternLayout[num].setTranslationY(0.0f);
            } else {
                animators.add(ObjectAnimator.ofFloat(this.patternLayout[num], (Property<FrameLayout, Float>) View.TRANSLATION_Y, this.patternLayout[num].getMeasuredHeight(), 0.0f));
            }
        } else {
            animators.add(ObjectAnimator.ofFloat(this.listView, (Property<RecyclerListView, Float>) View.TRANSLATION_Y, 0.0f));
            animators.add(ObjectAnimator.ofFloat(this.buttonsContainer, (Property<FrameLayout, Float>) View.TRANSLATION_Y, 0.0f));
            animators.add(ObjectAnimator.ofFloat(this.patternLayout[num], (Property<FrameLayout, Float>) View.TRANSLATION_Y, this.patternLayout[num].getMeasuredHeight()));
            animators.add(ObjectAnimator.ofFloat(this.checkBoxView[0], (Property<CheckBoxView, Float>) View.ALPHA, 1.0f));
            animators.add(ObjectAnimator.ofFloat(this.checkBoxView[2], (Property<CheckBoxView, Float>) View.ALPHA, 0.0f));
            animators.add(ObjectAnimator.ofFloat(this.backgroundImage, (Property<BackupImageView, Float>) View.ALPHA, 1.0f));
        }
        animatorSet.playTogether(animators);
        animatorSet.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.WallpaperActivity.10
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                if (show && WallpaperActivity.this.patternLayout[otherNum].getVisibility() == 0) {
                    WallpaperActivity.this.patternLayout[otherNum].setAlpha(1.0f);
                    WallpaperActivity.this.patternLayout[otherNum].setVisibility(4);
                } else if (!show) {
                    WallpaperActivity.this.patternLayout[num].setVisibility(4);
                }
                WallpaperActivity.this.checkBoxView[showMotion ? (char) 0 : (char) 2].setVisibility(4);
            }
        });
        animatorSet.setInterpolator(CubicBezierInterpolator.EASE_OUT);
        animatorSet.setDuration(200L);
        animatorSet.start();
    }

    private void animateMotionChange() {
        AnimatorSet animatorSet = this.motionAnimation;
        if (animatorSet != null) {
            animatorSet.cancel();
        }
        AnimatorSet animatorSet2 = new AnimatorSet();
        this.motionAnimation = animatorSet2;
        if (this.isMotion) {
            animatorSet2.playTogether(ObjectAnimator.ofFloat(this.backgroundImage, (Property<BackupImageView, Float>) View.SCALE_X, this.parallaxScale), ObjectAnimator.ofFloat(this.backgroundImage, (Property<BackupImageView, Float>) View.SCALE_Y, this.parallaxScale));
        } else {
            animatorSet2.playTogether(ObjectAnimator.ofFloat(this.backgroundImage, (Property<BackupImageView, Float>) View.SCALE_X, 1.0f), ObjectAnimator.ofFloat(this.backgroundImage, (Property<BackupImageView, Float>) View.SCALE_Y, 1.0f), ObjectAnimator.ofFloat(this.backgroundImage, (Property<BackupImageView, Float>) View.TRANSLATION_X, 0.0f), ObjectAnimator.ofFloat(this.backgroundImage, (Property<BackupImageView, Float>) View.TRANSLATION_Y, 0.0f));
        }
        this.motionAnimation.setInterpolator(CubicBezierInterpolator.EASE_OUT);
        this.motionAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.WallpaperActivity.11
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                WallpaperActivity.this.motionAnimation = null;
            }
        });
        this.motionAnimation.start();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void setBackgroundColor(int color) {
        this.backgroundColor = color;
        this.backgroundImage.setBackgroundColor(color);
        CheckBoxView[] checkBoxViewArr = this.checkBoxView;
        if (checkBoxViewArr[0] != null) {
            checkBoxViewArr[0].invalidate();
        }
        int patternColor = AndroidUtilities.getPatternColor(this.backgroundColor);
        this.patternColor = patternColor;
        Theme.applyChatServiceMessageColor(new int[]{patternColor, patternColor, patternColor, patternColor});
        BackupImageView backupImageView = this.backgroundImage;
        if (backupImageView != null) {
            backupImageView.getImageReceiver().setColorFilter(new PorterDuffColorFilter(this.patternColor, this.blendMode));
            this.backgroundImage.getImageReceiver().setAlpha(this.currentIntensity);
            this.backgroundImage.invalidate();
        }
        RecyclerListView recyclerListView = this.listView;
        if (recyclerListView != null) {
            recyclerListView.invalidateViews();
        }
        FrameLayout frameLayout = this.buttonsContainer;
        if (frameLayout != null) {
            int N = frameLayout.getChildCount();
            for (int a = 0; a < N; a++) {
                this.buttonsContainer.getChildAt(a).invalidate();
            }
        }
        RadialProgress2 radialProgress2 = this.radialProgress;
        if (radialProgress2 != null) {
            radialProgress2.setColors(Theme.key_chat_serviceBackground, Theme.key_chat_serviceBackground, Theme.key_chat_serviceText, Theme.key_chat_serviceText);
        }
    }

    private void setCurrentImage(boolean setThumb) {
        Object obj = this.currentWallpaper;
        if (obj instanceof TLRPC.TL_wallPaper) {
            TLRPC.TL_wallPaper wallPaper = (TLRPC.TL_wallPaper) obj;
            this.backgroundImage.setImage(ImageLocation.getForDocument(wallPaper.document), this.imageFilter, ImageLocation.getForDocument(setThumb ? FileLoader.getClosestPhotoSizeWithSize(wallPaper.document.thumbs, 100) : null, wallPaper.document), "100_100_b", "jpg", wallPaper.document.size, 1, wallPaper);
            return;
        }
        if (obj instanceof WallpapersListActivity.ColorWallpaper) {
            setBackgroundColor(((WallpapersListActivity.ColorWallpaper) obj).color);
            TLRPC.TL_wallPaper tL_wallPaper = this.selectedPattern;
            if (tL_wallPaper != null) {
                this.backgroundImage.setImage(ImageLocation.getForDocument(tL_wallPaper.document), this.imageFilter, null, null, "jpg", this.selectedPattern.document.size, 1, this.selectedPattern);
                return;
            }
            return;
        }
        if (obj instanceof WallpapersListActivity.FileWallpaper) {
            Bitmap bitmap = this.currentWallpaperBitmap;
            if (bitmap != null) {
                this.backgroundImage.setImageBitmap(bitmap);
                return;
            }
            WallpapersListActivity.FileWallpaper wallPaper2 = (WallpapersListActivity.FileWallpaper) obj;
            if (wallPaper2.originalPath != null) {
                this.backgroundImage.setImage(wallPaper2.originalPath.getAbsolutePath(), this.imageFilter, null);
                return;
            }
            if (wallPaper2.path != null) {
                this.backgroundImage.setImage(wallPaper2.path.getAbsolutePath(), this.imageFilter, null);
                return;
            } else if (wallPaper2.resId == -2) {
                this.backgroundImage.setImageDrawable(Theme.getThemedWallpaper(false));
                return;
            } else {
                if (wallPaper2.resId != 0) {
                    this.backgroundImage.setImageResource(wallPaper2.resId);
                    return;
                }
                return;
            }
        }
        if (obj instanceof MediaController.SearchImage) {
            MediaController.SearchImage wallPaper3 = (MediaController.SearchImage) obj;
            if (wallPaper3.photo != null) {
                TLRPC.PhotoSize thumb = FileLoader.getClosestPhotoSizeWithSize(wallPaper3.photo.sizes, 100);
                TLRPC.PhotoSize image = FileLoader.getClosestPhotoSizeWithSize(wallPaper3.photo.sizes, this.maxWallpaperSize, true);
                if (image == thumb) {
                    image = null;
                }
                int size = image != null ? image.size : 0;
                this.backgroundImage.setImage(ImageLocation.getForPhoto(image, wallPaper3.photo), this.imageFilter, ImageLocation.getForPhoto(thumb, wallPaper3.photo), "100_100_b", "jpg", size, 1, wallPaper3);
                return;
            }
            this.backgroundImage.setImage(wallPaper3.imageUrl, this.imageFilter, wallPaper3.thumbUrl, "100_100_b");
        }
    }

    private class PatternsAdapter extends RecyclerListView.SelectionAdapter {
        private Context mContext;

        public PatternsAdapter(Context context) {
            this.mContext = context;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            return super.getItemViewType(position);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            return (WallpaperActivity.this.patterns != null ? WallpaperActivity.this.patterns.size() : 0) + 1;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return false;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            PatternCell view = WallpaperActivity.this.new PatternCell(this.mContext);
            return new RecyclerListView.Holder(view);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            PatternCell view = (PatternCell) holder.itemView;
            if (position != 0) {
                view.setPattern((TLRPC.TL_wallPaper) WallpaperActivity.this.patterns.get(position - 1));
            } else {
                view.setPattern(null);
            }
            view.getImageReceiver().setColorFilter(new PorterDuffColorFilter(WallpaperActivity.this.patternColor, WallpaperActivity.this.blendMode));
        }
    }

    private class ListAdapter extends RecyclerListView.SelectionAdapter {
        private Context mContext;
        private ArrayList<MessageObject> messages = new ArrayList<>();

        public ListAdapter(Context context) {
            this.mContext = context;
            int date = ((int) (System.currentTimeMillis() / 1000)) - 3600;
            TLRPC.Message message = new TLRPC.TL_message();
            if (WallpaperActivity.this.currentWallpaper instanceof WallpapersListActivity.ColorWallpaper) {
                message.message = LocaleController.getString("BackgroundColorSinglePreviewLine2", R.string.BackgroundColorSinglePreviewLine2);
            } else {
                message.message = LocaleController.getString("BackgroundPreviewLine2", R.string.BackgroundPreviewLine2);
            }
            message.date = date + 60;
            message.dialog_id = 1L;
            message.flags = 259;
            message.from_id = UserConfig.getInstance(WallpaperActivity.this.currentAccount).getClientUserId();
            message.id = 1;
            message.media = new TLRPC.TL_messageMediaEmpty();
            message.out = true;
            message.to_id = new TLRPC.TL_peerUser();
            message.to_id.user_id = 0;
            MessageObject messageObject = new MessageObject(WallpaperActivity.this.currentAccount, message, true);
            messageObject.eventId = 1L;
            messageObject.resetLayout();
            this.messages.add(messageObject);
            TLRPC.Message message2 = new TLRPC.TL_message();
            if (WallpaperActivity.this.currentWallpaper instanceof WallpapersListActivity.ColorWallpaper) {
                message2.message = LocaleController.getString("BackgroundColorSinglePreviewLine1", R.string.BackgroundColorSinglePreviewLine1);
            } else {
                message2.message = LocaleController.getString("BackgroundPreviewLine1", R.string.BackgroundPreviewLine1);
            }
            message2.date = date + 60;
            message2.dialog_id = 1L;
            message2.flags = 265;
            message2.from_id = 0;
            message2.id = 1;
            message2.reply_to_msg_id = 5;
            message2.media = new TLRPC.TL_messageMediaEmpty();
            message2.out = false;
            message2.to_id = new TLRPC.TL_peerUser();
            message2.to_id.user_id = UserConfig.getInstance(WallpaperActivity.this.currentAccount).getClientUserId();
            MessageObject messageObject2 = new MessageObject(WallpaperActivity.this.currentAccount, message2, true);
            messageObject2.eventId = 1L;
            messageObject2.resetLayout();
            this.messages.add(messageObject2);
            TLRPC.Message message3 = new TLRPC.TL_message();
            message3.message = LocaleController.formatDateChat(date);
            message3.id = 0;
            message3.date = date;
            MessageObject messageObject3 = new MessageObject(WallpaperActivity.this.currentAccount, message3, false);
            messageObject3.type = 10;
            messageObject3.contentType = 1;
            messageObject3.isDateObject = true;
            this.messages.add(messageObject3);
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return false;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            return this.messages.size();
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup viewGroup, int viewType) {
            View view = null;
            if (viewType == 0) {
                view = new ChatMessageCell(this.mContext);
                ChatMessageCell chatMessageCell = (ChatMessageCell) view;
                chatMessageCell.setDelegate(new ChatMessageCell.ChatMessageCellDelegate() { // from class: im.uwrkaxlmjj.ui.WallpaperActivity.ListAdapter.1
                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ boolean canPerformActions() {
                        return ChatMessageCell.ChatMessageCellDelegate.CC.$default$canPerformActions(this);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void didLongPress(ChatMessageCell chatMessageCell2, float f, float f2) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$didLongPress(this, chatMessageCell2, f, f2);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void didLongPressUserAvatar(ChatMessageCell chatMessageCell2, TLRPC.User user, float f, float f2) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$didLongPressUserAvatar(this, chatMessageCell2, user, f, f2);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void didPressBotButton(ChatMessageCell chatMessageCell2, TLRPC.KeyboardButton keyboardButton) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressBotButton(this, chatMessageCell2, keyboardButton);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void didPressCancelSendButton(ChatMessageCell chatMessageCell2) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressCancelSendButton(this, chatMessageCell2);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void didPressChannelAvatar(ChatMessageCell chatMessageCell2, TLRPC.Chat chat, int i, float f, float f2) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressChannelAvatar(this, chatMessageCell2, chat, i, f, f2);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void didPressHiddenForward(ChatMessageCell chatMessageCell2) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressHiddenForward(this, chatMessageCell2);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void didPressImage(ChatMessageCell chatMessageCell2, float f, float f2) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressImage(this, chatMessageCell2, f, f2);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void didPressInstantButton(ChatMessageCell chatMessageCell2, int i) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressInstantButton(this, chatMessageCell2, i);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void didPressOther(ChatMessageCell chatMessageCell2, float f, float f2) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressOther(this, chatMessageCell2, f, f2);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void didPressReaction(ChatMessageCell chatMessageCell2, TLRPC.TL_reactionCount tL_reactionCount) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressReaction(this, chatMessageCell2, tL_reactionCount);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void didPressRedpkgTransfer(ChatMessageCell chatMessageCell2, MessageObject messageObject) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressRedpkgTransfer(this, chatMessageCell2, messageObject);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void didPressReplyMessage(ChatMessageCell chatMessageCell2, int i) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressReplyMessage(this, chatMessageCell2, i);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void didPressShare(ChatMessageCell chatMessageCell2) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressShare(this, chatMessageCell2);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void didPressSysNotifyVideoFullPlayer(ChatMessageCell chatMessageCell2) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressSysNotifyVideoFullPlayer(this, chatMessageCell2);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void didPressUrl(ChatMessageCell chatMessageCell2, CharacterStyle characterStyle, boolean z) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressUrl(this, chatMessageCell2, characterStyle, z);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void didPressUserAvatar(ChatMessageCell chatMessageCell2, TLRPC.User user, float f, float f2) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressUserAvatar(this, chatMessageCell2, user, f, f2);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void didPressViaBot(ChatMessageCell chatMessageCell2, String str) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressViaBot(this, chatMessageCell2, str);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void didPressVoteButton(ChatMessageCell chatMessageCell2, TLRPC.TL_pollAnswer tL_pollAnswer) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressVoteButton(this, chatMessageCell2, tL_pollAnswer);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void didStartVideoStream(MessageObject messageObject) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$didStartVideoStream(this, messageObject);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ String getAdminRank(int i) {
                        return ChatMessageCell.ChatMessageCellDelegate.CC.$default$getAdminRank(this, i);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void needOpenWebView(String str, String str2, String str3, String str4, int i, int i2) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$needOpenWebView(this, str, str2, str3, str4, i, i2);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ boolean needPlayMessage(MessageObject messageObject) {
                        return ChatMessageCell.ChatMessageCellDelegate.CC.$default$needPlayMessage(this, messageObject);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void setShouldNotRepeatSticker(MessageObject messageObject) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$setShouldNotRepeatSticker(this, messageObject);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ boolean shouldRepeatSticker(MessageObject messageObject) {
                        return ChatMessageCell.ChatMessageCellDelegate.CC.$default$shouldRepeatSticker(this, messageObject);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void videoTimerReached() {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$videoTimerReached(this);
                    }
                });
            } else if (viewType == 1) {
                view = new ChatActionCell(this.mContext);
                ((ChatActionCell) view).setDelegate(new ChatActionCell.ChatActionCellDelegate() { // from class: im.uwrkaxlmjj.ui.WallpaperActivity.ListAdapter.2
                    @Override // im.uwrkaxlmjj.ui.cells.ChatActionCell.ChatActionCellDelegate
                    public /* synthetic */ void didClickImage(ChatActionCell chatActionCell) {
                        ChatActionCell.ChatActionCellDelegate.CC.$default$didClickImage(this, chatActionCell);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatActionCell.ChatActionCellDelegate
                    public /* synthetic */ void didLongPress(ChatActionCell chatActionCell, float f, float f2) {
                        ChatActionCell.ChatActionCellDelegate.CC.$default$didLongPress(this, chatActionCell, f, f2);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatActionCell.ChatActionCellDelegate
                    public /* synthetic */ void didPressBotButton(MessageObject messageObject, TLRPC.KeyboardButton keyboardButton) {
                        ChatActionCell.ChatActionCellDelegate.CC.$default$didPressBotButton(this, messageObject, keyboardButton);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatActionCell.ChatActionCellDelegate
                    public /* synthetic */ void didPressReplyMessage(ChatActionCell chatActionCell, int i) {
                        ChatActionCell.ChatActionCellDelegate.CC.$default$didPressReplyMessage(this, chatActionCell, i);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatActionCell.ChatActionCellDelegate
                    public /* synthetic */ void didRedUrl(MessageObject messageObject) {
                        ChatActionCell.ChatActionCellDelegate.CC.$default$didRedUrl(this, messageObject);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatActionCell.ChatActionCellDelegate
                    public /* synthetic */ void needOpenUserProfile(int i) {
                        ChatActionCell.ChatActionCellDelegate.CC.$default$needOpenUserProfile(this, i);
                    }
                });
            }
            view.setLayoutParams(new RecyclerView.LayoutParams(-1, -2));
            return new RecyclerListView.Holder(view);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int i) {
            if (i >= 0 && i < this.messages.size()) {
                return this.messages.get(i).contentType;
            }
            return 4;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            boolean pinnedBotton;
            MessageObject message = this.messages.get(position);
            View view = holder.itemView;
            if (view instanceof ChatMessageCell) {
                ChatMessageCell messageCell = (ChatMessageCell) view;
                boolean pinnedTop = false;
                messageCell.isChat = false;
                int nextType = getItemViewType(position - 1);
                int prevType = getItemViewType(position + 1);
                if (!(message.messageOwner.reply_markup instanceof TLRPC.TL_replyInlineMarkup) && nextType == holder.getItemViewType()) {
                    MessageObject nextMessage = this.messages.get(position - 1);
                    pinnedBotton = nextMessage.isOutOwner() == message.isOutOwner() && Math.abs(nextMessage.messageOwner.date - message.messageOwner.date) <= 300;
                } else {
                    pinnedBotton = false;
                }
                if (prevType == holder.getItemViewType()) {
                    MessageObject prevMessage = this.messages.get(position + 1);
                    if (!(prevMessage.messageOwner.reply_markup instanceof TLRPC.TL_replyInlineMarkup) && prevMessage.isOutOwner() == message.isOutOwner() && Math.abs(prevMessage.messageOwner.date - message.messageOwner.date) <= 300) {
                        pinnedTop = true;
                    }
                } else {
                    pinnedTop = false;
                }
                messageCell.setFullyDraw(true);
                messageCell.setMessageObject(message, null, pinnedBotton, pinnedTop);
                return;
            }
            if (view instanceof ChatActionCell) {
                ChatActionCell actionCell = (ChatActionCell) view;
                actionCell.setMessageObject(message);
                actionCell.setAlpha(1.0f);
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public ThemeDescription[] getThemeDescriptions() {
        ArrayList<ThemeDescription> arrayList = new ArrayList<>();
        arrayList.add(new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundWhite));
        arrayList.add(new ThemeDescription(this.actionBar, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_actionBarDefault));
        arrayList.add(new ThemeDescription(this.listView, ThemeDescription.FLAG_LISTGLOWCOLOR, null, null, null, null, Theme.key_actionBarDefault));
        arrayList.add(new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_ITEMSCOLOR, null, null, null, null, Theme.key_actionBarDefaultIcon));
        arrayList.add(new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_TITLECOLOR, null, null, null, null, Theme.key_actionBarDefaultTitle));
        arrayList.add(new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SELECTORCOLOR, null, null, null, null, Theme.key_actionBarDefaultSelector));
        arrayList.add(new ThemeDescription(this.listView, ThemeDescription.FLAG_SELECTOR, null, null, null, null, Theme.key_listSelector));
        int a = 0;
        while (true) {
            FrameLayout[] frameLayoutArr = this.patternLayout;
            if (a >= frameLayoutArr.length) {
                break;
            }
            arrayList.add(new ThemeDescription(frameLayoutArr[a], 0, null, null, new Drawable[]{Theme.chat_composeShadowDrawable}, null, Theme.key_chat_messagePanelShadow));
            arrayList.add(new ThemeDescription(this.patternLayout[a], 0, null, Theme.chat_composeBackgroundPaint, null, null, Theme.key_chat_messagePanelBackground));
            a++;
        }
        int a2 = 0;
        while (true) {
            FrameLayout[] frameLayoutArr2 = this.patternsButtonsContainer;
            if (a2 >= frameLayoutArr2.length) {
                break;
            }
            arrayList.add(new ThemeDescription(frameLayoutArr2[a2], 0, null, null, new Drawable[]{Theme.chat_composeShadowDrawable}, null, Theme.key_chat_messagePanelShadow));
            arrayList.add(new ThemeDescription(this.patternsButtonsContainer[a2], 0, null, Theme.chat_composeBackgroundPaint, null, null, Theme.key_chat_messagePanelBackground));
            a2++;
        }
        arrayList.add(new ThemeDescription(this.bottomOverlayChat, 0, null, null, new Drawable[]{Theme.chat_composeShadowDrawable}, null, Theme.key_chat_messagePanelShadow));
        arrayList.add(new ThemeDescription(this.bottomOverlayChat, 0, null, Theme.chat_composeBackgroundPaint, null, null, Theme.key_chat_messagePanelBackground));
        arrayList.add(new ThemeDescription(this.bottomOverlayChatText, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_chat_fieldOverlayText));
        int a3 = 0;
        while (true) {
            TextView[] textViewArr = this.patternsSaveButton;
            if (a3 >= textViewArr.length) {
                break;
            }
            arrayList.add(new ThemeDescription(textViewArr[a3], ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_chat_fieldOverlayText));
            a3++;
        }
        int a4 = 0;
        while (true) {
            TextView[] textViewArr2 = this.patternsCancelButton;
            if (a4 >= textViewArr2.length) {
                break;
            }
            arrayList.add(new ThemeDescription(textViewArr2[a4], ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_chat_fieldOverlayText));
            a4++;
        }
        ColorPicker colorPicker = this.colorPicker;
        if (colorPicker != null) {
            colorPicker.provideThemeDescriptions(arrayList);
        }
        arrayList.add(new ThemeDescription(this.intensitySeekBar, 0, new Class[]{SeekBarView.class}, new String[]{"innerPaint1"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_player_progressBackground));
        arrayList.add(new ThemeDescription(this.intensitySeekBar, 0, new Class[]{SeekBarView.class}, new String[]{"outerPaint1"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_player_progress));
        arrayList.add(new ThemeDescription(this.intensityCell, 0, new Class[]{HeaderCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlueHeader));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_msgInDrawable, Theme.chat_msgInMediaDrawable}, null, Theme.key_chat_inBubble));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_msgInSelectedDrawable, Theme.chat_msgInMediaSelectedDrawable}, null, Theme.key_chat_inBubbleSelected));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_msgInShadowDrawable, Theme.chat_msgInMediaShadowDrawable}, null, Theme.key_chat_inBubbleShadow));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_msgOutDrawable, Theme.chat_msgOutMediaDrawable}, null, Theme.key_chat_outBubble));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_msgOutSelectedDrawable, Theme.chat_msgOutMediaSelectedDrawable}, null, Theme.key_chat_outBubbleSelected));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_msgOutShadowDrawable, Theme.chat_msgOutMediaShadowDrawable}, null, Theme.key_chat_outBubbleShadow));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_messageTextIn));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_messageTextOut));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_msgOutCheckDrawable}, null, Theme.key_chat_outSentCheck));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_msgOutCheckSelectedDrawable}, null, Theme.key_chat_outSentCheckSelected));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_msgOutCheckReadDrawable, Theme.chat_msgOutHalfCheckDrawable}, null, Theme.key_chat_outSentCheckRead));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_msgOutCheckReadSelectedDrawable, Theme.chat_msgOutHalfCheckSelectedDrawable}, null, Theme.key_chat_outSentCheckReadSelected));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_msgMediaCheckDrawable, Theme.chat_msgMediaHalfCheckDrawable}, null, Theme.key_chat_mediaSentCheck));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_inReplyLine));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_outReplyLine));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_inReplyNameText));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_outReplyNameText));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_inReplyMessageText));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_outReplyMessageText));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_inReplyMediaMessageSelectedText));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_outReplyMediaMessageSelectedText));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_inTimeText));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_outTimeText));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_inTimeSelectedText));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_outTimeSelectedText));
        return (ThemeDescription[]) arrayList.toArray(new ThemeDescription[0]);
    }
}
