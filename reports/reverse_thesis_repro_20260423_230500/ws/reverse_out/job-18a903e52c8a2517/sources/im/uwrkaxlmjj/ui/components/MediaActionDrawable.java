package im.uwrkaxlmjj.ui.components;

import android.graphics.ColorFilter;
import android.graphics.CornerPathEffect;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.RectF;
import android.graphics.drawable.Drawable;
import android.text.TextPaint;
import android.view.animation.DecelerateInterpolator;
import im.uwrkaxlmjj.messenger.AndroidUtilities;

/* JADX INFO: loaded from: classes5.dex */
public class MediaActionDrawable extends Drawable {
    private static final float CANCEL_TO_CHECK_STAGE1 = 0.5f;
    private static final float CANCEL_TO_CHECK_STAGE2 = 0.5f;
    private static final float DOWNLOAD_TO_CANCEL_STAGE1 = 0.5f;
    private static final float DOWNLOAD_TO_CANCEL_STAGE2 = 0.2f;
    private static final float DOWNLOAD_TO_CANCEL_STAGE3 = 0.3f;
    private static final float EPS = 0.001f;
    public static final int ICON_CANCEL = 3;
    public static final int ICON_CANCEL_FILL = 14;
    public static final int ICON_CANCEL_NOPROFRESS = 12;
    public static final int ICON_CANCEL_PERCENT = 13;
    public static final int ICON_CHECK = 6;
    public static final int ICON_DOWNLOAD = 2;
    public static final int ICON_EMPTY = 10;
    public static final int ICON_EMPTY_NOPROGRESS = 11;
    public static final int ICON_FILE = 5;
    public static final int ICON_FILE_APK = 20;
    public static final int ICON_FILE_COMPRESS = 15;
    public static final int ICON_FILE_DOC = 16;
    public static final int ICON_FILE_IPA = 21;
    public static final int ICON_FILE_PDF = 19;
    public static final int ICON_FILE_TXT = 18;
    public static final int ICON_FILE_XLS = 17;
    public static final int ICON_FIRE = 7;
    public static final int ICON_GIF = 8;
    public static final int ICON_NONE = 4;
    public static final int ICON_PAUSE = 1;
    public static final int ICON_PLAY = 0;
    public static final int ICON_SECRETCHECK = 9;
    private static final int pauseRotation = 90;
    private static final int playRotation = 0;
    private float animatedDownloadProgress;
    private boolean animatingTransition;
    private ColorFilter colorFilter;
    private int currentIcon;
    private MediaActionDrawableDelegate delegate;
    private float downloadProgress;
    private float downloadProgressAnimationStart;
    private float downloadProgressTime;
    private float downloadRadOffset;
    private boolean isMini;
    private long lastAnimationTime;
    private int nextIcon;
    private String percentString;
    private int percentStringWidth;
    private float savedTransitionProgress;
    private static final float[] playPath1 = {18.0f, 15.0f, 34.0f, 24.0f, 34.0f, 24.0f, 18.0f, 24.0f, 18.0f, 24.0f};
    private static final float[] playPath2 = {18.0f, 33.0f, 34.0f, 24.0f, 34.0f, 24.0f, 18.0f, 24.0f, 18.0f, 24.0f};
    private static final float[] playFinalPath = {18.0f, 15.0f, 34.0f, 24.0f, 18.0f, 33.0f};
    private static final float[] pausePath1 = {16.0f, 17.0f, 32.0f, 17.0f, 32.0f, 22.0f, 16.0f, 22.0f, 16.0f, 19.5f};
    private static final float[] pausePath2 = {16.0f, 31.0f, 32.0f, 31.0f, 32.0f, 26.0f, 16.0f, 26.0f, 16.0f, 28.5f};
    private TextPaint textPaint = new TextPaint(1);
    private Paint paint = new Paint(1);
    private Paint paint2 = new Paint(1);
    private Paint paint3 = new Paint(1);
    private Path path1 = new Path();
    private Path path2 = new Path();
    private RectF rect = new RectF();
    private float scale = 1.0f;
    private DecelerateInterpolator interpolator = new DecelerateInterpolator();
    private float transitionAnimationTime = 400.0f;
    private int lastPercent = -1;
    private float overrideAlpha = 1.0f;
    private float transitionProgress = 1.0f;

    public interface MediaActionDrawableDelegate {
        void invalidate();
    }

    public MediaActionDrawable() {
        this.paint.setColor(-1);
        this.paint.setStrokeCap(Paint.Cap.ROUND);
        this.paint.setStrokeWidth(AndroidUtilities.dp(3.0f));
        this.paint.setStyle(Paint.Style.STROKE);
        this.paint3.setColor(-1);
        this.textPaint.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        this.textPaint.setTextSize(AndroidUtilities.dp(13.0f));
        this.textPaint.setColor(-1);
        this.paint2.setColor(-1);
        this.paint2.setPathEffect(new CornerPathEffect(AndroidUtilities.dp(2.0f)));
    }

    @Override // android.graphics.drawable.Drawable
    public void setAlpha(int alpha) {
    }

    public void setOverrideAlpha(float alpha) {
        this.overrideAlpha = alpha;
    }

    @Override // android.graphics.drawable.Drawable
    public void setColorFilter(ColorFilter colorFilter) {
        this.paint.setColorFilter(colorFilter);
        this.paint2.setColorFilter(colorFilter);
        this.paint3.setColorFilter(colorFilter);
        this.textPaint.setColorFilter(colorFilter);
    }

    public void setColor(int value) {
        this.paint.setColor(value | (-16777216));
        this.paint2.setColor(value | (-16777216));
        this.paint3.setColor(value | (-16777216));
        this.textPaint.setColor((-16777216) | value);
        this.colorFilter = new PorterDuffColorFilter(value, PorterDuff.Mode.MULTIPLY);
    }

    public int getColor() {
        return this.paint.getColor();
    }

    public void setMini(boolean value) {
        this.isMini = value;
        this.paint.setStrokeWidth(AndroidUtilities.dp(value ? 2.0f : 3.0f));
    }

    @Override // android.graphics.drawable.Drawable
    public int getOpacity() {
        return -2;
    }

    public void setDelegate(MediaActionDrawableDelegate mediaActionDrawableDelegate) {
        this.delegate = mediaActionDrawableDelegate;
    }

    public boolean setIcon(int icon, boolean animated) {
        int i;
        if (this.currentIcon == icon && (i = this.nextIcon) != icon) {
            this.currentIcon = i;
            this.transitionProgress = 1.0f;
        }
        if (animated) {
            int i2 = this.currentIcon;
            if (i2 == icon || this.nextIcon == icon) {
                return false;
            }
            if (i2 == 2 && (icon == 3 || icon == 14)) {
                this.transitionAnimationTime = 400.0f;
            } else if (this.currentIcon != 4 && icon == 6) {
                this.transitionAnimationTime = 360.0f;
            } else if ((this.currentIcon == 4 && icon == 14) || (this.currentIcon == 14 && icon == 4)) {
                this.transitionAnimationTime = 160.0f;
            } else {
                this.transitionAnimationTime = 220.0f;
            }
            if (this.animatingTransition) {
                this.currentIcon = this.nextIcon;
            }
            this.animatingTransition = true;
            this.nextIcon = icon;
            this.savedTransitionProgress = this.transitionProgress;
            this.transitionProgress = 0.0f;
        } else {
            if (this.currentIcon == icon) {
                return false;
            }
            this.animatingTransition = false;
            this.nextIcon = icon;
            this.currentIcon = icon;
            this.savedTransitionProgress = this.transitionProgress;
            this.transitionProgress = 1.0f;
        }
        if (icon == 3 || icon == 14) {
            this.downloadRadOffset = 112.0f;
            this.animatedDownloadProgress = 0.0f;
            this.downloadProgressAnimationStart = 0.0f;
            this.downloadProgressTime = 0.0f;
        }
        invalidateSelf();
        return true;
    }

    public int getCurrentIcon() {
        return this.nextIcon;
    }

    public int getPreviousIcon() {
        return this.currentIcon;
    }

    public void setProgress(float value, boolean animated) {
        if (!animated) {
            this.animatedDownloadProgress = value;
            this.downloadProgressAnimationStart = value;
        } else {
            if (this.animatedDownloadProgress > value) {
                this.animatedDownloadProgress = value;
            }
            this.downloadProgressAnimationStart = this.animatedDownloadProgress;
        }
        this.downloadProgress = value;
        this.downloadProgressTime = 0.0f;
        invalidateSelf();
    }

    private float getCircleValue(float value) {
        while (value > 360.0f) {
            value -= 360.0f;
        }
        return value;
    }

    public float getProgressAlpha() {
        return 1.0f - this.transitionProgress;
    }

    public float getTransitionProgress() {
        if (this.animatingTransition) {
            return this.transitionProgress;
        }
        return 1.0f;
    }

    @Override // android.graphics.drawable.Drawable
    public void setBounds(int left, int top, int right, int bottom) {
        super.setBounds(left, top, right, bottom);
        float intrinsicWidth = (right - left) / getIntrinsicWidth();
        this.scale = intrinsicWidth;
        if (intrinsicWidth < 0.7f) {
            this.paint.setStrokeWidth(AndroidUtilities.dp(2.0f));
        }
    }

    @Override // android.graphics.drawable.Drawable
    public void invalidateSelf() {
        super.invalidateSelf();
        MediaActionDrawableDelegate mediaActionDrawableDelegate = this.delegate;
        if (mediaActionDrawableDelegate != null) {
            mediaActionDrawableDelegate.invalidate();
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:219:0x0619  */
    /* JADX WARN: Removed duplicated region for block: B:220:0x0620  */
    /* JADX WARN: Removed duplicated region for block: B:226:0x0648  */
    /* JADX WARN: Removed duplicated region for block: B:227:0x064b  */
    /* JADX WARN: Removed duplicated region for block: B:232:0x0656  */
    /* JADX WARN: Removed duplicated region for block: B:233:0x0659  */
    /* JADX WARN: Removed duplicated region for block: B:238:0x0666  */
    /* JADX WARN: Removed duplicated region for block: B:239:0x0669  */
    /* JADX WARN: Removed duplicated region for block: B:244:0x0677  */
    /* JADX WARN: Removed duplicated region for block: B:245:0x067a  */
    /* JADX WARN: Removed duplicated region for block: B:250:0x0686  */
    /* JADX WARN: Removed duplicated region for block: B:251:0x0689  */
    /* JADX WARN: Removed duplicated region for block: B:256:0x0697  */
    /* JADX WARN: Removed duplicated region for block: B:257:0x069a  */
    /* JADX WARN: Removed duplicated region for block: B:262:0x06a8  */
    /* JADX WARN: Removed duplicated region for block: B:263:0x06ab  */
    /* JADX WARN: Removed duplicated region for block: B:268:0x06b9  */
    /* JADX WARN: Removed duplicated region for block: B:269:0x06bc  */
    /* JADX WARN: Removed duplicated region for block: B:274:0x06ca  */
    /* JADX WARN: Removed duplicated region for block: B:275:0x06cd  */
    /* JADX WARN: Removed duplicated region for block: B:280:0x06db  */
    /* JADX WARN: Removed duplicated region for block: B:281:0x06e0  */
    /* JADX WARN: Removed duplicated region for block: B:291:0x0702  */
    /* JADX WARN: Removed duplicated region for block: B:293:0x070a  */
    /* JADX WARN: Removed duplicated region for block: B:294:0x070d  */
    /* JADX WARN: Removed duplicated region for block: B:297:0x0729  */
    /* JADX WARN: Removed duplicated region for block: B:300:0x0774  */
    /* JADX WARN: Removed duplicated region for block: B:305:0x0783  */
    /* JADX WARN: Removed duplicated region for block: B:307:0x0789  */
    /* JADX WARN: Removed duplicated region for block: B:308:0x078d  */
    /* JADX WARN: Removed duplicated region for block: B:314:0x07a4  */
    /* JADX WARN: Removed duplicated region for block: B:315:0x07a7  */
    /* JADX WARN: Removed duplicated region for block: B:318:0x07c1  */
    /* JADX WARN: Removed duplicated region for block: B:321:0x07fe  */
    /* JADX WARN: Removed duplicated region for block: B:326:0x080b  */
    /* JADX WARN: Removed duplicated region for block: B:328:0x0811  */
    /* JADX WARN: Removed duplicated region for block: B:329:0x0814  */
    /* JADX WARN: Removed duplicated region for block: B:335:0x083c  */
    /* JADX WARN: Removed duplicated region for block: B:340:0x0853  */
    /* JADX WARN: Removed duplicated region for block: B:343:0x0884  */
    /* JADX WARN: Removed duplicated region for block: B:353:0x08a2  */
    /* JADX WARN: Removed duplicated region for block: B:355:0x08a6  */
    /* JADX WARN: Removed duplicated region for block: B:358:0x08ac  */
    /* JADX WARN: Removed duplicated region for block: B:363:0x08b5  */
    /* JADX WARN: Removed duplicated region for block: B:371:0x08d5  */
    /* JADX WARN: Removed duplicated region for block: B:375:0x08e3  */
    /* JADX WARN: Removed duplicated region for block: B:378:0x08ef  */
    /* JADX WARN: Removed duplicated region for block: B:382:0x08fd  */
    /* JADX WARN: Removed duplicated region for block: B:384:0x0905  */
    /* JADX WARN: Removed duplicated region for block: B:387:0x090f A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:396:0x09c6  */
    /* JADX WARN: Removed duplicated region for block: B:398:0x09d0  */
    /* JADX WARN: Removed duplicated region for block: B:413:0x0a8b  */
    /* JADX WARN: Removed duplicated region for block: B:434:0x0bff  */
    /* JADX WARN: Removed duplicated region for block: B:436:0x0c03  */
    /* JADX WARN: Removed duplicated region for block: B:444:0x0c29  */
    /* JADX WARN: Removed duplicated region for block: B:447:0x0c46  */
    /* JADX WARN: Removed duplicated region for block: B:450:0x0c74  */
    /* JADX WARN: Removed duplicated region for block: B:452:0x0c92  */
    /* JADX WARN: Removed duplicated region for block: B:470:0x0cec  */
    /* JADX WARN: Removed duplicated region for block: B:472:0x0cf2  */
    /* JADX WARN: Removed duplicated region for block: B:490:0x0d51  */
    /* JADX WARN: Removed duplicated region for block: B:503:0x0d6f  */
    /* JADX WARN: Removed duplicated region for block: B:505:0x0d88  */
    /* JADX WARN: Removed duplicated region for block: B:514:0x0dbc  */
    @Override // android.graphics.drawable.Drawable
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void draw(android.graphics.Canvas r40) {
        /*
            Method dump skipped, instruction units count: 3568
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.components.MediaActionDrawable.draw(android.graphics.Canvas):void");
    }

    @Override // android.graphics.drawable.Drawable
    public int getIntrinsicWidth() {
        return AndroidUtilities.dp(48.0f);
    }

    @Override // android.graphics.drawable.Drawable
    public int getIntrinsicHeight() {
        return AndroidUtilities.dp(48.0f);
    }

    @Override // android.graphics.drawable.Drawable
    public int getMinimumWidth() {
        return AndroidUtilities.dp(48.0f);
    }

    @Override // android.graphics.drawable.Drawable
    public int getMinimumHeight() {
        return AndroidUtilities.dp(48.0f);
    }
}
