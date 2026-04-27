package im.uwrkaxlmjj.messenger;

import android.content.res.Resources;
import android.graphics.Bitmap;
import android.graphics.BitmapShader;
import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.Matrix;
import android.graphics.Paint;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.RectF;
import android.graphics.Shader;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.Drawable;
import android.view.View;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.components.AnimatedFileDrawable;
import im.uwrkaxlmjj.ui.components.RLottieDrawable;
import im.uwrkaxlmjj.ui.components.RecyclableDrawable;
import org.webrtc.mozi.JavaScreenCapturer;

/* JADX INFO: loaded from: classes2.dex */
public class ImageReceiver implements NotificationCenter.NotificationCenterDelegate {
    private static final int TYPE_CROSSFDADE = 2;
    public static final int TYPE_IMAGE = 0;
    public static final int TYPE_MEDIA = 3;
    public static final int TYPE_THUMB = 1;
    private static PorterDuffColorFilter selectedColorFilter = new PorterDuffColorFilter(-2236963, PorterDuff.Mode.MULTIPLY);
    private static PorterDuffColorFilter selectedGroupColorFilter = new PorterDuffColorFilter(-4473925, PorterDuff.Mode.MULTIPLY);
    private boolean allowDecodeSingleFrame;
    private boolean allowStartAnimation;
    private boolean animationReadySent;
    private int autoRepeat;
    private RectF bitmapRect;
    private boolean canceledLoading;
    private boolean centerRotation;
    private ColorFilter colorFilter;
    private byte crossfadeAlpha;
    private Drawable crossfadeImage;
    private String crossfadeKey;
    private BitmapShader crossfadeShader;
    private boolean crossfadeWithOldImage;
    private boolean crossfadeWithThumb;
    private boolean crossfadingWithThumb;
    private int currentAccount;
    private float currentAlpha;
    private int currentCacheType;
    private String currentExt;
    private int currentGuid;
    private Drawable currentImageDrawable;
    private String currentImageFilter;
    private String currentImageKey;
    private ImageLocation currentImageLocation;
    private boolean currentKeyQuality;
    private int currentLayerNum;
    private Drawable currentMediaDrawable;
    private String currentMediaFilter;
    private String currentMediaKey;
    private ImageLocation currentMediaLocation;
    private int currentOpenedLayerFlags;
    private Object currentParentObject;
    private int currentSize;
    private Drawable currentThumbDrawable;
    private String currentThumbFilter;
    private String currentThumbKey;
    private ImageLocation currentThumbLocation;
    private ImageReceiverDelegate delegate;
    private RectF drawRegion;
    private boolean forceCrossfade;
    private boolean forceLoding;
    private boolean forcePreview;
    private int imageH;
    private int imageOrientation;
    private BitmapShader imageShader;
    private int imageTag;
    private int imageW;
    private int imageX;
    private int imageY;
    private boolean invalidateAll;
    private boolean isAspectFit;
    private int isPressed;
    private boolean isVisible;
    private long lastUpdateAlphaTime;
    private boolean manualAlphaAnimator;
    private BitmapShader mediaShader;
    private int mediaTag;
    private boolean needsQualityThumb;
    private float overrideAlpha;
    private int param;
    private View parentView;
    private TLRPC.Document qulityThumbDocument;
    private Paint roundPaint;
    private int roundRadius;
    private RectF roundRect;
    private SetImageBackup setImageBackup;
    private Matrix shaderMatrix;
    private boolean shouldGenerateQualityThumb;
    private float sideClip;
    private Drawable staticThumbDrawable;
    private ImageLocation strippedLocation;
    private int thumbOrientation;
    private BitmapShader thumbShader;
    private int thumbTag;
    private boolean useSharedAnimationQueue;

    public interface ImageReceiverDelegate {
        void didSetImage(ImageReceiver imageReceiver, boolean z, boolean z2);

        void onAnimationReady(ImageReceiver imageReceiver);

        /* JADX INFO: renamed from: im.uwrkaxlmjj.messenger.ImageReceiver$ImageReceiverDelegate$-CC, reason: invalid class name */
        public final /* synthetic */ class CC {
            public static void $default$onAnimationReady(ImageReceiverDelegate _this, ImageReceiver imageReceiver) {
            }
        }
    }

    public static class BitmapHolder {
        public Bitmap bitmap;
        private String key;
        private boolean recycleOnRelease;

        public BitmapHolder(Bitmap b, String k) {
            this.bitmap = b;
            this.key = k;
            if (k != null) {
                ImageLoader.getInstance().incrementUseCount(this.key);
            }
        }

        public BitmapHolder(Bitmap b) {
            this.bitmap = b;
            this.recycleOnRelease = true;
        }

        public int getWidth() {
            Bitmap bitmap = this.bitmap;
            if (bitmap != null) {
                return bitmap.getWidth();
            }
            return 0;
        }

        public int getHeight() {
            Bitmap bitmap = this.bitmap;
            if (bitmap != null) {
                return bitmap.getHeight();
            }
            return 0;
        }

        public boolean isRecycled() {
            Bitmap bitmap = this.bitmap;
            return bitmap == null || bitmap.isRecycled();
        }

        public void release() {
            Bitmap bitmap;
            if (this.key == null) {
                if (this.recycleOnRelease && (bitmap = this.bitmap) != null) {
                    bitmap.recycle();
                }
                this.bitmap = null;
                return;
            }
            boolean canDelete = ImageLoader.getInstance().decrementUseCount(this.key);
            if (!ImageLoader.getInstance().isInMemCache(this.key, false) && canDelete) {
                this.bitmap.recycle();
            }
            this.key = null;
            this.bitmap = null;
        }
    }

    private class SetImageBackup {
        public int cacheType;
        public String ext;
        public String imageFilter;
        public ImageLocation imageLocation;
        public String mediaFilter;
        public ImageLocation mediaLocation;
        public Object parentObject;
        public int size;
        public Drawable thumb;
        public String thumbFilter;
        public ImageLocation thumbLocation;

        private SetImageBackup() {
        }
    }

    public ImageReceiver() {
        this(null);
    }

    public ImageReceiver(View view) {
        this.allowStartAnimation = true;
        this.autoRepeat = 1;
        this.drawRegion = new RectF();
        this.isVisible = true;
        this.roundRect = new RectF();
        this.bitmapRect = new RectF();
        this.shaderMatrix = new Matrix();
        this.overrideAlpha = 1.0f;
        this.crossfadeAlpha = (byte) 1;
        this.parentView = view;
        this.roundPaint = new Paint(3);
        this.currentAccount = UserConfig.selectedAccount;
    }

    public void cancelLoadImage() {
        this.forceLoding = false;
        ImageLoader.getInstance().cancelLoadingForImageReceiver(this, true);
        this.canceledLoading = true;
    }

    public void setForceLoading(boolean value) {
        this.forceLoding = value;
    }

    public boolean isForceLoding() {
        return this.forceLoding;
    }

    public void setStrippedLocation(ImageLocation location) {
        this.strippedLocation = location;
    }

    public ImageLocation getStrippedLocation() {
        return this.strippedLocation;
    }

    public void setImage(ImageLocation imageLocation, String imageFilter, Drawable thumb, String ext, Object parentObject, int cacheType) {
        setImage(imageLocation, imageFilter, null, null, thumb, 0, ext, parentObject, cacheType);
    }

    public void setImage(ImageLocation imageLocation, String imageFilter, Drawable thumb, int size, String ext, Object parentObject, int cacheType) {
        setImage(imageLocation, imageFilter, null, null, thumb, size, ext, parentObject, cacheType);
    }

    public void setImage(String imagePath, String imageFilter, Drawable thumb, String ext, int size) {
        setImage(ImageLocation.getForPath(imagePath), imageFilter, null, null, thumb, size, ext, null, 1);
    }

    public void setImage(ImageLocation imageLocation, String imageFilter, ImageLocation thumbLocation, String thumbFilter, String ext, Object parentObject, int cacheType) {
        setImage(imageLocation, imageFilter, thumbLocation, thumbFilter, null, 0, ext, parentObject, cacheType);
    }

    public void setImage(ImageLocation imageLocation, String imageFilter, ImageLocation thumbLocation, String thumbFilter, int size, String ext, Object parentObject, int cacheType) {
        setImage(imageLocation, imageFilter, thumbLocation, thumbFilter, null, size, ext, parentObject, cacheType);
    }

    public void setImage(ImageLocation fileLocation, String fileFilter, ImageLocation thumbLocation, String thumbFilter, Drawable thumb, int size, String ext, Object parentObject, int cacheType) {
        setImage(null, null, fileLocation, fileFilter, thumbLocation, thumbFilter, thumb, size, ext, parentObject, cacheType);
    }

    /* JADX WARN: Removed duplicated region for block: B:114:0x018e  */
    /* JADX WARN: Removed duplicated region for block: B:119:0x0197  */
    /* JADX WARN: Removed duplicated region for block: B:120:0x019a  */
    /* JADX WARN: Removed duplicated region for block: B:124:0x01a1  */
    /* JADX WARN: Removed duplicated region for block: B:125:0x01a6  */
    /* JADX WARN: Removed duplicated region for block: B:132:0x01c3  */
    /* JADX WARN: Removed duplicated region for block: B:142:0x024b  */
    /* JADX WARN: Removed duplicated region for block: B:145:0x0290  */
    /* JADX WARN: Removed duplicated region for block: B:162:0x02b3  */
    /* JADX WARN: Removed duplicated region for block: B:165:0x02c0  */
    /* JADX WARN: Removed duplicated region for block: B:172:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:74:0x012b  */
    /* JADX WARN: Removed duplicated region for block: B:75:0x0131  */
    /* JADX WARN: Removed duplicated region for block: B:94:0x0168  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void setImage(im.uwrkaxlmjj.messenger.ImageLocation r21, java.lang.String r22, im.uwrkaxlmjj.messenger.ImageLocation r23, java.lang.String r24, im.uwrkaxlmjj.messenger.ImageLocation r25, java.lang.String r26, android.graphics.drawable.Drawable r27, int r28, java.lang.String r29, java.lang.Object r30, int r31) {
        /*
            Method dump skipped, instruction units count: 726
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.ImageReceiver.setImage(im.uwrkaxlmjj.messenger.ImageLocation, java.lang.String, im.uwrkaxlmjj.messenger.ImageLocation, java.lang.String, im.uwrkaxlmjj.messenger.ImageLocation, java.lang.String, android.graphics.drawable.Drawable, int, java.lang.String, java.lang.Object, int):void");
    }

    public boolean canInvertBitmap() {
        return (this.currentMediaDrawable instanceof ExtendedBitmapDrawable) || (this.currentImageDrawable instanceof ExtendedBitmapDrawable) || (this.currentThumbDrawable instanceof ExtendedBitmapDrawable) || (this.staticThumbDrawable instanceof ExtendedBitmapDrawable);
    }

    public void setColorFilter(ColorFilter filter) {
        this.colorFilter = filter;
    }

    public void setDelegate(ImageReceiverDelegate delegate) {
        this.delegate = delegate;
    }

    public void setPressed(int value) {
        this.isPressed = value;
    }

    public boolean getPressed() {
        return this.isPressed != 0;
    }

    public void setOrientation(int angle, boolean center) {
        while (angle < 0) {
            angle += 360;
        }
        while (angle > 360) {
            angle -= 360;
        }
        this.thumbOrientation = angle;
        this.imageOrientation = angle;
        this.centerRotation = center;
    }

    public void setInvalidateAll(boolean value) {
        this.invalidateAll = value;
    }

    public Drawable getStaticThumb() {
        return this.staticThumbDrawable;
    }

    public int getAnimatedOrientation() {
        AnimatedFileDrawable animation = getAnimation();
        if (animation != null) {
            return animation.getOrientation();
        }
        return 0;
    }

    public int getOrientation() {
        return this.imageOrientation;
    }

    public void setLayerNum(int value) {
        this.currentLayerNum = value;
    }

    public void setImageBitmap(Bitmap bitmap) {
        setImageBitmap(bitmap != null ? new BitmapDrawable((Resources) null, bitmap) : null);
    }

    public void setImageBitmap(Drawable bitmap) {
        boolean z = true;
        ImageLoader.getInstance().cancelLoadingForImageReceiver(this, true);
        if (this.crossfadeWithOldImage) {
            if (this.currentImageDrawable != null) {
                recycleBitmap(null, 1);
                recycleBitmap(null, 2);
                recycleBitmap(null, 3);
                this.crossfadeShader = this.imageShader;
                this.crossfadeImage = this.currentImageDrawable;
                this.crossfadeKey = this.currentImageKey;
                this.crossfadingWithThumb = true;
            } else if (this.currentThumbDrawable != null) {
                recycleBitmap(null, 0);
                recycleBitmap(null, 2);
                recycleBitmap(null, 3);
                this.crossfadeShader = this.thumbShader;
                this.crossfadeImage = this.currentThumbDrawable;
                this.crossfadeKey = this.currentThumbKey;
                this.crossfadingWithThumb = true;
            } else if (this.staticThumbDrawable != null) {
                recycleBitmap(null, 0);
                recycleBitmap(null, 1);
                recycleBitmap(null, 2);
                recycleBitmap(null, 3);
                this.crossfadeShader = this.thumbShader;
                this.crossfadeImage = this.staticThumbDrawable;
                this.crossfadingWithThumb = true;
                this.crossfadeKey = null;
            } else {
                for (int a = 0; a < 4; a++) {
                    recycleBitmap(null, a);
                }
                this.crossfadeShader = null;
            }
        } else {
            for (int a2 = 0; a2 < 4; a2++) {
                recycleBitmap(null, a2);
            }
        }
        Drawable drawable = this.staticThumbDrawable;
        if (drawable instanceof RecyclableDrawable) {
            RecyclableDrawable drawable2 = (RecyclableDrawable) drawable;
            drawable2.recycle();
        }
        if (bitmap instanceof AnimatedFileDrawable) {
            AnimatedFileDrawable fileDrawable = (AnimatedFileDrawable) bitmap;
            fileDrawable.setParentView(this.parentView);
            fileDrawable.setUseSharedQueue(this.useSharedAnimationQueue);
            if (this.allowStartAnimation) {
                fileDrawable.start();
            }
            fileDrawable.setAllowDecodeSingleFrame(this.allowDecodeSingleFrame);
        } else if (bitmap instanceof RLottieDrawable) {
            RLottieDrawable fileDrawable2 = (RLottieDrawable) bitmap;
            fileDrawable2.addParentView(this.parentView);
            if (this.currentOpenedLayerFlags == 0) {
                fileDrawable2.start();
            }
            fileDrawable2.setAllowDecodeSingleFrame(true);
        }
        this.staticThumbDrawable = bitmap;
        int i = this.roundRadius;
        if (i != 0 && (bitmap instanceof BitmapDrawable)) {
            if (!(bitmap instanceof RLottieDrawable)) {
                if (bitmap instanceof AnimatedFileDrawable) {
                    ((AnimatedFileDrawable) bitmap).setRoundRadius(i);
                } else {
                    Bitmap object = ((BitmapDrawable) bitmap).getBitmap();
                    this.thumbShader = new BitmapShader(object, Shader.TileMode.CLAMP, Shader.TileMode.CLAMP);
                }
            }
        } else {
            this.thumbShader = null;
        }
        this.currentMediaLocation = null;
        this.currentMediaFilter = null;
        this.currentMediaDrawable = null;
        this.currentMediaKey = null;
        this.mediaShader = null;
        this.currentImageLocation = null;
        this.currentImageFilter = null;
        this.currentImageDrawable = null;
        this.currentImageKey = null;
        this.imageShader = null;
        this.currentThumbLocation = null;
        this.currentThumbFilter = null;
        this.currentThumbKey = null;
        this.currentKeyQuality = false;
        this.currentExt = null;
        this.currentSize = 0;
        this.currentCacheType = 0;
        this.currentAlpha = 1.0f;
        SetImageBackup setImageBackup = this.setImageBackup;
        if (setImageBackup != null) {
            setImageBackup.imageLocation = null;
            this.setImageBackup.thumbLocation = null;
            this.setImageBackup.mediaLocation = null;
            this.setImageBackup.thumb = null;
        }
        ImageReceiverDelegate imageReceiverDelegate = this.delegate;
        if (imageReceiverDelegate != null) {
            imageReceiverDelegate.didSetImage(this, (this.currentThumbDrawable == null && this.staticThumbDrawable == null) ? false : true, true);
        }
        View view = this.parentView;
        if (view != null) {
            if (this.invalidateAll) {
                view.invalidate();
            } else {
                int i2 = this.imageX;
                int i3 = this.imageY;
                view.invalidate(i2, i3, this.imageW + i2, this.imageH + i3);
            }
        }
        if (this.forceCrossfade && this.crossfadeWithOldImage && this.crossfadeImage != null) {
            this.currentAlpha = 0.0f;
            this.lastUpdateAlphaTime = System.currentTimeMillis();
            if (this.currentThumbDrawable == null && this.staticThumbDrawable == null) {
                z = false;
            }
            this.crossfadeWithThumb = z;
        }
    }

    public void clearImage() {
        for (int a = 0; a < 4; a++) {
            recycleBitmap(null, a);
        }
        ImageLoader.getInstance().cancelLoadingForImageReceiver(this, true);
    }

    public void onDetachedFromWindow() {
        if (this.currentImageLocation != null || this.currentMediaLocation != null || this.currentThumbLocation != null || this.staticThumbDrawable != null) {
            if (this.setImageBackup == null) {
                this.setImageBackup = new SetImageBackup();
            }
            this.setImageBackup.mediaLocation = this.currentMediaLocation;
            this.setImageBackup.mediaFilter = this.currentMediaFilter;
            this.setImageBackup.imageLocation = this.currentImageLocation;
            this.setImageBackup.imageFilter = this.currentImageFilter;
            this.setImageBackup.thumbLocation = this.currentThumbLocation;
            this.setImageBackup.thumbFilter = this.currentThumbFilter;
            this.setImageBackup.thumb = this.staticThumbDrawable;
            this.setImageBackup.size = this.currentSize;
            this.setImageBackup.ext = this.currentExt;
            this.setImageBackup.cacheType = this.currentCacheType;
            this.setImageBackup.parentObject = this.currentParentObject;
        }
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.didReplacedPhotoInMemCache);
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.stopAllHeavyOperations);
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.startAllHeavyOperations);
        clearImage();
    }

    public boolean onAttachedToWindow() {
        RLottieDrawable lottieDrawable;
        RLottieDrawable lottieDrawable2;
        int currentHeavyOperationFlags = NotificationCenter.getGlobalInstance().getCurrentHeavyOperationFlags();
        this.currentOpenedLayerFlags = currentHeavyOperationFlags;
        this.currentOpenedLayerFlags = currentHeavyOperationFlags & (~this.currentLayerNum);
        NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.didReplacedPhotoInMemCache);
        NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.stopAllHeavyOperations);
        NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.startAllHeavyOperations);
        SetImageBackup setImageBackup = this.setImageBackup;
        if (setImageBackup != null && (setImageBackup.imageLocation != null || this.setImageBackup.thumbLocation != null || this.setImageBackup.mediaLocation != null || this.setImageBackup.thumb != null)) {
            setImage(this.setImageBackup.mediaLocation, this.setImageBackup.mediaFilter, this.setImageBackup.imageLocation, this.setImageBackup.imageFilter, this.setImageBackup.thumbLocation, this.setImageBackup.thumbFilter, this.setImageBackup.thumb, this.setImageBackup.size, this.setImageBackup.ext, this.setImageBackup.parentObject, this.setImageBackup.cacheType);
            if (this.currentOpenedLayerFlags == 0 && (lottieDrawable2 = getLottieAnimation()) != null) {
                lottieDrawable2.start();
                return true;
            }
            return true;
        }
        if (this.currentOpenedLayerFlags == 0 && (lottieDrawable = getLottieAnimation()) != null) {
            lottieDrawable.start();
            return false;
        }
        return false;
    }

    private void drawDrawable(Canvas canvas, Drawable drawable, int alpha, BitmapShader shader, int orientation) {
        Paint paint;
        int i;
        int bitmapH;
        int bitmapW;
        if (!(drawable instanceof BitmapDrawable)) {
            this.drawRegion.set(this.imageX, this.imageY, r3 + this.imageW, r5 + this.imageH);
            drawable.setBounds((int) this.drawRegion.left, (int) this.drawRegion.top, (int) this.drawRegion.right, (int) this.drawRegion.bottom);
            if (this.isVisible) {
                try {
                    drawable.setAlpha(alpha);
                    drawable.draw(canvas);
                    return;
                } catch (Exception e) {
                    FileLog.e(e);
                    return;
                }
            }
            return;
        }
        BitmapDrawable bitmapDrawable = (BitmapDrawable) drawable;
        if (shader != null) {
            paint = this.roundPaint;
        } else {
            Paint paint2 = bitmapDrawable.getPaint();
            paint = paint2;
        }
        boolean hasFilter = (paint == null || paint.getColorFilter() == null) ? false : true;
        if (hasFilter && this.isPressed == 0) {
            if (shader != null) {
                this.roundPaint.setColorFilter(null);
            } else if (this.staticThumbDrawable != drawable) {
                bitmapDrawable.setColorFilter(null);
            }
        } else if (!hasFilter && (i = this.isPressed) != 0) {
            if (i == 1) {
                if (shader != null) {
                    this.roundPaint.setColorFilter(selectedColorFilter);
                } else {
                    bitmapDrawable.setColorFilter(selectedColorFilter);
                }
            } else if (shader != null) {
                this.roundPaint.setColorFilter(selectedGroupColorFilter);
            } else {
                bitmapDrawable.setColorFilter(selectedGroupColorFilter);
            }
        }
        ColorFilter colorFilter = this.colorFilter;
        if (colorFilter != null) {
            if (shader != null) {
                this.roundPaint.setColorFilter(colorFilter);
            } else {
                bitmapDrawable.setColorFilter(colorFilter);
            }
        }
        if ((bitmapDrawable instanceof AnimatedFileDrawable) || (bitmapDrawable instanceof RLottieDrawable)) {
            int bitmapW2 = orientation % 360;
            if (bitmapW2 == 90 || orientation % 360 == 270) {
                int bitmapW3 = bitmapDrawable.getIntrinsicHeight();
                bitmapH = bitmapDrawable.getIntrinsicWidth();
                bitmapW = bitmapW3;
            } else {
                int bitmapW4 = bitmapDrawable.getIntrinsicWidth();
                bitmapH = bitmapDrawable.getIntrinsicHeight();
                bitmapW = bitmapW4;
            }
        } else if (orientation % 360 == 90 || orientation % 360 == 270) {
            int bitmapW5 = bitmapDrawable.getBitmap().getHeight();
            bitmapH = bitmapDrawable.getBitmap().getWidth();
            bitmapW = bitmapW5;
        } else {
            int bitmapW6 = bitmapDrawable.getBitmap().getWidth();
            bitmapH = bitmapDrawable.getBitmap().getHeight();
            bitmapW = bitmapW6;
        }
        int bitmapW7 = this.imageW;
        float f = this.sideClip;
        float realImageW = bitmapW7 - (f * 2.0f);
        float realImageH = this.imageH - (f * 2.0f);
        float scaleW = bitmapW7 == 0 ? 1.0f : bitmapW / realImageW;
        float scaleH = this.imageH == 0 ? 1.0f : bitmapH / realImageH;
        if (shader == null) {
            if (this.isAspectFit) {
                float scale = Math.max(scaleW, scaleH);
                canvas.save();
                int bitmapW8 = (int) (bitmapW / scale);
                int bitmapH2 = (int) (bitmapH / scale);
                RectF rectF = this.drawRegion;
                int i2 = this.imageX;
                int i3 = this.imageW;
                int i4 = this.imageY;
                int i5 = this.imageH;
                rectF.set(i2 + ((i3 - bitmapW8) / 2.0f), i4 + ((i5 - bitmapH2) / 2.0f), i2 + ((i3 + bitmapW8) / 2.0f), i4 + ((i5 + bitmapH2) / 2.0f));
                bitmapDrawable.setBounds((int) this.drawRegion.left, (int) this.drawRegion.top, (int) this.drawRegion.right, (int) this.drawRegion.bottom);
                if (bitmapDrawable instanceof AnimatedFileDrawable) {
                    ((AnimatedFileDrawable) bitmapDrawable).setActualDrawRect(this.drawRegion.left, this.drawRegion.top, this.drawRegion.width(), this.drawRegion.height());
                }
                if (this.isVisible) {
                    try {
                        bitmapDrawable.setAlpha(alpha);
                        bitmapDrawable.draw(canvas);
                    } catch (Exception e2) {
                        onBitmapException(bitmapDrawable);
                        FileLog.e(e2);
                    }
                }
                canvas.restore();
            } else if (Math.abs(scaleW - scaleH) > 1.0E-5f) {
                canvas.save();
                int i6 = this.imageX;
                int i7 = this.imageY;
                canvas.clipRect(i6, i7, this.imageW + i6, this.imageH + i7);
                if (orientation % 360 != 0) {
                    if (this.centerRotation) {
                        canvas.rotate(orientation, this.imageW / 2, this.imageH / 2);
                    } else {
                        canvas.rotate(orientation, 0.0f, 0.0f);
                    }
                }
                if (bitmapW / scaleH > this.imageW) {
                    int bitmapW9 = (int) (bitmapW / scaleH);
                    RectF rectF2 = this.drawRegion;
                    int i8 = this.imageX;
                    rectF2.set(i8 - ((bitmapW9 - r4) / 2.0f), this.imageY, i8 + ((r4 + bitmapW9) / 2.0f), r8 + this.imageH);
                } else {
                    int bitmapH3 = (int) (bitmapH / scaleW);
                    RectF rectF3 = this.drawRegion;
                    int i9 = this.imageX;
                    int i10 = this.imageY;
                    int i11 = this.imageH;
                    rectF3.set(i9, i10 - ((bitmapH3 - i11) / 2.0f), i9 + r4, i10 + ((i11 + bitmapH3) / 2.0f));
                }
                if (bitmapDrawable instanceof AnimatedFileDrawable) {
                    ((AnimatedFileDrawable) bitmapDrawable).setActualDrawRect(this.imageX, this.imageY, this.imageW, this.imageH);
                }
                if (orientation % 360 != 90 && orientation % 360 != 270) {
                    bitmapDrawable.setBounds((int) this.drawRegion.left, (int) this.drawRegion.top, (int) this.drawRegion.right, (int) this.drawRegion.bottom);
                } else {
                    float width = this.drawRegion.width() / 2.0f;
                    float height = this.drawRegion.height() / 2.0f;
                    float centerX = this.drawRegion.centerX();
                    float centerY = this.drawRegion.centerY();
                    bitmapDrawable.setBounds((int) (centerX - height), (int) (centerY - width), (int) (centerX + height), (int) (centerY + width));
                }
                if (this.isVisible) {
                    try {
                        bitmapDrawable.setAlpha(alpha);
                        bitmapDrawable.draw(canvas);
                    } catch (Exception e3) {
                        onBitmapException(bitmapDrawable);
                        FileLog.e(e3);
                    }
                }
                canvas.restore();
            } else {
                canvas.save();
                if (orientation % 360 != 0) {
                    if (this.centerRotation) {
                        canvas.rotate(orientation, this.imageW / 2, this.imageH / 2);
                    } else {
                        canvas.rotate(orientation, 0.0f, 0.0f);
                    }
                }
                this.drawRegion.set(this.imageX, this.imageY, r3 + this.imageW, r5 + this.imageH);
                if (bitmapDrawable instanceof AnimatedFileDrawable) {
                    ((AnimatedFileDrawable) bitmapDrawable).setActualDrawRect(this.imageX, this.imageY, this.imageW, this.imageH);
                }
                if (orientation % 360 != 90 && orientation % 360 != 270) {
                    bitmapDrawable.setBounds((int) this.drawRegion.left, (int) this.drawRegion.top, (int) this.drawRegion.right, (int) this.drawRegion.bottom);
                } else {
                    float width2 = this.drawRegion.width() / 2.0f;
                    float height2 = this.drawRegion.height() / 2.0f;
                    float centerX2 = this.drawRegion.centerX();
                    float centerY2 = this.drawRegion.centerY();
                    bitmapDrawable.setBounds((int) (centerX2 - height2), (int) (centerY2 - width2), (int) (centerX2 + height2), (int) (centerY2 + width2));
                }
                if (this.isVisible) {
                    try {
                        bitmapDrawable.setAlpha(alpha);
                        bitmapDrawable.draw(canvas);
                    } catch (Exception e4) {
                        onBitmapException(bitmapDrawable);
                        FileLog.e(e4);
                    }
                }
                canvas.restore();
            }
        } else if (!this.isAspectFit) {
            this.roundPaint.setShader(shader);
            float scale2 = 1.0f / Math.min(scaleW, scaleH);
            RectF rectF4 = this.roundRect;
            int i12 = this.imageX;
            float f2 = this.sideClip;
            rectF4.set(i12 + f2, this.imageY + f2, (i12 + this.imageW) - f2, (r11 + this.imageH) - f2);
            this.shaderMatrix.reset();
            if (Math.abs(scaleW - scaleH) <= 5.0E-4f) {
                RectF rectF5 = this.drawRegion;
                int i13 = this.imageX;
                int i14 = this.imageY;
                rectF5.set(i13, i14, i13 + realImageW, i14 + realImageH);
            } else if (bitmapW / scaleH > realImageW) {
                int bitmapW10 = (int) (bitmapW / scaleH);
                RectF rectF6 = this.drawRegion;
                int i15 = this.imageX;
                int i16 = this.imageY;
                rectF6.set(i15 - ((bitmapW10 - realImageW) / 2.0f), i16, i15 + ((bitmapW10 + realImageW) / 2.0f), i16 + realImageH);
            } else {
                int bitmapH4 = (int) (bitmapH / scaleW);
                RectF rectF7 = this.drawRegion;
                int i17 = this.imageX;
                int i18 = this.imageY;
                rectF7.set(i17, i18 - ((bitmapH4 - realImageH) / 2.0f), i17 + realImageW, i18 + ((bitmapH4 + realImageH) / 2.0f));
            }
            if (this.isVisible) {
                this.shaderMatrix.reset();
                this.shaderMatrix.setTranslate(this.drawRegion.left + this.sideClip, this.drawRegion.top + this.sideClip);
                if (orientation != 90) {
                    if (orientation != 180) {
                        if (orientation == 270) {
                            this.shaderMatrix.preRotate(270.0f);
                            this.shaderMatrix.preTranslate(-this.drawRegion.height(), 0.0f);
                        }
                    } else {
                        this.shaderMatrix.preRotate(180.0f);
                        this.shaderMatrix.preTranslate(-this.drawRegion.width(), -this.drawRegion.height());
                    }
                } else {
                    this.shaderMatrix.preRotate(90.0f);
                    this.shaderMatrix.preTranslate(0.0f, -this.drawRegion.width());
                }
                this.shaderMatrix.preScale(scale2, scale2);
                shader.setLocalMatrix(this.shaderMatrix);
                this.roundPaint.setAlpha(alpha);
                RectF rectF8 = this.roundRect;
                int i19 = this.roundRadius;
                canvas.drawRoundRect(rectF8, i19, i19, this.roundPaint);
            }
        } else {
            float scale3 = Math.max(scaleW, scaleH);
            int bitmapW11 = (int) (bitmapW / scale3);
            int bitmapH5 = (int) (bitmapH / scale3);
            RectF rectF9 = this.drawRegion;
            int i20 = this.imageX;
            int i21 = this.imageW;
            int i22 = this.imageY;
            int i23 = this.imageH;
            rectF9.set(i20 + ((i21 - bitmapW11) / 2), i22 + ((i23 - bitmapH5) / 2), i20 + ((i21 + bitmapW11) / 2), i22 + ((i23 + bitmapH5) / 2));
            if (this.isVisible) {
                this.roundPaint.setShader(shader);
                this.shaderMatrix.reset();
                this.shaderMatrix.setTranslate(this.drawRegion.left, this.drawRegion.top);
                this.shaderMatrix.preScale(1.0f / scale3, 1.0f / scale3);
                shader.setLocalMatrix(this.shaderMatrix);
                this.roundPaint.setAlpha(alpha);
                this.roundRect.set(this.drawRegion);
                RectF rectF10 = this.roundRect;
                int i24 = this.roundRadius;
                canvas.drawRoundRect(rectF10, i24, i24, this.roundPaint);
            }
        }
    }

    private void onBitmapException(Drawable bitmapDrawable) {
        if (bitmapDrawable == this.currentMediaDrawable && this.currentMediaKey != null) {
            ImageLoader.getInstance().removeImage(this.currentMediaKey);
            this.currentMediaKey = null;
        } else if (bitmapDrawable == this.currentImageDrawable && this.currentImageKey != null) {
            ImageLoader.getInstance().removeImage(this.currentImageKey);
            this.currentImageKey = null;
        } else if (bitmapDrawable == this.currentThumbDrawable && this.currentThumbKey != null) {
            ImageLoader.getInstance().removeImage(this.currentThumbKey);
            this.currentThumbKey = null;
        }
        setImage(this.currentMediaLocation, this.currentMediaFilter, this.currentImageLocation, this.currentImageFilter, this.currentThumbLocation, this.currentThumbFilter, this.currentThumbDrawable, this.currentSize, this.currentExt, this.currentParentObject, this.currentCacheType);
    }

    private void checkAlphaAnimation(boolean skip) {
        if (!this.manualAlphaAnimator && this.currentAlpha != 1.0f) {
            if (!skip) {
                long currentTime = System.currentTimeMillis();
                long dt = currentTime - this.lastUpdateAlphaTime;
                if (dt > 18) {
                    dt = 18;
                }
                float f = this.currentAlpha + (dt / 150.0f);
                this.currentAlpha = f;
                if (f > 1.0f) {
                    this.currentAlpha = 1.0f;
                    if (this.crossfadeImage != null) {
                        recycleBitmap(null, 2);
                        this.crossfadeShader = null;
                    }
                }
            }
            this.lastUpdateAlphaTime = System.currentTimeMillis();
            View view = this.parentView;
            if (view != null) {
                if (this.invalidateAll) {
                    view.invalidate();
                    return;
                }
                int i = this.imageX;
                int i2 = this.imageY;
                view.invalidate(i, i2, this.imageW + i, this.imageH + i2);
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:87:0x013e  */
    /* JADX WARN: Removed duplicated region for block: B:89:0x0144 A[Catch: Exception -> 0x01a3, TryCatch #0 {Exception -> 0x01a3, blocks: (B:3:0x0004, B:5:0x0011, B:13:0x0024, B:22:0x003e, B:24:0x0044, B:27:0x004a, B:50:0x00b4, B:52:0x00b8, B:55:0x00be, B:93:0x017b, B:97:0x0182, B:56:0x00cf, B:58:0x00d3, B:60:0x00db, B:62:0x00e1, B:65:0x00e6, B:67:0x00ea, B:70:0x00ef, B:72:0x00f3, B:74:0x00f7, B:89:0x0144, B:75:0x0102, B:77:0x0106, B:78:0x0111, B:80:0x0115, B:81:0x0120, B:83:0x0124, B:84:0x012f, B:86:0x0133, B:90:0x0156, B:91:0x016a, B:99:0x0186, B:101:0x018a, B:103:0x019f, B:28:0x0058, B:30:0x005c, B:33:0x0062, B:35:0x0066, B:36:0x0074, B:38:0x0078, B:40:0x007c, B:41:0x0089, B:43:0x008f, B:44:0x009c, B:46:0x00a0, B:17:0x002f, B:19:0x0033, B:21:0x0039, B:8:0x0019), top: B:108:0x0004 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean draw(android.graphics.Canvas r19) {
        /*
            Method dump skipped, instruction units count: 424
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.ImageReceiver.draw(android.graphics.Canvas):boolean");
    }

    public void setManualAlphaAnimator(boolean value) {
        this.manualAlphaAnimator = value;
    }

    public float getCurrentAlpha() {
        return this.currentAlpha;
    }

    public void setCurrentAlpha(float value) {
        this.currentAlpha = value;
    }

    public Drawable getDrawable() {
        Drawable drawable = this.currentMediaDrawable;
        if (drawable != null) {
            return drawable;
        }
        Drawable drawable2 = this.currentImageDrawable;
        if (drawable2 != null) {
            return drawable2;
        }
        Drawable drawable3 = this.currentThumbDrawable;
        if (drawable3 != null) {
            return drawable3;
        }
        Drawable drawable4 = this.staticThumbDrawable;
        if (drawable4 != null) {
            return drawable4;
        }
        return null;
    }

    public Bitmap getBitmap() {
        AnimatedFileDrawable animation = getAnimation();
        RLottieDrawable lottieDrawable = getLottieAnimation();
        if (lottieDrawable != null && lottieDrawable.hasBitmap()) {
            return lottieDrawable.getAnimatedBitmap();
        }
        if (animation != null && animation.hasBitmap()) {
            return animation.getAnimatedBitmap();
        }
        Drawable drawable = this.currentMediaDrawable;
        if ((drawable instanceof BitmapDrawable) && !(drawable instanceof AnimatedFileDrawable) && !(drawable instanceof RLottieDrawable)) {
            return ((BitmapDrawable) drawable).getBitmap();
        }
        Drawable drawable2 = this.currentImageDrawable;
        if ((drawable2 instanceof BitmapDrawable) && !(drawable2 instanceof AnimatedFileDrawable) && !(this.currentMediaDrawable instanceof RLottieDrawable)) {
            return ((BitmapDrawable) drawable2).getBitmap();
        }
        Drawable drawable3 = this.currentThumbDrawable;
        if ((drawable3 instanceof BitmapDrawable) && !(drawable3 instanceof AnimatedFileDrawable) && !(this.currentMediaDrawable instanceof RLottieDrawable)) {
            return ((BitmapDrawable) drawable3).getBitmap();
        }
        Drawable drawable4 = this.staticThumbDrawable;
        if (drawable4 instanceof BitmapDrawable) {
            return ((BitmapDrawable) drawable4).getBitmap();
        }
        return null;
    }

    public BitmapHolder getBitmapSafe() {
        Bitmap bitmap = null;
        String key = null;
        AnimatedFileDrawable animation = getAnimation();
        RLottieDrawable lottieDrawable = getLottieAnimation();
        if (lottieDrawable != null && lottieDrawable.hasBitmap()) {
            bitmap = lottieDrawable.getAnimatedBitmap();
        } else if (animation != null && animation.hasBitmap()) {
            bitmap = animation.getAnimatedBitmap();
        } else {
            Drawable drawable = this.currentMediaDrawable;
            if ((drawable instanceof BitmapDrawable) && !(drawable instanceof AnimatedFileDrawable) && !(drawable instanceof RLottieDrawable)) {
                bitmap = ((BitmapDrawable) drawable).getBitmap();
                key = this.currentMediaKey;
            } else {
                Drawable drawable2 = this.currentImageDrawable;
                if ((drawable2 instanceof BitmapDrawable) && !(drawable2 instanceof AnimatedFileDrawable) && !(this.currentMediaDrawable instanceof RLottieDrawable)) {
                    bitmap = ((BitmapDrawable) drawable2).getBitmap();
                    key = this.currentImageKey;
                } else {
                    Drawable drawable3 = this.currentThumbDrawable;
                    if ((drawable3 instanceof BitmapDrawable) && !(drawable3 instanceof AnimatedFileDrawable) && !(this.currentMediaDrawable instanceof RLottieDrawable)) {
                        bitmap = ((BitmapDrawable) drawable3).getBitmap();
                        key = this.currentThumbKey;
                    } else {
                        Drawable drawable4 = this.staticThumbDrawable;
                        if (drawable4 instanceof BitmapDrawable) {
                            bitmap = ((BitmapDrawable) drawable4).getBitmap();
                        }
                    }
                }
            }
        }
        if (bitmap != null) {
            return new BitmapHolder(bitmap, key);
        }
        return null;
    }

    public Bitmap getThumbBitmap() {
        Drawable drawable = this.currentThumbDrawable;
        if (drawable instanceof BitmapDrawable) {
            return ((BitmapDrawable) drawable).getBitmap();
        }
        Drawable drawable2 = this.staticThumbDrawable;
        if (drawable2 instanceof BitmapDrawable) {
            return ((BitmapDrawable) drawable2).getBitmap();
        }
        return null;
    }

    public BitmapHolder getThumbBitmapSafe() {
        Bitmap bitmap = null;
        String key = null;
        Drawable drawable = this.currentThumbDrawable;
        if (drawable instanceof BitmapDrawable) {
            bitmap = ((BitmapDrawable) drawable).getBitmap();
            key = this.currentThumbKey;
        } else {
            Drawable drawable2 = this.staticThumbDrawable;
            if (drawable2 instanceof BitmapDrawable) {
                bitmap = ((BitmapDrawable) drawable2).getBitmap();
            }
        }
        if (bitmap != null) {
            return new BitmapHolder(bitmap, key);
        }
        return null;
    }

    public int getBitmapWidth() {
        getDrawable();
        AnimatedFileDrawable animation = getAnimation();
        if (animation != null) {
            int i = this.imageOrientation;
            return (i % 360 == 0 || i % 360 == 180) ? animation.getIntrinsicWidth() : animation.getIntrinsicHeight();
        }
        RLottieDrawable lottieDrawable = getLottieAnimation();
        if (lottieDrawable != null) {
            return lottieDrawable.getIntrinsicWidth();
        }
        Bitmap bitmap = getBitmap();
        if (bitmap == null) {
            Drawable drawable = this.staticThumbDrawable;
            if (drawable != null) {
                return drawable.getIntrinsicWidth();
            }
            return 1;
        }
        int i2 = this.imageOrientation;
        return (i2 % 360 == 0 || i2 % 360 == 180) ? bitmap.getWidth() : bitmap.getHeight();
    }

    public int getBitmapHeight() {
        getDrawable();
        AnimatedFileDrawable animation = getAnimation();
        if (animation != null) {
            int i = this.imageOrientation;
            return (i % 360 == 0 || i % 360 == 180) ? animation.getIntrinsicHeight() : animation.getIntrinsicWidth();
        }
        RLottieDrawable lottieDrawable = getLottieAnimation();
        if (lottieDrawable != null) {
            return lottieDrawable.getIntrinsicHeight();
        }
        Bitmap bitmap = getBitmap();
        if (bitmap == null) {
            Drawable drawable = this.staticThumbDrawable;
            if (drawable != null) {
                return drawable.getIntrinsicHeight();
            }
            return 1;
        }
        int i2 = this.imageOrientation;
        return (i2 % 360 == 0 || i2 % 360 == 180) ? bitmap.getHeight() : bitmap.getWidth();
    }

    public void setVisible(boolean value, boolean invalidate) {
        View view;
        if (this.isVisible == value) {
            return;
        }
        this.isVisible = value;
        if (invalidate && (view = this.parentView) != null) {
            if (this.invalidateAll) {
                view.invalidate();
                return;
            }
            int i = this.imageX;
            int i2 = this.imageY;
            view.invalidate(i, i2, this.imageW + i, this.imageH + i2);
        }
    }

    public boolean getVisible() {
        return this.isVisible;
    }

    public void setAlpha(float value) {
        this.overrideAlpha = value;
    }

    public void setCrossfadeAlpha(byte value) {
        this.crossfadeAlpha = value;
    }

    public boolean hasImageSet() {
        return (this.currentImageDrawable == null && this.currentMediaDrawable == null && this.currentThumbDrawable == null && this.staticThumbDrawable == null && this.currentImageKey == null && this.currentMediaKey == null) ? false : true;
    }

    public boolean hasBitmapImage() {
        return (this.currentImageDrawable == null && this.currentThumbDrawable == null && this.staticThumbDrawable == null && this.currentMediaDrawable == null) ? false : true;
    }

    public boolean hasNotThumb() {
        return (this.currentImageDrawable == null && this.currentMediaDrawable == null) ? false : true;
    }

    public boolean hasStaticThumb() {
        return this.staticThumbDrawable != null;
    }

    public void setAspectFit(boolean value) {
        this.isAspectFit = value;
    }

    public boolean isAspectFit() {
        return this.isAspectFit;
    }

    public void setParentView(View view) {
        this.parentView = view;
        AnimatedFileDrawable animation = getAnimation();
        if (animation != null) {
            animation.setParentView(this.parentView);
        }
    }

    public void setImageX(int x) {
        this.imageX = x;
    }

    public void setImageY(int y) {
        this.imageY = y;
    }

    public void setImageWidth(int width) {
        this.imageW = width;
    }

    public void setImageCoords(int x, int y, int width, int height) {
        this.imageX = x;
        this.imageY = y;
        this.imageW = width;
        this.imageH = height;
    }

    public void setSideClip(float value) {
        this.sideClip = value;
    }

    public float getCenterX() {
        return this.imageX + (this.imageW / 2.0f);
    }

    public float getCenterY() {
        return this.imageY + (this.imageH / 2.0f);
    }

    public int getImageX() {
        return this.imageX;
    }

    public int getImageX2() {
        return this.imageX + this.imageW;
    }

    public int getImageY() {
        return this.imageY;
    }

    public int getImageY2() {
        return this.imageY + this.imageH;
    }

    public int getImageWidth() {
        return this.imageW;
    }

    public int getImageHeight() {
        return this.imageH;
    }

    public float getImageAspectRatio() {
        float fWidth;
        float fHeight;
        if (this.imageOrientation % JavaScreenCapturer.DEGREE_180 != 0) {
            fWidth = this.drawRegion.height();
            fHeight = this.drawRegion.width();
        } else {
            fWidth = this.drawRegion.width();
            fHeight = this.drawRegion.height();
        }
        return fWidth / fHeight;
    }

    public String getExt() {
        return this.currentExt;
    }

    public boolean isInsideImage(float x, float y) {
        if (x >= this.imageX && x <= r0 + this.imageW) {
            if (y >= this.imageY && y <= r0 + this.imageH) {
                return true;
            }
        }
        return false;
    }

    public RectF getDrawRegion() {
        return this.drawRegion;
    }

    public int getNewGuid() {
        int i = this.currentGuid + 1;
        this.currentGuid = i;
        return i;
    }

    public String getImageKey() {
        return this.currentImageKey;
    }

    public String getMediaKey() {
        return this.currentMediaKey;
    }

    public String getThumbKey() {
        return this.currentThumbKey;
    }

    public int getSize() {
        return this.currentSize;
    }

    public ImageLocation getMediaLocation() {
        return this.currentMediaLocation;
    }

    public ImageLocation getImageLocation() {
        return this.currentImageLocation;
    }

    public ImageLocation getThumbLocation() {
        return this.currentThumbLocation;
    }

    public String getMediaFilter() {
        return this.currentMediaFilter;
    }

    public String getImageFilter() {
        return this.currentImageFilter;
    }

    public String getThumbFilter() {
        return this.currentThumbFilter;
    }

    public int getCacheType() {
        return this.currentCacheType;
    }

    public void setForcePreview(boolean value) {
        this.forcePreview = value;
    }

    public void setForceCrossfade(boolean value) {
        this.forceCrossfade = value;
    }

    public boolean isForcePreview() {
        return this.forcePreview;
    }

    public void setRoundRadius(int value) {
        this.roundRadius = value;
    }

    public void setCurrentAccount(int value) {
        this.currentAccount = value;
    }

    public int getRoundRadius() {
        return this.roundRadius;
    }

    public Object getParentObject() {
        return this.currentParentObject;
    }

    public void setNeedsQualityThumb(boolean value) {
        this.needsQualityThumb = value;
    }

    public void setQualityThumbDocument(TLRPC.Document document) {
        this.qulityThumbDocument = document;
    }

    public TLRPC.Document getQulityThumbDocument() {
        return this.qulityThumbDocument;
    }

    public void setCrossfadeWithOldImage(boolean value) {
        this.crossfadeWithOldImage = value;
    }

    public boolean isNeedsQualityThumb() {
        return this.needsQualityThumb;
    }

    public boolean isCurrentKeyQuality() {
        return this.currentKeyQuality;
    }

    public int getCurrentAccount() {
        return this.currentAccount;
    }

    public void setShouldGenerateQualityThumb(boolean value) {
        this.shouldGenerateQualityThumb = value;
    }

    public boolean isShouldGenerateQualityThumb() {
        return this.shouldGenerateQualityThumb;
    }

    public void setAllowStartAnimation(boolean value) {
        this.allowStartAnimation = value;
    }

    public void setAllowDecodeSingleFrame(boolean value) {
        this.allowDecodeSingleFrame = value;
    }

    public void setAutoRepeat(int value) {
        this.autoRepeat = value;
        RLottieDrawable drawable = getLottieAnimation();
        if (drawable != null) {
            drawable.setAutoRepeat(value);
        }
    }

    public void setUseSharedAnimationQueue(boolean value) {
        this.useSharedAnimationQueue = value;
    }

    public boolean isAllowStartAnimation() {
        return this.allowStartAnimation;
    }

    public void startAnimation() {
        AnimatedFileDrawable animation = getAnimation();
        if (animation != null) {
            animation.setUseSharedQueue(this.useSharedAnimationQueue);
            animation.start();
        }
    }

    public void stopAnimation() {
        AnimatedFileDrawable animation = getAnimation();
        if (animation != null) {
            animation.stop();
        }
    }

    public boolean isAnimationRunning() {
        AnimatedFileDrawable animation = getAnimation();
        return animation != null && animation.isRunning();
    }

    public AnimatedFileDrawable getAnimation() {
        Drawable drawable = this.currentMediaDrawable;
        if (drawable instanceof AnimatedFileDrawable) {
            return (AnimatedFileDrawable) drawable;
        }
        Drawable drawable2 = this.currentImageDrawable;
        if (drawable2 instanceof AnimatedFileDrawable) {
            return (AnimatedFileDrawable) drawable2;
        }
        Drawable drawable3 = this.currentThumbDrawable;
        if (drawable3 instanceof AnimatedFileDrawable) {
            return (AnimatedFileDrawable) drawable3;
        }
        Drawable drawable4 = this.staticThumbDrawable;
        if (drawable4 instanceof AnimatedFileDrawable) {
            return (AnimatedFileDrawable) drawable4;
        }
        return null;
    }

    public RLottieDrawable getLottieAnimation() {
        Drawable drawable = this.currentMediaDrawable;
        if (drawable instanceof RLottieDrawable) {
            return (RLottieDrawable) drawable;
        }
        Drawable drawable2 = this.currentImageDrawable;
        if (drawable2 instanceof RLottieDrawable) {
            return (RLottieDrawable) drawable2;
        }
        Drawable drawable3 = this.currentThumbDrawable;
        if (drawable3 instanceof RLottieDrawable) {
            return (RLottieDrawable) drawable3;
        }
        Drawable drawable4 = this.staticThumbDrawable;
        if (drawable4 instanceof RLottieDrawable) {
            return (RLottieDrawable) drawable4;
        }
        return null;
    }

    protected int getTag(int type) {
        if (type == 1) {
            return this.thumbTag;
        }
        if (type == 3) {
            return this.mediaTag;
        }
        return this.imageTag;
    }

    protected void setTag(int value, int type) {
        if (type == 1) {
            this.thumbTag = value;
        } else if (type == 3) {
            this.mediaTag = value;
        } else {
            this.imageTag = value;
        }
    }

    public void setParam(int value) {
        this.param = value;
    }

    public int getParam() {
        return this.param;
    }

    protected boolean setImageBitmapByKey(Drawable drawable, String key, int type, boolean memCache, int guid) {
        Drawable drawable2;
        boolean z = false;
        if (drawable == null || key == null || this.currentGuid != guid) {
            return false;
        }
        if (type == 0) {
            if (!key.equals(this.currentImageKey)) {
                return false;
            }
            if (!(drawable instanceof AnimatedFileDrawable)) {
                ImageLoader.getInstance().incrementUseCount(this.currentImageKey);
            }
            this.currentImageDrawable = drawable;
            if (drawable instanceof ExtendedBitmapDrawable) {
                this.imageOrientation = ((ExtendedBitmapDrawable) drawable).getOrientation();
            }
            int i = this.roundRadius;
            if (i != 0 && (drawable instanceof BitmapDrawable)) {
                if (!(drawable instanceof RLottieDrawable)) {
                    if (drawable instanceof AnimatedFileDrawable) {
                        AnimatedFileDrawable animatedFileDrawable = (AnimatedFileDrawable) drawable;
                        animatedFileDrawable.setRoundRadius(i);
                    } else {
                        BitmapDrawable bitmapDrawable = (BitmapDrawable) drawable;
                        this.imageShader = new BitmapShader(bitmapDrawable.getBitmap(), Shader.TileMode.CLAMP, Shader.TileMode.CLAMP);
                    }
                }
            } else {
                this.imageShader = null;
            }
            if ((!memCache && !this.forcePreview) || this.forceCrossfade) {
                boolean allowCorssfade = true;
                Drawable drawable3 = this.currentMediaDrawable;
                if (((drawable3 instanceof AnimatedFileDrawable) && ((AnimatedFileDrawable) drawable3).hasBitmap()) || (this.currentImageDrawable instanceof RLottieDrawable)) {
                    allowCorssfade = false;
                }
                if (allowCorssfade && ((this.currentThumbDrawable == null && this.staticThumbDrawable == null) || this.currentAlpha == 1.0f || this.forceCrossfade)) {
                    this.currentAlpha = 0.0f;
                    this.lastUpdateAlphaTime = System.currentTimeMillis();
                    this.crossfadeWithThumb = (this.crossfadeImage == null && this.currentThumbDrawable == null && this.staticThumbDrawable == null) ? false : true;
                }
            } else {
                this.currentAlpha = 1.0f;
            }
        } else if (type == 3) {
            if (!key.equals(this.currentMediaKey)) {
                return false;
            }
            if (!(drawable instanceof AnimatedFileDrawable)) {
                ImageLoader.getInstance().incrementUseCount(this.currentMediaKey);
            }
            this.currentMediaDrawable = drawable;
            int i2 = this.roundRadius;
            if (i2 != 0 && (drawable instanceof BitmapDrawable)) {
                if (!(drawable instanceof RLottieDrawable)) {
                    if (drawable instanceof AnimatedFileDrawable) {
                        AnimatedFileDrawable animatedFileDrawable2 = (AnimatedFileDrawable) drawable;
                        animatedFileDrawable2.setRoundRadius(i2);
                    } else {
                        BitmapDrawable bitmapDrawable2 = (BitmapDrawable) drawable;
                        this.mediaShader = new BitmapShader(bitmapDrawable2.getBitmap(), Shader.TileMode.CLAMP, Shader.TileMode.CLAMP);
                    }
                }
            } else {
                this.mediaShader = null;
            }
            if (this.currentImageDrawable == null) {
                if ((!memCache && !this.forcePreview) || this.forceCrossfade) {
                    if ((this.currentThumbDrawable == null && this.staticThumbDrawable == null) || this.currentAlpha == 1.0f || this.forceCrossfade) {
                        this.currentAlpha = 0.0f;
                        this.lastUpdateAlphaTime = System.currentTimeMillis();
                        this.crossfadeWithThumb = (this.crossfadeImage == null && this.currentThumbDrawable == null && this.staticThumbDrawable == null) ? false : true;
                    }
                } else {
                    this.currentAlpha = 1.0f;
                }
            }
        } else if (type == 1) {
            if (this.currentThumbDrawable != null) {
                return false;
            }
            if (!this.forcePreview) {
                AnimatedFileDrawable animation = getAnimation();
                if (animation != null && animation.hasBitmap()) {
                    return false;
                }
                Drawable drawable4 = this.currentImageDrawable;
                if ((drawable4 != null && !(drawable4 instanceof AnimatedFileDrawable)) || ((drawable2 = this.currentMediaDrawable) != null && !(drawable2 instanceof AnimatedFileDrawable))) {
                    return false;
                }
            }
            if (!key.equals(this.currentThumbKey)) {
                return false;
            }
            ImageLoader.getInstance().incrementUseCount(this.currentThumbKey);
            this.currentThumbDrawable = drawable;
            if (drawable instanceof ExtendedBitmapDrawable) {
                this.thumbOrientation = ((ExtendedBitmapDrawable) drawable).getOrientation();
            }
            int i3 = this.roundRadius;
            if (i3 != 0 && (drawable instanceof BitmapDrawable)) {
                if (!(drawable instanceof RLottieDrawable)) {
                    if (drawable instanceof AnimatedFileDrawable) {
                        AnimatedFileDrawable animatedFileDrawable3 = (AnimatedFileDrawable) drawable;
                        animatedFileDrawable3.setRoundRadius(i3);
                    } else {
                        BitmapDrawable bitmapDrawable3 = (BitmapDrawable) drawable;
                        this.thumbShader = new BitmapShader(bitmapDrawable3.getBitmap(), Shader.TileMode.CLAMP, Shader.TileMode.CLAMP);
                    }
                }
            } else {
                this.thumbShader = null;
            }
            if (!memCache && this.crossfadeAlpha != 2) {
                Object obj = this.currentParentObject;
                if ((obj instanceof MessageObject) && ((MessageObject) obj).isRoundVideo() && ((MessageObject) this.currentParentObject).isSending()) {
                    this.currentAlpha = 1.0f;
                } else {
                    this.currentAlpha = 0.0f;
                    this.lastUpdateAlphaTime = System.currentTimeMillis();
                    this.crossfadeWithThumb = this.staticThumbDrawable != null && this.currentImageKey == null && this.currentMediaKey == null;
                }
            } else {
                this.currentAlpha = 1.0f;
            }
        }
        if (drawable instanceof AnimatedFileDrawable) {
            AnimatedFileDrawable fileDrawable = (AnimatedFileDrawable) drawable;
            fileDrawable.setParentView(this.parentView);
            fileDrawable.setUseSharedQueue(this.useSharedAnimationQueue);
            if (this.allowStartAnimation) {
                fileDrawable.start();
            }
            fileDrawable.setAllowDecodeSingleFrame(this.allowDecodeSingleFrame);
            this.animationReadySent = false;
        } else if (drawable instanceof RLottieDrawable) {
            RLottieDrawable fileDrawable2 = (RLottieDrawable) drawable;
            fileDrawable2.addParentView(this.parentView);
            if (this.currentOpenedLayerFlags == 0) {
                fileDrawable2.start();
            }
            fileDrawable2.setAllowDecodeSingleFrame(true);
            fileDrawable2.setAutoRepeat(this.autoRepeat);
            this.animationReadySent = false;
        }
        View view = this.parentView;
        if (view != null) {
            if (this.invalidateAll) {
                view.invalidate();
            } else {
                int i4 = this.imageX;
                int i5 = this.imageY;
                view.invalidate(i4, i5, this.imageW + i4, this.imageH + i5);
            }
        }
        ImageReceiverDelegate imageReceiverDelegate = this.delegate;
        if (imageReceiverDelegate != null) {
            boolean z2 = (this.currentImageDrawable == null && this.currentThumbDrawable == null && this.staticThumbDrawable == null && this.currentMediaDrawable == null) ? false : true;
            if (this.currentImageDrawable == null && this.currentMediaDrawable == null) {
                z = true;
            }
            imageReceiverDelegate.didSetImage(this, z2, z);
        }
        return true;
    }

    private void recycleBitmap(String newKey, int type) {
        String key;
        Drawable image;
        String replacedKey;
        if (type == 3) {
            key = this.currentMediaKey;
            image = this.currentMediaDrawable;
        } else if (type == 2) {
            key = this.crossfadeKey;
            image = this.crossfadeImage;
        } else if (type == 1) {
            key = this.currentThumbKey;
            image = this.currentThumbDrawable;
        } else {
            key = this.currentImageKey;
            image = this.currentImageDrawable;
        }
        if (key != null && key.startsWith("-") && (replacedKey = ImageLoader.getInstance().getReplacedKey(key)) != null) {
            key = replacedKey;
        }
        if (image instanceof RLottieDrawable) {
            RLottieDrawable lottieDrawable = (RLottieDrawable) image;
            lottieDrawable.removeParentView(this.parentView);
        }
        ImageLoader.getInstance().getReplacedKey(key);
        if (key != null && ((newKey == null || !newKey.equals(key)) && image != null)) {
            if (image instanceof RLottieDrawable) {
                RLottieDrawable fileDrawable = (RLottieDrawable) image;
                boolean canDelete = ImageLoader.getInstance().decrementUseCount(key);
                if (!ImageLoader.getInstance().isInMemCache(key, true) && canDelete) {
                    fileDrawable.recycle();
                }
            } else if (image instanceof AnimatedFileDrawable) {
                AnimatedFileDrawable fileDrawable2 = (AnimatedFileDrawable) image;
                fileDrawable2.recycle();
            } else if (image instanceof BitmapDrawable) {
                Bitmap bitmap = ((BitmapDrawable) image).getBitmap();
                boolean canDelete2 = ImageLoader.getInstance().decrementUseCount(key);
                if (!ImageLoader.getInstance().isInMemCache(key, false) && canDelete2) {
                    bitmap.recycle();
                }
            }
        }
        if (type == 3) {
            this.currentMediaKey = null;
            this.currentMediaDrawable = null;
        } else if (type == 2) {
            this.crossfadeKey = null;
            this.crossfadeImage = null;
        } else if (type == 1) {
            this.currentThumbDrawable = null;
            this.currentThumbKey = null;
        } else {
            this.currentImageDrawable = null;
            this.currentImageKey = null;
        }
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        int i;
        RLottieDrawable lottieDrawable;
        RLottieDrawable lottieDrawable2;
        if (id != NotificationCenter.didReplacedPhotoInMemCache) {
            if (id == NotificationCenter.stopAllHeavyOperations) {
                Integer layer = (Integer) args[0];
                if (this.currentLayerNum >= layer.intValue()) {
                    return;
                }
                int iIntValue = this.currentOpenedLayerFlags | layer.intValue();
                this.currentOpenedLayerFlags = iIntValue;
                if (iIntValue != 0 && (lottieDrawable2 = getLottieAnimation()) != null) {
                    lottieDrawable2.stop();
                    return;
                }
                return;
            }
            if (id == NotificationCenter.startAllHeavyOperations) {
                Integer layer2 = (Integer) args[0];
                if (this.currentLayerNum >= layer2.intValue() || (i = this.currentOpenedLayerFlags) == 0) {
                    return;
                }
                int i2 = i & (~layer2.intValue());
                this.currentOpenedLayerFlags = i2;
                if (i2 == 0 && (lottieDrawable = getLottieAnimation()) != null) {
                    lottieDrawable.start();
                    return;
                }
                return;
            }
            return;
        }
        String oldKey = (String) args[0];
        String str = this.currentMediaKey;
        if (str != null && str.equals(oldKey)) {
            this.currentMediaKey = (String) args[1];
            this.currentMediaLocation = (ImageLocation) args[2];
            SetImageBackup setImageBackup = this.setImageBackup;
            if (setImageBackup != null) {
                setImageBackup.mediaLocation = (ImageLocation) args[2];
            }
        }
        String str2 = this.currentImageKey;
        if (str2 != null && str2.equals(oldKey)) {
            this.currentImageKey = (String) args[1];
            this.currentImageLocation = (ImageLocation) args[2];
            SetImageBackup setImageBackup2 = this.setImageBackup;
            if (setImageBackup2 != null) {
                setImageBackup2.imageLocation = (ImageLocation) args[2];
            }
        }
        String str3 = this.currentThumbKey;
        if (str3 != null && str3.equals(oldKey)) {
            this.currentThumbKey = (String) args[1];
            this.currentThumbLocation = (ImageLocation) args[2];
            SetImageBackup setImageBackup3 = this.setImageBackup;
            if (setImageBackup3 != null) {
                setImageBackup3.thumbLocation = (ImageLocation) args[2];
            }
        }
    }
}
