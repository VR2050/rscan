package im.uwrkaxlmjj.ui;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Matrix;
import android.graphics.Paint;
import android.graphics.drawable.BitmapDrawable;
import android.net.Uri;
import android.os.Bundle;
import android.view.MotionEvent;
import android.view.View;
import android.widget.FrameLayout;
import com.socks.library.KLog;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.Bitmaps;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.ImageLoader;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import java.io.File;
import java.io.FileNotFoundException;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class PhotoCropActivity extends BaseFragment {
    private static final int done_button = 1;
    private String bitmapKey;
    private PhotoEditActivityDelegate delegate;
    private boolean doneButtonPressed;
    private BitmapDrawable drawable;
    private Bitmap imageToCrop;
    private boolean sameBitmap;
    private PhotoCropView view;

    public interface PhotoEditActivityDelegate {
        void didFinishEdit(Bitmap bitmap);
    }

    private class PhotoCropView extends FrameLayout {
        int bitmapHeight;
        int bitmapWidth;
        int bitmapX;
        int bitmapY;
        Paint circlePaint;
        int draggingState;
        boolean freeform;
        Paint halfPaint;
        float oldX;
        float oldY;
        Paint rectPaint;
        float rectSizeX;
        float rectSizeY;
        float rectX;
        float rectY;
        int viewHeight;
        int viewWidth;

        public PhotoCropView(Context context) {
            super(context);
            this.rectPaint = null;
            this.circlePaint = null;
            this.halfPaint = null;
            this.rectSizeX = 600.0f;
            this.rectSizeY = 600.0f;
            this.rectX = -1.0f;
            this.rectY = -1.0f;
            this.draggingState = 0;
            this.oldX = 0.0f;
            this.oldY = 0.0f;
            init();
        }

        private void init() {
            Paint paint = new Paint();
            this.rectPaint = paint;
            paint.setColor(1073412858);
            this.rectPaint.setStrokeWidth(AndroidUtilities.dp(2.0f));
            this.rectPaint.setStyle(Paint.Style.STROKE);
            Paint paint2 = new Paint();
            this.circlePaint = paint2;
            paint2.setColor(-1);
            Paint paint3 = new Paint();
            this.halfPaint = paint3;
            paint3.setColor(-939524096);
            setBackgroundColor(Theme.ACTION_BAR_MEDIA_PICKER_COLOR);
            setOnTouchListener(new View.OnTouchListener() { // from class: im.uwrkaxlmjj.ui.PhotoCropActivity.PhotoCropView.1
                @Override // android.view.View.OnTouchListener
                public boolean onTouch(View view, MotionEvent motionEvent) {
                    float x = motionEvent.getX();
                    float y = motionEvent.getY();
                    int cornerSide = AndroidUtilities.dp(14.0f);
                    if (motionEvent.getAction() == 0) {
                        if (PhotoCropView.this.rectX - cornerSide < x && PhotoCropView.this.rectX + cornerSide > x && PhotoCropView.this.rectY - cornerSide < y && PhotoCropView.this.rectY + cornerSide > y) {
                            PhotoCropView.this.draggingState = 1;
                        } else if ((PhotoCropView.this.rectX - cornerSide) + PhotoCropView.this.rectSizeX < x && PhotoCropView.this.rectX + cornerSide + PhotoCropView.this.rectSizeX > x && PhotoCropView.this.rectY - cornerSide < y && PhotoCropView.this.rectY + cornerSide > y) {
                            PhotoCropView.this.draggingState = 2;
                        } else if (PhotoCropView.this.rectX - cornerSide < x && PhotoCropView.this.rectX + cornerSide > x && (PhotoCropView.this.rectY - cornerSide) + PhotoCropView.this.rectSizeY < y && PhotoCropView.this.rectY + cornerSide + PhotoCropView.this.rectSizeY > y) {
                            PhotoCropView.this.draggingState = 3;
                        } else if ((PhotoCropView.this.rectX - cornerSide) + PhotoCropView.this.rectSizeX < x && PhotoCropView.this.rectX + cornerSide + PhotoCropView.this.rectSizeX > x && (PhotoCropView.this.rectY - cornerSide) + PhotoCropView.this.rectSizeY < y && PhotoCropView.this.rectY + cornerSide + PhotoCropView.this.rectSizeY > y) {
                            PhotoCropView.this.draggingState = 4;
                        } else if (PhotoCropView.this.rectX < x && PhotoCropView.this.rectX + PhotoCropView.this.rectSizeX > x && PhotoCropView.this.rectY < y && PhotoCropView.this.rectY + PhotoCropView.this.rectSizeY > y) {
                            PhotoCropView.this.draggingState = 5;
                        } else {
                            PhotoCropView.this.draggingState = 0;
                        }
                        if (PhotoCropView.this.draggingState != 0) {
                            PhotoCropView.this.requestDisallowInterceptTouchEvent(true);
                        }
                        PhotoCropView.this.oldX = x;
                        PhotoCropView.this.oldY = y;
                    } else if (motionEvent.getAction() == 1) {
                        PhotoCropView.this.draggingState = 0;
                    } else if (motionEvent.getAction() == 2 && PhotoCropView.this.draggingState != 0) {
                        float diffX = x - PhotoCropView.this.oldX;
                        float diffY = y - PhotoCropView.this.oldY;
                        if (PhotoCropView.this.draggingState == 5) {
                            PhotoCropView.this.rectX += diffX;
                            PhotoCropView.this.rectY += diffY;
                            if (PhotoCropView.this.rectX < PhotoCropView.this.bitmapX) {
                                PhotoCropView.this.rectX = r4.bitmapX;
                            } else if (PhotoCropView.this.rectX + PhotoCropView.this.rectSizeX > PhotoCropView.this.bitmapX + PhotoCropView.this.bitmapWidth) {
                                PhotoCropView.this.rectX = (r4.bitmapX + PhotoCropView.this.bitmapWidth) - PhotoCropView.this.rectSizeX;
                            }
                            if (PhotoCropView.this.rectY < PhotoCropView.this.bitmapY) {
                                PhotoCropView.this.rectY = r4.bitmapY;
                            } else if (PhotoCropView.this.rectY + PhotoCropView.this.rectSizeY > PhotoCropView.this.bitmapY + PhotoCropView.this.bitmapHeight) {
                                PhotoCropView.this.rectY = (r4.bitmapY + PhotoCropView.this.bitmapHeight) - PhotoCropView.this.rectSizeY;
                            }
                        } else if (PhotoCropView.this.draggingState == 1) {
                            if (PhotoCropView.this.rectSizeX - diffX < 160.0f) {
                                diffX = PhotoCropView.this.rectSizeX - 160.0f;
                            }
                            if (PhotoCropView.this.rectX + diffX < PhotoCropView.this.bitmapX) {
                                diffX = PhotoCropView.this.bitmapX - PhotoCropView.this.rectX;
                            }
                            if (!PhotoCropView.this.freeform) {
                                if (PhotoCropView.this.rectY + diffX < PhotoCropView.this.bitmapY) {
                                    diffX = PhotoCropView.this.bitmapY - PhotoCropView.this.rectY;
                                }
                                PhotoCropView.this.rectX += diffX;
                                PhotoCropView.this.rectY += diffX;
                                PhotoCropView.this.rectSizeX -= diffX;
                                PhotoCropView.this.rectSizeY -= diffX;
                            } else {
                                if (PhotoCropView.this.rectSizeY - diffY < 160.0f) {
                                    diffY = PhotoCropView.this.rectSizeY - 160.0f;
                                }
                                if (PhotoCropView.this.rectY + diffY < PhotoCropView.this.bitmapY) {
                                    diffY = PhotoCropView.this.bitmapY - PhotoCropView.this.rectY;
                                }
                                PhotoCropView.this.rectX += diffX;
                                PhotoCropView.this.rectY += diffY;
                                PhotoCropView.this.rectSizeX -= diffX;
                                PhotoCropView.this.rectSizeY -= diffY;
                            }
                        } else if (PhotoCropView.this.draggingState == 2) {
                            if (PhotoCropView.this.rectSizeX + diffX < 160.0f) {
                                diffX = -(PhotoCropView.this.rectSizeX - 160.0f);
                            }
                            if (PhotoCropView.this.rectX + PhotoCropView.this.rectSizeX + diffX > PhotoCropView.this.bitmapX + PhotoCropView.this.bitmapWidth) {
                                diffX = ((PhotoCropView.this.bitmapX + PhotoCropView.this.bitmapWidth) - PhotoCropView.this.rectX) - PhotoCropView.this.rectSizeX;
                            }
                            if (!PhotoCropView.this.freeform) {
                                if (PhotoCropView.this.rectY - diffX < PhotoCropView.this.bitmapY) {
                                    diffX = PhotoCropView.this.rectY - PhotoCropView.this.bitmapY;
                                }
                                PhotoCropView.this.rectY -= diffX;
                                PhotoCropView.this.rectSizeX += diffX;
                                PhotoCropView.this.rectSizeY += diffX;
                            } else {
                                if (PhotoCropView.this.rectSizeY - diffY < 160.0f) {
                                    diffY = PhotoCropView.this.rectSizeY - 160.0f;
                                }
                                if (PhotoCropView.this.rectY + diffY < PhotoCropView.this.bitmapY) {
                                    diffY = PhotoCropView.this.bitmapY - PhotoCropView.this.rectY;
                                }
                                PhotoCropView.this.rectY += diffY;
                                PhotoCropView.this.rectSizeX += diffX;
                                PhotoCropView.this.rectSizeY -= diffY;
                            }
                        } else if (PhotoCropView.this.draggingState == 3) {
                            if (PhotoCropView.this.rectSizeX - diffX < 160.0f) {
                                diffX = PhotoCropView.this.rectSizeX - 160.0f;
                            }
                            if (PhotoCropView.this.rectX + diffX < PhotoCropView.this.bitmapX) {
                                diffX = PhotoCropView.this.bitmapX - PhotoCropView.this.rectX;
                            }
                            if (!PhotoCropView.this.freeform) {
                                if ((PhotoCropView.this.rectY + PhotoCropView.this.rectSizeX) - diffX > PhotoCropView.this.bitmapY + PhotoCropView.this.bitmapHeight) {
                                    diffX = ((PhotoCropView.this.rectY + PhotoCropView.this.rectSizeX) - PhotoCropView.this.bitmapY) - PhotoCropView.this.bitmapHeight;
                                }
                                PhotoCropView.this.rectX += diffX;
                                PhotoCropView.this.rectSizeX -= diffX;
                                PhotoCropView.this.rectSizeY -= diffX;
                            } else {
                                if (PhotoCropView.this.rectY + PhotoCropView.this.rectSizeY + diffY > PhotoCropView.this.bitmapY + PhotoCropView.this.bitmapHeight) {
                                    diffY = ((PhotoCropView.this.bitmapY + PhotoCropView.this.bitmapHeight) - PhotoCropView.this.rectY) - PhotoCropView.this.rectSizeY;
                                }
                                PhotoCropView.this.rectX += diffX;
                                PhotoCropView.this.rectSizeX -= diffX;
                                PhotoCropView.this.rectSizeY += diffY;
                                if (PhotoCropView.this.rectSizeY < 160.0f) {
                                    PhotoCropView.this.rectSizeY = 160.0f;
                                }
                            }
                        } else if (PhotoCropView.this.draggingState == 4) {
                            if (PhotoCropView.this.rectX + PhotoCropView.this.rectSizeX + diffX > PhotoCropView.this.bitmapX + PhotoCropView.this.bitmapWidth) {
                                diffX = ((PhotoCropView.this.bitmapX + PhotoCropView.this.bitmapWidth) - PhotoCropView.this.rectX) - PhotoCropView.this.rectSizeX;
                            }
                            if (!PhotoCropView.this.freeform) {
                                if (PhotoCropView.this.rectY + PhotoCropView.this.rectSizeX + diffX > PhotoCropView.this.bitmapY + PhotoCropView.this.bitmapHeight) {
                                    diffX = ((PhotoCropView.this.bitmapY + PhotoCropView.this.bitmapHeight) - PhotoCropView.this.rectY) - PhotoCropView.this.rectSizeX;
                                }
                                PhotoCropView.this.rectSizeX += diffX;
                                PhotoCropView.this.rectSizeY += diffX;
                            } else {
                                if (PhotoCropView.this.rectY + PhotoCropView.this.rectSizeY + diffY > PhotoCropView.this.bitmapY + PhotoCropView.this.bitmapHeight) {
                                    diffY = ((PhotoCropView.this.bitmapY + PhotoCropView.this.bitmapHeight) - PhotoCropView.this.rectY) - PhotoCropView.this.rectSizeY;
                                }
                                PhotoCropView.this.rectSizeX += diffX;
                                PhotoCropView.this.rectSizeY += diffY;
                            }
                            if (PhotoCropView.this.rectSizeX < 160.0f) {
                                PhotoCropView.this.rectSizeX = 160.0f;
                            }
                            if (PhotoCropView.this.rectSizeY < 160.0f) {
                                PhotoCropView.this.rectSizeY = 160.0f;
                            }
                        }
                        PhotoCropView.this.oldX = x;
                        PhotoCropView.this.oldY = y;
                        PhotoCropView.this.invalidate();
                    }
                    return true;
                }
            });
        }

        private void updateBitmapSize() {
            if (this.viewWidth == 0 || this.viewHeight == 0 || PhotoCropActivity.this.imageToCrop == null) {
                return;
            }
            float f = this.rectX - this.bitmapX;
            int i = this.bitmapWidth;
            float percX = f / i;
            float f2 = this.rectY - this.bitmapY;
            int i2 = this.bitmapHeight;
            float percY = f2 / i2;
            float percSizeX = this.rectSizeX / i;
            float percSizeY = this.rectSizeY / i2;
            float w = PhotoCropActivity.this.imageToCrop.getWidth();
            float h = PhotoCropActivity.this.imageToCrop.getHeight();
            int i3 = this.viewWidth;
            float scaleX = i3 / w;
            int i4 = this.viewHeight;
            float scaleY = i4 / h;
            if (scaleX > scaleY) {
                this.bitmapHeight = i4;
                this.bitmapWidth = (int) Math.ceil(w * scaleY);
            } else {
                this.bitmapWidth = i3;
                this.bitmapHeight = (int) Math.ceil(h * scaleX);
            }
            this.bitmapX = ((this.viewWidth - this.bitmapWidth) / 2) + AndroidUtilities.dp(14.0f);
            int iDp = ((this.viewHeight - this.bitmapHeight) / 2) + AndroidUtilities.dp(14.0f);
            this.bitmapY = iDp;
            if (this.rectX == -1.0f && this.rectY == -1.0f) {
                if (this.freeform) {
                    this.rectY = iDp;
                    this.rectX = this.bitmapX;
                    this.rectSizeX = this.bitmapWidth;
                    this.rectSizeY = this.bitmapHeight;
                } else {
                    if (this.bitmapWidth > this.bitmapHeight) {
                        this.rectY = iDp;
                        this.rectX = ((this.viewWidth - r11) / 2) + AndroidUtilities.dp(14.0f);
                        int i5 = this.bitmapHeight;
                        this.rectSizeX = i5;
                        this.rectSizeY = i5;
                    } else {
                        this.rectX = this.bitmapX;
                        this.rectY = ((this.viewHeight - r10) / 2) + AndroidUtilities.dp(14.0f);
                        int i6 = this.bitmapWidth;
                        this.rectSizeX = i6;
                        this.rectSizeY = i6;
                    }
                }
            } else {
                int i7 = this.bitmapWidth;
                this.rectX = (i7 * percX) + this.bitmapX;
                int i8 = this.bitmapHeight;
                this.rectY = (i8 * percY) + this.bitmapY;
                this.rectSizeX = i7 * percSizeX;
                this.rectSizeY = i8 * percSizeY;
            }
            invalidate();
        }

        @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
        protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
            super.onLayout(changed, left, top, right, bottom);
            this.viewWidth = (right - left) - AndroidUtilities.dp(28.0f);
            this.viewHeight = (bottom - top) - AndroidUtilities.dp(28.0f);
            updateBitmapSize();
        }

        public Bitmap getBitmap() {
            float f = this.rectX - this.bitmapX;
            int i = this.bitmapWidth;
            float percX = f / i;
            float percY = (this.rectY - this.bitmapY) / this.bitmapHeight;
            float percSizeX = this.rectSizeX / i;
            float percSizeY = this.rectSizeY / i;
            int x = (int) (PhotoCropActivity.this.imageToCrop.getWidth() * percX);
            int y = (int) (PhotoCropActivity.this.imageToCrop.getHeight() * percY);
            int sizeX = (int) (PhotoCropActivity.this.imageToCrop.getWidth() * percSizeX);
            int sizeY = (int) (PhotoCropActivity.this.imageToCrop.getWidth() * percSizeY);
            if (x < 0) {
                x = 0;
            }
            if (y < 0) {
                y = 0;
            }
            if (x + sizeX > PhotoCropActivity.this.imageToCrop.getWidth()) {
                sizeX = PhotoCropActivity.this.imageToCrop.getWidth() - x;
            }
            if (y + sizeY > PhotoCropActivity.this.imageToCrop.getHeight()) {
                sizeY = PhotoCropActivity.this.imageToCrop.getHeight() - y;
            }
            try {
                return Bitmaps.createBitmap(PhotoCropActivity.this.imageToCrop, x, y, sizeX, sizeY);
            } catch (Throwable e) {
                FileLog.e(e);
                System.gc();
                try {
                    return Bitmaps.createBitmap(PhotoCropActivity.this.imageToCrop, x, y, sizeX, sizeY);
                } catch (Throwable e2) {
                    FileLog.e(e2);
                    return null;
                }
            }
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            KLog.d("--------重绘");
            if (PhotoCropActivity.this.drawable != null) {
                try {
                    PhotoCropActivity.this.drawable.setBounds(this.bitmapX, this.bitmapY, this.bitmapX + this.bitmapWidth, this.bitmapY + this.bitmapHeight);
                    PhotoCropActivity.this.drawable.draw(canvas);
                } catch (Throwable e) {
                    FileLog.e(e);
                }
            }
            canvas.drawRect(this.bitmapX, this.bitmapY, r0 + this.bitmapWidth, this.rectY, this.halfPaint);
            float f = this.bitmapX;
            float f2 = this.rectY;
            canvas.drawRect(f, f2, this.rectX, f2 + this.rectSizeY, this.halfPaint);
            float f3 = this.rectX + this.rectSizeX;
            float f4 = this.rectY;
            canvas.drawRect(f3, f4, this.bitmapX + this.bitmapWidth, f4 + this.rectSizeY, this.halfPaint);
            canvas.drawRect(this.bitmapX, this.rectSizeY + this.rectY, r0 + this.bitmapWidth, this.bitmapY + this.bitmapHeight, this.halfPaint);
            float f5 = this.rectX;
            float f6 = this.rectY;
            canvas.drawRect(f5, f6, f5 + this.rectSizeX, f6 + this.rectSizeY, this.rectPaint);
            int side = AndroidUtilities.dp(1.0f);
            float f7 = this.rectX;
            canvas.drawRect(f7 + side, this.rectY + side, f7 + side + AndroidUtilities.dp(20.0f), this.rectY + (side * 3), this.circlePaint);
            float f8 = this.rectX;
            float f9 = this.rectY;
            canvas.drawRect(f8 + side, f9 + side, f8 + (side * 3), f9 + side + AndroidUtilities.dp(20.0f), this.circlePaint);
            float fDp = ((this.rectX + this.rectSizeX) - side) - AndroidUtilities.dp(20.0f);
            float f10 = this.rectY;
            canvas.drawRect(fDp, f10 + side, (this.rectX + this.rectSizeX) - side, f10 + (side * 3), this.circlePaint);
            float f11 = this.rectX;
            float f12 = this.rectSizeX;
            float f13 = this.rectY;
            canvas.drawRect((f11 + f12) - (side * 3), f13 + side, (f11 + f12) - side, f13 + side + AndroidUtilities.dp(20.0f), this.circlePaint);
            canvas.drawRect(this.rectX + side, ((this.rectY + this.rectSizeY) - side) - AndroidUtilities.dp(20.0f), this.rectX + (side * 3), (this.rectY + this.rectSizeY) - side, this.circlePaint);
            float f14 = this.rectX;
            canvas.drawRect(f14 + side, (this.rectY + this.rectSizeY) - (side * 3), f14 + side + AndroidUtilities.dp(20.0f), (this.rectY + this.rectSizeY) - side, this.circlePaint);
            float fDp2 = ((this.rectX + this.rectSizeX) - side) - AndroidUtilities.dp(20.0f);
            float f15 = this.rectY;
            float f16 = this.rectSizeY;
            canvas.drawRect(fDp2, (f15 + f16) - (side * 3), (this.rectX + this.rectSizeX) - side, (f15 + f16) - side, this.circlePaint);
            canvas.drawRect((this.rectX + this.rectSizeX) - (side * 3), ((this.rectY + this.rectSizeY) - side) - AndroidUtilities.dp(20.0f), (this.rectX + this.rectSizeX) - side, (this.rectY + this.rectSizeY) - side, this.circlePaint);
            for (int a = 1; a < 3; a++) {
                float f17 = this.rectX;
                float f18 = this.rectSizeX;
                float f19 = this.rectY;
                canvas.drawRect(f17 + ((f18 / 3.0f) * a), f19 + side, f17 + side + ((f18 / 3.0f) * a), (f19 + this.rectSizeY) - side, this.circlePaint);
                float f20 = this.rectX;
                float f21 = this.rectY;
                float f22 = this.rectSizeY;
                canvas.drawRect(f20 + side, ((f22 / 3.0f) * a) + f21, this.rectSizeX + (f20 - side), f21 + ((f22 / 3.0f) * a) + side, this.circlePaint);
            }
        }
    }

    public PhotoCropActivity(Bundle args) {
        super(args);
        this.delegate = null;
        this.sameBitmap = false;
        this.doneButtonPressed = false;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() throws FileNotFoundException {
        int size;
        KLog.d("-----???????");
        this.swipeBackEnabled = false;
        if (this.imageToCrop == null) {
            String photoPath = getArguments().getString("photoPath");
            Uri photoUri = (Uri) getArguments().getParcelable("photoUri");
            if (photoPath == null && photoUri == null) {
                return false;
            }
            if (photoPath != null) {
                File f = new File(photoPath);
                if (!f.exists()) {
                    return false;
                }
            }
            if (AndroidUtilities.isTablet()) {
                size = AndroidUtilities.dp(520.0f);
            } else {
                size = Math.max(AndroidUtilities.displaySize.x, AndroidUtilities.displaySize.y);
            }
            Bitmap bitmapLoadBitmap = ImageLoader.loadBitmap(photoPath, photoUri, size, size, true);
            this.imageToCrop = bitmapLoadBitmap;
            if (bitmapLoadBitmap == null) {
                return false;
            }
        }
        this.drawable = new BitmapDrawable(this.imageToCrop);
        super.onFragmentCreate();
        return true;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public Bitmap rotateBitmap(Bitmap origin, float alpha) {
        if (origin == null) {
            return null;
        }
        int width = origin.getWidth();
        int height = origin.getHeight();
        Matrix matrix = new Matrix();
        matrix.setRotate(90.0f);
        Bitmap newBM = Bitmap.createBitmap(origin, 0, 0, width, height, matrix, false);
        if (newBM.equals(origin)) {
            return newBM;
        }
        origin.recycle();
        return newBM;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        Bitmap bitmap;
        super.onFragmentDestroy();
        if (this.bitmapKey != null && ImageLoader.getInstance().decrementUseCount(this.bitmapKey) && !ImageLoader.getInstance().isInMemCache(this.bitmapKey, false)) {
            this.bitmapKey = null;
        }
        if (this.bitmapKey == null && (bitmap = this.imageToCrop) != null && !this.sameBitmap) {
            bitmap.recycle();
            this.imageToCrop = null;
        }
        this.drawable = null;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.actionBar.setBackgroundColor(Theme.ACTION_BAR_MEDIA_PICKER_COLOR);
        this.actionBar.setItemsBackgroundColor(Theme.ACTION_BAR_PICKER_SELECTOR_COLOR, false);
        this.actionBar.setTitleColor(-1);
        this.actionBar.setItemsColor(-1, false);
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setAllowOverlayTitle(true);
        this.actionBar.setTitle(LocaleController.getString("CropImage", R.string.CropImage));
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.PhotoCropActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    PhotoCropActivity photoCropActivity = PhotoCropActivity.this;
                    photoCropActivity.imageToCrop = photoCropActivity.rotateBitmap(photoCropActivity.imageToCrop, 90.0f);
                    PhotoCropActivity.this.drawable = new BitmapDrawable(PhotoCropActivity.this.imageToCrop);
                    PhotoCropActivity.this.view.invalidate();
                    return;
                }
                if (id == 1) {
                    if (PhotoCropActivity.this.delegate != null && !PhotoCropActivity.this.doneButtonPressed) {
                        Bitmap bitmap = PhotoCropActivity.this.view.getBitmap();
                        if (bitmap == PhotoCropActivity.this.imageToCrop) {
                            PhotoCropActivity.this.sameBitmap = true;
                        }
                        PhotoCropActivity.this.delegate.didFinishEdit(bitmap);
                        PhotoCropActivity.this.doneButtonPressed = true;
                    }
                    PhotoCropActivity.this.finishFragment();
                }
            }
        });
        ActionBarMenu menu = this.actionBar.createMenu();
        menu.addItemWithWidth(1, R.drawable.ic_done, AndroidUtilities.dp(56.0f));
        PhotoCropView photoCropView = new PhotoCropView(context);
        this.view = photoCropView;
        this.fragmentView = photoCropView;
        ((PhotoCropView) this.fragmentView).freeform = getArguments().getBoolean("freeform", false);
        this.fragmentView.setLayoutParams(new FrameLayout.LayoutParams(-1, -1));
        return this.fragmentView;
    }

    public void setDelegate(PhotoEditActivityDelegate delegate) {
        this.delegate = delegate;
    }
}
