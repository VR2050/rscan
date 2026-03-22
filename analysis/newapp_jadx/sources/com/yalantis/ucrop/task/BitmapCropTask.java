package com.yalantis.ucrop.task;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.Matrix;
import android.graphics.RectF;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.ParcelFileDescriptor;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.exifinterface.media.ExifInterface;
import com.yalantis.ucrop.callback.BitmapCropCallback;
import com.yalantis.ucrop.model.CropParameters;
import com.yalantis.ucrop.model.ImageState;
import com.yalantis.ucrop.util.BitmapLoadUtils;
import com.yalantis.ucrop.util.FileUtils;
import com.yalantis.ucrop.util.ImageHeaderParser;
import com.yalantis.ucrop.util.MimeType;
import com.yalantis.ucrop.util.SdkUtils;
import java.io.File;
import java.io.FileInputStream;
import java.io.OutputStream;
import java.lang.ref.WeakReference;

/* loaded from: classes2.dex */
public class BitmapCropTask extends AsyncTask<Void, Void, Throwable> {
    private static final String TAG = "BitmapCropTask";
    private int cropOffsetX;
    private int cropOffsetY;
    private final Bitmap.CompressFormat mCompressFormat;
    private final int mCompressQuality;
    private final WeakReference<Context> mContextWeakReference;
    private final BitmapCropCallback mCropCallback;
    private final RectF mCropRect;
    private int mCroppedImageHeight;
    private int mCroppedImageWidth;
    private float mCurrentAngle;
    private final RectF mCurrentImageRect;
    private float mCurrentScale;
    private final String mImageInputPath;
    private final String mImageOutputPath;
    private final int mMaxResultImageSizeX;
    private final int mMaxResultImageSizeY;
    private Bitmap mViewBitmap;

    public BitmapCropTask(@NonNull Context context, @Nullable Bitmap bitmap, @NonNull ImageState imageState, @NonNull CropParameters cropParameters, @Nullable BitmapCropCallback bitmapCropCallback) {
        this.mContextWeakReference = new WeakReference<>(context);
        this.mViewBitmap = bitmap;
        this.mCropRect = imageState.getCropRect();
        this.mCurrentImageRect = imageState.getCurrentImageRect();
        this.mCurrentScale = imageState.getCurrentScale();
        this.mCurrentAngle = imageState.getCurrentAngle();
        this.mMaxResultImageSizeX = cropParameters.getMaxResultImageSizeX();
        this.mMaxResultImageSizeY = cropParameters.getMaxResultImageSizeY();
        this.mCompressFormat = cropParameters.getCompressFormat();
        this.mCompressQuality = cropParameters.getCompressQuality();
        this.mImageInputPath = cropParameters.getImageInputPath();
        this.mImageOutputPath = cropParameters.getImageOutputPath();
        this.mCropCallback = bitmapCropCallback;
    }

    private boolean crop() {
        ExifInterface exifInterface;
        if (this.mMaxResultImageSizeX > 0 && this.mMaxResultImageSizeY > 0) {
            float width = this.mCropRect.width() / this.mCurrentScale;
            float height = this.mCropRect.height() / this.mCurrentScale;
            int i2 = this.mMaxResultImageSizeX;
            if (width > i2 || height > this.mMaxResultImageSizeY) {
                float min = Math.min(i2 / width, this.mMaxResultImageSizeY / height);
                Bitmap createScaledBitmap = Bitmap.createScaledBitmap(this.mViewBitmap, Math.round(r2.getWidth() * min), Math.round(this.mViewBitmap.getHeight() * min), false);
                Bitmap bitmap = this.mViewBitmap;
                if (bitmap != createScaledBitmap) {
                    bitmap.recycle();
                }
                this.mViewBitmap = createScaledBitmap;
                this.mCurrentScale /= min;
            }
        }
        if (this.mCurrentAngle != 0.0f) {
            Matrix matrix = new Matrix();
            matrix.setRotate(this.mCurrentAngle, this.mViewBitmap.getWidth() / 2, this.mViewBitmap.getHeight() / 2);
            Bitmap bitmap2 = this.mViewBitmap;
            Bitmap createBitmap = Bitmap.createBitmap(bitmap2, 0, 0, bitmap2.getWidth(), this.mViewBitmap.getHeight(), matrix, true);
            Bitmap bitmap3 = this.mViewBitmap;
            if (bitmap3 != createBitmap) {
                bitmap3.recycle();
            }
            this.mViewBitmap = createBitmap;
        }
        this.cropOffsetX = Math.round((this.mCropRect.left - this.mCurrentImageRect.left) / this.mCurrentScale);
        this.cropOffsetY = Math.round((this.mCropRect.top - this.mCurrentImageRect.top) / this.mCurrentScale);
        this.mCroppedImageWidth = Math.round(this.mCropRect.width() / this.mCurrentScale);
        int round = Math.round(this.mCropRect.height() / this.mCurrentScale);
        this.mCroppedImageHeight = round;
        if (!shouldCrop(this.mCroppedImageWidth, round)) {
            if (SdkUtils.isQ() && MimeType.isContent(this.mImageInputPath)) {
                ParcelFileDescriptor openFileDescriptor = getContext().getContentResolver().openFileDescriptor(Uri.parse(this.mImageInputPath), "r");
                FileUtils.copyFile(new FileInputStream(openFileDescriptor.getFileDescriptor()), this.mImageOutputPath);
                BitmapLoadUtils.close(openFileDescriptor);
            } else {
                FileUtils.copyFile(this.mImageInputPath, this.mImageOutputPath);
            }
            return false;
        }
        ParcelFileDescriptor parcelFileDescriptor = null;
        if (SdkUtils.isQ() && MimeType.isContent(this.mImageInputPath)) {
            parcelFileDescriptor = getContext().getContentResolver().openFileDescriptor(Uri.parse(this.mImageInputPath), "r");
            exifInterface = new ExifInterface(new FileInputStream(parcelFileDescriptor.getFileDescriptor()));
        } else {
            exifInterface = new ExifInterface(this.mImageInputPath);
        }
        saveImage(Bitmap.createBitmap(this.mViewBitmap, this.cropOffsetX, this.cropOffsetY, this.mCroppedImageWidth, this.mCroppedImageHeight));
        if (this.mCompressFormat.equals(Bitmap.CompressFormat.JPEG)) {
            ImageHeaderParser.copyExif(exifInterface, this.mCroppedImageWidth, this.mCroppedImageHeight, this.mImageOutputPath);
        }
        if (parcelFileDescriptor == null) {
            return true;
        }
        BitmapLoadUtils.close(parcelFileDescriptor);
        return true;
    }

    private Context getContext() {
        return this.mContextWeakReference.get();
    }

    private void saveImage(@NonNull Bitmap bitmap) {
        Context context = getContext();
        if (context == null) {
            return;
        }
        OutputStream outputStream = null;
        try {
            outputStream = context.getContentResolver().openOutputStream(Uri.fromFile(new File(this.mImageOutputPath)));
            bitmap.compress(this.mCompressFormat, this.mCompressQuality, outputStream);
            bitmap.recycle();
        } finally {
            BitmapLoadUtils.close(outputStream);
        }
    }

    private boolean shouldCrop(int i2, int i3) {
        int round = Math.round(Math.max(i2, i3) / 1000.0f) + 1;
        if (this.mMaxResultImageSizeX > 0 && this.mMaxResultImageSizeY > 0) {
            return true;
        }
        float f2 = round;
        return Math.abs(this.mCropRect.left - this.mCurrentImageRect.left) > f2 || Math.abs(this.mCropRect.top - this.mCurrentImageRect.top) > f2 || Math.abs(this.mCropRect.bottom - this.mCurrentImageRect.bottom) > f2 || Math.abs(this.mCropRect.right - this.mCurrentImageRect.right) > f2 || this.mCurrentAngle != 0.0f;
    }

    @Override // android.os.AsyncTask
    @Nullable
    public Throwable doInBackground(Void... voidArr) {
        Bitmap bitmap = this.mViewBitmap;
        if (bitmap == null) {
            return new NullPointerException("ViewBitmap is null");
        }
        if (bitmap.isRecycled()) {
            return new NullPointerException("ViewBitmap is recycled");
        }
        if (this.mCurrentImageRect.isEmpty()) {
            return new NullPointerException("CurrentImageRect is empty");
        }
        try {
            crop();
            this.mViewBitmap = null;
            return null;
        } catch (Throwable th) {
            return th;
        }
    }

    @Override // android.os.AsyncTask
    public void onPostExecute(@Nullable Throwable th) {
        BitmapCropCallback bitmapCropCallback = this.mCropCallback;
        if (bitmapCropCallback != null) {
            if (th != null) {
                bitmapCropCallback.onCropFailure(th);
            } else {
                this.mCropCallback.onBitmapCropped(Uri.fromFile(new File(this.mImageOutputPath)), this.cropOffsetX, this.cropOffsetY, this.mCroppedImageWidth, this.mCroppedImageHeight);
            }
        }
    }
}
