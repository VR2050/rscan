package com.yalantis.ucrop.task;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Matrix;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.ParcelFileDescriptor;
import android.text.TextUtils;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.content.ContextCompat;
import com.yalantis.ucrop.callback.BitmapLoadCallback;
import com.yalantis.ucrop.model.ExifInfo;
import com.yalantis.ucrop.util.BitmapLoadUtils;
import com.yalantis.ucrop.util.FileUtils;
import com.yalantis.ucrop.util.MimeType;
import com.yalantis.ucrop.util.SdkUtils;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileDescriptor;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.ref.WeakReference;
import java.net.URL;
import java.util.Objects;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes2.dex */
public class BitmapLoadTask extends AsyncTask<Void, Void, BitmapWorkerResult> {
    private static final String TAG = "BitmapWorkerTask";
    private final BitmapLoadCallback mBitmapLoadCallback;
    private WeakReference<Context> mContextWeakReference;
    private Uri mInputUri;
    private Uri mOutputUri;
    private final int mRequiredHeight;
    private final int mRequiredWidth;

    public BitmapLoadTask(@NonNull Context context, @NonNull Uri uri, @Nullable Uri uri2, int i2, int i3, BitmapLoadCallback bitmapLoadCallback) {
        this.mContextWeakReference = new WeakReference<>(context);
        this.mInputUri = uri;
        this.mOutputUri = uri2;
        this.mRequiredWidth = i2;
        this.mRequiredHeight = i3;
        this.mBitmapLoadCallback = bitmapLoadCallback;
    }

    private void copyFile(@NonNull Uri uri, @Nullable Uri uri2) {
        InputStream inputStream;
        FileOutputStream fileOutputStream;
        Objects.requireNonNull(uri2, "Output Uri is null - cannot copy image");
        FileOutputStream fileOutputStream2 = null;
        try {
            inputStream = getContext().getContentResolver().openInputStream(uri);
            try {
                fileOutputStream = new FileOutputStream(new File(uri2.getPath()));
            } catch (Throwable th) {
                th = th;
            }
        } catch (Throwable th2) {
            th = th2;
            inputStream = null;
        }
        try {
            if (inputStream == null) {
                throw new NullPointerException("InputStream for given input Uri is null");
            }
            byte[] bArr = new byte[1024];
            while (true) {
                int read = inputStream.read(bArr);
                if (read <= 0) {
                    BitmapLoadUtils.close(fileOutputStream);
                    BitmapLoadUtils.close(inputStream);
                    this.mInputUri = this.mOutputUri;
                    return;
                }
                fileOutputStream.write(bArr, 0, read);
            }
        } catch (Throwable th3) {
            th = th3;
            fileOutputStream2 = fileOutputStream;
            BitmapLoadUtils.close(fileOutputStream2);
            BitmapLoadUtils.close(inputStream);
            this.mInputUri = this.mOutputUri;
            throw th;
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r6v0, types: [android.net.Uri, java.lang.Object] */
    /* JADX WARN: Type inference failed for: r6v1 */
    /* JADX WARN: Type inference failed for: r6v10, types: [java.io.OutputStream] */
    /* JADX WARN: Type inference failed for: r6v11 */
    /* JADX WARN: Type inference failed for: r6v12 */
    /* JADX WARN: Type inference failed for: r6v2 */
    /* JADX WARN: Type inference failed for: r6v3 */
    /* JADX WARN: Type inference failed for: r6v4, types: [java.io.Closeable] */
    /* JADX WARN: Type inference failed for: r6v5 */
    /* JADX WARN: Type inference failed for: r6v6 */
    /* JADX WARN: Type inference failed for: r6v7, types: [java.io.Closeable] */
    /* JADX WARN: Type inference failed for: r6v8 */
    /* JADX WARN: Type inference failed for: r6v9 */
    private void downloadFile(@NonNull Uri uri, @Nullable Uri uri2) {
        BufferedInputStream bufferedInputStream;
        byte[] bArr;
        Objects.requireNonNull(uri2, "Output Uri is null - cannot download image");
        BufferedOutputStream bufferedOutputStream = null;
        try {
            try {
                URL url = new URL(uri.toString());
                bArr = new byte[1024];
                bufferedInputStream = new BufferedInputStream(url.openStream());
                try {
                    uri2 = getContext().getContentResolver().openOutputStream(uri2);
                } catch (Exception e2) {
                    e = e2;
                    uri2 = 0;
                } catch (Throwable th) {
                    th = th;
                    uri2 = 0;
                }
            } catch (Throwable th2) {
                th = th2;
            }
        } catch (Exception e3) {
            e = e3;
            uri2 = 0;
            bufferedInputStream = null;
        } catch (Throwable th3) {
            th = th3;
            uri2 = 0;
            bufferedInputStream = null;
        }
        if (uri2 != 0) {
            try {
                BufferedOutputStream bufferedOutputStream2 = new BufferedOutputStream(uri2);
                while (true) {
                    try {
                        int read = bufferedInputStream.read(bArr);
                        if (read <= -1) {
                            break;
                        } else {
                            bufferedOutputStream2.write(bArr, 0, read);
                        }
                    } catch (Exception e4) {
                        e = e4;
                        bufferedOutputStream = bufferedOutputStream2;
                        e.printStackTrace();
                        uri2 = uri2;
                        this.mInputUri = this.mOutputUri;
                        BitmapLoadUtils.close(bufferedOutputStream);
                        BitmapLoadUtils.close(bufferedInputStream);
                        BitmapLoadUtils.close(uri2);
                    } catch (Throwable th4) {
                        th = th4;
                        bufferedOutputStream = bufferedOutputStream2;
                        this.mInputUri = this.mOutputUri;
                        BitmapLoadUtils.close(bufferedOutputStream);
                        BitmapLoadUtils.close(bufferedInputStream);
                        BitmapLoadUtils.close(uri2);
                        throw th;
                    }
                }
                bufferedOutputStream2.flush();
                bufferedOutputStream = bufferedOutputStream2;
                uri2 = uri2;
            } catch (Exception e5) {
                e = e5;
            }
        }
        this.mInputUri = this.mOutputUri;
        BitmapLoadUtils.close(bufferedOutputStream);
        BitmapLoadUtils.close(bufferedInputStream);
        BitmapLoadUtils.close(uri2);
    }

    private Context getContext() {
        return this.mContextWeakReference.get();
    }

    private String getFilePath() {
        if (ContextCompat.checkSelfPermission(getContext(), "android.permission.READ_EXTERNAL_STORAGE") == 0) {
            return FileUtils.getPath(getContext(), this.mInputUri);
        }
        return null;
    }

    private void processInputUri() {
        String scheme = this.mInputUri.getScheme();
        if ("http".equals(scheme) || "https".equals(scheme)) {
            try {
                downloadFile(this.mInputUri, this.mOutputUri);
            } catch (IOException | NullPointerException e2) {
                throw e2;
            }
        } else {
            if (!"content".equals(scheme)) {
                if (!"file".equals(scheme)) {
                    throw new IllegalArgumentException(C1499a.m637w("Invalid Uri scheme", scheme));
                }
                return;
            }
            String filePath = getFilePath();
            if (!TextUtils.isEmpty(filePath) && new File(filePath).exists()) {
                this.mInputUri = SdkUtils.isQ() ? this.mInputUri : Uri.fromFile(new File(filePath));
                return;
            }
            try {
                copyFile(this.mInputUri, this.mOutputUri);
            } catch (IOException | NullPointerException e3) {
                throw e3;
            }
        }
    }

    @Override // android.os.AsyncTask
    @NonNull
    public BitmapWorkerResult doInBackground(Void... voidArr) {
        if (this.mInputUri == null) {
            return new BitmapWorkerResult(new NullPointerException("Input Uri cannot be null"));
        }
        try {
            processInputUri();
            try {
                ParcelFileDescriptor openFileDescriptor = getContext().getContentResolver().openFileDescriptor(this.mInputUri, "r");
                if (openFileDescriptor == null) {
                    StringBuilder m586H = C1499a.m586H("ParcelFileDescriptor was null for given Uri: [");
                    m586H.append(this.mInputUri);
                    m586H.append("]");
                    return new BitmapWorkerResult(new NullPointerException(m586H.toString()));
                }
                FileDescriptor fileDescriptor = openFileDescriptor.getFileDescriptor();
                BitmapFactory.Options options = new BitmapFactory.Options();
                options.inJustDecodeBounds = true;
                BitmapFactory.decodeFileDescriptor(fileDescriptor, null, options);
                if (options.outWidth == -1 || options.outHeight == -1) {
                    StringBuilder m586H2 = C1499a.m586H("Bounds for bitmap could not be retrieved from the Uri: [");
                    m586H2.append(this.mInputUri);
                    m586H2.append("]");
                    return new BitmapWorkerResult(new IllegalArgumentException(m586H2.toString()));
                }
                options.inSampleSize = BitmapLoadUtils.calculateInSampleSize(options, this.mRequiredWidth, this.mRequiredHeight);
                boolean z = false;
                options.inJustDecodeBounds = false;
                Bitmap bitmap = null;
                while (!z) {
                    try {
                        bitmap = BitmapFactory.decodeFileDescriptor(fileDescriptor, null, options);
                        z = true;
                    } catch (OutOfMemoryError unused) {
                        options.inSampleSize *= 2;
                    }
                }
                if (bitmap == null) {
                    StringBuilder m586H3 = C1499a.m586H("Bitmap could not be decoded from the Uri: [");
                    m586H3.append(this.mInputUri);
                    m586H3.append("]");
                    return new BitmapWorkerResult(new IllegalArgumentException(m586H3.toString()));
                }
                BitmapLoadUtils.close(openFileDescriptor);
                int exifOrientation = BitmapLoadUtils.getExifOrientation(getContext(), this.mInputUri);
                int exifToDegrees = BitmapLoadUtils.exifToDegrees(exifOrientation);
                int exifToTranslation = BitmapLoadUtils.exifToTranslation(exifOrientation);
                ExifInfo exifInfo = new ExifInfo(exifOrientation, exifToDegrees, exifToTranslation);
                Matrix matrix = new Matrix();
                if (exifToDegrees != 0) {
                    matrix.preRotate(exifToDegrees);
                }
                if (exifToTranslation != 1) {
                    matrix.postScale(exifToTranslation, 1.0f);
                }
                return !matrix.isIdentity() ? new BitmapWorkerResult(BitmapLoadUtils.transformBitmap(bitmap, matrix), exifInfo) : new BitmapWorkerResult(bitmap, exifInfo);
            } catch (FileNotFoundException e2) {
                return new BitmapWorkerResult(e2);
            }
        } catch (IOException | NullPointerException e3) {
            return new BitmapWorkerResult(e3);
        }
    }

    @Override // android.os.AsyncTask
    public void onPostExecute(@NonNull BitmapWorkerResult bitmapWorkerResult) {
        Exception exc = bitmapWorkerResult.mBitmapWorkerException;
        if (exc != null) {
            this.mBitmapLoadCallback.onFailure(exc);
            return;
        }
        String uri = this.mInputUri.toString();
        BitmapLoadCallback bitmapLoadCallback = this.mBitmapLoadCallback;
        Bitmap bitmap = bitmapWorkerResult.mBitmapResult;
        ExifInfo exifInfo = bitmapWorkerResult.mExifInfo;
        if (!MimeType.isContent(uri)) {
            uri = this.mInputUri.getPath();
        }
        Uri uri2 = this.mOutputUri;
        bitmapLoadCallback.onBitmapLoaded(bitmap, exifInfo, uri, uri2 == null ? null : uri2.getPath());
    }

    public static class BitmapWorkerResult {
        public Bitmap mBitmapResult;
        public Exception mBitmapWorkerException;
        public ExifInfo mExifInfo;

        public BitmapWorkerResult(@NonNull Bitmap bitmap, @NonNull ExifInfo exifInfo) {
            this.mBitmapResult = bitmap;
            this.mExifInfo = exifInfo;
        }

        public BitmapWorkerResult(@NonNull Exception exc) {
            this.mBitmapWorkerException = exc;
        }
    }
}
