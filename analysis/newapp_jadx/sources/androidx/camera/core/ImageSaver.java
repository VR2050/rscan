package androidx.camera.core;

import android.content.ContentValues;
import android.net.Uri;
import android.os.Build;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.camera.core.ImageCapture;
import androidx.camera.core.ImageSaver;
import androidx.camera.core.internal.utils.ImageUtil;
import java.io.File;
import java.io.FileInputStream;
import java.io.OutputStream;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;

/* loaded from: classes.dex */
public final class ImageSaver implements Runnable {
    private static final int COPY_BUFFER_SIZE = 1024;
    private static final int NOT_PENDING = 0;
    private static final int PENDING = 1;
    private static final String TAG = "ImageSaver";
    private static final String TEMP_FILE_PREFIX = "CameraX";
    private static final String TEMP_FILE_SUFFIX = ".tmp";
    public final OnImageSavedCallback mCallback;
    private final Executor mExecutor;
    private final ImageProxy mImage;
    private final int mOrientation;

    @NonNull
    private final ImageCapture.OutputFileOptions mOutputFileOptions;

    /* renamed from: androidx.camera.core.ImageSaver$1 */
    public static /* synthetic */ class C01611 {

        /* renamed from: $SwitchMap$androidx$camera$core$internal$utils$ImageUtil$CodecFailedException$FailureType */
        public static final /* synthetic */ int[] f113x12b8ec9c;

        static {
            ImageUtil.CodecFailedException.FailureType.values();
            int[] iArr = new int[3];
            f113x12b8ec9c = iArr;
            try {
                iArr[ImageUtil.CodecFailedException.FailureType.ENCODE_FAILED.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                f113x12b8ec9c[ImageUtil.CodecFailedException.FailureType.DECODE_FAILED.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                f113x12b8ec9c[ImageUtil.CodecFailedException.FailureType.UNKNOWN.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
        }
    }

    public interface OnImageSavedCallback {
        void onError(SaveError saveError, String str, @Nullable Throwable th);

        void onImageSaved(@NonNull ImageCapture.OutputFileResults outputFileResults);
    }

    public enum SaveError {
        FILE_IO_FAILED,
        ENCODE_FAILED,
        CROP_FAILED,
        UNKNOWN
    }

    public ImageSaver(ImageProxy imageProxy, @NonNull ImageCapture.OutputFileOptions outputFileOptions, int i2, Executor executor, OnImageSavedCallback onImageSavedCallback) {
        this.mImage = imageProxy;
        this.mOutputFileOptions = outputFileOptions;
        this.mOrientation = i2;
        this.mCallback = onImageSavedCallback;
        this.mExecutor = executor;
    }

    private void copyTempFileToOutputStream(@NonNull File file, @NonNull OutputStream outputStream) {
        FileInputStream fileInputStream = new FileInputStream(file);
        try {
            byte[] bArr = new byte[1024];
            while (true) {
                int read = fileInputStream.read(bArr);
                if (read <= 0) {
                    fileInputStream.close();
                    return;
                }
                outputStream.write(bArr, 0, read);
            }
        } catch (Throwable th) {
            try {
                fileInputStream.close();
            } catch (Throwable th2) {
                th.addSuppressed(th2);
            }
            throw th;
        }
    }

    private boolean copyTempFileToUri(@NonNull File file, @NonNull Uri uri) {
        OutputStream openOutputStream = this.mOutputFileOptions.getContentResolver().openOutputStream(uri);
        if (openOutputStream == null) {
            if (openOutputStream != null) {
                openOutputStream.close();
            }
            return false;
        }
        try {
            copyTempFileToOutputStream(file, openOutputStream);
            openOutputStream.close();
            return true;
        } catch (Throwable th) {
            try {
                openOutputStream.close();
            } catch (Throwable th2) {
                th.addSuppressed(th2);
            }
            throw th;
        }
    }

    private boolean isSaveToFile() {
        return this.mOutputFileOptions.getFile() != null;
    }

    private boolean isSaveToMediaStore() {
        return (this.mOutputFileOptions.getSaveCollection() == null || this.mOutputFileOptions.getContentResolver() == null || this.mOutputFileOptions.getContentValues() == null) ? false : true;
    }

    private boolean isSaveToOutputStream() {
        return this.mOutputFileOptions.getOutputStream() != null;
    }

    private void postError(final SaveError saveError, final String str, @Nullable final Throwable th) {
        try {
            this.mExecutor.execute(new Runnable() { // from class: e.a.a.p0
                @Override // java.lang.Runnable
                public final void run() {
                    ImageSaver imageSaver = ImageSaver.this;
                    imageSaver.mCallback.onError(saveError, str, th);
                }
            });
        } catch (RejectedExecutionException unused) {
            Logger.m125e(TAG, "Application executor rejected executing OnImageSavedCallback.onError callback. Skipping.");
        }
    }

    private void postSuccess(@Nullable final Uri uri) {
        try {
            this.mExecutor.execute(new Runnable() { // from class: e.a.a.o0
                @Override // java.lang.Runnable
                public final void run() {
                    ImageSaver.this.mCallback.onImageSaved(new ImageCapture.OutputFileResults(uri));
                }
            });
        } catch (RejectedExecutionException unused) {
            Logger.m125e(TAG, "Application executor rejected executing OnImageSavedCallback.onImageSaved callback. Skipping.");
        }
    }

    private void setContentValuePending(@NonNull ContentValues contentValues, int i2) {
        if (Build.VERSION.SDK_INT >= 29) {
            contentValues.put("is_pending", Integer.valueOf(i2));
        }
    }

    private void setUriNotPending(@NonNull Uri uri) {
        if (Build.VERSION.SDK_INT >= 29) {
            ContentValues contentValues = new ContentValues();
            setContentValuePending(contentValues, 0);
            this.mOutputFileOptions.getContentResolver().update(uri, contentValues, null, null);
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:39:0x0161, code lost:
    
        if (r6 == null) goto L95;
     */
    /* JADX WARN: Code restructure failed: missing block: B:40:0x0163, code lost:
    
        postError(r6, r7, r2);
     */
    /* JADX WARN: Code restructure failed: missing block: B:41:?, code lost:
    
        return;
     */
    /* JADX WARN: Code restructure failed: missing block: B:43:0x0167, code lost:
    
        postSuccess(r5);
     */
    /* JADX WARN: Code restructure failed: missing block: B:44:0x016a, code lost:
    
        return;
     */
    /* JADX WARN: Code restructure failed: missing block: B:89:0x014e, code lost:
    
        if (isSaveToFile() == false) goto L48;
     */
    /* JADX WARN: Code restructure failed: missing block: B:96:0x015e, code lost:
    
        if (isSaveToFile() == false) goto L48;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:49:0x011a A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:86:0x0138  */
    /* JADX WARN: Removed duplicated region for block: B:91:0x0144 A[Catch: all -> 0x0129, TRY_LEAVE, TryCatch #4 {all -> 0x0129, blocks: (B:7:0x0017, B:35:0x00fb, B:84:0x012e, B:87:0x013a, B:90:0x013f, B:91:0x0144, B:94:0x0156, B:48:0x0122, B:53:0x011f), top: B:6:0x0017 }] */
    /* JADX WARN: Type inference failed for: r1v3, types: [java.lang.IllegalArgumentException] */
    /* JADX WARN: Type inference failed for: r1v4 */
    /* JADX WARN: Type inference failed for: r1v5, types: [java.io.IOException] */
    /* JADX WARN: Type inference failed for: r1v6, types: [java.lang.IllegalArgumentException] */
    /* JADX WARN: Type inference failed for: r1v7 */
    /* JADX WARN: Type inference failed for: r1v9, types: [java.io.IOException] */
    /* JADX WARN: Type inference failed for: r5v22, types: [android.net.Uri] */
    /* JADX WARN: Type inference failed for: r9v0, types: [androidx.camera.core.ImageSaver] */
    @Override // java.lang.Runnable
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void run() {
        /*
            Method dump skipped, instructions count: 382
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.camera.core.ImageSaver.run():void");
    }
}
