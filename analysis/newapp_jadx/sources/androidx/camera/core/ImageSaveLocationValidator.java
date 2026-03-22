package androidx.camera.core;

import android.content.ContentResolver;
import android.content.ContentValues;
import android.net.Uri;
import androidx.annotation.NonNull;
import androidx.camera.core.ImageCapture;
import androidx.camera.core.internal.compat.quirk.DeviceQuirks;
import androidx.camera.core.internal.compat.quirk.HuaweiMediaStoreLocationValidationQuirk;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public class ImageSaveLocationValidator {
    private static final String TAG = "SaveLocationValidator";

    private ImageSaveLocationValidator() {
    }

    private static boolean canSaveToFile(@NonNull File file) {
        try {
            new FileOutputStream(file).close();
            return true;
        } catch (IOException e2) {
            StringBuilder m586H = C1499a.m586H("Failed to open a write stream to ");
            m586H.append(file.toString());
            Logger.m126e(TAG, m586H.toString(), e2);
            return false;
        }
    }

    private static boolean canSaveToMediaStore(@NonNull ContentResolver contentResolver, @NonNull Uri uri, @NonNull ContentValues contentValues) {
        try {
            Uri insert = contentResolver.insert(uri, contentValues);
            if (insert == null) {
                return false;
            }
            try {
                try {
                    OutputStream openOutputStream = contentResolver.openOutputStream(insert);
                    boolean z = openOutputStream != null;
                    if (openOutputStream != null) {
                        openOutputStream.close();
                    }
                    return z;
                } catch (IOException e2) {
                    Logger.m126e(TAG, "Failed to open a write stream to" + insert.toString(), e2);
                    try {
                        contentResolver.delete(insert, null, null);
                    } catch (IllegalArgumentException e3) {
                        StringBuilder m586H = C1499a.m586H("Failed to delete inserted row at ");
                        m586H.append(insert.toString());
                        Logger.m126e(TAG, m586H.toString(), e3);
                    }
                    return false;
                }
            } finally {
                try {
                    contentResolver.delete(insert, null, null);
                } catch (IllegalArgumentException e4) {
                    StringBuilder m586H2 = C1499a.m586H("Failed to delete inserted row at ");
                    m586H2.append(insert.toString());
                    Logger.m126e(TAG, m586H2.toString(), e4);
                }
            }
        } catch (IllegalArgumentException e5) {
            StringBuilder m586H3 = C1499a.m586H("Failed to insert into ");
            m586H3.append(uri.toString());
            Logger.m126e(TAG, m586H3.toString(), e5);
            return false;
        }
    }

    private static boolean isSaveToFile(@NonNull ImageCapture.OutputFileOptions outputFileOptions) {
        return outputFileOptions.getFile() != null;
    }

    private static boolean isSaveToMediaStore(@NonNull ImageCapture.OutputFileOptions outputFileOptions) {
        return (outputFileOptions.getSaveCollection() == null || outputFileOptions.getContentResolver() == null || outputFileOptions.getContentValues() == null) ? false : true;
    }

    public static boolean isValid(@NonNull ImageCapture.OutputFileOptions outputFileOptions) {
        if (isSaveToFile(outputFileOptions)) {
            return canSaveToFile(outputFileOptions.getFile());
        }
        if (!isSaveToMediaStore(outputFileOptions)) {
            return true;
        }
        HuaweiMediaStoreLocationValidationQuirk huaweiMediaStoreLocationValidationQuirk = (HuaweiMediaStoreLocationValidationQuirk) DeviceQuirks.get(HuaweiMediaStoreLocationValidationQuirk.class);
        return huaweiMediaStoreLocationValidationQuirk != null ? huaweiMediaStoreLocationValidationQuirk.canSaveToMediaStore() : canSaveToMediaStore(outputFileOptions.getContentResolver(), outputFileOptions.getSaveCollection(), outputFileOptions.getContentValues());
    }
}
