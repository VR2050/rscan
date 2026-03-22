package androidx.camera.view.video;

import android.content.ContentResolver;
import android.content.ContentValues;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.camera.view.video.OutputFileOptions;
import java.io.File;
import java.util.Objects;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public final class AutoValue_OutputFileOptions extends OutputFileOptions {
    private final ContentResolver contentResolver;
    private final ContentValues contentValues;
    private final File file;
    private final ParcelFileDescriptor fileDescriptor;
    private final Metadata metadata;
    private final Uri saveCollection;

    public static final class Builder extends OutputFileOptions.Builder {
        private ContentResolver contentResolver;
        private ContentValues contentValues;
        private File file;
        private ParcelFileDescriptor fileDescriptor;
        private Metadata metadata;
        private Uri saveCollection;

        @Override // androidx.camera.view.video.OutputFileOptions.Builder
        public OutputFileOptions build() {
            String str = this.metadata == null ? " metadata" : "";
            if (str.isEmpty()) {
                return new AutoValue_OutputFileOptions(this.file, this.fileDescriptor, this.contentResolver, this.saveCollection, this.contentValues, this.metadata);
            }
            throw new IllegalStateException(C1499a.m637w("Missing required properties:", str));
        }

        @Override // androidx.camera.view.video.OutputFileOptions.Builder
        public OutputFileOptions.Builder setContentResolver(@Nullable ContentResolver contentResolver) {
            this.contentResolver = contentResolver;
            return this;
        }

        @Override // androidx.camera.view.video.OutputFileOptions.Builder
        public OutputFileOptions.Builder setContentValues(@Nullable ContentValues contentValues) {
            this.contentValues = contentValues;
            return this;
        }

        @Override // androidx.camera.view.video.OutputFileOptions.Builder
        public OutputFileOptions.Builder setFile(@Nullable File file) {
            this.file = file;
            return this;
        }

        @Override // androidx.camera.view.video.OutputFileOptions.Builder
        public OutputFileOptions.Builder setFileDescriptor(@Nullable ParcelFileDescriptor parcelFileDescriptor) {
            this.fileDescriptor = parcelFileDescriptor;
            return this;
        }

        @Override // androidx.camera.view.video.OutputFileOptions.Builder
        public OutputFileOptions.Builder setMetadata(Metadata metadata) {
            Objects.requireNonNull(metadata, "Null metadata");
            this.metadata = metadata;
            return this;
        }

        @Override // androidx.camera.view.video.OutputFileOptions.Builder
        public OutputFileOptions.Builder setSaveCollection(@Nullable Uri uri) {
            this.saveCollection = uri;
            return this;
        }
    }

    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof OutputFileOptions)) {
            return false;
        }
        OutputFileOptions outputFileOptions = (OutputFileOptions) obj;
        File file = this.file;
        if (file != null ? file.equals(outputFileOptions.getFile()) : outputFileOptions.getFile() == null) {
            ParcelFileDescriptor parcelFileDescriptor = this.fileDescriptor;
            if (parcelFileDescriptor != null ? parcelFileDescriptor.equals(outputFileOptions.getFileDescriptor()) : outputFileOptions.getFileDescriptor() == null) {
                ContentResolver contentResolver = this.contentResolver;
                if (contentResolver != null ? contentResolver.equals(outputFileOptions.getContentResolver()) : outputFileOptions.getContentResolver() == null) {
                    Uri uri = this.saveCollection;
                    if (uri != null ? uri.equals(outputFileOptions.getSaveCollection()) : outputFileOptions.getSaveCollection() == null) {
                        ContentValues contentValues = this.contentValues;
                        if (contentValues != null ? contentValues.equals(outputFileOptions.getContentValues()) : outputFileOptions.getContentValues() == null) {
                            if (this.metadata.equals(outputFileOptions.getMetadata())) {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        return false;
    }

    @Override // androidx.camera.view.video.OutputFileOptions
    @Nullable
    public ContentResolver getContentResolver() {
        return this.contentResolver;
    }

    @Override // androidx.camera.view.video.OutputFileOptions
    @Nullable
    public ContentValues getContentValues() {
        return this.contentValues;
    }

    @Override // androidx.camera.view.video.OutputFileOptions
    @Nullable
    public File getFile() {
        return this.file;
    }

    @Override // androidx.camera.view.video.OutputFileOptions
    @Nullable
    public ParcelFileDescriptor getFileDescriptor() {
        return this.fileDescriptor;
    }

    @Override // androidx.camera.view.video.OutputFileOptions
    @NonNull
    public Metadata getMetadata() {
        return this.metadata;
    }

    @Override // androidx.camera.view.video.OutputFileOptions
    @Nullable
    public Uri getSaveCollection() {
        return this.saveCollection;
    }

    public int hashCode() {
        File file = this.file;
        int hashCode = ((file == null ? 0 : file.hashCode()) ^ 1000003) * 1000003;
        ParcelFileDescriptor parcelFileDescriptor = this.fileDescriptor;
        int hashCode2 = (hashCode ^ (parcelFileDescriptor == null ? 0 : parcelFileDescriptor.hashCode())) * 1000003;
        ContentResolver contentResolver = this.contentResolver;
        int hashCode3 = (hashCode2 ^ (contentResolver == null ? 0 : contentResolver.hashCode())) * 1000003;
        Uri uri = this.saveCollection;
        int hashCode4 = (hashCode3 ^ (uri == null ? 0 : uri.hashCode())) * 1000003;
        ContentValues contentValues = this.contentValues;
        return ((hashCode4 ^ (contentValues != null ? contentValues.hashCode() : 0)) * 1000003) ^ this.metadata.hashCode();
    }

    public String toString() {
        StringBuilder m586H = C1499a.m586H("OutputFileOptions{file=");
        m586H.append(this.file);
        m586H.append(", fileDescriptor=");
        m586H.append(this.fileDescriptor);
        m586H.append(", contentResolver=");
        m586H.append(this.contentResolver);
        m586H.append(", saveCollection=");
        m586H.append(this.saveCollection);
        m586H.append(", contentValues=");
        m586H.append(this.contentValues);
        m586H.append(", metadata=");
        m586H.append(this.metadata);
        m586H.append("}");
        return m586H.toString();
    }

    private AutoValue_OutputFileOptions(@Nullable File file, @Nullable ParcelFileDescriptor parcelFileDescriptor, @Nullable ContentResolver contentResolver, @Nullable Uri uri, @Nullable ContentValues contentValues, Metadata metadata) {
        this.file = file;
        this.fileDescriptor = parcelFileDescriptor;
        this.contentResolver = contentResolver;
        this.saveCollection = uri;
        this.contentValues = contentValues;
        this.metadata = metadata;
    }
}
