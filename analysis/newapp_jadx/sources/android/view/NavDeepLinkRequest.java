package android.view;

import android.content.Intent;
import android.net.Uri;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import java.util.regex.Pattern;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public class NavDeepLinkRequest {
    private final String mAction;
    private final String mMimeType;
    private final Uri mUri;

    public static final class Builder {
        private String mAction;
        private String mMimeType;
        private Uri mUri;

        private Builder() {
        }

        @NonNull
        public static Builder fromAction(@NonNull String str) {
            if (str.isEmpty()) {
                throw new IllegalArgumentException("The NavDeepLinkRequest cannot have an empty action.");
            }
            Builder builder = new Builder();
            builder.setAction(str);
            return builder;
        }

        @NonNull
        public static Builder fromMimeType(@NonNull String str) {
            Builder builder = new Builder();
            builder.setMimeType(str);
            return builder;
        }

        @NonNull
        public static Builder fromUri(@NonNull Uri uri) {
            Builder builder = new Builder();
            builder.setUri(uri);
            return builder;
        }

        @NonNull
        public NavDeepLinkRequest build() {
            return new NavDeepLinkRequest(this.mUri, this.mAction, this.mMimeType);
        }

        @NonNull
        public Builder setAction(@NonNull String str) {
            if (str.isEmpty()) {
                throw new IllegalArgumentException("The NavDeepLinkRequest cannot have an empty action.");
            }
            this.mAction = str;
            return this;
        }

        @NonNull
        public Builder setMimeType(@NonNull String str) {
            if (!Pattern.compile("^[-\\w*.]+/[-\\w+*.]+$").matcher(str).matches()) {
                throw new IllegalArgumentException(C1499a.m639y("The given mimeType ", str, " does not match to required \"type/subtype\" format"));
            }
            this.mMimeType = str;
            return this;
        }

        @NonNull
        public Builder setUri(@NonNull Uri uri) {
            this.mUri = uri;
            return this;
        }
    }

    public NavDeepLinkRequest(@NonNull Intent intent) {
        this(intent.getData(), intent.getAction(), intent.getType());
    }

    @Nullable
    public String getAction() {
        return this.mAction;
    }

    @Nullable
    public String getMimeType() {
        return this.mMimeType;
    }

    @Nullable
    public Uri getUri() {
        return this.mUri;
    }

    @NonNull
    public String toString() {
        StringBuilder m590L = C1499a.m590L("NavDeepLinkRequest", "{");
        if (this.mUri != null) {
            m590L.append(" uri=");
            m590L.append(this.mUri.toString());
        }
        if (this.mAction != null) {
            m590L.append(" action=");
            m590L.append(this.mAction);
        }
        if (this.mMimeType != null) {
            m590L.append(" mimetype=");
            m590L.append(this.mMimeType);
        }
        m590L.append(" }");
        return m590L.toString();
    }

    public NavDeepLinkRequest(@Nullable Uri uri, @Nullable String str, @Nullable String str2) {
        this.mUri = uri;
        this.mAction = str;
        this.mMimeType = str2;
    }
}
