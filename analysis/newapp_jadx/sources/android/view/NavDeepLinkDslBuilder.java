package android.view;

import android.view.NavDeepLink;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

@NavDeepLinkDsl
@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000 \n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\f\b\u0007\u0018\u00002\u00020\u0001B\u0007¢\u0006\u0004\b\u0017\u0010\u0018J\u000f\u0010\u0005\u001a\u00020\u0002H\u0000¢\u0006\u0004\b\u0003\u0010\u0004R$\u0010\u0007\u001a\u0004\u0018\u00010\u00068\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u0007\u0010\b\u001a\u0004\b\t\u0010\n\"\u0004\b\u000b\u0010\fR\u0016\u0010\u000e\u001a\u00020\r8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b\u000e\u0010\u000fR$\u0010\u0010\u001a\u0004\u0018\u00010\u00068\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u0010\u0010\b\u001a\u0004\b\u0011\u0010\n\"\u0004\b\u0012\u0010\fR.\u0010\u0014\u001a\u0004\u0018\u00010\u00062\b\u0010\u0013\u001a\u0004\u0018\u00010\u00068\u0006@FX\u0086\u000e¢\u0006\u0012\n\u0004\b\u0014\u0010\b\u001a\u0004\b\u0015\u0010\n\"\u0004\b\u0016\u0010\f¨\u0006\u0019"}, m5311d2 = {"Landroidx/navigation/NavDeepLinkDslBuilder;", "", "Landroidx/navigation/NavDeepLink;", "build$navigation_common_ktx_release", "()Landroidx/navigation/NavDeepLink;", "build", "", "uriPattern", "Ljava/lang/String;", "getUriPattern", "()Ljava/lang/String;", "setUriPattern", "(Ljava/lang/String;)V", "Landroidx/navigation/NavDeepLink$Builder;", "builder", "Landroidx/navigation/NavDeepLink$Builder;", "mimeType", "getMimeType", "setMimeType", "p", "action", "getAction", "setAction", "<init>", "()V", "navigation-common-ktx_release"}, m5312k = 1, m5313mv = {1, 4, 0})
/* loaded from: classes.dex */
public final class NavDeepLinkDslBuilder {

    @Nullable
    private String action;
    private final NavDeepLink.Builder builder = new NavDeepLink.Builder();

    @Nullable
    private String mimeType;

    @Nullable
    private String uriPattern;

    @NotNull
    public final NavDeepLink build$navigation_common_ktx_release() {
        NavDeepLink.Builder builder = this.builder;
        String str = this.uriPattern;
        if (!((str == null && this.action == null && this.mimeType == null) ? false : true)) {
            throw new IllegalStateException("The NavDeepLink must have an uri, action, and/or mimeType.".toString());
        }
        if (str != null) {
            builder.setUriPattern(str);
        }
        String str2 = this.action;
        if (str2 != null) {
            builder.setAction(str2);
        }
        String str3 = this.mimeType;
        if (str3 != null) {
            builder.setMimeType(str3);
        }
        NavDeepLink build = builder.build();
        Intrinsics.checkExpressionValueIsNotNull(build, "builder.apply {\n        …eType(it) }\n    }.build()");
        return build;
    }

    @Nullable
    public final String getAction() {
        return this.action;
    }

    @Nullable
    public final String getMimeType() {
        return this.mimeType;
    }

    @Nullable
    public final String getUriPattern() {
        return this.uriPattern;
    }

    public final void setAction(@Nullable String str) {
        if (str != null) {
            if (str.length() == 0) {
                throw new IllegalArgumentException("The NavDeepLink cannot have an empty action.");
            }
        }
        this.action = str;
    }

    public final void setMimeType(@Nullable String str) {
        this.mimeType = str;
    }

    public final void setUriPattern(@Nullable String str) {
        this.uriPattern = str;
    }
}
