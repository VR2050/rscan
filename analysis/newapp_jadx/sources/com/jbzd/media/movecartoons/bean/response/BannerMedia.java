package com.jbzd.media.movecartoons.bean.response;

import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000 \n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000b\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\t\n\u0002\u0010\b\n\u0002\b\u000e\b\u0086\b\u0018\u00002\u00020\u0001B)\u0012\b\b\u0002\u0010\t\u001a\u00020\u0002\u0012\n\b\u0002\u0010\n\u001a\u0004\u0018\u00010\u0005\u0012\n\b\u0002\u0010\u000b\u001a\u0004\u0018\u00010\u0005¢\u0006\u0004\b\u001b\u0010\u001cJ\u0010\u0010\u0003\u001a\u00020\u0002HÆ\u0003¢\u0006\u0004\b\u0003\u0010\u0004J\u0012\u0010\u0006\u001a\u0004\u0018\u00010\u0005HÆ\u0003¢\u0006\u0004\b\u0006\u0010\u0007J\u0012\u0010\b\u001a\u0004\u0018\u00010\u0005HÆ\u0003¢\u0006\u0004\b\b\u0010\u0007J2\u0010\f\u001a\u00020\u00002\b\b\u0002\u0010\t\u001a\u00020\u00022\n\b\u0002\u0010\n\u001a\u0004\u0018\u00010\u00052\n\b\u0002\u0010\u000b\u001a\u0004\u0018\u00010\u0005HÆ\u0001¢\u0006\u0004\b\f\u0010\rJ\u0010\u0010\u000e\u001a\u00020\u0005HÖ\u0001¢\u0006\u0004\b\u000e\u0010\u0007J\u0010\u0010\u0010\u001a\u00020\u000fHÖ\u0001¢\u0006\u0004\b\u0010\u0010\u0011J\u001a\u0010\u0013\u001a\u00020\u00022\b\u0010\u0012\u001a\u0004\u0018\u00010\u0001HÖ\u0003¢\u0006\u0004\b\u0013\u0010\u0014R\u0019\u0010\t\u001a\u00020\u00028\u0006@\u0006¢\u0006\f\n\u0004\b\t\u0010\u0015\u001a\u0004\b\t\u0010\u0004R\u001b\u0010\n\u001a\u0004\u0018\u00010\u00058\u0006@\u0006¢\u0006\f\n\u0004\b\n\u0010\u0016\u001a\u0004\b\u0017\u0010\u0007R\u001b\u0010\u000b\u001a\u0004\u0018\u00010\u00058\u0006@\u0006¢\u0006\f\n\u0004\b\u000b\u0010\u0016\u001a\u0004\b\u0018\u0010\u0007R\u0013\u0010\u001a\u001a\u00020\u000f8F@\u0006¢\u0006\u0006\u001a\u0004\b\u0019\u0010\u0011¨\u0006\u001d"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/bean/response/BannerMedia;", "", "", "component1", "()Z", "", "component2", "()Ljava/lang/String;", "component3", "is_video", "url", "video_url", "copy", "(ZLjava/lang/String;Ljava/lang/String;)Lcom/jbzd/media/movecartoons/bean/response/BannerMedia;", "toString", "", "hashCode", "()I", "other", "equals", "(Ljava/lang/Object;)Z", "Z", "Ljava/lang/String;", "getUrl", "getVideo_url", "getViewType", "viewType", "<init>", "(ZLjava/lang/String;Ljava/lang/String;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final /* data */ class BannerMedia {
    private final boolean is_video;

    @Nullable
    private final String url;

    @Nullable
    private final String video_url;

    public BannerMedia() {
        this(false, null, null, 7, null);
    }

    public BannerMedia(boolean z, @Nullable String str, @Nullable String str2) {
        this.is_video = z;
        this.url = str;
        this.video_url = str2;
    }

    public static /* synthetic */ BannerMedia copy$default(BannerMedia bannerMedia, boolean z, String str, String str2, int i2, Object obj) {
        if ((i2 & 1) != 0) {
            z = bannerMedia.is_video;
        }
        if ((i2 & 2) != 0) {
            str = bannerMedia.url;
        }
        if ((i2 & 4) != 0) {
            str2 = bannerMedia.video_url;
        }
        return bannerMedia.copy(z, str, str2);
    }

    /* renamed from: component1, reason: from getter */
    public final boolean getIs_video() {
        return this.is_video;
    }

    @Nullable
    /* renamed from: component2, reason: from getter */
    public final String getUrl() {
        return this.url;
    }

    @Nullable
    /* renamed from: component3, reason: from getter */
    public final String getVideo_url() {
        return this.video_url;
    }

    @NotNull
    public final BannerMedia copy(boolean is_video, @Nullable String url, @Nullable String video_url) {
        return new BannerMedia(is_video, url, video_url);
    }

    public boolean equals(@Nullable Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof BannerMedia)) {
            return false;
        }
        BannerMedia bannerMedia = (BannerMedia) other;
        return this.is_video == bannerMedia.is_video && Intrinsics.areEqual(this.url, bannerMedia.url) && Intrinsics.areEqual(this.video_url, bannerMedia.video_url);
    }

    @Nullable
    public final String getUrl() {
        return this.url;
    }

    @Nullable
    public final String getVideo_url() {
        return this.video_url;
    }

    public final int getViewType() {
        return !this.is_video ? 1 : 2;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r0v1, types: [int] */
    /* JADX WARN: Type inference failed for: r0v6 */
    /* JADX WARN: Type inference failed for: r0v7 */
    public int hashCode() {
        boolean z = this.is_video;
        ?? r0 = z;
        if (z) {
            r0 = 1;
        }
        int i2 = r0 * 31;
        String str = this.url;
        int hashCode = (i2 + (str == null ? 0 : str.hashCode())) * 31;
        String str2 = this.video_url;
        return hashCode + (str2 != null ? str2.hashCode() : 0);
    }

    public final boolean is_video() {
        return this.is_video;
    }

    @NotNull
    public String toString() {
        StringBuilder m586H = C1499a.m586H("BannerMedia(is_video=");
        m586H.append(this.is_video);
        m586H.append(", url=");
        m586H.append((Object) this.url);
        m586H.append(", video_url=");
        m586H.append((Object) this.video_url);
        m586H.append(')');
        return m586H.toString();
    }

    public /* synthetic */ BannerMedia(boolean z, String str, String str2, int i2, DefaultConstructorMarker defaultConstructorMarker) {
        this((i2 & 1) != 0 ? false : z, (i2 & 2) != 0 ? "" : str, (i2 & 4) != 0 ? "" : str2);
    }
}
