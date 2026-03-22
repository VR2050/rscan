package com.jbzd.media.movecartoons.bean.response;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000 \n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0002\b\f\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0010\u000b\n\u0002\b\n\b\u0086\b\u0018\u00002\u00020\u0001B'\u0012\u0006\u0010\b\u001a\u00020\u0002\u0012\u0006\u0010\t\u001a\u00020\u0002\u0012\u0006\u0010\n\u001a\u00020\u0002\u0012\u0006\u0010\u000b\u001a\u00020\u0002¢\u0006\u0004\b\u001b\u0010\u001cJ\u0010\u0010\u0003\u001a\u00020\u0002HÆ\u0003¢\u0006\u0004\b\u0003\u0010\u0004J\u0010\u0010\u0005\u001a\u00020\u0002HÆ\u0003¢\u0006\u0004\b\u0005\u0010\u0004J\u0010\u0010\u0006\u001a\u00020\u0002HÆ\u0003¢\u0006\u0004\b\u0006\u0010\u0004J\u0010\u0010\u0007\u001a\u00020\u0002HÆ\u0003¢\u0006\u0004\b\u0007\u0010\u0004J8\u0010\f\u001a\u00020\u00002\b\b\u0002\u0010\b\u001a\u00020\u00022\b\b\u0002\u0010\t\u001a\u00020\u00022\b\b\u0002\u0010\n\u001a\u00020\u00022\b\b\u0002\u0010\u000b\u001a\u00020\u0002HÆ\u0001¢\u0006\u0004\b\f\u0010\rJ\u0010\u0010\u000e\u001a\u00020\u0002HÖ\u0001¢\u0006\u0004\b\u000e\u0010\u0004J\u0010\u0010\u0010\u001a\u00020\u000fHÖ\u0001¢\u0006\u0004\b\u0010\u0010\u0011J\u001a\u0010\u0014\u001a\u00020\u00132\b\u0010\u0012\u001a\u0004\u0018\u00010\u0001HÖ\u0003¢\u0006\u0004\b\u0014\u0010\u0015R\u0019\u0010\u000b\u001a\u00020\u00028\u0006@\u0006¢\u0006\f\n\u0004\b\u000b\u0010\u0016\u001a\u0004\b\u0017\u0010\u0004R\u0019\u0010\b\u001a\u00020\u00028\u0006@\u0006¢\u0006\f\n\u0004\b\b\u0010\u0016\u001a\u0004\b\u0018\u0010\u0004R\u0019\u0010\n\u001a\u00020\u00028\u0006@\u0006¢\u0006\f\n\u0004\b\n\u0010\u0016\u001a\u0004\b\u0019\u0010\u0004R\u0019\u0010\t\u001a\u00020\u00028\u0006@\u0006¢\u0006\f\n\u0004\b\t\u0010\u0016\u001a\u0004\b\u001a\u0010\u0004¨\u0006\u001d"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/bean/response/ShareBean;", "", "", "component1", "()Ljava/lang/String;", "component2", "component3", "component4", "register_at", "id", "nickname", "img", "copy", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Lcom/jbzd/media/movecartoons/bean/response/ShareBean;", "toString", "", "hashCode", "()I", "other", "", "equals", "(Ljava/lang/Object;)Z", "Ljava/lang/String;", "getImg", "getRegister_at", "getNickname", "getId", "<init>", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final /* data */ class ShareBean {

    @NotNull
    private final String id;

    @NotNull
    private final String img;

    @NotNull
    private final String nickname;

    @NotNull
    private final String register_at;

    public ShareBean(@NotNull String register_at, @NotNull String id, @NotNull String nickname, @NotNull String img) {
        Intrinsics.checkNotNullParameter(register_at, "register_at");
        Intrinsics.checkNotNullParameter(id, "id");
        Intrinsics.checkNotNullParameter(nickname, "nickname");
        Intrinsics.checkNotNullParameter(img, "img");
        this.register_at = register_at;
        this.id = id;
        this.nickname = nickname;
        this.img = img;
    }

    public static /* synthetic */ ShareBean copy$default(ShareBean shareBean, String str, String str2, String str3, String str4, int i2, Object obj) {
        if ((i2 & 1) != 0) {
            str = shareBean.register_at;
        }
        if ((i2 & 2) != 0) {
            str2 = shareBean.id;
        }
        if ((i2 & 4) != 0) {
            str3 = shareBean.nickname;
        }
        if ((i2 & 8) != 0) {
            str4 = shareBean.img;
        }
        return shareBean.copy(str, str2, str3, str4);
    }

    @NotNull
    /* renamed from: component1, reason: from getter */
    public final String getRegister_at() {
        return this.register_at;
    }

    @NotNull
    /* renamed from: component2, reason: from getter */
    public final String getId() {
        return this.id;
    }

    @NotNull
    /* renamed from: component3, reason: from getter */
    public final String getNickname() {
        return this.nickname;
    }

    @NotNull
    /* renamed from: component4, reason: from getter */
    public final String getImg() {
        return this.img;
    }

    @NotNull
    public final ShareBean copy(@NotNull String register_at, @NotNull String id, @NotNull String nickname, @NotNull String img) {
        Intrinsics.checkNotNullParameter(register_at, "register_at");
        Intrinsics.checkNotNullParameter(id, "id");
        Intrinsics.checkNotNullParameter(nickname, "nickname");
        Intrinsics.checkNotNullParameter(img, "img");
        return new ShareBean(register_at, id, nickname, img);
    }

    public boolean equals(@Nullable Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof ShareBean)) {
            return false;
        }
        ShareBean shareBean = (ShareBean) other;
        return Intrinsics.areEqual(this.register_at, shareBean.register_at) && Intrinsics.areEqual(this.id, shareBean.id) && Intrinsics.areEqual(this.nickname, shareBean.nickname) && Intrinsics.areEqual(this.img, shareBean.img);
    }

    @NotNull
    public final String getId() {
        return this.id;
    }

    @NotNull
    public final String getImg() {
        return this.img;
    }

    @NotNull
    public final String getNickname() {
        return this.nickname;
    }

    @NotNull
    public final String getRegister_at() {
        return this.register_at;
    }

    public int hashCode() {
        return this.img.hashCode() + C1499a.m598T(this.nickname, C1499a.m598T(this.id, this.register_at.hashCode() * 31, 31), 31);
    }

    @NotNull
    public String toString() {
        StringBuilder m586H = C1499a.m586H("ShareBean(register_at=");
        m586H.append(this.register_at);
        m586H.append(", id=");
        m586H.append(this.id);
        m586H.append(", nickname=");
        m586H.append(this.nickname);
        m586H.append(", img=");
        return C1499a.m581C(m586H, this.img, ')');
    }
}
