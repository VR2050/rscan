package com.jbzd.media.movecartoons.bean.response;

import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000,\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0010\u000b\n\u0002\b\b\b\u0086\b\u0018\u00002\u00020\u0001B#\u0012\f\u0010\u0007\u001a\b\u0012\u0004\u0012\u00020\u00030\u0002\u0012\f\u0010\b\u001a\b\u0012\u0004\u0012\u00020\u00030\u0002¢\u0006\u0004\b\u0018\u0010\u0019J\u0016\u0010\u0004\u001a\b\u0012\u0004\u0012\u00020\u00030\u0002HÆ\u0003¢\u0006\u0004\b\u0004\u0010\u0005J\u0016\u0010\u0006\u001a\b\u0012\u0004\u0012\u00020\u00030\u0002HÆ\u0003¢\u0006\u0004\b\u0006\u0010\u0005J0\u0010\t\u001a\u00020\u00002\u000e\b\u0002\u0010\u0007\u001a\b\u0012\u0004\u0012\u00020\u00030\u00022\u000e\b\u0002\u0010\b\u001a\b\u0012\u0004\u0012\u00020\u00030\u0002HÆ\u0001¢\u0006\u0004\b\t\u0010\nJ\u0010\u0010\f\u001a\u00020\u000bHÖ\u0001¢\u0006\u0004\b\f\u0010\rJ\u0010\u0010\u000f\u001a\u00020\u000eHÖ\u0001¢\u0006\u0004\b\u000f\u0010\u0010J\u001a\u0010\u0013\u001a\u00020\u00122\b\u0010\u0011\u001a\u0004\u0018\u00010\u0001HÖ\u0003¢\u0006\u0004\b\u0013\u0010\u0014R\u001f\u0010\u0007\u001a\b\u0012\u0004\u0012\u00020\u00030\u00028\u0006@\u0006¢\u0006\f\n\u0004\b\u0007\u0010\u0015\u001a\u0004\b\u0016\u0010\u0005R\u001f\u0010\b\u001a\b\u0012\u0004\u0012\u00020\u00030\u00028\u0006@\u0006¢\u0006\f\n\u0004\b\b\u0010\u0015\u001a\u0004\b\u0017\u0010\u0005¨\u0006\u001a"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/bean/response/FollowBean;", "", "", "Lcom/jbzd/media/movecartoons/bean/response/FollowItem;", "component1", "()Ljava/util/List;", "component2", "follows", "recommended", "copy", "(Ljava/util/List;Ljava/util/List;)Lcom/jbzd/media/movecartoons/bean/response/FollowBean;", "", "toString", "()Ljava/lang/String;", "", "hashCode", "()I", "other", "", "equals", "(Ljava/lang/Object;)Z", "Ljava/util/List;", "getFollows", "getRecommended", "<init>", "(Ljava/util/List;Ljava/util/List;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final /* data */ class FollowBean {

    @NotNull
    private final List<FollowItem> follows;

    @NotNull
    private final List<FollowItem> recommended;

    public FollowBean(@NotNull List<FollowItem> follows, @NotNull List<FollowItem> recommended) {
        Intrinsics.checkNotNullParameter(follows, "follows");
        Intrinsics.checkNotNullParameter(recommended, "recommended");
        this.follows = follows;
        this.recommended = recommended;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static /* synthetic */ FollowBean copy$default(FollowBean followBean, List list, List list2, int i2, Object obj) {
        if ((i2 & 1) != 0) {
            list = followBean.follows;
        }
        if ((i2 & 2) != 0) {
            list2 = followBean.recommended;
        }
        return followBean.copy(list, list2);
    }

    @NotNull
    public final List<FollowItem> component1() {
        return this.follows;
    }

    @NotNull
    public final List<FollowItem> component2() {
        return this.recommended;
    }

    @NotNull
    public final FollowBean copy(@NotNull List<FollowItem> follows, @NotNull List<FollowItem> recommended) {
        Intrinsics.checkNotNullParameter(follows, "follows");
        Intrinsics.checkNotNullParameter(recommended, "recommended");
        return new FollowBean(follows, recommended);
    }

    public boolean equals(@Nullable Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof FollowBean)) {
            return false;
        }
        FollowBean followBean = (FollowBean) other;
        return Intrinsics.areEqual(this.follows, followBean.follows) && Intrinsics.areEqual(this.recommended, followBean.recommended);
    }

    @NotNull
    public final List<FollowItem> getFollows() {
        return this.follows;
    }

    @NotNull
    public final List<FollowItem> getRecommended() {
        return this.recommended;
    }

    public int hashCode() {
        return this.recommended.hashCode() + (this.follows.hashCode() * 31);
    }

    @NotNull
    public String toString() {
        StringBuilder m586H = C1499a.m586H("FollowBean(follows=");
        m586H.append(this.follows);
        m586H.append(", recommended=");
        m586H.append(this.recommended);
        m586H.append(')');
        return m586H.toString();
    }
}
