package com.jbzd.media.movecartoons.bean.event;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000 \n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0002\b\b\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0010\u000b\n\u0002\b\u0007\b\u0086\b\u0018\u00002\u00020\u0001B\u0017\u0012\u0006\u0010\u0006\u001a\u00020\u0002\u0012\u0006\u0010\u0007\u001a\u00020\u0002¢\u0006\u0004\b\u0014\u0010\u0015J\u0010\u0010\u0003\u001a\u00020\u0002HÆ\u0003¢\u0006\u0004\b\u0003\u0010\u0004J\u0010\u0010\u0005\u001a\u00020\u0002HÆ\u0003¢\u0006\u0004\b\u0005\u0010\u0004J$\u0010\b\u001a\u00020\u00002\b\b\u0002\u0010\u0006\u001a\u00020\u00022\b\b\u0002\u0010\u0007\u001a\u00020\u0002HÆ\u0001¢\u0006\u0004\b\b\u0010\tJ\u0010\u0010\n\u001a\u00020\u0002HÖ\u0001¢\u0006\u0004\b\n\u0010\u0004J\u0010\u0010\f\u001a\u00020\u000bHÖ\u0001¢\u0006\u0004\b\f\u0010\rJ\u001a\u0010\u0010\u001a\u00020\u000f2\b\u0010\u000e\u001a\u0004\u0018\u00010\u0001HÖ\u0003¢\u0006\u0004\b\u0010\u0010\u0011R\u0019\u0010\u0006\u001a\u00020\u00028\u0006@\u0006¢\u0006\f\n\u0004\b\u0006\u0010\u0012\u001a\u0004\b\u0013\u0010\u0004R\u0019\u0010\u0007\u001a\u00020\u00028\u0006@\u0006¢\u0006\f\n\u0004\b\u0007\u0010\u0012\u001a\u0004\b\u0007\u0010\u0004¨\u0006\u0016"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/bean/event/EventFollowBlock;", "", "", "component1", "()Ljava/lang/String;", "component2", "blockId", "isFollow", "copy", "(Ljava/lang/String;Ljava/lang/String;)Lcom/jbzd/media/movecartoons/bean/event/EventFollowBlock;", "toString", "", "hashCode", "()I", "other", "", "equals", "(Ljava/lang/Object;)Z", "Ljava/lang/String;", "getBlockId", "<init>", "(Ljava/lang/String;Ljava/lang/String;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final /* data */ class EventFollowBlock {

    @NotNull
    private final String blockId;

    @NotNull
    private final String isFollow;

    public EventFollowBlock(@NotNull String blockId, @NotNull String isFollow) {
        Intrinsics.checkNotNullParameter(blockId, "blockId");
        Intrinsics.checkNotNullParameter(isFollow, "isFollow");
        this.blockId = blockId;
        this.isFollow = isFollow;
    }

    public static /* synthetic */ EventFollowBlock copy$default(EventFollowBlock eventFollowBlock, String str, String str2, int i2, Object obj) {
        if ((i2 & 1) != 0) {
            str = eventFollowBlock.blockId;
        }
        if ((i2 & 2) != 0) {
            str2 = eventFollowBlock.isFollow;
        }
        return eventFollowBlock.copy(str, str2);
    }

    @NotNull
    /* renamed from: component1, reason: from getter */
    public final String getBlockId() {
        return this.blockId;
    }

    @NotNull
    /* renamed from: component2, reason: from getter */
    public final String getIsFollow() {
        return this.isFollow;
    }

    @NotNull
    public final EventFollowBlock copy(@NotNull String blockId, @NotNull String isFollow) {
        Intrinsics.checkNotNullParameter(blockId, "blockId");
        Intrinsics.checkNotNullParameter(isFollow, "isFollow");
        return new EventFollowBlock(blockId, isFollow);
    }

    public boolean equals(@Nullable Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof EventFollowBlock)) {
            return false;
        }
        EventFollowBlock eventFollowBlock = (EventFollowBlock) other;
        return Intrinsics.areEqual(this.blockId, eventFollowBlock.blockId) && Intrinsics.areEqual(this.isFollow, eventFollowBlock.isFollow);
    }

    @NotNull
    public final String getBlockId() {
        return this.blockId;
    }

    public int hashCode() {
        return this.isFollow.hashCode() + (this.blockId.hashCode() * 31);
    }

    @NotNull
    public final String isFollow() {
        return this.isFollow;
    }

    @NotNull
    public String toString() {
        StringBuilder m586H = C1499a.m586H("EventFollowBlock(blockId=");
        m586H.append(this.blockId);
        m586H.append(", isFollow=");
        return C1499a.m581C(m586H, this.isFollow, ')');
    }
}
