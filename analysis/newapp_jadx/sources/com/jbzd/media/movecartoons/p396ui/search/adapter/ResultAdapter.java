package com.jbzd.media.movecartoons.p396ui.search.adapter;

import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.google.android.material.shadow.ShadowDrawableWrapper;
import com.jbzd.media.movecartoons.bean.response.VideoItemBean;
import com.jbzd.media.movecartoons.p396ui.index.home.VideoItemShowKt;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000*\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0000\n\u0002\u0010!\n\u0002\b\u0004\u0018\u00002\u000e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00030\u0001B!\u0012\u0006\u0010\n\u001a\u00020\t\u0012\u0010\b\u0002\u0010\f\u001a\n\u0012\u0004\u0012\u00020\u0002\u0018\u00010\u000b¢\u0006\u0004\b\r\u0010\u000eJ\u001f\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0004\u001a\u00020\u00032\u0006\u0010\u0005\u001a\u00020\u0002H\u0014¢\u0006\u0004\b\u0007\u0010\b¨\u0006\u000f"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/search/adapter/ResultAdapter;", "Lcom/chad/library/adapter/base/BaseQuickAdapter;", "Lcom/jbzd/media/movecartoons/bean/response/VideoItemBean;", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "helper", "item", "", "convert", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/VideoItemBean;)V", "", "layoutResId", "", "data", "<init>", "(ILjava/util/List;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class ResultAdapter extends BaseQuickAdapter<VideoItemBean, BaseViewHolder> {
    public /* synthetic */ ResultAdapter(int i2, List list, int i3, DefaultConstructorMarker defaultConstructorMarker) {
        this(i2, (i3 & 2) != 0 ? null : list);
    }

    public ResultAdapter(int i2, @Nullable List<VideoItemBean> list) {
        super(i2, list);
    }

    @Override // com.chad.library.adapter.base.BaseQuickAdapter
    public void convert(@NotNull BaseViewHolder helper, @NotNull VideoItemBean item) {
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(item, "item");
        VideoItemShowKt.showVideoItemMsg(getContext(), helper, item, (r29 & 8) != 0 ? 1.5d : ShadowDrawableWrapper.COS_45, (r29 & 16) != 0 ? false : true, (r29 & 32) != 0 ? false : false, (r29 & 64) != 0 ? false : false, (r29 & 128) != 0 ? false : false, (r29 & 256) != 0, (r29 & 512) != 0 ? false : false, (r29 & 1024) != 0 ? false : true, (r29 & 2048) != 0 ? false : false);
    }
}
