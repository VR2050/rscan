package com.jbzd.media.movecartoons.p396ui.download;

import androidx.recyclerview.widget.DiffUtil;
import com.jbzd.media.movecartoons.bean.response.DownloadListBean;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0018\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0002\b\u0006\u0018\u00002\b\u0012\u0004\u0012\u00020\u00020\u0001B\u0007¢\u0006\u0004\b\t\u0010\nJ\u001f\u0010\u0006\u001a\u00020\u00052\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0004\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0006\u0010\u0007J\u001f\u0010\b\u001a\u00020\u00052\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0004\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\b\u0010\u0007¨\u0006\u000b"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/download/DownloadAdapterCall;", "Landroidx/recyclerview/widget/DiffUtil$ItemCallback;", "Lcom/jbzd/media/movecartoons/bean/response/DownloadListBean;", "oldItem", "newItem", "", "areItemsTheSame", "(Lcom/jbzd/media/movecartoons/bean/response/DownloadListBean;Lcom/jbzd/media/movecartoons/bean/response/DownloadListBean;)Z", "areContentsTheSame", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class DownloadAdapterCall extends DiffUtil.ItemCallback<DownloadListBean> {
    @Override // androidx.recyclerview.widget.DiffUtil.ItemCallback
    public boolean areContentsTheSame(@NotNull DownloadListBean oldItem, @NotNull DownloadListBean newItem) {
        Intrinsics.checkNotNullParameter(oldItem, "oldItem");
        Intrinsics.checkNotNullParameter(newItem, "newItem");
        return oldItem.downloadTotal == newItem.downloadTotal && oldItem.isSelect == newItem.isSelect;
    }

    @Override // androidx.recyclerview.widget.DiffUtil.ItemCallback
    public boolean areItemsTheSame(@NotNull DownloadListBean oldItem, @NotNull DownloadListBean newItem) {
        Intrinsics.checkNotNullParameter(oldItem, "oldItem");
        Intrinsics.checkNotNullParameter(newItem, "newItem");
        return Intrinsics.areEqual(oldItem.f9946id, newItem.f9946id);
    }
}
