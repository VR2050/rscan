package com.jbzd.media.movecartoons.p396ui.index.show;

import android.annotation.SuppressLint;
import android.widget.LinearLayout;
import android.widget.TextView;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.bean.response.tag.TagBean;
import com.qnmd.adnnm.da0yzo.R;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000%\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\b*\u0001\u0000\b\n\u0018\u00002\u000e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00030\u0001J\u001f\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0004\u001a\u00020\u00032\u0006\u0010\u0005\u001a\u00020\u0002H\u0014¢\u0006\u0004\b\u0007\u0010\bJ\u0017\u0010\u000b\u001a\u00020\u00062\u0006\u0010\n\u001a\u00020\tH\u0007¢\u0006\u0004\b\u000b\u0010\fJ\r\u0010\r\u001a\u00020\t¢\u0006\u0004\b\r\u0010\u000eR\u0016\u0010\u000f\u001a\u00020\t8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u000f\u0010\u0010¨\u0006\u0011"}, m5311d2 = {"com/jbzd/media/movecartoons/ui/index/show/ShowTabFragment$mFilterAdapter$1", "Lcom/chad/library/adapter/base/BaseQuickAdapter;", "Lcom/jbzd/media/movecartoons/bean/response/tag/TagBean;", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "helper", "item", "", "convert", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/tag/TagBean;)V", "", "position", "setSelectedPosition", "(I)V", "getSelectedPosition", "()I", "selectedPosition", "I", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class ShowTabFragment$mFilterAdapter$1 extends BaseQuickAdapter<TagBean, BaseViewHolder> {
    private int selectedPosition;

    public ShowTabFragment$mFilterAdapter$1() {
        super(R.layout.item_show_flavor_hor, null, 2, null);
    }

    public final int getSelectedPosition() {
        return this.selectedPosition;
    }

    @SuppressLint({"NotifyDataSetChanged"})
    public final void setSelectedPosition(int position) {
        if (this.selectedPosition == position) {
            position = 0;
        }
        this.selectedPosition = position;
        notifyDataSetChanged();
    }

    @Override // com.chad.library.adapter.base.BaseQuickAdapter
    public void convert(@NotNull BaseViewHolder helper, @NotNull TagBean item) {
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(item, "item");
        String str = item.name;
        if (str == null) {
            str = "";
        }
        helper.m3919i(R.id.tv_name, Intrinsics.stringPlus("X", str));
        ((TextView) helper.m3912b(R.id.tv_name)).setSelected(this.selectedPosition == helper.getLayoutPosition());
        ((LinearLayout) helper.m3912b(R.id.ll_parent)).setSelected(this.selectedPosition == helper.getLayoutPosition());
    }
}
