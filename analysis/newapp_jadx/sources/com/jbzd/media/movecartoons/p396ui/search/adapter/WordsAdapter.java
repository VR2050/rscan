package com.jbzd.media.movecartoons.p396ui.search.adapter;

import android.widget.TextView;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.bean.response.HotSearch;
import com.qnmd.adnnm.da0yzo.R;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000*\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0000\n\u0002\u0010!\n\u0002\b\u0004\u0018\u00002\u000e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00030\u0001B!\u0012\u0006\u0010\n\u001a\u00020\t\u0012\u0010\b\u0002\u0010\f\u001a\n\u0012\u0004\u0012\u00020\u0002\u0018\u00010\u000b¢\u0006\u0004\b\r\u0010\u000eJ\u001f\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0004\u001a\u00020\u00032\u0006\u0010\u0005\u001a\u00020\u0002H\u0014¢\u0006\u0004\b\u0007\u0010\b¨\u0006\u000f"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/search/adapter/WordsAdapter;", "Lcom/chad/library/adapter/base/BaseQuickAdapter;", "Lcom/jbzd/media/movecartoons/bean/response/HotSearch$HotWord;", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "helper", "item", "", "convert", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/HotSearch$HotWord;)V", "", "layoutResId", "", "data", "<init>", "(ILjava/util/List;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class WordsAdapter extends BaseQuickAdapter<HotSearch.HotWord, BaseViewHolder> {
    public /* synthetic */ WordsAdapter(int i2, List list, int i3, DefaultConstructorMarker defaultConstructorMarker) {
        this(i2, (i3 & 2) != 0 ? null : list);
    }

    public WordsAdapter(int i2, @Nullable List<HotSearch.HotWord> list) {
        super(i2, list);
    }

    @Override // com.chad.library.adapter.base.BaseQuickAdapter
    public void convert(@NotNull BaseViewHolder helper, @NotNull HotSearch.HotWord item) {
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(item, "item");
        String str = item.name;
        if (str == null) {
            str = "";
        }
        helper.m3919i(R.id.tv_content, str);
        int itemPosition = getItemPosition(item);
        helper.m3919i(R.id.tv_index, String.valueOf(itemPosition + 1));
        TextView textView = (TextView) helper.m3912b(R.id.tv_index);
        if (itemPosition == 0) {
            textView.setBackgroundResource(R.drawable.bg_popular_index1);
            return;
        }
        if (itemPosition == 1) {
            textView.setBackgroundResource(R.drawable.bg_popular_index2);
        } else if (itemPosition != 2) {
            textView.setBackgroundResource(R.drawable.bg_popular_index);
        } else {
            textView.setBackgroundResource(R.drawable.bg_popular_index3);
        }
    }
}
