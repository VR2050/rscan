package com.jbzd.media.movecartoons.p396ui.search.adapter;

import android.R;
import android.widget.CompoundButton;
import androidx.annotation.RequiresApi;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.bean.response.FilterData;
import com.jbzd.media.movecartoons.p396ui.search.adapter.LibraryAdapter;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0010\b\n\u0000\n\u0002\u0010!\n\u0002\b\u0004\u0018\u00002\u000e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00030\u0001B!\u0012\u0006\u0010\u0011\u001a\u00020\u0010\u0012\u0010\b\u0002\u0010\u0013\u001a\n\u0012\u0004\u0012\u00020\u0002\u0018\u00010\u0012¢\u0006\u0004\b\u0014\u0010\u0015J\u001f\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0004\u001a\u00020\u00032\u0006\u0010\u0005\u001a\u00020\u0002H\u0015¢\u0006\u0004\b\u0007\u0010\bR$\u0010\n\u001a\u0004\u0018\u00010\t8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\n\u0010\u000b\u001a\u0004\b\f\u0010\r\"\u0004\b\u000e\u0010\u000f¨\u0006\u0016"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/search/adapter/LibraryAdapter;", "Lcom/chad/library/adapter/base/BaseQuickAdapter;", "Lcom/jbzd/media/movecartoons/bean/response/FilterData;", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "helper", "item", "", "convert", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/FilterData;)V", "Lcom/jbzd/media/movecartoons/ui/search/adapter/CheckChange;", "change", "Lcom/jbzd/media/movecartoons/ui/search/adapter/CheckChange;", "getChange", "()Lcom/jbzd/media/movecartoons/ui/search/adapter/CheckChange;", "setChange", "(Lcom/jbzd/media/movecartoons/ui/search/adapter/CheckChange;)V", "", "layoutResId", "", "data", "<init>", "(ILjava/util/List;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class LibraryAdapter extends BaseQuickAdapter<FilterData, BaseViewHolder> {

    @Nullable
    private CheckChange change;

    public /* synthetic */ LibraryAdapter(int i2, List list, int i3, DefaultConstructorMarker defaultConstructorMarker) {
        this(i2, (i3 & 2) != 0 ? null : list);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: convert$lambda-1$lambda-0, reason: not valid java name */
    public static final void m5983convert$lambda1$lambda0(FilterData item, LibraryAdapter this$0, CompoundButton compoundButton, boolean z) {
        Intrinsics.checkNotNullParameter(item, "$item");
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        item.isSelected = z;
        int itemCount = this$0.getItemCount();
        if (itemCount > 0) {
            int i2 = 0;
            while (true) {
                int i3 = i2 + 1;
                FilterData item2 = this$0.getItem(i2);
                if (!Intrinsics.areEqual(item2, item)) {
                    item2.isSelected = false;
                }
                if (i3 >= itemCount) {
                    break;
                } else {
                    i2 = i3;
                }
            }
        }
        CheckChange change = this$0.getChange();
        if (change != null) {
            change.change(item);
        }
        this$0.notifyDataSetChanged();
    }

    @Nullable
    public final CheckChange getChange() {
        return this.change;
    }

    public final void setChange(@Nullable CheckChange checkChange) {
        this.change = checkChange;
    }

    public LibraryAdapter(int i2, @Nullable List<FilterData> list) {
        super(i2, list);
    }

    @Override // com.chad.library.adapter.base.BaseQuickAdapter
    @RequiresApi(23)
    public void convert(@NotNull BaseViewHolder helper, @NotNull final FilterData item) {
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(item, "item");
        String name = item.getName();
        if (name == null) {
            name = "";
        }
        helper.m3919i(R.id.text1, name);
        CompoundButton compoundButton = (CompoundButton) helper.m3912b(R.id.text1);
        compoundButton.setOnCheckedChangeListener(null);
        compoundButton.setChecked(item.isSelected);
        compoundButton.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() { // from class: b.a.a.a.t.m.i.a
            @Override // android.widget.CompoundButton.OnCheckedChangeListener
            public final void onCheckedChanged(CompoundButton compoundButton2, boolean z) {
                LibraryAdapter.m5983convert$lambda1$lambda0(FilterData.this, this, compoundButton2, z);
            }
        });
    }
}
