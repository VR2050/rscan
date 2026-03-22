package com.jbzd.media.movecartoons.p396ui.dialog;

import android.annotation.SuppressLint;
import android.text.TextUtils;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.qnmd.adnnm.da0yzo.R;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0835a0;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000$\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0007\n\u0002\u0010!\n\u0002\b\u0004\u0018\u00002\u000e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00030\u0001B\u0015\u0012\f\u0010\u000f\u001a\b\u0012\u0004\u0012\u00020\u00020\u000e¢\u0006\u0004\b\u0010\u0010\u0011J\u001f\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0004\u001a\u00020\u00032\u0006\u0010\u0005\u001a\u00020\u0002H\u0014¢\u0006\u0004\b\u0007\u0010\bJ\u0019\u0010\n\u001a\u00020\u00062\b\u0010\t\u001a\u0004\u0018\u00010\u0002H\u0007¢\u0006\u0004\b\n\u0010\u000bR\u0018\u0010\f\u001a\u0004\u0018\u00010\u00028\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\f\u0010\r¨\u0006\u0012"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/OrderAdapter;", "Lcom/chad/library/adapter/base/BaseQuickAdapter;", "Lb/a/a/a/a/a0;", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "helper", "item", "", "convert", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lb/a/a/a/a/a0;)V", "curOrderBy", "updateCur", "(Lb/a/a/a/a/a0;)V", "mCurOrderBy", "Lb/a/a/a/a/a0;", "", "data", "<init>", "(Ljava/util/List;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class OrderAdapter extends BaseQuickAdapter<C0835a0, BaseViewHolder> {

    @Nullable
    private C0835a0 mCurOrderBy;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public OrderAdapter(@NotNull List<C0835a0> data) {
        super(R.layout.item_pop_order_by, data);
        Intrinsics.checkNotNullParameter(data, "data");
    }

    @Override // com.chad.library.adapter.base.BaseQuickAdapter
    public void convert(@NotNull BaseViewHolder helper, @NotNull C0835a0 item) {
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(item, "item");
        String str = item.f223b;
        if (str == null) {
            str = "";
        }
        helper.m3919i(R.id.text, str);
        String str2 = item.f222a;
        C0835a0 c0835a0 = this.mCurOrderBy;
        if (TextUtils.equals(str2, c0835a0 == null ? null : c0835a0.f222a)) {
            helper.m3921k(R.id.text, R.color.main_ff9d00);
        } else {
            helper.m3921k(R.id.text, R.color.white);
        }
    }

    @SuppressLint({"NotifyDataSetChanged"})
    public final void updateCur(@Nullable C0835a0 curOrderBy) {
        this.mCurOrderBy = curOrderBy;
        notifyDataSetChanged();
    }
}
