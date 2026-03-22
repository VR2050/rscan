package com.jbzd.media.movecartoons.core;

import com.chad.library.adapter.base.BaseMultiItemQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import java.util.HashMap;
import java.util.Map;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import p005b.p067b.p068a.p069a.p070a.p074j.InterfaceC1296a;
import p005b.p067b.p068a.p069a.p070a.p078m.InterfaceC1320h;

/* JADX INFO: Add missing generic type declarations: [T] */
@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0013\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000*\u0001\u0000\b\n\u0018\u00002\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00020\u00020\u00012\u00020\u0003¨\u0006\u0004"}, m5311d2 = {"com/jbzd/media/movecartoons/core/BaseMutiListFragment$adapter$2$1", "Lcom/chad/library/adapter/base/BaseMultiItemQuickAdapter;", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "Lb/b/a/a/a/m/h;", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class BaseMutiListFragment$adapter$2$1<T> extends BaseMultiItemQuickAdapter<T, BaseViewHolder> implements InterfaceC1320h {

    /* renamed from: c */
    public final /* synthetic */ BaseMutiListFragment<T> f10041c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public BaseMutiListFragment$adapter$2$1(BaseMutiListFragment<T> baseMutiListFragment) {
        super(null);
        this.f10041c = baseMutiListFragment;
        HashMap<Integer, Integer> allItemType = baseMutiListFragment.getAllItemType();
        if (allItemType == null) {
            return;
        }
        for (Map.Entry<Integer, Integer> entry : allItemType.entrySet()) {
            addItemType(entry.getKey().intValue(), entry.getValue().intValue());
        }
    }

    @Override // com.chad.library.adapter.base.BaseQuickAdapter
    public void convert(BaseViewHolder helper, Object obj) {
        InterfaceC1296a item = (InterfaceC1296a) obj;
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(item, "item");
        this.f10041c.bindItem(helper, item);
    }
}
