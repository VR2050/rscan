package com.jbzd.media.movecartoons.core;

import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p005b.p067b.p068a.p069a.p070a.p078m.InterfaceC1320h;

/* JADX INFO: Add missing generic type declarations: [T] */
@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000)\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010 \n\u0002\u0010\u0000\n\u0002\b\u0003*\u0001\u0000\b\n\u0018\u00002\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00020\u00020\u00012\u00020\u0003J\u001f\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0004\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00028\u0000H\u0014¢\u0006\u0004\b\u0007\u0010\bJ-\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0004\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00028\u00002\f\u0010\u000b\u001a\b\u0012\u0004\u0012\u00020\n0\tH\u0014¢\u0006\u0004\b\u0007\u0010\f¨\u0006\r"}, m5311d2 = {"com/jbzd/media/movecartoons/core/BaseListFragment$adapter$2$1", "Lcom/chad/library/adapter/base/BaseQuickAdapter;", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "Lb/b/a/a/a/m/h;", "helper", "item", "", "convert", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Ljava/lang/Object;)V", "", "", "payloads", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Ljava/lang/Object;Ljava/util/List;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class BaseListFragment$adapter$2$1<T> extends BaseQuickAdapter<T, BaseViewHolder> implements InterfaceC1320h {

    /* renamed from: c */
    public final /* synthetic */ BaseListFragment<T> f10035c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public BaseListFragment$adapter$2$1(BaseListFragment<T> baseListFragment, int i2) {
        super(i2, null, 2, null);
        this.f10035c = baseListFragment;
    }

    @Override // com.chad.library.adapter.base.BaseQuickAdapter
    public void convert(@NotNull BaseViewHolder helper, T item) {
        Intrinsics.checkNotNullParameter(helper, "helper");
        this.f10035c.bindItem(helper, item);
    }

    @Override // com.chad.library.adapter.base.BaseQuickAdapter
    public void convert(@NotNull BaseViewHolder helper, T item, @NotNull List<? extends Object> payloads) {
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(payloads, "payloads");
        this.f10035c.bindConvert(helper, item, payloads);
    }
}
