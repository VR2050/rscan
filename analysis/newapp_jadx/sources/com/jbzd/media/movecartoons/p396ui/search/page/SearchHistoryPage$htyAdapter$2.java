package com.jbzd.media.movecartoons.p396ui.search.page;

import android.view.View;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.jbzd.media.movecartoons.p396ui.search.adapter.HtyAdapter;
import com.jbzd.media.movecartoons.p396ui.search.page.SearchHistoryPage;
import com.jbzd.media.movecartoons.p396ui.search.page.SearchHistoryPage$htyAdapter$2;
import com.qnmd.adnnm.da0yzo.R;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import org.jetbrains.annotations.NotNull;
import p005b.p006a.p007a.p008a.p009a.C0841d0;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\b\n\u0002\u0018\u0002\n\u0002\b\u0002\u0010\u0001\u001a\u00020\u0000H\n¢\u0006\u0004\b\u0001\u0010\u0002"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/search/adapter/HtyAdapter;", "<anonymous>", "()Lcom/jbzd/media/movecartoons/ui/search/adapter/HtyAdapter;"}, m5312k = 3, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class SearchHistoryPage$htyAdapter$2 extends Lambda implements Function0<HtyAdapter> {
    public final /* synthetic */ SearchHistoryPage this$0;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public SearchHistoryPage$htyAdapter$2(SearchHistoryPage searchHistoryPage) {
        super(0);
        this.this$0 = searchHistoryPage;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: invoke$lambda-1$lambda-0, reason: not valid java name */
    public static final void m5991invoke$lambda1$lambda0(SearchHistoryPage this$0, BaseQuickAdapter adapter, View view, int i2) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        String valueOf = String.valueOf(adapter.getItem(i2));
        if (C0841d0.m178a(valueOf)) {
            this$0.historyList = C0841d0.m179b();
        }
        this$0.searchData(valueOf);
    }

    /* JADX WARN: Can't rename method to resolve collision */
    @Override // kotlin.jvm.functions.Function0
    @NotNull
    public final HtyAdapter invoke() {
        HtyAdapter htyAdapter = new HtyAdapter(R.layout.item_search_hty, null, 2, null);
        final SearchHistoryPage searchHistoryPage = this.this$0;
        htyAdapter.setOnItemClickListener(new InterfaceC1304d() { // from class: b.a.a.a.t.m.k.e
            @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d
            public final void onItemClick(BaseQuickAdapter baseQuickAdapter, View view, int i2) {
                SearchHistoryPage$htyAdapter$2.m5991invoke$lambda1$lambda0(SearchHistoryPage.this, baseQuickAdapter, view, i2);
            }
        });
        return htyAdapter;
    }
}
