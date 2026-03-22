package com.jbzd.media.movecartoons.p396ui.search.page;

import android.view.View;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.jbzd.media.movecartoons.bean.response.HotSearch;
import com.jbzd.media.movecartoons.p396ui.search.adapter.WordsAdapter;
import com.jbzd.media.movecartoons.p396ui.search.page.SearchHistoryPage;
import com.jbzd.media.movecartoons.p396ui.search.page.SearchHistoryPage$wordsAdapter$2;
import com.qnmd.adnnm.da0yzo.R;
import java.util.Objects;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import org.jetbrains.annotations.NotNull;
import p005b.p006a.p007a.p008a.p009a.C0841d0;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\b\n\u0002\u0018\u0002\n\u0002\b\u0002\u0010\u0001\u001a\u00020\u0000H\n¢\u0006\u0004\b\u0001\u0010\u0002"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/search/adapter/WordsAdapter;", "<anonymous>", "()Lcom/jbzd/media/movecartoons/ui/search/adapter/WordsAdapter;"}, m5312k = 3, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class SearchHistoryPage$wordsAdapter$2 extends Lambda implements Function0<WordsAdapter> {
    public final /* synthetic */ SearchHistoryPage this$0;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public SearchHistoryPage$wordsAdapter$2(SearchHistoryPage searchHistoryPage) {
        super(0);
        this.this$0 = searchHistoryPage;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: invoke$lambda-1$lambda-0, reason: not valid java name */
    public static final void m5992invoke$lambda1$lambda0(SearchHistoryPage this$0, BaseQuickAdapter adapter, View view, int i2) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        Object item = adapter.getItem(i2);
        Objects.requireNonNull(item, "null cannot be cast to non-null type com.jbzd.media.movecartoons.bean.response.HotSearch.HotWord");
        HotSearch.HotWord hotWord = (HotSearch.HotWord) item;
        String str = hotWord.name;
        Intrinsics.checkNotNullExpressionValue(str, "item.name");
        if (C0841d0.m178a(str)) {
            this$0.historyList = C0841d0.m179b();
        }
        String str2 = hotWord.name;
        if (str2 == null) {
            str2 = "";
        }
        this$0.searchData(str2);
    }

    /* JADX WARN: Can't rename method to resolve collision */
    @Override // kotlin.jvm.functions.Function0
    @NotNull
    public final WordsAdapter invoke() {
        WordsAdapter wordsAdapter = new WordsAdapter(R.layout.item_search_popular, null, 2, null);
        final SearchHistoryPage searchHistoryPage = this.this$0;
        wordsAdapter.setOnItemClickListener(new InterfaceC1304d() { // from class: b.a.a.a.t.m.k.f
            @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d
            public final void onItemClick(BaseQuickAdapter baseQuickAdapter, View view, int i2) {
                SearchHistoryPage$wordsAdapter$2.m5992invoke$lambda1$lambda0(SearchHistoryPage.this, baseQuickAdapter, view, i2);
            }
        });
        return wordsAdapter;
    }
}
