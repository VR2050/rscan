package com.jbzd.media.movecartoons.p396ui.search.page;

import android.content.Context;
import android.view.View;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.jbzd.media.movecartoons.bean.response.HotTagAndCategor;
import com.jbzd.media.movecartoons.p396ui.index.post.block.PostCategoryDetailActivity;
import com.jbzd.media.movecartoons.p396ui.search.adapter.WordsPostAdapter;
import com.jbzd.media.movecartoons.p396ui.search.page.SearchHistoryPage;
import com.jbzd.media.movecartoons.p396ui.search.page.SearchHistoryPage$wordsPostAdapter$2;
import com.qnmd.adnnm.da0yzo.R;
import java.util.Objects;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import org.jetbrains.annotations.NotNull;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\b\n\u0002\u0018\u0002\n\u0002\b\u0002\u0010\u0001\u001a\u00020\u0000H\n¢\u0006\u0004\b\u0001\u0010\u0002"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/search/adapter/WordsPostAdapter;", "<anonymous>", "()Lcom/jbzd/media/movecartoons/ui/search/adapter/WordsPostAdapter;"}, m5312k = 3, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class SearchHistoryPage$wordsPostAdapter$2 extends Lambda implements Function0<WordsPostAdapter> {
    public final /* synthetic */ SearchHistoryPage this$0;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public SearchHistoryPage$wordsPostAdapter$2(SearchHistoryPage searchHistoryPage) {
        super(0);
        this.this$0 = searchHistoryPage;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: invoke$lambda-1$lambda-0, reason: not valid java name */
    public static final void m5993invoke$lambda1$lambda0(SearchHistoryPage this$0, BaseQuickAdapter adapter, View view, int i2) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        Object item = adapter.getItem(i2);
        Objects.requireNonNull(item, "null cannot be cast to non-null type com.jbzd.media.movecartoons.bean.response.HotTagAndCategor");
        HotTagAndCategor hotTagAndCategor = (HotTagAndCategor) item;
        PostCategoryDetailActivity.Companion companion = PostCategoryDetailActivity.INSTANCE;
        Context requireContext = this$0.requireContext();
        Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
        String id = hotTagAndCategor.getId();
        Intrinsics.checkNotNullExpressionValue(id, "item.id");
        String position = hotTagAndCategor.getPosition();
        Intrinsics.checkNotNullExpressionValue(position, "item.position");
        companion.start(requireContext, id, position);
    }

    /* JADX WARN: Can't rename method to resolve collision */
    @Override // kotlin.jvm.functions.Function0
    @NotNull
    public final WordsPostAdapter invoke() {
        WordsPostAdapter wordsPostAdapter = new WordsPostAdapter(R.layout.item_search_popular, null, 2, null);
        final SearchHistoryPage searchHistoryPage = this.this$0;
        wordsPostAdapter.setOnItemClickListener(new InterfaceC1304d() { // from class: b.a.a.a.t.m.k.g
            @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d
            public final void onItemClick(BaseQuickAdapter baseQuickAdapter, View view, int i2) {
                SearchHistoryPage$wordsPostAdapter$2.m5993invoke$lambda1$lambda0(SearchHistoryPage.this, baseQuickAdapter, view, i2);
            }
        });
        return wordsPostAdapter;
    }
}
