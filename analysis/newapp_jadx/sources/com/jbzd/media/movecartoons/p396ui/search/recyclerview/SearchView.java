package com.jbzd.media.movecartoons.p396ui.search.recyclerview;

import android.content.Context;
import android.util.AttributeSet;
import android.view.View;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.jbzd.media.movecartoons.p396ui.search.adapter.LibraryAdapter;
import com.jbzd.media.movecartoons.p396ui.search.recyclerview.SearchView;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.utils.GridItemDecoration;
import java.util.Objects;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001e\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\u0018\u00002\u00020\u0001B\u0019\u0012\u0006\u0010\u0006\u001a\u00020\u0005\u0012\b\u0010\b\u001a\u0004\u0018\u00010\u0007¢\u0006\u0004\b\t\u0010\nJ\u000f\u0010\u0003\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0003\u0010\u0004¨\u0006\u000b"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/search/recyclerview/SearchView;", "Landroidx/recyclerview/widget/RecyclerView;", "Lcom/jbzd/media/movecartoons/ui/search/adapter/LibraryAdapter;", "getAdapter", "()Lcom/jbzd/media/movecartoons/ui/search/adapter/LibraryAdapter;", "Landroid/content/Context;", "context", "Landroid/util/AttributeSet;", "attrs", "<init>", "(Landroid/content/Context;Landroid/util/AttributeSet;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class SearchView extends RecyclerView {
    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public SearchView(@NotNull Context context, @Nullable AttributeSet attributeSet) {
        super(context, attributeSet);
        Intrinsics.checkNotNullParameter(context, "context");
        setLayoutManager(new LinearLayoutManager(getContext(), 0, false));
        if (getItemDecorationCount() == 0) {
            GridItemDecoration.C4053a c4053a = new GridItemDecoration.C4053a(context);
            c4053a.m4576a(R.color.transparent);
            c4053a.f10336d = C2354n.m2437V(context, 1.0d);
            c4053a.f10337e = C2354n.m2437V(context, 5.0d);
            c4053a.f10339g = false;
            c4053a.f10340h = false;
            c4053a.f10338f = false;
            addItemDecoration(new GridItemDecoration(c4053a));
        }
        LibraryAdapter libraryAdapter = new LibraryAdapter(R.layout.item_search_checkbox, null, 2, 0 == true ? 1 : 0);
        libraryAdapter.setOnItemClickListener(new InterfaceC1304d() { // from class: b.a.a.a.t.m.l.a
            @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d
            public final void onItemClick(BaseQuickAdapter baseQuickAdapter, View view, int i2) {
                SearchView.m5995lambda1$lambda0(baseQuickAdapter, view, i2);
            }
        });
        Unit unit = Unit.INSTANCE;
        setAdapter(libraryAdapter);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: lambda-1$lambda-0, reason: not valid java name */
    public static final void m5995lambda1$lambda0(BaseQuickAdapter adapter, View view, int i2) {
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        Object item = adapter.getItem(i2);
        Objects.requireNonNull(item, "null cannot be cast to non-null type com.jbzd.media.movecartoons.bean.response.FilterData");
    }

    public void _$_clearFindViewByIdCache() {
    }

    @Override // androidx.recyclerview.widget.RecyclerView
    @NotNull
    public LibraryAdapter getAdapter() {
        RecyclerView.Adapter adapter = super.getAdapter();
        Objects.requireNonNull(adapter, "null cannot be cast to non-null type com.jbzd.media.movecartoons.ui.search.adapter.LibraryAdapter");
        return (LibraryAdapter) adapter;
    }
}
