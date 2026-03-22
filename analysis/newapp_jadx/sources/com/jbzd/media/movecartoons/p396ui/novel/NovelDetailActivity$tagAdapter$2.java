package com.jbzd.media.movecartoons.p396ui.novel;

import android.view.View;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.bean.response.comicsinfo.Tags;
import com.jbzd.media.movecartoons.p396ui.novel.NovelDetailActivity;
import com.jbzd.media.movecartoons.p396ui.novel.NovelDetailActivity$tagAdapter$2;
import com.jbzd.media.movecartoons.p396ui.search.ComicsModuleDetailActivity;
import com.qnmd.adnnm.da0yzo.R;
import java.util.HashMap;
import java.util.Objects;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import org.jetbrains.annotations.NotNull;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d;
import p005b.p199l.p258c.C2480j;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0007\n\u0002\b\u0003*\u0001\u0000\u0010\u0001\u001a\u00020\u0000H\n¢\u0006\u0004\b\u0001\u0010\u0002"}, m5311d2 = {"com/jbzd/media/movecartoons/ui/novel/NovelDetailActivity$tagAdapter$2$1", "<anonymous>", "()Lcom/jbzd/media/movecartoons/ui/novel/NovelDetailActivity$tagAdapter$2$1;"}, m5312k = 3, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class NovelDetailActivity$tagAdapter$2 extends Lambda implements Function0<C38361> {
    public final /* synthetic */ NovelDetailActivity this$0;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public NovelDetailActivity$tagAdapter$2(NovelDetailActivity novelDetailActivity) {
        super(0);
        this.this$0 = novelDetailActivity;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: invoke$lambda-1$lambda-0, reason: not valid java name */
    public static final void m5922invoke$lambda1$lambda0(NovelDetailActivity this$0, BaseQuickAdapter adapter, View view, int i2) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        Object obj = adapter.getData().get(i2);
        Objects.requireNonNull(obj, "null cannot be cast to non-null type com.jbzd.media.movecartoons.bean.response.comicsinfo.Tags");
        Tags tags = (Tags) obj;
        HashMap hashMap = new HashMap();
        String id = tags.getId();
        Intrinsics.checkNotNullExpressionValue(id, "item.id");
        hashMap.put("tag_id", id);
        ComicsModuleDetailActivity.Companion companion = ComicsModuleDetailActivity.INSTANCE;
        String name = tags.getName();
        Intrinsics.checkNotNullExpressionValue(name, "item.name");
        String m2853g = new C2480j().m2853g(hashMap);
        Intrinsics.checkNotNullExpressionValue(m2853g, "Gson().toJson(mapsFilter)");
        companion.start(this$0, name, m2853g, "novel");
    }

    /* JADX WARN: Can't rename method to resolve collision */
    /* JADX WARN: Type inference failed for: r0v0, types: [com.chad.library.adapter.base.BaseQuickAdapter, com.jbzd.media.movecartoons.ui.novel.NovelDetailActivity$tagAdapter$2$1] */
    @Override // kotlin.jvm.functions.Function0
    @NotNull
    public final C38361 invoke() {
        ?? r0 = new BaseQuickAdapter<Tags, BaseViewHolder>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelDetailActivity$tagAdapter$2.1
            @Override // com.chad.library.adapter.base.BaseQuickAdapter
            public void convert(@NotNull BaseViewHolder helper, @NotNull Tags item) {
                Intrinsics.checkNotNullParameter(helper, "helper");
                Intrinsics.checkNotNullParameter(item, "item");
                helper.m3919i(R.id.tv_content, item.getName());
            }
        };
        final NovelDetailActivity novelDetailActivity = this.this$0;
        r0.setOnItemClickListener(new InterfaceC1304d() { // from class: b.a.a.a.t.j.n
            @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d
            public final void onItemClick(BaseQuickAdapter baseQuickAdapter, View view, int i2) {
                NovelDetailActivity$tagAdapter$2.m5922invoke$lambda1$lambda0(NovelDetailActivity.this, baseQuickAdapter, view, i2);
            }
        });
        return r0;
    }
}
