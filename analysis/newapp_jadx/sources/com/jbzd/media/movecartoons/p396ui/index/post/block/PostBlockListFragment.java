package com.jbzd.media.movecartoons.p396ui.index.post.block;

import android.content.Context;
import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.annotation.RequiresApi;
import androidx.core.app.NotificationCompat;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.bean.response.PostBlockListBean;
import com.jbzd.media.movecartoons.core.BaseListFragment;
import com.jbzd.media.movecartoons.p396ui.index.post.block.PostBlockListFragment;
import com.jbzd.media.movecartoons.p396ui.index.post.block.PostCategoryDetailActivity;
import com.qnmd.adnnm.da0yzo.R;
import java.util.HashMap;
import java.util.List;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0843e0;
import p005b.p006a.p007a.p008a.p009a.C0859m0;
import p005b.p006a.p007a.p008a.p017r.C0917a;
import p005b.p067b.p068a.p069a.p070a.p078m.C1318f;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.InterfaceC3053d1;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000H\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0005\u0018\u0000  2\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0001 B\u0007¢\u0006\u0004\b\u001f\u0010\u0014J\u0017\u0010\u0006\u001a\u00020\u00052\u0006\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u0006\u0010\u0007J\u000f\u0010\t\u001a\u00020\bH\u0016¢\u0006\u0004\b\t\u0010\nJ\u000f\u0010\f\u001a\u00020\u000bH\u0016¢\u0006\u0004\b\f\u0010\rJ\u001f\u0010\u0011\u001a\u00020\u00052\u0006\u0010\u000f\u001a\u00020\u000e2\u0006\u0010\u0010\u001a\u00020\u0002H\u0017¢\u0006\u0004\b\u0011\u0010\u0012J\u000f\u0010\u0013\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\u0013\u0010\u0014J3\u0010\u001a\u001a\u00020\u00052\u0012\u0010\u0016\u001a\u000e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u000e0\u00152\u0006\u0010\u0018\u001a\u00020\u00172\u0006\u0010\u0019\u001a\u00020\u000bH\u0016¢\u0006\u0004\b\u001a\u0010\u001bJ\u000f\u0010\u001d\u001a\u00020\u001cH\u0016¢\u0006\u0004\b\u001d\u0010\u001e¨\u0006!"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/post/block/PostBlockListFragment;", "Lcom/jbzd/media/movecartoons/core/BaseListFragment;", "Lcom/jbzd/media/movecartoons/bean/response/PostBlockListBean$CategoriesBean;", "", "object_id", "", "followBlock", "(Ljava/lang/String;)V", "Landroidx/recyclerview/widget/RecyclerView$LayoutManager;", "getLayoutManager", "()Landroidx/recyclerview/widget/RecyclerView$LayoutManager;", "", "getItemLayoutId", "()I", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "helper", "item", "bindItem", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/PostBlockListBean$CategoriesBean;)V", "registerItemChildEvent", "()V", "Lcom/chad/library/adapter/base/BaseQuickAdapter;", "adapter", "Landroid/view/View;", "view", "position", "onItemChildClick", "(Lcom/chad/library/adapter/base/BaseQuickAdapter;Landroid/view/View;I)V", "Lc/a/d1;", "request", "()Lc/a/d1;", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class PostBlockListFragment extends BaseListFragment<PostBlockListBean.CategoriesBean> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);
    public static Function1<? super List<? extends PostBlockListBean.CategoriesBean>, Unit> callBack;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000*\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u000b\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0013\u0010\u0014J6\u0010\u000b\u001a\u00020\n2'\u0010\t\u001a#\u0012\u0019\u0012\u0017\u0012\u0004\u0012\u00020\u00040\u0003¢\u0006\f\b\u0005\u0012\b\b\u0006\u0012\u0004\b\b(\u0007\u0012\u0004\u0012\u00020\b0\u0002¢\u0006\u0004\b\u000b\u0010\fRC\u0010\r\u001a#\u0012\u0019\u0012\u0017\u0012\u0004\u0012\u00020\u00040\u0003¢\u0006\f\b\u0005\u0012\b\b\u0006\u0012\u0004\b\b(\u0007\u0012\u0004\u0012\u00020\b0\u00028\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\b\r\u0010\u000e\u001a\u0004\b\u000f\u0010\u0010\"\u0004\b\u0011\u0010\u0012¨\u0006\u0015"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/post/block/PostBlockListFragment$Companion;", "", "Lkotlin/Function1;", "", "Lcom/jbzd/media/movecartoons/bean/response/PostBlockListBean$CategoriesBean;", "Lkotlin/ParameterName;", "name", "banner", "", NotificationCompat.CATEGORY_CALL, "Lcom/jbzd/media/movecartoons/ui/index/post/block/PostBlockListFragment;", "newInstance", "(Lkotlin/jvm/functions/Function1;)Lcom/jbzd/media/movecartoons/ui/index/post/block/PostBlockListFragment;", "callBack", "Lkotlin/jvm/functions/Function1;", "getCallBack", "()Lkotlin/jvm/functions/Function1;", "setCallBack", "(Lkotlin/jvm/functions/Function1;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final Function1<List<? extends PostBlockListBean.CategoriesBean>, Unit> getCallBack() {
            Function1 function1 = PostBlockListFragment.callBack;
            if (function1 != null) {
                return function1;
            }
            Intrinsics.throwUninitializedPropertyAccessException("callBack");
            throw null;
        }

        @NotNull
        public final PostBlockListFragment newInstance(@NotNull Function1<? super List<? extends PostBlockListBean.CategoriesBean>, Unit> call) {
            Intrinsics.checkNotNullParameter(call, "call");
            PostBlockListFragment postBlockListFragment = new PostBlockListFragment();
            PostBlockListFragment.INSTANCE.setCallBack(call);
            return postBlockListFragment;
        }

        public final void setCallBack(@NotNull Function1<? super List<? extends PostBlockListBean.CategoriesBean>, Unit> function1) {
            Intrinsics.checkNotNullParameter(function1, "<set-?>");
            PostBlockListFragment.callBack = function1;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindItem$lambda-2$lambda-1$lambda-0, reason: not valid java name */
    public static final void m5843bindItem$lambda2$lambda1$lambda0(PostBlockListBean.CategoriesBean item, BaseViewHolder this_run, PostBlockListFragment this$0, View view) {
        Intrinsics.checkNotNullParameter(item, "$item");
        Intrinsics.checkNotNullParameter(this_run, "$this_run");
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        if (Intrinsics.areEqual(item.getHas_follow(), "y")) {
            item.setHas_follow("n");
        } else {
            item.setHas_follow("y");
        }
        ((TextView) this_run.m3912b(R.id.itv_postuser_follow)).setSelected(Intrinsics.areEqual(item.getHas_follow(), "y"));
        this$0.getAdapter().notifyItemChanged(this_run.getAdapterPosition());
        String id = item.getId();
        Intrinsics.checkNotNullExpressionValue(id, "item.id");
        this$0.followBlock(id);
    }

    private final void followBlock(String object_id) {
        C0917a.m221e(C0917a.f372a, "system/doFollow", String.class, C1499a.m596R("object_id", object_id, "object_type", "category"), new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.post.block.PostBlockListFragment$followBlock$2
            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(String str) {
                invoke2(str);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable String str) {
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.post.block.PostBlockListFragment$followBlock$3
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                invoke2(exc);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Exception it) {
                Intrinsics.checkNotNullParameter(it, "it");
                PostBlockListFragment.this.didRequestError();
            }
        }, false, false, null, false, 480);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment, com.jbzd.media.movecartoons.core.MyThemeFragment, com.qunidayede.supportlibrary.core.view.BaseThemeFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public int getItemLayoutId() {
        return R.layout.item_postblock;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @NotNull
    public RecyclerView.LayoutManager getLayoutManager() {
        return new GridLayoutManager(requireContext(), 1);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public void onItemChildClick(@NotNull BaseQuickAdapter<PostBlockListBean.CategoriesBean, BaseViewHolder> adapter, @NotNull View view, int position) {
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        super.onItemChildClick(adapter, view, position);
        PostBlockListBean.CategoriesBean item = adapter.getItem(position);
        PostCategoryDetailActivity.Companion companion = PostCategoryDetailActivity.INSTANCE;
        Context requireContext = requireContext();
        Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
        String id = item.getId();
        Intrinsics.checkNotNullExpressionValue(id, "item.id");
        String position2 = item.getPosition();
        Intrinsics.checkNotNullExpressionValue(position2, "item.position");
        companion.start(requireContext, id, position2);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public void registerItemChildEvent() {
        registerItemChildClick(R.id.ll_postblock);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @NotNull
    public InterfaceC3053d1 request() {
        C0917a c0917a = C0917a.f372a;
        HashMap m595Q = C1499a.m595Q("page_size", "10");
        m595Q.put("id", ModulePostBlockActivity.INSTANCE.getBlock_id());
        Unit unit = Unit.INSTANCE;
        return C0917a.m221e(c0917a, "post/block", PostBlockListBean.class, m595Q, new Function1<PostBlockListBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.post.block.PostBlockListFragment$request$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(PostBlockListBean postBlockListBean) {
                invoke2(postBlockListBean);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable PostBlockListBean postBlockListBean) {
                if (postBlockListBean != null) {
                    C1318f loadMoreModule = PostBlockListFragment.this.getAdapter().getLoadMoreModule();
                    if (loadMoreModule != null) {
                        loadMoreModule.f1059h = false;
                    }
                    C1318f loadMoreModule2 = PostBlockListFragment.this.getAdapter().getLoadMoreModule();
                    if (loadMoreModule2 != null) {
                        loadMoreModule2.m334k(false);
                    }
                    PostBlockListFragment.this.didRequestComplete(postBlockListBean.getCategories());
                    C1318f loadMoreModule3 = PostBlockListFragment.this.getAdapter().getLoadMoreModule();
                    if (loadMoreModule3 != null) {
                        loadMoreModule3.m330f();
                    }
                    C1318f loadMoreModule4 = PostBlockListFragment.this.getAdapter().getLoadMoreModule();
                    if (loadMoreModule4 == null) {
                        return;
                    }
                    loadMoreModule4.m331g(true);
                }
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.post.block.PostBlockListFragment$request$3
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                invoke2(exc);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Exception it) {
                Intrinsics.checkNotNullParameter(it, "it");
                PostBlockListFragment.this.didRequestError();
            }
        }, false, false, null, false, 480);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @RequiresApi(23)
    public void bindItem(@NotNull final BaseViewHolder helper, @NotNull final PostBlockListBean.CategoriesBean item) {
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(item, "item");
        C2354n.m2455a2(requireContext()).m3298p(item.getImg()).m3295i0().m757R((ImageView) helper.m3912b(R.id.iv_postblock));
        View view = helper.m3912b(R.id.iv_postblock);
        Intrinsics.checkNotNullParameter(view, "view");
        view.setOutlineProvider(new C0859m0(5.0d));
        view.setClipToOutline(true);
        String name = item.getName();
        if (name == null) {
            name = "";
        }
        helper.m3919i(R.id.tv_postblock_name, name);
        helper.m3919i(R.id.tv_postblock_follow, Intrinsics.stringPlus(item.getFollow(), "关注"));
        helper.m3919i(R.id.tv_postblock_click, Intrinsics.stringPlus(C0843e0.m182a(item.getPost_click()), "浏览"));
        TextView textView = (TextView) helper.m3912b(R.id.itv_postuser_follow);
        helper.m3919i(R.id.itv_postuser_follow, Intrinsics.areEqual(item.getHas_follow(), "y") ? "已关注" : "+关注");
        ((TextView) helper.m3912b(R.id.itv_postuser_follow)).setSelected(Intrinsics.areEqual(item.getHas_follow(), "y"));
        helper.m3920j(R.id.itv_postuser_follow, Intrinsics.areEqual(item.getHas_follow(), "y") ? requireContext().getColor(R.color.black40) : requireContext().getColor(R.color.black));
        textView.setOnClickListener(new View.OnClickListener() { // from class: b.a.a.a.t.g.l.g.a
            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                PostBlockListFragment.m5843bindItem$lambda2$lambda1$lambda0(PostBlockListBean.CategoriesBean.this, helper, this, view2);
            }
        });
    }
}
