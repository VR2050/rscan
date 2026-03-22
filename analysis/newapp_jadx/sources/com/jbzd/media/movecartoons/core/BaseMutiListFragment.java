package com.jbzd.media.movecartoons.core;

import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import androidx.core.content.ContextCompat;
import androidx.exifinterface.media.ExifInterface;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout;
import com.chad.library.adapter.base.BaseMultiItemQuickAdapter;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.R$id;
import com.jbzd.media.movecartoons.core.BaseMutiListFragment;
import com.qnmd.adnnm.da0yzo.R;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p067b.p068a.p069a.p070a.p074j.InterfaceC1296a;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1302b;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1303c;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1306f;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1308h;
import p005b.p067b.p068a.p069a.p070a.p078m.C1318f;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.InterfaceC3053d1;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u008c\u0001\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010\u000b\n\u0002\b\u0003\n\u0002\u0010\u0015\n\u0002\b\t\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010 \n\u0002\b\t\n\u0002\u0010\u000e\n\u0002\b\u001b\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0006\b&\u0018\u0000*\b\b\u0000\u0010\u0002*\u00020\u00012\n\u0012\u0006\u0012\u0004\u0018\u00010\u00040\u0003B\u0007¢\u0006\u0004\bb\u0010\nJ\u000f\u0010\u0006\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\u0006\u0010\u0007J\u000f\u0010\t\u001a\u00020\bH\u0016¢\u0006\u0004\b\t\u0010\nJ\u000f\u0010\f\u001a\u00020\u000bH\u0016¢\u0006\u0004\b\f\u0010\rJ\u0011\u0010\u000f\u001a\u0004\u0018\u00010\u000eH\u0016¢\u0006\u0004\b\u000f\u0010\u0010J\u001f\u0010\u0014\u001a\u00020\b2\u0006\u0010\u0012\u001a\u00020\u00112\u0006\u0010\u0013\u001a\u00028\u0000H&¢\u0006\u0004\b\u0014\u0010\u0015J/\u0010\u0018\u001a\"\u0012\u0004\u0012\u00020\u0005\u0012\u0004\u0012\u00020\u0005\u0018\u00010\u0016j\u0010\u0012\u0004\u0012\u00020\u0005\u0012\u0004\u0012\u00020\u0005\u0018\u0001`\u0017H&¢\u0006\u0004\b\u0018\u0010\u0019J3\u0010\u001f\u001a\u00020\b2\u0012\u0010\u001b\u001a\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00020\u00110\u001a2\u0006\u0010\u001d\u001a\u00020\u001c2\u0006\u0010\u001e\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\u001f\u0010 J3\u0010\"\u001a\u00020!2\u0012\u0010\u001b\u001a\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00020\u00110\u001a2\u0006\u0010\u001d\u001a\u00020\u001c2\u0006\u0010\u001e\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\"\u0010#J\u000f\u0010$\u001a\u00020\bH\u0016¢\u0006\u0004\b$\u0010\nJ\u001b\u0010'\u001a\u00020\b2\n\u0010&\u001a\u00020%\"\u00020\u0005H\u0016¢\u0006\u0004\b'\u0010(J\u001b\u0010)\u001a\u00020\b2\n\u0010&\u001a\u00020%\"\u00020\u0005H\u0016¢\u0006\u0004\b)\u0010(J3\u0010*\u001a\u00020\b2\u0012\u0010\u001b\u001a\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00020\u00110\u001a2\u0006\u0010\u001d\u001a\u00020\u001c2\u0006\u0010\u001e\u001a\u00020\u0005H\u0016¢\u0006\u0004\b*\u0010 J3\u0010+\u001a\u00020!2\u0012\u0010\u001b\u001a\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00020\u00110\u001a2\u0006\u0010\u001d\u001a\u00020\u001c2\u0006\u0010\u001e\u001a\u00020\u0005H\u0016¢\u0006\u0004\b+\u0010#J\r\u0010,\u001a\u00020\b¢\u0006\u0004\b,\u0010\nJ\u000f\u0010-\u001a\u00020\bH\u0016¢\u0006\u0004\b-\u0010\nJ\u000f\u0010.\u001a\u00020\bH\u0016¢\u0006\u0004\b.\u0010\nJ\u0011\u00100\u001a\u0004\u0018\u00010/H&¢\u0006\u0004\b0\u00101J\u001f\u00104\u001a\u00020\b2\u000e\u00103\u001a\n\u0012\u0004\u0012\u00028\u0000\u0018\u000102H\u0016¢\u0006\u0004\b4\u00105J\u000f\u00106\u001a\u00020\bH\u0016¢\u0006\u0004\b6\u0010\nJ\u000f\u00107\u001a\u00020\bH\u0016¢\u0006\u0004\b7\u0010\nJ\u000f\u00108\u001a\u00020\bH\u0016¢\u0006\u0004\b8\u0010\nJ\u000f\u00109\u001a\u00020!H\u0016¢\u0006\u0004\b9\u0010:J\u000f\u0010;\u001a\u00020!H\u0016¢\u0006\u0004\b;\u0010:J\u000f\u0010=\u001a\u00020<H\u0016¢\u0006\u0004\b=\u0010>J\u000f\u0010?\u001a\u00020\u0005H\u0016¢\u0006\u0004\b?\u0010\u0007J\u000f\u0010@\u001a\u00020\u001cH\u0016¢\u0006\u0004\b@\u0010AJ\u000f\u0010B\u001a\u00020\u001cH\u0016¢\u0006\u0004\bB\u0010AJ\u000f\u0010C\u001a\u00020!H\u0016¢\u0006\u0004\bC\u0010:J\u000f\u0010D\u001a\u00020\u0005H\u0016¢\u0006\u0004\bD\u0010\u0007J\u000f\u0010E\u001a\u00020\u0005H\u0016¢\u0006\u0004\bE\u0010\u0007J\u000f\u0010F\u001a\u00020\u0005H\u0016¢\u0006\u0004\bF\u0010\u0007J\u000f\u0010G\u001a\u00020\u0005H\u0016¢\u0006\u0004\bG\u0010\u0007J\u000f\u0010H\u001a\u00020\bH\u0016¢\u0006\u0004\bH\u0010\nR\"\u0010I\u001a\u00020\u00058\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\bI\u0010J\u001a\u0004\bK\u0010\u0007\"\u0004\bL\u0010MR$\u0010N\u001a\u0004\u0018\u00010/8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\bN\u0010O\u001a\u0004\bP\u00101\"\u0004\bQ\u0010RR$\u0010S\u001a\u0004\u0018\u00010\u000e8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\bS\u0010T\u001a\u0004\bU\u0010\u0010\"\u0004\bV\u0010WR)\u0010\u001b\u001a\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00020\u00110X8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bY\u0010Z\u001a\u0004\b[\u0010\\R\u001d\u0010a\u001a\u00020]8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b^\u0010Z\u001a\u0004\b_\u0010`¨\u0006c"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/core/BaseMutiListFragment;", "Lb/b/a/a/a/j/a;", ExifInterface.GPS_DIRECTION_TRUE, "Lcom/jbzd/media/movecartoons/core/MyThemeFragment;", "", "", "getLayout", "()I", "", "initViews", "()V", "Landroidx/recyclerview/widget/RecyclerView$LayoutManager;", "getLayoutManager", "()Landroidx/recyclerview/widget/RecyclerView$LayoutManager;", "Landroidx/recyclerview/widget/RecyclerView$ItemDecoration;", "getItemDecoration", "()Landroidx/recyclerview/widget/RecyclerView$ItemDecoration;", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "helper", "item", "bindItem", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lb/b/a/a/a/j/a;)V", "Ljava/util/HashMap;", "Lkotlin/collections/HashMap;", "getAllItemType", "()Ljava/util/HashMap;", "Lcom/chad/library/adapter/base/BaseQuickAdapter;", "adapter", "Landroid/view/View;", "view", "position", "onItemClick", "(Lcom/chad/library/adapter/base/BaseQuickAdapter;Landroid/view/View;I)V", "", "onItemLongClick", "(Lcom/chad/library/adapter/base/BaseQuickAdapter;Landroid/view/View;I)Z", "registerItemChildEvent", "", "viewIds", "registerItemChildClick", "([I)V", "registerItemChildLongClick", "onItemChildClick", "onItemChildLongClick", "reset", "refresh", "loadMore", "Lc/a/d1;", "request", "()Lc/a/d1;", "", "t", "didRequestComplete", "(Ljava/util/List;)V", "didRequestError", "showEmptyDataView", "showErrorView", "getRefreshEnable", "()Z", "getLoadMoreEnable", "", "getEmptyTips", "()Ljava/lang/String;", "getEmptyTipsColors", "getEmptyDataView", "()Landroid/view/View;", "getErrorView", "autoRefresh", "getLeftPadding", "getRightPadding", "getTopPadding", "getBottomPadding", "onDestroyView", "currentPage", "I", "getCurrentPage", "setCurrentPage", "(I)V", "loadJob", "Lc/a/d1;", "getLoadJob", "setLoadJob", "(Lc/a/d1;)V", "mItemDecoration", "Landroidx/recyclerview/widget/RecyclerView$ItemDecoration;", "getMItemDecoration", "setMItemDecoration", "(Landroidx/recyclerview/widget/RecyclerView$ItemDecoration;)V", "Lcom/chad/library/adapter/base/BaseMultiItemQuickAdapter;", "adapter$delegate", "Lkotlin/Lazy;", "getAdapter", "()Lcom/chad/library/adapter/base/BaseMultiItemQuickAdapter;", "Landroidx/recyclerview/widget/RecyclerView;", "rv_content$delegate", "getRv_content", "()Landroidx/recyclerview/widget/RecyclerView;", "rv_content", "<init>", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public abstract class BaseMutiListFragment<T extends InterfaceC1296a> extends MyThemeFragment<Object> {

    @Nullable
    private InterfaceC3053d1 loadJob;

    @Nullable
    private RecyclerView.ItemDecoration mItemDecoration;
    private int currentPage = 1;

    /* renamed from: rv_content$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rv_content = LazyKt__LazyJVMKt.lazy(new C3627c(this));

    /* renamed from: adapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy adapter = LazyKt__LazyJVMKt.lazy(new C3625a(this));

    /* renamed from: com.jbzd.media.movecartoons.core.BaseMutiListFragment$a */
    public static final class C3625a extends Lambda implements Function0<BaseMutiListFragment$adapter$2$1> {

        /* renamed from: c */
        public final /* synthetic */ BaseMutiListFragment<T> f10040c;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public C3625a(BaseMutiListFragment<T> baseMutiListFragment) {
            super(0);
            this.f10040c = baseMutiListFragment;
        }

        @Override // kotlin.jvm.functions.Function0
        public BaseMutiListFragment$adapter$2$1 invoke() {
            C1318f loadMoreModule;
            BaseMutiListFragment$adapter$2$1 baseMutiListFragment$adapter$2$1 = new BaseMutiListFragment$adapter$2$1(this.f10040c);
            final BaseMutiListFragment<T> baseMutiListFragment = this.f10040c;
            baseMutiListFragment$adapter$2$1.setOnItemClickListener(new InterfaceC1304d() { // from class: b.a.a.a.n.m
                @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d
                public final void onItemClick(BaseQuickAdapter adapter, View view, int i2) {
                    BaseMutiListFragment this$0 = BaseMutiListFragment.this;
                    Intrinsics.checkNotNullParameter(this$0, "this$0");
                    Intrinsics.checkNotNullParameter(adapter, "adapter");
                    Intrinsics.checkNotNullParameter(view, "view");
                    this$0.onItemClick(adapter, view, i2);
                }
            });
            baseMutiListFragment$adapter$2$1.setOnItemLongClickListener(new InterfaceC1306f() { // from class: b.a.a.a.n.j
                @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1306f
                /* renamed from: a */
                public final boolean mo214a(BaseQuickAdapter adapter, View view, int i2) {
                    BaseMutiListFragment this$0 = BaseMutiListFragment.this;
                    Intrinsics.checkNotNullParameter(this$0, "this$0");
                    Intrinsics.checkNotNullParameter(adapter, "adapter");
                    Intrinsics.checkNotNullParameter(view, "view");
                    return this$0.onItemLongClick(adapter, view, i2);
                }
            });
            baseMutiListFragment$adapter$2$1.setOnItemChildClickListener(new InterfaceC1302b() { // from class: b.a.a.a.n.i
                @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1302b
                /* renamed from: a */
                public final void mo215a(BaseQuickAdapter adapter, View view, int i2) {
                    BaseMutiListFragment this$0 = BaseMutiListFragment.this;
                    Intrinsics.checkNotNullParameter(this$0, "this$0");
                    Intrinsics.checkNotNullParameter(adapter, "adapter");
                    Intrinsics.checkNotNullParameter(view, "view");
                    this$0.onItemChildClick(adapter, view, i2);
                }
            });
            baseMutiListFragment$adapter$2$1.setOnItemChildLongClickListener(new InterfaceC1303c() { // from class: b.a.a.a.n.l
                @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1303c
                /* renamed from: a */
                public final boolean mo213a(BaseQuickAdapter adapter, View view, int i2) {
                    BaseMutiListFragment this$0 = BaseMutiListFragment.this;
                    Intrinsics.checkNotNullParameter(this$0, "this$0");
                    Intrinsics.checkNotNullParameter(adapter, "adapter");
                    Intrinsics.checkNotNullParameter(view, "view");
                    return this$0.onItemChildLongClick(adapter, view, i2);
                }
            });
            if (baseMutiListFragment.getLoadMoreEnable() && (loadMoreModule = baseMutiListFragment$adapter$2$1.getLoadMoreModule()) != null) {
                loadMoreModule.setOnLoadMoreListener(new InterfaceC1308h() { // from class: b.a.a.a.n.k
                    @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1308h
                    /* renamed from: a */
                    public final void mo216a() {
                        BaseMutiListFragment this$0 = BaseMutiListFragment.this;
                        Intrinsics.checkNotNullParameter(this$0, "this$0");
                        this$0.loadMore();
                    }
                });
                loadMoreModule.f1059h = true;
                loadMoreModule.f1058g = true;
                loadMoreModule.f1060i = true;
            }
            return baseMutiListFragment$adapter$2$1;
        }
    }

    /* renamed from: com.jbzd.media.movecartoons.core.BaseMutiListFragment$b */
    public static final class C3626b extends Lambda implements Function1<View, Unit> {

        /* renamed from: c */
        public final /* synthetic */ BaseMutiListFragment<T> f10042c;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public C3626b(BaseMutiListFragment<T> baseMutiListFragment) {
            super(1);
            this.f10042c = baseMutiListFragment;
        }

        @Override // kotlin.jvm.functions.Function1
        public Unit invoke(View view) {
            View it = view;
            Intrinsics.checkNotNullParameter(it, "it");
            this.f10042c.getAdapter().setEmptyView(R.layout.loading_view);
            this.f10042c.refresh();
            return Unit.INSTANCE;
        }
    }

    /* renamed from: com.jbzd.media.movecartoons.core.BaseMutiListFragment$c */
    public static final class C3627c extends Lambda implements Function0<RecyclerView> {

        /* renamed from: c */
        public final /* synthetic */ BaseMutiListFragment<T> f10043c;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public C3627c(BaseMutiListFragment<T> baseMutiListFragment) {
            super(0);
            this.f10043c = baseMutiListFragment;
        }

        @Override // kotlin.jvm.functions.Function0
        public RecyclerView invoke() {
            View view = this.f10043c.getView();
            RecyclerView recyclerView = view == null ? null : (RecyclerView) view.findViewById(R.id.rv_content);
            Objects.requireNonNull(recyclerView, "null cannot be cast to non-null type androidx.recyclerview.widget.RecyclerView");
            return recyclerView;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initViews$lambda-2$lambda-1, reason: not valid java name */
    public static final void m5738initViews$lambda2$lambda1(BaseMutiListFragment this$0) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        this$0.refresh();
    }

    @Override // com.jbzd.media.movecartoons.core.MyThemeFragment, com.qunidayede.supportlibrary.core.view.BaseThemeFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    public boolean autoRefresh() {
        return true;
    }

    public abstract void bindItem(@NotNull BaseViewHolder helper, @NotNull T item);

    public void didRequestComplete(@Nullable List<? extends T> t) {
        View view = getView();
        ((SwipeRefreshLayout) (view == null ? null : view.findViewById(R$id.swipeLayout))).setRefreshing(false);
        if (this.currentPage == 1) {
            if (t == null || t.isEmpty()) {
                getAdapter().setNewData(null);
                showEmptyDataView();
                return;
            } else {
                getAdapter().removeEmptyView();
                BaseMultiItemQuickAdapter<T, BaseViewHolder> adapter = getAdapter();
                Objects.requireNonNull(t, "null cannot be cast to non-null type java.util.ArrayList<T of com.jbzd.media.movecartoons.core.BaseMutiListFragment>");
                adapter.setNewData((ArrayList) t);
                return;
            }
        }
        C1318f loadMoreModule = getAdapter().getLoadMoreModule();
        if (loadMoreModule != null) {
            loadMoreModule.m330f();
        }
        if (!(t == null || t.isEmpty())) {
            getAdapter().addData((Collection) t);
            return;
        }
        C1318f loadMoreModule2 = getAdapter().getLoadMoreModule();
        if (loadMoreModule2 == null) {
            return;
        }
        C1318f.m324h(loadMoreModule2, false, 1, null);
    }

    public void didRequestError() {
        View view = getView();
        ((SwipeRefreshLayout) (view == null ? null : view.findViewById(R$id.swipeLayout))).setRefreshing(false);
        C1318f loadMoreModule = getAdapter().getLoadMoreModule();
        if (loadMoreModule != null) {
            loadMoreModule.m334k(true);
        }
        if (this.currentPage == 1) {
            showErrorView();
            return;
        }
        C1318f loadMoreModule2 = getAdapter().getLoadMoreModule();
        if (loadMoreModule2 == null) {
            return;
        }
        loadMoreModule2.m332i();
    }

    @NotNull
    public final BaseMultiItemQuickAdapter<T, BaseViewHolder> getAdapter() {
        return (BaseMultiItemQuickAdapter) this.adapter.getValue();
    }

    @Nullable
    public abstract HashMap<Integer, Integer> getAllItemType();

    public int getBottomPadding() {
        return 0;
    }

    public final int getCurrentPage() {
        return this.currentPage;
    }

    @NotNull
    public View getEmptyDataView() {
        View inflate = getLayoutInflater().inflate(R.layout.empty_view, (ViewGroup) getRv_content(), false);
        Intrinsics.checkNotNullExpressionValue(inflate, "layoutInflater.inflate(R.layout.empty_view, rv_content, false)");
        View findViewById = inflate.findViewById(R.id.tv_empty_tips);
        Objects.requireNonNull(findViewById, "null cannot be cast to non-null type android.widget.TextView");
        TextView textView = (TextView) findViewById;
        textView.setText(getEmptyTips());
        textView.setTextColor(getEmptyTipsColors());
        return inflate;
    }

    @NotNull
    public String getEmptyTips() {
        String string = getResources().getString(R.string.empty_no_data);
        Intrinsics.checkNotNullExpressionValue(string, "resources.getString(R.string.empty_no_data)");
        return string;
    }

    public int getEmptyTipsColors() {
        return ContextCompat.getColor(requireContext(), R.color.color_666666);
    }

    @NotNull
    public View getErrorView() {
        View errorView = getLayoutInflater().inflate(R.layout.error_view, (ViewGroup) getRv_content(), false);
        View findViewById = errorView.findViewById(R.id.btn_retry);
        Objects.requireNonNull(findViewById, "null cannot be cast to non-null type android.view.View");
        C2354n.m2374A(findViewById, 0L, new C3626b(this), 1);
        Intrinsics.checkNotNullExpressionValue(errorView, "errorView");
        return errorView;
    }

    @Nullable
    public RecyclerView.ItemDecoration getItemDecoration() {
        return null;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public int getLayout() {
        return R.layout.list_frag;
    }

    @NotNull
    public RecyclerView.LayoutManager getLayoutManager() {
        return new LinearLayoutManager(requireContext());
    }

    public int getLeftPadding() {
        return 0;
    }

    @Nullable
    public final InterfaceC3053d1 getLoadJob() {
        return this.loadJob;
    }

    public boolean getLoadMoreEnable() {
        return true;
    }

    @Nullable
    public final RecyclerView.ItemDecoration getMItemDecoration() {
        return this.mItemDecoration;
    }

    public boolean getRefreshEnable() {
        return true;
    }

    public int getRightPadding() {
        return 0;
    }

    @NotNull
    public final RecyclerView getRv_content() {
        return (RecyclerView) this.rv_content.getValue();
    }

    public int getTopPadding() {
        return 0;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public void initViews() {
        getRv_content().setPadding(getLeftPadding(), getTopPadding(), getRightPadding(), getBottomPadding());
        this.mItemDecoration = getItemDecoration();
        RecyclerView rv_content = getRv_content();
        rv_content.setLayoutManager(getLayoutManager());
        rv_content.setAdapter(getAdapter());
        if (getMItemDecoration() != null) {
            RecyclerView.ItemDecoration mItemDecoration = getMItemDecoration();
            Intrinsics.checkNotNull(mItemDecoration);
            rv_content.addItemDecoration(mItemDecoration);
        }
        registerItemChildEvent();
        View view = getView();
        SwipeRefreshLayout swipeRefreshLayout = (SwipeRefreshLayout) (view == null ? null : view.findViewById(R$id.swipeLayout));
        swipeRefreshLayout.setColorSchemeColors(swipeRefreshLayout.getResources().getColor(R.color.color_gold_main));
        swipeRefreshLayout.setOnRefreshListener(new SwipeRefreshLayout.OnRefreshListener() { // from class: b.a.a.a.n.h
            @Override // androidx.swiperefreshlayout.widget.SwipeRefreshLayout.OnRefreshListener
            public final void onRefresh() {
                BaseMutiListFragment.m5738initViews$lambda2$lambda1(BaseMutiListFragment.this);
            }
        });
        View view2 = getView();
        ((SwipeRefreshLayout) (view2 == null ? null : view2.findViewById(R$id.swipeLayout))).setEnabled(getRefreshEnable());
        if (autoRefresh()) {
            View view3 = getView();
            ((SwipeRefreshLayout) (view3 != null ? view3.findViewById(R$id.swipeLayout) : null)).setRefreshing(true);
            refresh();
        }
    }

    public void loadMore() {
        this.currentPage++;
        this.loadJob = request();
    }

    @Override // androidx.fragment.app.Fragment
    public void onDestroyView() {
        super.onDestroyView();
        cancelJob(this.loadJob);
    }

    public void onItemChildClick(@NotNull BaseQuickAdapter<T, BaseViewHolder> adapter, @NotNull View view, int position) {
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
    }

    public boolean onItemChildLongClick(@NotNull BaseQuickAdapter<T, BaseViewHolder> adapter, @NotNull View view, int position) {
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        return false;
    }

    public void onItemClick(@NotNull BaseQuickAdapter<T, BaseViewHolder> adapter, @NotNull View view, int position) {
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
    }

    public boolean onItemLongClick(@NotNull BaseQuickAdapter<T, BaseViewHolder> adapter, @NotNull View view, int position) {
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        return false;
    }

    public void refresh() {
        C1318f loadMoreModule = getAdapter().getLoadMoreModule();
        if (loadMoreModule != null) {
            loadMoreModule.m334k(false);
        }
        this.currentPage = 1;
        this.loadJob = request();
    }

    public void registerItemChildClick(@NotNull int... viewIds) {
        Intrinsics.checkNotNullParameter(viewIds, "viewIds");
        int length = viewIds.length;
        int i2 = 0;
        while (i2 < length) {
            int i3 = viewIds[i2];
            i2++;
            getAdapter().addChildClickViewIds(i3);
        }
    }

    public void registerItemChildEvent() {
    }

    public void registerItemChildLongClick(@NotNull int... viewIds) {
        Intrinsics.checkNotNullParameter(viewIds, "viewIds");
        int length = viewIds.length;
        int i2 = 0;
        while (i2 < length) {
            int i3 = viewIds[i2];
            i2++;
            getAdapter().addChildLongClickViewIds(i3);
        }
    }

    @Nullable
    public abstract InterfaceC3053d1 request();

    public final void reset() {
        getAdapter().setNewData(null);
        getAdapter().setEmptyView(R.layout.loading_view);
        refresh();
    }

    public final void setCurrentPage(int i2) {
        this.currentPage = i2;
    }

    public final void setLoadJob(@Nullable InterfaceC3053d1 interfaceC3053d1) {
        this.loadJob = interfaceC3053d1;
    }

    public final void setMItemDecoration(@Nullable RecyclerView.ItemDecoration itemDecoration) {
        this.mItemDecoration = itemDecoration;
    }

    public void showEmptyDataView() {
        getAdapter().setEmptyView(getEmptyDataView());
    }

    public void showErrorView() {
        getAdapter().setEmptyView(getErrorView());
    }
}
