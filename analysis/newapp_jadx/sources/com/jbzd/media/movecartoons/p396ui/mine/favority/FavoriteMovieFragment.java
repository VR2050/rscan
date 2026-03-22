package com.jbzd.media.movecartoons.p396ui.mine.favority;

import android.content.Context;
import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.recyclerview.widget.RecyclerView;
import com.drake.brv.BindingAdapter;
import com.drake.brv.PageRefreshLayout;
import com.google.android.material.imageview.ShapeableImageView;
import com.jbzd.media.movecartoons.bean.response.VideoItemBean;
import com.jbzd.media.movecartoons.databinding.ActPageBinding;
import com.jbzd.media.movecartoons.p396ui.BaseListFragment;
import com.jbzd.media.movecartoons.p396ui.index.selected.child.PlayListActivity;
import com.jbzd.media.movecartoons.p396ui.movie.MovieDetailsActivity;
import com.qnmd.adnnm.da0yzo.R;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Reflection;
import kotlin.jvm.internal.TypeIntrinsics;
import net.sourceforge.pinyin4j.ChineseToPinyinResource;
import org.jetbrains.annotations.NotNull;
import p005b.p006a.p007a.p008a.p017r.InterfaceC0921e;
import p005b.p006a.p007a.p008a.p017r.p021n.C0944a;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.p383b2.InterfaceC3006b;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000J\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010!\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0010\u000b\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0006\u0018\u00002\b\u0012\u0004\u0012\u00020\u00020\u0001B\u0007¢\u0006\u0004\b \u0010!J\u001f\u0010\b\u001a\u00020\u00072\u0006\u0010\u0004\u001a\u00020\u00032\u0006\u0010\u0006\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\b\u0010\tJ#\u0010\u000e\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u00020\u00020\r0\f2\u0006\u0010\u000b\u001a\u00020\nH\u0016¢\u0006\u0004\b\u000e\u0010\u000fJ#\u0010\u0013\u001a\u00020\u00072\n\u0010\u0011\u001a\u00060\u0010R\u00020\u00032\u0006\u0010\u0012\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0013\u0010\u0014J'\u0010\u0018\u001a\u00020\u00072\u0006\u0010\u0004\u001a\u00020\u00032\u0006\u0010\u0015\u001a\u00020\n2\u0006\u0010\u0017\u001a\u00020\u0016H\u0016¢\u0006\u0004\b\u0018\u0010\u0019J\u0017\u0010\u001a\u001a\u00020\u00072\u0006\u0010\u0004\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u001a\u0010\u001bJ\u0017\u0010\u001e\u001a\u00020\u00072\u0006\u0010\u001d\u001a\u00020\u001cH\u0016¢\u0006\u0004\b\u001e\u0010\u001f¨\u0006\""}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/mine/favority/FavoriteMovieFragment;", "Lcom/jbzd/media/movecartoons/ui/BaseListFragment;", "Lcom/jbzd/media/movecartoons/bean/response/VideoItemBean;", "Lcom/drake/brv/BindingAdapter;", "adapter", "Landroidx/recyclerview/widget/RecyclerView;", "rv", "", "addItemListType", "(Lcom/drake/brv/BindingAdapter;Landroidx/recyclerview/widget/RecyclerView;)V", "", "page", "Lc/a/b2/b;", "", "initFlow", "(I)Lc/a/b2/b;", "Lcom/drake/brv/BindingAdapter$BindingViewHolder;", "vh", "data", "onDataBinding", "(Lcom/drake/brv/BindingAdapter$BindingViewHolder;Lcom/jbzd/media/movecartoons/bean/response/VideoItemBean;)V", "position", "", "checked", "onItemCheck", "(Lcom/drake/brv/BindingAdapter;IZ)V", "onViewClick", "(Lcom/drake/brv/BindingAdapter;)V", "Landroid/view/View;", "view", "onHandleChoice", "(Landroid/view/View;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class FavoriteMovieFragment extends BaseListFragment<VideoItemBean> {
    @Override // com.jbzd.media.movecartoons.p396ui.BaseListFragment, com.qunidayede.supportlibrary.core.view.BaseBindingFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.jbzd.media.movecartoons.p396ui.BaseListFragment
    public void addItemListType(@NotNull BindingAdapter adapter, @NotNull RecyclerView rv) {
        boolean m616f0 = C1499a.m616f0(adapter, "adapter", rv, "rv", VideoItemBean.class);
        final int i2 = R.layout.item_video_layout;
        if (m616f0) {
            adapter.f8910l.put(Reflection.typeOf(VideoItemBean.class), new Function2<Object, Integer, Integer>() { // from class: com.jbzd.media.movecartoons.ui.mine.favority.FavoriteMovieFragment$addItemListType$$inlined$addType$1
                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                {
                    super(2);
                }

                @NotNull
                public final Integer invoke(@NotNull Object obj, int i3) {
                    Intrinsics.checkNotNullParameter(obj, "$this$null");
                    return Integer.valueOf(i2);
                }

                @Override // kotlin.jvm.functions.Function2
                public /* bridge */ /* synthetic */ Integer invoke(Object obj, Integer num) {
                    return invoke(obj, num.intValue());
                }
            });
        } else {
            adapter.f8909k.put(Reflection.typeOf(VideoItemBean.class), new Function2<Object, Integer, Integer>() { // from class: com.jbzd.media.movecartoons.ui.mine.favority.FavoriteMovieFragment$addItemListType$$inlined$addType$2
                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                {
                    super(2);
                }

                @NotNull
                public final Integer invoke(@NotNull Object obj, int i3) {
                    Intrinsics.checkNotNullParameter(obj, "$this$null");
                    return Integer.valueOf(i2);
                }

                @Override // kotlin.jvm.functions.Function2
                public /* bridge */ /* synthetic */ Integer invoke(Object obj, Integer num) {
                    return invoke(obj, num.intValue());
                }
            });
        }
    }

    @Override // com.jbzd.media.movecartoons.p396ui.BaseListFragment
    @NotNull
    public InterfaceC3006b<List<VideoItemBean>> initFlow(int page) {
        return ((InterfaceC0921e) LazyKt__LazyJVMKt.lazy(C0944a.a.f472c).getValue()).m232B(page);
    }

    @Override // com.jbzd.media.movecartoons.p396ui.BaseListFragment
    public void onHandleChoice(@NotNull View view) {
        Intrinsics.checkNotNullParameter(view, "view");
        final BindingAdapter adapter = getAdapter();
        if (adapter == null) {
            return;
        }
        ArrayList arrayList = new ArrayList();
        List<Object> list = adapter.f8920v;
        List mutableList = list == null ? null : CollectionsKt___CollectionsKt.toMutableList((Collection) list);
        final List list2 = TypeIntrinsics.isMutableList(mutableList) ? mutableList : null;
        if (list2 == null) {
            list2 = new ArrayList();
        }
        Iterator<T> it = adapter.f8923y.iterator();
        String ids = "";
        while (it.hasNext()) {
            VideoItemBean videoItemBean = (VideoItemBean) adapter.m3930g(((Number) it.next()).intValue());
            list2.remove(videoItemBean);
            arrayList.add(videoItemBean);
            if (ids.length() > 0) {
                ids = Intrinsics.stringPlus(ids, ChineseToPinyinResource.Field.COMMA);
            }
            ids = Intrinsics.stringPlus(ids, videoItemBean.f10000id);
        }
        Lazy lazy = LazyKt__LazyJVMKt.lazy(C0944a.a.f472c);
        Intrinsics.checkNotNullParameter(ids, "ids");
        C2354n.m2441W0(((InterfaceC0921e) lazy.getValue()).m243b(ids), this, new Function1<Object, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.favority.FavoriteMovieFragment$onHandleChoice$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Object obj) {
                invoke2(obj);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Object lifecycleLoadingDialog) {
                ActPageBinding bodyBinding;
                Intrinsics.checkNotNullParameter(lifecycleLoadingDialog, "$this$lifecycleLoadingDialog");
                BindingAdapter.m3925p(BindingAdapter.this, list2, false, null, 6, null);
                if (BindingAdapter.this.getItemCount() == 0) {
                    bodyBinding = this.getBodyBinding();
                    PageRefreshLayout pageRefreshLayout = bodyBinding.pager;
                    Intrinsics.checkNotNullExpressionValue(pageRefreshLayout, "bodyBinding.pager");
                    PageRefreshLayout.m3949F(pageRefreshLayout, null, 1, null);
                }
            }
        }, false, null, 12);
    }

    @Override // com.jbzd.media.movecartoons.p396ui.BaseListFragment
    public void onItemCheck(@NotNull BindingAdapter adapter, int position, boolean checked) {
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        ((VideoItemBean) adapter.m3930g(position)).isSelect = checked;
        adapter.notifyItemChanged(position);
    }

    @Override // com.jbzd.media.movecartoons.p396ui.BaseListFragment
    public void onViewClick(@NotNull BindingAdapter adapter) {
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        adapter.m3937n(new int[]{R.id.root}, new Function2<BindingAdapter.BindingViewHolder, Integer, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.favority.FavoriteMovieFragment$onViewClick$1
            {
                super(2);
            }

            @Override // kotlin.jvm.functions.Function2
            public /* bridge */ /* synthetic */ Unit invoke(BindingAdapter.BindingViewHolder bindingViewHolder, Integer num) {
                invoke(bindingViewHolder, num.intValue());
                return Unit.INSTANCE;
            }

            public final void invoke(@NotNull BindingAdapter.BindingViewHolder onClick, int i2) {
                Intrinsics.checkNotNullParameter(onClick, "$this$onClick");
                VideoItemBean videoItemBean = (VideoItemBean) onClick.m3942b();
                if (videoItemBean.isLong()) {
                    MovieDetailsActivity.Companion companion = MovieDetailsActivity.INSTANCE;
                    Context requireContext = FavoriteMovieFragment.this.requireContext();
                    Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                    String str = videoItemBean.f10000id;
                    if (str == null) {
                        str = "";
                    }
                    companion.start(requireContext, str);
                    return;
                }
                if (videoItemBean.isShort()) {
                    HashMap hashMap = new HashMap();
                    hashMap.put("page", String.valueOf(videoItemBean.realPage));
                    PlayListActivity.Companion companion2 = PlayListActivity.INSTANCE;
                    Context requireContext2 = FavoriteMovieFragment.this.requireContext();
                    Intrinsics.checkNotNullExpressionValue(requireContext2, "requireContext()");
                    companion2.start(requireContext2, (r13 & 2) != 0 ? null : videoItemBean.f10000id, (r13 & 4) != 0 ? null : hashMap, (r13 & 8) != 0 ? null : null, (r13 & 16) != 0 ? false : false);
                }
            }
        });
    }

    @Override // com.jbzd.media.movecartoons.p396ui.BaseListFragment
    public void onDataBinding(@NotNull BindingAdapter.BindingViewHolder vh, @NotNull VideoItemBean data) {
        Intrinsics.checkNotNullParameter(vh, "vh");
        Intrinsics.checkNotNullParameter(data, "data");
        C2354n.m2455a2(requireContext()).m3298p(data.img_x).m3295i0().m757R((ShapeableImageView) vh.m3941a(R.id.iv_video));
        ((TextView) vh.m3941a(R.id.tv_name)).setText(data.name);
        ((TextView) vh.m3941a(R.id.tv_video_click)).setText(Intrinsics.stringPlus("人气·", data.click));
        TextView textView = (TextView) vh.m3941a(R.id.tv_video_type);
        ImageView imageView = (ImageView) vh.m3941a(R.id.img_icon_money);
        if (!data.getIsMoneyVideo()) {
            imageView.setVisibility(8);
        } else {
            imageView.setVisibility(0);
            textView.setText(data.money);
        }
    }
}
