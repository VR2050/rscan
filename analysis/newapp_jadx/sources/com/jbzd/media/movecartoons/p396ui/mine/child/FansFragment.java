package com.jbzd.media.movecartoons.p396ui.mine.child;

import android.widget.TextView;
import androidx.recyclerview.widget.RecyclerView;
import com.drake.brv.BindingAdapter;
import com.google.android.material.imageview.ShapeableImageView;
import com.jbzd.media.movecartoons.bean.response.FollowItem;
import com.jbzd.media.movecartoons.bean.response.UserFollowResponse;
import com.jbzd.media.movecartoons.p396ui.BaseListFragment;
import com.qnmd.adnnm.da0yzo.R;
import java.util.List;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Reflection;
import org.jetbrains.annotations.NotNull;
import p005b.p006a.p007a.p008a.p017r.InterfaceC0921e;
import p005b.p006a.p007a.p008a.p017r.p021n.C0944a;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.p383b2.InterfaceC3006b;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000:\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010\b\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010!\n\u0002\b\u0007\u0018\u00002\b\u0012\u0004\u0012\u00020\u00020\u0001B\u0007¢\u0006\u0004\b\u0017\u0010\u0018J\u001f\u0010\b\u001a\u00020\u00072\u0006\u0010\u0004\u001a\u00020\u00032\u0006\u0010\u0006\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\b\u0010\tJ#\u0010\r\u001a\u00020\u00072\n\u0010\u000b\u001a\u00060\nR\u00020\u00032\u0006\u0010\f\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\r\u0010\u000eJ#\u0010\u0013\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u00020\u00020\u00120\u00112\u0006\u0010\u0010\u001a\u00020\u000fH\u0016¢\u0006\u0004\b\u0013\u0010\u0014J\u0017\u0010\u0015\u001a\u00020\u00072\u0006\u0010\u0004\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0015\u0010\u0016¨\u0006\u0019"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/mine/child/FansFragment;", "Lcom/jbzd/media/movecartoons/ui/BaseListFragment;", "Lcom/jbzd/media/movecartoons/bean/response/FollowItem;", "Lcom/drake/brv/BindingAdapter;", "adapter", "Landroidx/recyclerview/widget/RecyclerView;", "rv", "", "addItemListType", "(Lcom/drake/brv/BindingAdapter;Landroidx/recyclerview/widget/RecyclerView;)V", "Lcom/drake/brv/BindingAdapter$BindingViewHolder;", "vh", "data", "onDataBinding", "(Lcom/drake/brv/BindingAdapter$BindingViewHolder;Lcom/jbzd/media/movecartoons/bean/response/FollowItem;)V", "", "page", "Lc/a/b2/b;", "", "initFlow", "(I)Lc/a/b2/b;", "onViewClick", "(Lcom/drake/brv/BindingAdapter;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class FansFragment extends BaseListFragment<FollowItem> {
    @Override // com.jbzd.media.movecartoons.p396ui.BaseListFragment, com.qunidayede.supportlibrary.core.view.BaseBindingFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.jbzd.media.movecartoons.p396ui.BaseListFragment
    public void addItemListType(@NotNull BindingAdapter adapter, @NotNull RecyclerView rv) {
        boolean m616f0 = C1499a.m616f0(adapter, "adapter", rv, "rv", FollowItem.class);
        final int i2 = R.layout.item_follow;
        if (m616f0) {
            adapter.f8910l.put(Reflection.typeOf(FollowItem.class), new Function2<Object, Integer, Integer>() { // from class: com.jbzd.media.movecartoons.ui.mine.child.FansFragment$addItemListType$$inlined$addType$1
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
            adapter.f8909k.put(Reflection.typeOf(FollowItem.class), new Function2<Object, Integer, Integer>() { // from class: com.jbzd.media.movecartoons.ui.mine.child.FansFragment$addItemListType$$inlined$addType$2
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
    public InterfaceC3006b<List<FollowItem>> initFlow(int page) {
        return ((InterfaceC0921e) LazyKt__LazyJVMKt.lazy(C0944a.a.f472c).getValue()).m234D(page);
    }

    @Override // com.jbzd.media.movecartoons.p396ui.BaseListFragment
    public void onViewClick(@NotNull final BindingAdapter adapter) {
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        adapter.m3937n(new int[]{R.id.itv_item_follow_state}, new Function2<BindingAdapter.BindingViewHolder, Integer, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.child.FansFragment$onViewClick$1
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(2);
            }

            @Override // kotlin.jvm.functions.Function2
            public /* bridge */ /* synthetic */ Unit invoke(BindingAdapter.BindingViewHolder bindingViewHolder, Integer num) {
                invoke(bindingViewHolder, num.intValue());
                return Unit.INSTANCE;
            }

            public final void invoke(@NotNull final BindingAdapter.BindingViewHolder onClick, int i2) {
                Intrinsics.checkNotNullParameter(onClick, "$this$onClick");
                final FollowItem followItem = (FollowItem) onClick.m3942b();
                Lazy lazy = LazyKt__LazyJVMKt.lazy(C0944a.a.f472c);
                String userId = followItem.getUser_id();
                Intrinsics.checkNotNullParameter(userId, "userId");
                InterfaceC3006b<UserFollowResponse> m240J = ((InterfaceC0921e) lazy.getValue()).m240J(userId);
                FansFragment fansFragment = FansFragment.this;
                final BindingAdapter bindingAdapter = adapter;
                C2354n.m2441W0(m240J, fansFragment, new Function1<UserFollowResponse, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.child.FansFragment$onViewClick$1.1
                    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                    {
                        super(1);
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(UserFollowResponse userFollowResponse) {
                        invoke2(userFollowResponse);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull UserFollowResponse lifecycleLoadingDialog) {
                        Intrinsics.checkNotNullParameter(lifecycleLoadingDialog, "$this$lifecycleLoadingDialog");
                        FollowItem followItem2 = FollowItem.this;
                        String str = lifecycleLoadingDialog.status;
                        Intrinsics.checkNotNullExpressionValue(str, "this.status");
                        followItem2.setHas_follow(str);
                        bindingAdapter.notifyItemChanged(onClick.getLayoutPosition());
                    }
                }, false, null, 12);
            }
        });
    }

    @Override // com.jbzd.media.movecartoons.p396ui.BaseListFragment
    public void onDataBinding(@NotNull BindingAdapter.BindingViewHolder vh, @NotNull FollowItem data) {
        Intrinsics.checkNotNullParameter(vh, "vh");
        Intrinsics.checkNotNullParameter(data, "data");
        C2354n.m2455a2(requireContext()).m3298p(data.getImg()).m3288b0().m757R((ShapeableImageView) vh.m3941a(R.id.civ_avatar));
        ((TextView) vh.m3941a(R.id.tv_postdetail_nickname)).setText(data.getNickname());
        TextView textView = (TextView) vh.m3941a(R.id.itv_item_follow_state);
        textView.setSelected(Intrinsics.areEqual(data.getHas_follow(), "y"));
        textView.setText(Intrinsics.areEqual(data.getHas_follow(), "y") ? "已关注" : "关注");
    }
}
