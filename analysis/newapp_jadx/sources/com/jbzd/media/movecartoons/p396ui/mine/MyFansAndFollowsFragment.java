package com.jbzd.media.movecartoons.p396ui.mine;

import android.content.Context;
import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.core.app.NotificationCompat;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.bean.event.EventFollow;
import com.jbzd.media.movecartoons.bean.event.EventSubscription;
import com.jbzd.media.movecartoons.bean.response.PostHomeResponse;
import com.jbzd.media.movecartoons.core.BaseListFragment;
import com.jbzd.media.movecartoons.p396ui.mine.MyFansAndFollowsFragment;
import com.jbzd.media.movecartoons.p396ui.post.user.UserPostHomeActivity;
import com.jbzd.media.movecartoons.view.image.CircleImageView;
import com.qnmd.adnnm.da0yzo.R;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.greenrobot.eventbus.ThreadMode;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.json.JSONObject;
import p005b.p006a.p007a.p008a.p009a.C0843e0;
import p005b.p006a.p007a.p008a.p017r.C0917a;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.InterfaceC3053d1;
import p476m.p496b.p497a.C4909c;
import p476m.p496b.p497a.InterfaceC4919m;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000P\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\t\u0018\u0000 )2\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0001)B\u0007¢\u0006\u0004\b(\u0010 J\u0017\u0010\u0006\u001a\u00020\u00052\u0006\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u0006\u0010\u0007J\u000f\u0010\t\u001a\u00020\bH\u0016¢\u0006\u0004\b\t\u0010\nJ\u000f\u0010\f\u001a\u00020\u000bH\u0016¢\u0006\u0004\b\f\u0010\rJ\u001f\u0010\u0011\u001a\u00020\u00052\u0006\u0010\u000f\u001a\u00020\u000e2\u0006\u0010\u0010\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0011\u0010\u0012J\u0011\u0010\u0014\u001a\u0004\u0018\u00010\u0013H\u0016¢\u0006\u0004\b\u0014\u0010\u0015J3\u0010\u001b\u001a\u00020\u00052\u0012\u0010\u0017\u001a\u000e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u000e0\u00162\u0006\u0010\u0019\u001a\u00020\u00182\u0006\u0010\u001a\u001a\u00020\u000bH\u0016¢\u0006\u0004\b\u001b\u0010\u001cJ\u000f\u0010\u001d\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u001d\u0010\u001eJ\u000f\u0010\u001f\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\u001f\u0010 J\u0017\u0010#\u001a\u00020\u00052\u0006\u0010\"\u001a\u00020!H\u0007¢\u0006\u0004\b#\u0010$J\u000f\u0010%\u001a\u00020\u0005H\u0016¢\u0006\u0004\b%\u0010 J\u000f\u0010&\u001a\u00020\u0005H\u0016¢\u0006\u0004\b&\u0010 J\u000f\u0010'\u001a\u00020\u0005H\u0016¢\u0006\u0004\b'\u0010 ¨\u0006*"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/mine/MyFansAndFollowsFragment;", "Lcom/jbzd/media/movecartoons/core/BaseListFragment;", "Lcom/jbzd/media/movecartoons/bean/response/PostHomeResponse$HLSFollowerBean;", "", "userId", "", "follow", "(Ljava/lang/String;)V", "Landroidx/recyclerview/widget/RecyclerView$LayoutManager;", "getLayoutManager", "()Landroidx/recyclerview/widget/RecyclerView$LayoutManager;", "", "getItemLayoutId", "()I", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "helper", "item", "bindItem", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/PostHomeResponse$HLSFollowerBean;)V", "Lc/a/d1;", "request", "()Lc/a/d1;", "Lcom/chad/library/adapter/base/BaseQuickAdapter;", "adapter", "Landroid/view/View;", "view", "position", "onItemClick", "(Lcom/chad/library/adapter/base/BaseQuickAdapter;Landroid/view/View;I)V", "getEmptyTips", "()Ljava/lang/String;", "onDestroy", "()V", "Lcom/jbzd/media/movecartoons/bean/event/EventFollow;", NotificationCompat.CATEGORY_EVENT, "onFollow", "(Lcom/jbzd/media/movecartoons/bean/event/EventFollow;)V", "onStart", "onDestroyView", "registerItemChildEvent", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class MyFansAndFollowsFragment extends BaseListFragment<PostHomeResponse.HLSFollowerBean> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @NotNull
    private static String into_type = "";

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u000b\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\r\u0010\u000eJ\u0015\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0005\u0010\u0006R\"\u0010\u0007\u001a\u00020\u00028\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u0007\u0010\b\u001a\u0004\b\t\u0010\n\"\u0004\b\u000b\u0010\f¨\u0006\u000f"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/mine/MyFansAndFollowsFragment$Companion;", "", "", "type", "Lcom/jbzd/media/movecartoons/ui/mine/MyFansAndFollowsFragment;", "newInstance", "(Ljava/lang/String;)Lcom/jbzd/media/movecartoons/ui/mine/MyFansAndFollowsFragment;", "into_type", "Ljava/lang/String;", "getInto_type", "()Ljava/lang/String;", "setInto_type", "(Ljava/lang/String;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final String getInto_type() {
            return MyFansAndFollowsFragment.into_type;
        }

        @NotNull
        public final MyFansAndFollowsFragment newInstance(@NotNull String type) {
            Intrinsics.checkNotNullParameter(type, "type");
            setInto_type(type);
            return new MyFansAndFollowsFragment();
        }

        public final void setInto_type(@NotNull String str) {
            Intrinsics.checkNotNullParameter(str, "<set-?>");
            MyFansAndFollowsFragment.into_type = str;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindItem$lambda-2$lambda-1$lambda-0, reason: not valid java name */
    public static final void m5861bindItem$lambda2$lambda1$lambda0(MyFansAndFollowsFragment this$0, BaseViewHolder this_run, PostHomeResponse.HLSFollowerBean item, TextView this_apply, View view) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(this_run, "$this_run");
        Intrinsics.checkNotNullParameter(item, "$item");
        Intrinsics.checkNotNullParameter(this_apply, "$this_apply");
        this$0.getAdapter().getData().get(this_run.getAdapterPosition()).has_follow = Intrinsics.areEqual(item.has_follow, "n") ? "y" : "n";
        this_apply.setSelected(Intrinsics.areEqual(this$0.getAdapter().getData().get(this_run.getAdapterPosition()).has_follow, "y"));
        this_run.m3919i(R.id.itv_postuser_follow, Intrinsics.areEqual(this$0.getAdapter().getData().get(this_run.getAdapterPosition()).has_follow, "y") ? "已关注" : "+关注");
        this$0.getAdapter().notifyItemChanged(this_run.getAdapterPosition());
        if (Intrinsics.areEqual(item.user_id, "")) {
            String str = item.f9978id;
            Intrinsics.checkNotNullExpressionValue(str, "item.id");
            this$0.follow(str);
        } else {
            String str2 = item.user_id;
            Intrinsics.checkNotNullExpressionValue(str2, "item.user_id");
            this$0.follow(str2);
        }
    }

    private final void follow(final String userId) {
        C0917a c0917a = C0917a.f372a;
        HashMap m595Q = C1499a.m595Q("id", userId);
        Unit unit = Unit.INSTANCE;
        C0917a.m221e(c0917a, "user/doFollow", Object.class, m595Q, new Function1<Object, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MyFansAndFollowsFragment$follow$2
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
            public final void invoke2(@Nullable Object obj) {
                if (obj == null) {
                    return;
                }
                String str = userId;
                C4909c m5569b = C4909c.m5569b();
                String obj2 = obj.toString();
                HashMap hashMap = new HashMap();
                if (!(obj2 == null || obj2.length() == 0)) {
                    try {
                        JSONObject jSONObject = new JSONObject(obj2);
                        Iterator<String> keys = jSONObject.keys();
                        while (keys.hasNext()) {
                            String key = keys.next();
                            String value = jSONObject.getString(key);
                            Intrinsics.checkNotNullExpressionValue(key, "key");
                            Intrinsics.checkNotNullExpressionValue(value, "value");
                            hashMap.put(key, value);
                        }
                    } catch (Exception e2) {
                        e2.printStackTrace();
                    }
                }
                m5569b.m5574g(new EventSubscription(str, (String) hashMap.get(NotificationCompat.CATEGORY_STATUS)));
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MyFansAndFollowsFragment$follow$3
            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                invoke2(exc);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Exception it) {
                Intrinsics.checkNotNullParameter(it, "it");
            }
        }, false, false, null, false, 480);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment, com.jbzd.media.movecartoons.core.MyThemeFragment, com.qunidayede.supportlibrary.core.view.BaseThemeFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @NotNull
    public String getEmptyTips() {
        return "未找到相关内容";
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public int getItemLayoutId() {
        return R.layout.item_follow_upper;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @NotNull
    public RecyclerView.LayoutManager getLayoutManager() {
        return new GridLayoutManager(requireContext(), 1);
    }

    @Override // androidx.fragment.app.Fragment
    public void onDestroy() {
        super.onDestroy();
        cancelJob(getLoadJob());
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment, androidx.fragment.app.Fragment
    public void onDestroyView() {
        super.onDestroyView();
        C4909c.m5569b().m5580m(this);
    }

    @InterfaceC4919m(threadMode = ThreadMode.MAIN)
    public final void onFollow(@NotNull EventFollow event) {
        Intrinsics.checkNotNullParameter(event, "event");
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public void onItemClick(@NotNull BaseQuickAdapter<PostHomeResponse.HLSFollowerBean, BaseViewHolder> adapter, @NotNull View view, int position) {
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        C2354n.m2525w0("进入用户详情~.~");
    }

    @Override // androidx.fragment.app.Fragment
    public void onStart() {
        super.onStart();
        if (C4909c.m5569b().m5573f(this)) {
            return;
        }
        C4909c.m5569b().m5578k(this);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public void registerItemChildEvent() {
        registerItemChildClick(R.id.ll_follow_item);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @Nullable
    public InterfaceC3053d1 request() {
        HashMap hashMap = new HashMap();
        hashMap.put("page", String.valueOf(getCurrentPage()));
        hashMap.put("page_size", getPageSize());
        Unit unit = Unit.INSTANCE;
        setLoadJob(C0917a.m222f(C0917a.f372a, "user/up", PostHomeResponse.HLSFollowerBean.class, hashMap, new Function1<List<? extends PostHomeResponse.HLSFollowerBean>, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MyFansAndFollowsFragment$request$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(List<? extends PostHomeResponse.HLSFollowerBean> list) {
                invoke2(list);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable List<? extends PostHomeResponse.HLSFollowerBean> list) {
                MyFansAndFollowsFragment.this.didRequestComplete(list == null ? null : CollectionsKt___CollectionsKt.toMutableList((Collection) list));
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MyFansAndFollowsFragment$request$3
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
                MyFansAndFollowsFragment.this.didRequestError();
            }
        }, false, false, null, false, 480));
        return getLoadJob();
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public void bindItem(@NotNull final BaseViewHolder helper, @NotNull final PostHomeResponse.HLSFollowerBean item) {
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(item, "item");
        C2354n.m2455a2(requireContext()).m3298p(item.img).m3292f0().m757R((ImageView) helper.m3912b(R.id.civ_avatar));
        helper.m3916f(R.id.iv_subheader_vip, true);
        helper.m3916f(R.id.iv_subheader_vip, !Intrinsics.areEqual(item.is_up, "y"));
        helper.m3919i(R.id.tv_postdetail_nickname, item.nickname);
        helper.m3919i(R.id.tv_follow_fans, Intrinsics.stringPlus("粉丝", C0843e0.m182a(item.fans)));
        helper.m3919i(R.id.tv_follow_follows, Intrinsics.stringPlus("关注", C0843e0.m182a(item.follow)));
        final TextView textView = (TextView) helper.m3912b(R.id.itv_postuser_follow);
        helper.m3919i(R.id.itv_postuser_follow, Intrinsics.areEqual(item.has_follow, "y") ? "已关注" : "+关注");
        textView.setSelected(Intrinsics.areEqual(item.has_follow, "y"));
        textView.setOnClickListener(new View.OnClickListener() { // from class: b.a.a.a.t.h.b
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                MyFansAndFollowsFragment.m5861bindItem$lambda2$lambda1$lambda0(MyFansAndFollowsFragment.this, helper, item, textView, view);
            }
        });
        C2354n.m2374A(helper.m3912b(R.id.civ_avatar), 0L, new Function1<CircleImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MyFansAndFollowsFragment$bindItem$1$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(CircleImageView circleImageView) {
                invoke2(circleImageView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull CircleImageView it) {
                Intrinsics.checkNotNullParameter(it, "it");
                if (Intrinsics.areEqual(PostHomeResponse.HLSFollowerBean.this.user_id, "")) {
                    UserPostHomeActivity.Companion companion = UserPostHomeActivity.Companion;
                    Context requireContext = this.requireContext();
                    Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                    String str = PostHomeResponse.HLSFollowerBean.this.f9978id;
                    Intrinsics.checkNotNullExpressionValue(str, "item.id");
                    companion.start(requireContext, str);
                    return;
                }
                UserPostHomeActivity.Companion companion2 = UserPostHomeActivity.Companion;
                Context requireContext2 = this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext2, "requireContext()");
                String str2 = PostHomeResponse.HLSFollowerBean.this.user_id;
                Intrinsics.checkNotNullExpressionValue(str2, "item.user_id");
                companion2.start(requireContext2, str2);
            }
        }, 1);
    }
}
