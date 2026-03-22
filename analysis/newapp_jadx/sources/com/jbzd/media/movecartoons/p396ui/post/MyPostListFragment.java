package com.jbzd.media.movecartoons.p396ui.post;

import android.os.Bundle;
import android.widget.ImageView;
import android.widget.LinearLayout;
import androidx.core.app.NotificationCompat;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.bean.response.FindBean;
import com.jbzd.media.movecartoons.bean.response.PostListBean;
import com.jbzd.media.movecartoons.p396ui.search.child.CommonPostListFragment;
import com.qnmd.adnnm.da0yzo.R;
import java.io.Serializable;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p017r.C0917a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.InterfaceC3053d1;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000D\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u000b\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0010\b\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0014\u0018\u0000 .2\u00020\u0001:\u0001.B\u0007¢\u0006\u0004\b-\u0010\u0011J:\u0010\u000b\u001a\u00020\t2\u0006\u0010\u0003\u001a\u00020\u00022!\u0010\n\u001a\u001d\u0012\u0013\u0012\u00110\u0005¢\u0006\f\b\u0006\u0012\b\b\u0007\u0012\u0004\b\b(\b\u0012\u0004\u0012\u00020\t0\u0004H\u0002¢\u0006\u0004\b\u000b\u0010\fJ\u000f\u0010\u000e\u001a\u00020\rH\u0016¢\u0006\u0004\b\u000e\u0010\u000fJ\u000f\u0010\u0010\u001a\u00020\tH\u0016¢\u0006\u0004\b\u0010\u0010\u0011J\u000f\u0010\u0012\u001a\u00020\tH\u0016¢\u0006\u0004\b\u0012\u0010\u0011J\u000f\u0010\u0013\u001a\u00020\rH\u0016¢\u0006\u0004\b\u0013\u0010\u000fJ\u001f\u0010\u0018\u001a\u00020\t2\u0006\u0010\u0015\u001a\u00020\u00142\u0006\u0010\u0017\u001a\u00020\u0016H\u0016¢\u0006\u0004\b\u0018\u0010\u0019J\u000f\u0010\u001a\u001a\u00020\tH\u0016¢\u0006\u0004\b\u001a\u0010\u0011J\u000f\u0010\u001c\u001a\u00020\u001bH\u0016¢\u0006\u0004\b\u001c\u0010\u001dJ\u000f\u0010\u001e\u001a\u00020\rH\u0016¢\u0006\u0004\b\u001e\u0010\u000fJ\u000f\u0010\u001f\u001a\u00020\rH\u0016¢\u0006\u0004\b\u001f\u0010\u000fR\u0018\u0010 \u001a\u0004\u0018\u00010\u001b8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b \u0010!R\u001d\u0010&\u001a\u00020\u00028B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\"\u0010#\u001a\u0004\b$\u0010%R\"\u0010'\u001a\u00020\u00058\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b'\u0010(\u001a\u0004\b)\u0010*\"\u0004\b+\u0010,¨\u0006/"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/post/MyPostListFragment;", "Lcom/jbzd/media/movecartoons/ui/search/child/CommonPostListFragment;", "", "id", "Lkotlin/Function1;", "", "Lkotlin/ParameterName;", "name", "bool", "", FindBean.status_success, "postDelete", "(Ljava/lang/String;Lkotlin/jvm/functions/Function1;)V", "", "getLayout", "()I", "initViews", "()V", "onResume", "getItemLayoutId", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "helper", "Lcom/jbzd/media/movecartoons/bean/response/PostListBean;", "item", "bindItem", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/PostListBean;)V", "registerItemChildEvent", "Lc/a/d1;", "request", "()Lc/a/d1;", "getLeftPadding", "getRightPadding", "doFollowJob", "Lc/a/d1;", "mPostType$delegate", "Lkotlin/Lazy;", "getMPostType", "()Ljava/lang/String;", "mPostType", "refresh", "Z", "getRefresh", "()Z", "setRefresh", "(Z)V", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class MyPostListFragment extends CommonPostListFragment {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @NotNull
    private static final String KEY_TAB = "tab_key";

    @Nullable
    private InterfaceC3053d1 doFollowJob;

    /* renamed from: mPostType$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mPostType = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.post.MyPostListFragment$mPostType$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final String invoke() {
            Bundle arguments = MyPostListFragment.this.getArguments();
            Serializable serializable = arguments == null ? null : arguments.getSerializable("tab_key");
            Objects.requireNonNull(serializable, "null cannot be cast to non-null type kotlin.String");
            return (String) serializable;
        }
    });
    private boolean refresh = true;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0007\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\t\u0010\nJ\u0017\u0010\u0005\u001a\u00020\u00042\b\u0010\u0003\u001a\u0004\u0018\u00010\u0002¢\u0006\u0004\b\u0005\u0010\u0006R\u0016\u0010\u0007\u001a\u00020\u00028\u0002@\u0002X\u0082T¢\u0006\u0006\n\u0004\b\u0007\u0010\b¨\u0006\u000b"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/post/MyPostListFragment$Companion;", "", "", "type", "Lcom/jbzd/media/movecartoons/ui/post/MyPostListFragment;", "newInstance", "(Ljava/lang/String;)Lcom/jbzd/media/movecartoons/ui/post/MyPostListFragment;", "KEY_TAB", "Ljava/lang/String;", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final MyPostListFragment newInstance(@Nullable String type) {
            MyPostListFragment myPostListFragment = new MyPostListFragment();
            myPostListFragment.setIntoType("userPostHomePage");
            Bundle bundle = new Bundle();
            bundle.putSerializable(MyPostListFragment.KEY_TAB, type);
            Unit unit = Unit.INSTANCE;
            myPostListFragment.setArguments(bundle);
            return myPostListFragment;
        }
    }

    private final String getMPostType() {
        return (String) this.mPostType.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void postDelete(String id, final Function1<? super Boolean, Unit> success) {
        HashMap hashMap = new HashMap();
        hashMap.put("id", id);
        this.doFollowJob = C0917a.m221e(C0917a.f372a, "post/delete", String.class, hashMap, new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.MyPostListFragment$postDelete$1
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(String str) {
                invoke2(str);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable String str) {
                C2354n.m2409L1("删除成功");
                success.invoke(Boolean.TRUE);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.MyPostListFragment$postDelete$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
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
                C2354n.m2449Z("删除失败");
                success.invoke(Boolean.FALSE);
            }
        }, false, false, null, false, 480);
    }

    @Override // com.jbzd.media.movecartoons.p396ui.search.child.CommonPostListFragment, com.jbzd.media.movecartoons.p396ui.search.child.BaseCommonPostListFragment, com.jbzd.media.movecartoons.core.BaseListFragment, com.jbzd.media.movecartoons.core.MyThemeFragment, com.qunidayede.supportlibrary.core.view.BaseThemeFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.jbzd.media.movecartoons.p396ui.search.child.CommonPostListFragment, com.jbzd.media.movecartoons.core.BaseListFragment
    public int getItemLayoutId() {
        return R.layout.item_posthome_postitem;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public int getLayout() {
        return R.layout.list_frag;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public int getLeftPadding() {
        return 0;
    }

    public final boolean getRefresh() {
        return this.refresh;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public int getRightPadding() {
        return 0;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void initViews() {
        super.initViews();
        request();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment, androidx.fragment.app.Fragment
    public void onResume() {
        super.onResume();
        this.refresh = true;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public void registerItemChildEvent() {
    }

    @Override // com.jbzd.media.movecartoons.p396ui.search.child.BaseCommonPostListFragment, com.jbzd.media.movecartoons.core.BaseListFragment
    @NotNull
    public InterfaceC3053d1 request() {
        HashMap hashMap = new HashMap();
        hashMap.put(NotificationCompat.CATEGORY_STATUS, getMPostType());
        hashMap.put("page", String.valueOf(getCurrentPage()));
        return C0917a.m222f(C0917a.f372a, "post/my", PostListBean.class, hashMap, new Function1<List<? extends PostListBean>, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.MyPostListFragment$request$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(List<? extends PostListBean> list) {
                invoke2(list);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable List<? extends PostListBean> list) {
                if (list == null) {
                    return;
                }
                MyPostListFragment.this.didRequestComplete(CollectionsKt___CollectionsKt.toMutableList((Collection) list));
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.MyPostListFragment$request$3
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

    public final void setRefresh(boolean z) {
        this.refresh = z;
    }

    /* JADX WARN: Can't rename method to resolve collision */
    @Override // com.jbzd.media.movecartoons.p396ui.search.child.CommonPostListFragment, com.jbzd.media.movecartoons.core.BaseListFragment
    public void bindItem(@NotNull BaseViewHolder helper, @NotNull final PostListBean item) {
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(item, "item");
        super.bindItem(helper, item);
        ((LinearLayout) helper.m3912b(R.id.ll_mypost_time_del)).setVisibility(0);
        C2354n.m2374A(helper.m3912b(R.id.iv_mypost_del), 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.MyPostListFragment$bindItem$1$1
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ImageView imageView) {
                invoke2(imageView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull ImageView it) {
                Intrinsics.checkNotNullParameter(it, "it");
                MyPostListFragment myPostListFragment = MyPostListFragment.this;
                String str = item.f9980id;
                Intrinsics.checkNotNullExpressionValue(str, "item.id");
                final MyPostListFragment myPostListFragment2 = MyPostListFragment.this;
                final PostListBean postListBean = item;
                myPostListFragment.postDelete(str, new Function1<Boolean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.MyPostListFragment$bindItem$1$1.1
                    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                    {
                        super(1);
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(Boolean bool) {
                        invoke(bool.booleanValue());
                        return Unit.INSTANCE;
                    }

                    public final void invoke(boolean z) {
                        MyPostListFragment.this.hideLoadingDialog();
                        MyPostListFragment.this.getAdapter().getData().remove(postListBean);
                        MyPostListFragment.this.getAdapter().notifyDataSetChanged();
                    }
                });
            }
        }, 1);
    }
}
